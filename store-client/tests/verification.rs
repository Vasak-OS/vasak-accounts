//! Pruebas sin bus: un impostor que se presenta como dueño no es de confianza,
//! y el servicio de verdad sí.
//!
//! El sabotaje es real —un proceso de verdad hace de impostor, con su propio
//! `/proc/<pid>/exe`, que es justo lo que el verificador mira—, no una prueba en
//! negativo. Ver `sabotaje-que-escribe-el-estado-real`.
//!
//! Están en `tests/` y no en línea a propósito: así SonarCloud no cuenta las
//! líneas de las pruebas como código de producción a cubrir. El cableado de zbus
//! contra un bus de verdad va en `tests/real_bus.rs`.
//!
//! Nada de esto escribe en un registro la ruta del dueño: los `panic!` y los
//! `assert!` no interpolan el `exe`, para que CodeQL no vea una fuga de la ruta
//! de un proceso ajeno.

use std::path::PathBuf;
use std::process::{Child, Command};

use vasak_accounts_store_client::{
    trusted_owner, BoxFuture, OwnerResolver, ServiceIdentity, TrustError, INSTALLED_EXECUTABLE,
    SERVICE_NAME,
};

/// Un proceso de verdad que hace de impostor: existe, tiene su `exe`, y no es el
/// servicio. Se mata solo al salir del alcance.
struct Impostor(Child);

impl Impostor {
    fn start() -> Self {
        let child = Command::new("sleep")
            .arg("120")
            .spawn()
            .expect("no se pudo arrancar el proceso impostor");
        Impostor(child)
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }

    /// El binario que el impostor ejecuta de verdad, para la prueba del camino
    /// que **sí** confía. Se lee del enlace del núcleo, no de la crate.
    fn executable(&self) -> PathBuf {
        std::fs::read_link(format!("/proc/{}/exe", self.pid()))
            .expect("el impostor tiene que tener un exe")
    }
}

impl Drop for Impostor {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Un resolvedor que contesta lo que se le diga, sin bus. El pid que devuelve es
/// el de un proceso de verdad, así que `/proc/<pid>/exe` se lee de verdad.
struct FakeResolver {
    owner: Option<String>,
    pid: u32,
}

impl OwnerResolver for FakeResolver {
    fn name_owner<'a>(&'a self, _name: &'a str) -> BoxFuture<'a, Result<Option<String>, String>> {
        let owner = self.owner.clone();
        Box::pin(async move { Ok(owner) })
    }

    fn process_id<'a>(&'a self, _unique_name: &'a str) -> BoxFuture<'a, Result<u32, String>> {
        let pid = self.pid;
        Box::pin(async move { Ok(pid) })
    }
}

#[tokio::test]
async fn un_impostor_que_toma_el_nombre_no_es_de_confianza() {
    let impostor = Impostor::start();
    let resolver = FakeResolver {
        owner: Some(":1.42".to_owned()),
        pid: impostor.pid(),
    };

    let resultado = trusted_owner(&resolver, SERVICE_NAME, &ServiceIdentity::installed()).await;

    match resultado {
        Err(TrustError::WrongOwner { pid, executable }) => {
            assert_eq!(pid, impostor.pid());
            // Se leyó su exe de verdad, y no es el del servicio. No se imprime.
            assert!(executable.is_some());
            assert!(executable.as_deref() != Some(std::path::Path::new(INSTALLED_EXECUTABLE)));
        }
        _ => panic!("un impostor tenía que ser rechazado"),
    }
}

#[tokio::test]
async fn el_dueno_cuyo_exe_coincide_es_de_confianza() {
    let servicio = Impostor::start();
    let resolver = FakeResolver {
        owner: Some(":1.7".to_owned()),
        pid: servicio.pid(),
    };

    // La identidad apunta al binario que el proceso ejecuta de verdad: es lo que
    // pasaría si ese proceso fuera el servicio instalado.
    let identity = ServiceIdentity {
        executable: servicio.executable(),
    };

    let owner = trusted_owner(&resolver, SERVICE_NAME, &identity)
        .await
        .expect("el dueño cuyo exe coincide tiene que ser de confianza");
    assert_eq!(owner, ":1.7");
}

#[tokio::test]
async fn un_nombre_sin_dueno_no_es_de_confianza() {
    let resolver = FakeResolver {
        owner: None,
        pid: 0,
    };
    let resultado = trusted_owner(&resolver, SERVICE_NAME, &ServiceIdentity::installed()).await;
    assert!(matches!(resultado, Err(TrustError::NoOwner)));
}

#[tokio::test]
async fn un_error_del_bus_al_resolver_el_dueno_no_es_de_confianza() {
    struct Roto;
    impl OwnerResolver for Roto {
        fn name_owner<'a>(
            &'a self,
            _name: &'a str,
        ) -> BoxFuture<'a, Result<Option<String>, String>> {
            Box::pin(async { Err("el bus no contesta".to_owned()) })
        }
        fn process_id<'a>(&'a self, _unique_name: &'a str) -> BoxFuture<'a, Result<u32, String>> {
            Box::pin(async { Ok(0) })
        }
    }
    let resultado = trusted_owner(&Roto, SERVICE_NAME, &ServiceIdentity::installed()).await;
    assert!(matches!(resultado, Err(TrustError::Bus(_))));
}

#[tokio::test]
async fn un_error_del_bus_al_pedir_el_pid_no_es_de_confianza() {
    struct SinPid;
    impl OwnerResolver for SinPid {
        fn name_owner<'a>(
            &'a self,
            _name: &'a str,
        ) -> BoxFuture<'a, Result<Option<String>, String>> {
            Box::pin(async { Ok(Some(":1.9".to_owned())) })
        }
        fn process_id<'a>(&'a self, _unique_name: &'a str) -> BoxFuture<'a, Result<u32, String>> {
            Box::pin(async { Err("no se pudo leer el pid".to_owned()) })
        }
    }
    let resultado = trusted_owner(&SinPid, SERVICE_NAME, &ServiceIdentity::installed()).await;
    assert!(matches!(resultado, Err(TrustError::Bus(_))));
}

#[tokio::test]
async fn un_pid_que_no_existe_no_es_de_confianza() {
    // El pid máximo de Linux es 2^22; éste no puede existir, así que el `exe` no
    // se puede leer: falla cerrado como «el proceso se fue».
    let resolver = FakeResolver {
        owner: Some(":1.3".to_owned()),
        pid: u32::MAX,
    };
    let resultado = trusted_owner(&resolver, SERVICE_NAME, &ServiceIdentity::installed()).await;
    assert!(matches!(resultado, Err(TrustError::ProcessGone(_))));
}

#[tokio::test]
async fn un_proceso_vivo_cuyo_exe_no_es_el_servicio_se_rechaza() {
    // Un proceso de verdad, con un `exe` que se lee de verdad, pero que no es el
    // binario esperado: se rechaza aunque el proceso exista. El cgroup ya no
    // participa —no hay respaldo que un atacante del mismo uid pueda forjar—.
    let impostor = Impostor::start();
    let resolver = FakeResolver {
        owner: Some(":1.5".to_owned()),
        pid: impostor.pid(),
    };
    let identity = ServiceIdentity {
        executable: PathBuf::from("/usr/bin/no-existe-este-binario"),
    };
    let resultado = trusted_owner(&resolver, SERVICE_NAME, &identity).await;
    assert!(matches!(resultado, Err(TrustError::WrongOwner { .. })));
}

#[test]
fn los_mensajes_de_error_no_llevan_la_ruta_del_dueno() {
    // `Display` es lo que un consumidor escribe en su registro: no puede llevar
    // la ruta de un proceso ajeno.
    let con_ruta = TrustError::WrongOwner {
        pid: 4242,
        executable: Some(PathBuf::from("/tmp/impostor-secreto")),
    };
    let texto = con_ruta.to_string();
    assert!(texto.contains("4242"));
    assert!(!texto.contains("impostor-secreto"));

    // Las demás variantes también dan un texto con su dato clave.
    assert!(TrustError::NoOwner.to_string().contains(SERVICE_NAME));
    assert!(TrustError::Bus("roto".to_owned())
        .to_string()
        .contains("roto"));
    assert!(TrustError::ProcessGone(7).to_string().contains('7'));
}

#[test]
fn la_identidad_por_omision_es_la_del_servicio_instalado() {
    let por_omision = ServiceIdentity::default();
    assert_eq!(por_omision.executable, PathBuf::from(INSTALLED_EXECUTABLE));
}
