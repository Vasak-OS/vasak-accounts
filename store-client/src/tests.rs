//! Pruebas del lado del consumidor: un impostor que toma el nombre no es de
//! confianza, y el servicio de verdad sí.
//!
//! Se sabotea de verdad —un proceso real toma el nombre, o se le presenta al
//! verificador como dueño— y se comprueba que el cliente **rehúsa**. No es una
//! prueba en negativo: el impostor existe y tiene su propio `/proc/<pid>/exe`,
//! que es justo lo que el verificador mira. Ver `sabotaje-que-escribe-el-estado-real`.

use super::*;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

/// Un proceso de verdad que hace de impostor: existe, tiene su `exe`, y no es
/// el servicio. Se mata solo al salir del alcance.
struct Impostor(Child);

impl Impostor {
    /// Arranca un `sleep` largo. Su `/proc/<pid>/exe` es el de `sleep`, que no
    /// es `/usr/bin/vasak-accounts-sync`.
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
    /// que **sí** confía.
    fn executable(&self) -> PathBuf {
        process_executable(self.pid()).expect("el impostor tiene que tener un exe")
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

    // La identidad de producción: el binario instalado del servicio.
    let resultado = trusted_owner(&resolver, SERVICE_NAME, &ServiceIdentity::installed()).await;

    match resultado {
        Err(TrustError::WrongOwner { pid, executable }) => {
            assert_eq!(pid, impostor.pid());
            // Se leyó su exe de verdad, y no es el del servicio.
            assert!(executable.is_some());
            assert_ne!(executable.unwrap(), PathBuf::from(INSTALLED_EXECUTABLE));
        }
        otro => panic!("un impostor tenía que ser rechazado, no {otro:?}"),
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
        unit: "ninguna.service".to_owned(),
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
async fn un_error_del_bus_no_es_de_confianza() {
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
async fn el_respaldo_por_cgroup_reconoce_la_unidad_del_proceso() {
    // El cgroup del propio proceso de prueba existe y se puede leer; se busca en
    // él una línea que exista de verdad, para ejercitar la rama del respaldo sin
    // depender de que el servicio esté corriendo.
    let pid = std::process::id();
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .expect("el cgroup del proceso de prueba se tiene que poder leer");
    let primera = cgroup
        .lines()
        .next()
        .and_then(|l| l.rsplit('/').next())
        .filter(|s| !s.is_empty())
        .expect("el cgroup tiene que tener al menos una hoja");

    let resolver = FakeResolver {
        owner: Some(":1.1".to_owned()),
        pid,
    };
    // Un exe que no coincide fuerza a caer al respaldo; la unidad es la hoja del
    // cgroup de verdad del proceso de prueba.
    let identity = ServiceIdentity {
        executable: PathBuf::from("/usr/bin/no-existe-este-binario"),
        unit: primera.to_owned(),
    };

    let owner = trusted_owner(&resolver, SERVICE_NAME, &identity)
        .await
        .expect("el respaldo por cgroup tenía que reconocer la unidad");
    assert_eq!(owner, ":1.1");
}

// ── Las pruebas de bus real ─────────────────────────────────────────────────
//
// Levantan un `dbus-daemon` propio, el proceso de prueba toma el nombre en él, y
// el `DbusOwnerResolver` lo resuelve de verdad. Prueban el cableado de zbus, no
// sólo la lógica. Si no hay `dbus-daemon`, se avisan y no corren —las de arriba
// ya garantizan el rechazo sin bus—.

/// Un `dbus-daemon` de sesión sólo para la prueba. Se mata al salir del alcance.
struct TestBus {
    child: Child,
    address: String,
    config: PathBuf,
}

impl TestBus {
    /// Levanta el bus, o `None` si no hay `dbus-daemon` en el equipo.
    fn launch() -> Option<Self> {
        let config = std::env::temp_dir().join(format!(
            "vasak-store-client-bus-{}-{}.conf",
            std::process::id(),
            fastish_id()
        ));
        std::fs::write(
            &config,
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:tmpdir=/tmp</listen>
  <policy context="default">
    <allow own="*"/>
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
  </policy>
</busconfig>
"#,
        )
        .ok()?;

        let mut child = Command::new("dbus-daemon")
            .arg(format!("--config-file={}", config.display()))
            .arg("--print-address")
            .arg("--nofork")
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| {
                let _ = std::fs::remove_file(&config);
            })
            .ok()?;

        let stdout = child.stdout.take()?;
        let mut address = String::new();
        if BufReader::new(stdout).read_line(&mut address).is_err() || address.trim().is_empty() {
            let _ = child.kill();
            let _ = std::fs::remove_file(&config);
            return None;
        }

        Some(TestBus {
            child,
            address: address.trim().to_owned(),
            config,
        })
    }

    fn address(&self) -> &str {
        &self.address
    }
}

impl Drop for TestBus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config);
    }
}

/// Un identificador barato y único por proceso, para el nombre del archivo de
/// configuración del bus.
fn fastish_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[tokio::test]
async fn un_impostor_que_toma_el_nombre_en_un_bus_real_es_rechazado() {
    let Some(bus) = TestBus::launch() else {
        eprintln!("sin dbus-daemon: se omite la prueba de bus real");
        return;
    };
    let connection = zbus::connection::Builder::address(bus.address())
        .expect("la dirección del bus de prueba tiene que ser válida")
        .build()
        .await
        .expect("conectar al bus de prueba");

    // El proceso de prueba toma el nombre del servicio. Su exe es el runner de
    // cargo, no `/usr/bin/vasak-accounts-sync`: es el impostor.
    connection
        .request_name(SERVICE_NAME)
        .await
        .expect("tomar el nombre en el bus de prueba");

    let resultado = trusted_sync_owner(&connection).await;
    match resultado {
        Err(TrustError::WrongOwner { pid, .. }) => {
            assert_eq!(pid, std::process::id());
        }
        otro => panic!("el impostor del bus real tenía que ser rechazado, no {otro:?}"),
    }
}

#[tokio::test]
async fn el_servicio_de_verdad_en_un_bus_real_es_de_confianza() {
    let Some(bus) = TestBus::launch() else {
        eprintln!("sin dbus-daemon: se omite la prueba de bus real");
        return;
    };
    let connection = zbus::connection::Builder::address(bus.address())
        .expect("la dirección del bus de prueba tiene que ser válida")
        .build()
        .await
        .expect("conectar al bus de prueba");

    connection
        .request_name(SERVICE_NAME)
        .await
        .expect("tomar el nombre en el bus de prueba");

    // La identidad apunta al binario que el proceso de prueba ejecuta de verdad:
    // es lo que pasaría si el dueño del nombre fuera el servicio instalado.
    let identity = ServiceIdentity {
        executable: process_executable(std::process::id()).expect("el proceso tiene exe"),
        unit: "ninguna.service".to_owned(),
    };
    let resolver = DbusOwnerResolver::new(&connection)
        .await
        .expect("crear el resolvedor");

    let owner = trusted_owner(&resolver, SERVICE_NAME, &identity)
        .await
        .expect("el dueño cuyo exe coincide tiene que ser de confianza");
    assert!(
        owner.starts_with(':'),
        "el dueño verificado tiene que ser un nombre único, fue {owner}"
    );
}
