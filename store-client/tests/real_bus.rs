//! Pruebas de bus real: levantan un `dbus-daemon` propio, el proceso de prueba
//! toma el nombre del servicio en él, y el `DbusOwnerResolver` lo resuelve de
//! verdad. Prueban el cableado de zbus (`GetNameOwner`,
//! `GetConnectionUnixProcessID`), no sólo la lógica.
//!
//! El CI instala `dbus` (`paquetes_rust: dbus` en el `ci.yml`), así que acá sí
//! corren y cubren el `DbusOwnerResolver`. Si por lo que sea no hay
//! `dbus-daemon`, se avisan y no corren —las de `verification.rs` ya garantizan
//! el rechazo sin bus—.
//!
//! No se escribe en ningún registro la ruta del dueño: los `panic!` y los
//! `assert!` no interpolan el `exe`.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use vasak_accounts_store_client::{
    trusted_owner, trusted_sync_owner, DbusOwnerResolver, ServiceIdentity, TrustError, SERVICE_NAME,
};

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

async fn connect(bus: &TestBus) -> zbus::Connection {
    zbus::connection::Builder::address(bus.address())
        .expect("la dirección del bus de prueba tiene que ser válida")
        .build()
        .await
        .expect("conectar al bus de prueba")
}

#[tokio::test]
async fn un_impostor_que_toma_el_nombre_en_un_bus_real_es_rechazado() {
    let Some(bus) = TestBus::launch() else {
        eprintln!("sin dbus-daemon: se omite la prueba de bus real");
        return;
    };
    let connection = connect(&bus).await;

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
        _ => panic!("el impostor del bus real tenía que ser rechazado"),
    }
}

#[tokio::test]
async fn el_servicio_de_verdad_en_un_bus_real_es_de_confianza() {
    let Some(bus) = TestBus::launch() else {
        eprintln!("sin dbus-daemon: se omite la prueba de bus real");
        return;
    };
    let connection = connect(&bus).await;

    connection
        .request_name(SERVICE_NAME)
        .await
        .expect("tomar el nombre en el bus de prueba");

    // La identidad apunta al binario que el proceso de prueba ejecuta de verdad:
    // es lo que pasaría si el dueño del nombre fuera el servicio instalado. Así
    // se ejercita el camino que **sí** confía con el `DbusOwnerResolver` real.
    let identity = ServiceIdentity {
        executable: std::fs::read_link(format!("/proc/{}/exe", std::process::id()))
            .expect("el proceso de prueba tiene exe"),
        unit: "ninguna.service".to_owned(),
    };
    let resolver = DbusOwnerResolver::new(&connection)
        .await
        .expect("crear el resolvedor");

    let owner = trusted_owner(&resolver, SERVICE_NAME, &identity)
        .await
        .expect("el dueño cuyo exe coincide tiene que ser de confianza");
    assert!(owner.starts_with(':'));
}

#[tokio::test]
async fn un_nombre_sin_dueno_en_un_bus_real_no_es_de_confianza() {
    let Some(bus) = TestBus::launch() else {
        eprintln!("sin dbus-daemon: se omite la prueba de bus real");
        return;
    };
    // Nadie toma el nombre: el bus no le encuentra dueño.
    let connection = connect(&bus).await;
    let resultado = trusted_sync_owner(&connection).await;
    assert!(matches!(resultado, Err(TrustError::NoOwner)));
}
