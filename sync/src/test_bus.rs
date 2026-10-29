//! Un bus de verdad para probar los métodos de `AccountsSync` **de punta a punta**.
//!
//! Los métodos que resuelven una cuenta hablan con el servicio de cuentas por el
//! bus del **sistema** (`Broker::connect`) y con el llavero por el bus de
//! **sesión**, y ninguno de los dos se puede inyectar: el único camino es tener
//! un bus. Acá se levanta un `dbus-daemon` privado, de la prueba, y se le
//! sirven un servicio de cuentas falso y el llavero falso de `store::key`.
//!
//! Dos cosas son de **todo el proceso** y por eso se fijan una sola vez, al
//! levantar el bus: `DBUS_SYSTEM_BUS_ADDRESS` (que es lo que lee
//! `Connection::system`) y `XDG_DATA_HOME` (donde cae la cola de salida). Como
//! los nombres de bus también son únicos, las pruebas que usan el bus **van en
//! fila**: [`Fixture::start`] toma un candado que se suelta al terminar.
//!
//! Hace falta `dbus-daemon` instalado. Si no está, las pruebas **fallan** con
//! eso dicho; no se saltean, porque una prueba que se salta en silencio es una
//! prueba que nadie nota que no corre.

use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};

use futures_util::future::{BoxFuture, FutureExt};

use crate::access::tests::Answer;
use crate::access::{Access, CallerProcess, PermissionBackend, SystemClock};
use crate::store::key::tests::{fake_keyring_on_bus, Shared};
use crate::store::key::SecretServiceKeys;

pub(crate) const SYNC_PATH: &str = "/ar/net/vasak/os/AccountsSync";
pub(crate) const SYNC_INTERFACE: &str = "ar.net.vasak.os.AccountsSync";

/// Una conexión por cabo del bus: el candado de las pruebas en fila.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Daemon {
    address: String,
    /// Mientras esté abierta, el `dbus-daemon` vive: el `sh` que lo lanzó lo mata
    /// cuando esta punta se cierra, que es cuando termina el proceso de pruebas
    /// (por las buenas o no), sin dejar un demonio huérfano.
    _keepalive: ChildStdin,
    _stdout: BufReader<std::process::ChildStdout>,
}

fn daemon() -> &'static Daemon {
    static DAEMON: OnceLock<Daemon> = OnceLock::new();
    DAEMON.get_or_init(|| {
        // No se espera al `sh`: vive lo que dure el proceso de pruebas (ver `_keepalive`).
        #[allow(clippy::zombie_processes)]
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(
                "dbus-daemon --session --nofork --address=unix:tmpdir=/tmp --print-address=1 & \
                 pid=$!; exec >/dev/null; cat; kill $pid",
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("no se pudo lanzar `sh`");
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut address = String::new();
        stdout.read_line(&mut address).unwrap();
        let address = address.trim().to_string();
        assert!(
            address.starts_with("unix:"),
            "no se pudo levantar `dbus-daemon` (¿está instalado?): {address:?}"
        );

        // Lo que es de todo el proceso, antes de que nadie conecte.
        let data_home =
            std::env::temp_dir().join(format!("vasak-sync-pruebas-{}", std::process::id()));
        std::fs::create_dir_all(&data_home).unwrap();
        std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", &address);
        std::env::set_var("XDG_DATA_HOME", &data_home);

        install_log_capture();

        Daemon {
            address,
            _keepalive: child.stdin.take().unwrap(),
            _stdout: stdout,
        }
    })
}

// ── Las trazas, capturadas ──────────────────────────────────────────────

static LOGS: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct Capture;

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOGS.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        Capture
    }
}

/// Un suscriptor global que junta lo que traza **este servicio** (`trace` y para
/// arriba), de cualquier hilo: el parseo del `.p12` corre en `spawn_blocking`.
///
/// Sólo el de este crate y sin el puente de `log`: las demás pruebas del proceso
/// (las de tiempo, que miden con reloj de pared) no pagan el formato de los
/// mensajes de `rrule` ni de `zbus`. Los mensajes de `zbus` a nivel `trace`
/// llevan la forma del cuerpo de las llamadas y no sus valores. Si ya hay un
/// suscriptor puesto, se queda el que estaba.
fn install_log_capture() {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "vasak_accounts_sync=trace",
        ))
        .with_ansi(false)
        .with_writer(Capture)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// Todo lo trazado desde el último [`Fixture::start`].
pub(crate) fn captured_logs() -> String {
    String::from_utf8_lossy(&LOGS.lock().unwrap()).into_owned()
}

// ── El servicio de cuentas falso ────────────────────────────────────────

/// `ListAccounts` y `GetAccountData`, con la forma que contesta el de verdad.
struct FakeAccountManager(Vec<(String, String)>);

#[zbus::interface(name = "ar.net.vasak.os.AccountManager")]
impl FakeAccountManager {
    async fn list_accounts(&self) -> String {
        let accounts: Vec<_> = self
            .0
            .iter()
            .map(|(id, _)| {
                serde_json::json!({
                    "id": id,
                    "display_name": id,
                    "provider_type": "custom",
                    "capabilities": ["email"],
                    "needs_reauth": false,
                })
            })
            .collect();
        serde_json::to_string(&accounts).unwrap()
    }

    async fn get_account_data(
        &self,
        account_id: String,
        capability: String,
    ) -> zbus::fdo::Result<String> {
        let (_, address) = self
            .0
            .iter()
            .find(|(id, _)| *id == account_id)
            .ok_or_else(|| zbus::fdo::Error::Failed("cuenta no encontrada".into()))?;
        Ok(serde_json::json!({
            "account_id": account_id,
            "capability": capability,
            "config": { "username": address },
        })
        .to_string())
    }
}

// ── La puerta de permisos del fixture ─────────────────────────────────────

/// Un [`PermissionBackend`] que contesta siempre lo mismo, **sin tocar ningún
/// bus**: la puerta de permisos de las pruebas de `AccountsSync`. Reusa el
/// [`Answer`] de `access::tests`. Por omisión el fixture lo arma con
/// [`Answer::Allow`], así que las pruebas que no son del gating ni se enteran.
struct FixedPermission(Answer);

impl PermissionBackend for FixedPermission {
    fn caller_process(
        &self,
        _unique_name: String,
    ) -> BoxFuture<'static, Result<CallerProcess, String>> {
        async {
            Ok(CallerProcess {
                pid: std::process::id(),
                pidfd: None,
            })
        }
        .boxed()
    }

    fn start_time(&self, _caller: &CallerProcess) -> Result<u64, String> {
        Ok(0)
    }

    fn check_permission_for(
        &self,
        _pid: u32,
        _start_time: u64,
        _resource: String,
        _detail: String,
    ) -> BoxFuture<'static, Result<bool, String>> {
        let answer = self.0;
        async move {
            match answer {
                Answer::Allow => Ok(true),
                Answer::Deny => Ok(false),
                Answer::Fail => Err("permiso roto (prueba)".to_string()),
            }
        }
        .boxed()
    }
}

// ── Todo junto ──────────────────────────────────────────────────────────

/// Un servicio `AccountsSync` de verdad, un servicio de cuentas con las cuentas
/// que se pidan y un llavero vacío, todos en el bus de la prueba, y un cliente.
pub(crate) struct Fixture {
    /// El cliente: la ventana de correo.
    pub client: zbus::Connection,
    /// El estado del llavero falso, para bloquearlo.
    pub keyring: Shared,
    /// La conexión del llavero falso, para avisar el bloqueo.
    pub keyring_server: zbus::Connection,
    service: zbus::Connection,
    _accounts: zbus::Connection,
    // Último: el candado se suelta después de cerrar todo lo de arriba.
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    /// `accounts`: `(id, dirección)` de cada cuenta que conoce el servicio de
    /// cuentas. La puerta de permisos de las mutaciones S/MIME dice que **sí** a
    /// todo: lo que prueban casi todas las pruebas es otra cosa.
    pub(crate) async fn start(accounts: &[(&str, &str)]) -> Self {
        Self::start_with_permission(accounts, Answer::Allow).await
    }

    /// Lo mismo, pero con la respuesta que da la puerta de permisos a las
    /// mutaciones de identidad S/MIME (`Allow`/`Deny`/`Fail`): para las pruebas
    /// del gating de `vasak-accounts#135`.
    pub(crate) async fn start_with_permission(accounts: &[(&str, &str)], answer: Answer) -> Self {
        let guard = LOCK.lock().await;
        let address = daemon().address.as_str();
        LOGS.lock().unwrap().clear();
        // La cola de salida de la prueba anterior no es de ésta.
        let _ = tokio::fs::remove_dir_all(crate::outbox::outbox_dir()).await;

        use zbus::fdo::RequestNameFlags::{AllowReplacement, DoNotQueue, ReplaceExisting};
        let flags = AllowReplacement | DoNotQueue | ReplaceExisting;

        let fake_accounts = FakeAccountManager(
            accounts
                .iter()
                .map(|(id, address)| (id.to_string(), address.to_string()))
                .collect(),
        );
        let account_service = zbus::connection::Builder::address(address)
            .unwrap()
            .serve_at("/ar/net/vasak/os/AccountManager", fake_accounts)
            .unwrap()
            .build()
            .await
            .unwrap();
        account_service
            .request_name_with_flags("ar.net.vasak.os.AccountManager", flags)
            .await
            .unwrap();

        let (keyring_server, keyring) = fake_keyring_on_bus(address).await;

        let access = Arc::new(Access::new(
            Arc::new(FixedPermission(answer)),
            Arc::new(SystemClock),
        ));
        let service = zbus::connection::Builder::address(address)
            .unwrap()
            .serve_at(
                SYNC_PATH,
                crate::Service {
                    access: Some(access),
                    ..Default::default()
                },
            )
            .unwrap()
            .build()
            .await
            .unwrap();

        let client = zbus::connection::Builder::address(address)
            .unwrap()
            .build()
            .await
            .unwrap();

        Self {
            client,
            keyring,
            keyring_server,
            service,
            _accounts: account_service,
            _guard: guard,
        }
    }

    /// Llama a un método de `AccountsSync` como la ventana.
    pub(crate) async fn call<B>(&self, method: &str, body: &B) -> zbus::Result<zbus::Message>
    where
        B: serde::ser::Serialize + zbus::zvariant::DynamicType,
    {
        self.client
            .call_method(
                self.service.unique_name().map(|n| n.as_str()),
                SYNC_PATH,
                Some(SYNC_INTERFACE),
                method,
                body,
            )
            .await
    }

    /// El cliente real del llavero, el mismo que usa el servicio, para mirar lo
    /// que quedó guardado.
    pub(crate) fn keys(&self) -> SecretServiceKeys {
        SecretServiceKeys::on_session_bus(self.client.clone())
    }
}

/// El nombre de error D-Bus y el texto de un rechazo; falla si no fue un rechazo.
pub(crate) fn error_of(result: zbus::Result<zbus::Message>) -> (String, String) {
    match result {
        Err(zbus::Error::MethodError(name, description, _)) => {
            (name.to_string(), description.unwrap_or_default())
        }
        other => panic!("se esperaba un error de D-Bus: {other:?}"),
    }
}
