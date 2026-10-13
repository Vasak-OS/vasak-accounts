//! Confiar en el almacén sólo si quien lo contesta es el servicio de verdad.
//!
//! ── El problema ───────────────────────────────────────────────────────────
//!
//! `vasak-accounts-sync` es un servicio del usuario en el bus **de sesión**,
//! con el nombre bien conocido [`SERVICE_NAME`]. La política por omisión del
//! bus de sesión deja que **cualquier** proceso tome un nombre que nadie tiene.
//! Si el sincronizador todavía no arrancó, se cayó, o está en los ~10 s de
//! espera antes de reiniciarse, otro proceso de la sesión puede tomar el nombre
//! y hacerse pasar por el almacén: devolverle a las aplicaciones contactos,
//! eventos y correo inventados bajo la cuenta real de la persona, y enterarse
//! de los ids de las cuentas. No puede sacar credenciales —cuando el almacén
//! falla, la aplicación cae al servicio de cuentas, en el bus del sistema—,
//! pero sí mentirle a la persona sobre lo que tiene guardado.
//!
//! El servicio ya comprueba **a quien lo llama** (pid + pidfd + permisos, en
//! `sync/src/access.rs`). Lo que falta, y vive acá, es la comprobación
//! **simétrica del lado del consumidor**: verificar al servicio antes de
//! confiar en lo que contesta.
//!
//! ── La comprobación ───────────────────────────────────────────────────────
//!
//! Una vez por conexión, antes de la primera llamada:
//!
//! 1. `GetNameOwner(`[`SERVICE_NAME`]`)` → el **nombre único** del dueño
//!    (`:1.42`). Lo da el bus, no se puede inventar. Sin dueño, no se confía.
//! 2. `GetConnectionUnixProcessID(`dueño`)` → su **pid**.
//! 3. `/proc/<pid>/exe` tiene que ser [`INSTALLED_EXECUTABLE`]. Ese enlace lo
//!    mantiene el núcleo y **no se puede falsear**: apunta al binario que el
//!    proceso está ejecutando de verdad. Como respaldo, cuando el `exe` no se
//!    puede leer, que el cgroup del proceso nombre a [`INSTALLED_UNIT`] —un
//!    respaldo **más débil**, ver abajo—.
//!
//! Y, lo importante, **las llamadas siguientes van dirigidas al nombre único
//! verificado**, no al nombre bien conocido: si el nombre cambia de dueño
//! después de la comprobación, los pedidos siguen yendo a la conexión que se
//! verificó, no a la del impostor. [`trusted_sync_owner`] devuelve ese nombre
//! único justamente para eso.
//!
//! **Comparar el uid no alcanza:** quien ataca corre como el mismo usuario.
//!
//! ── Falla cerrado ─────────────────────────────────────────────────────────
//!
//! Cualquier cosa que impida comprobar —el nombre sin dueño, el bus que no
//! contesta, el pid que no se puede leer, el `exe` que no coincide— es un
//! [`TrustError`] y significa **no confiar**. El consumidor lo trata como «el
//! almacén no está disponible» y cae a su camino de error de siempre.
//!
//! ── Lo que el respaldo de cgroup no da ────────────────────────────────────
//!
//! El `exe` es la comprobación fuerte: para que `/proc/<pid>/exe` diga
//! `/usr/bin/vasak-accounts-sync`, el proceso tiene que **ser** ese binario.
//! El cgroup, en cambio, lo puede forjar el mismo atacante de igual uid:
//! `systemd-run --user --unit=vasak-accounts-sync.service …` pone a un proceso
//! cualquiera en un cgroup con ese nombre. Por eso el cgroup es sólo un
//! respaldo para cuando el `exe` no se puede leer (sistemas endurecidos con
//! Yama o un `hidepid` alto), y entre procesos del mismo usuario —el caso de
//! esta amenaza— el `exe` siempre se puede leer. La revisión de seguridad
//! puede quitar el respaldo: está aislado en [`process_in_unit`].

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

/// El nombre bien conocido del sincronizador en el bus de sesión. El almacén
/// (`ar.net.vasak.os.AccountsStore`) se publica en la misma conexión, así que
/// este nombre es el que hay que verificar.
pub const SERVICE_NAME: &str = "ar.net.vasak.os.AccountsSync";

/// El objeto del almacén local, para que las aplicaciones no repitan la ruta.
pub const STORE_PATH: &str = "/ar/net/vasak/os/AccountsStore";

/// La interfaz del almacén local.
pub const STORE_INTERFACE: &str = "ar.net.vasak.os.AccountsStore";

/// Dónde instala el paquete el binario del servicio. Es contra esto que se
/// compara `/proc/<pid>/exe` del dueño del nombre.
pub const INSTALLED_EXECUTABLE: &str = "/usr/bin/vasak-accounts-sync";

/// La unidad de systemd del servicio, para el respaldo por cgroup.
pub const INSTALLED_UNIT: &str = "vasak-accounts-sync.service";

/// Un futuro en una caja, para que el rasgo [`OwnerResolver`] tenga métodos
/// asíncronos sin arrastrar `async-trait`. Es el mismo molde que usa
/// `sync/src/access.rs` del otro lado.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// La identidad que se espera del dueño del nombre: su binario y su unidad.
///
/// [`ServiceIdentity::installed`] es la de producción. Las pruebas construyen
/// una que apunta a otro binario para ejercitar el camino que **sí** confía sin
/// tener instalado el servicio.
#[derive(Debug, Clone)]
pub struct ServiceIdentity {
    /// El binario que el dueño del nombre tiene que estar ejecutando.
    pub executable: PathBuf,
    /// La unidad de systemd, para el respaldo por cgroup.
    pub unit: String,
}

impl ServiceIdentity {
    /// La identidad del servicio tal como lo instala el paquete.
    pub fn installed() -> Self {
        Self {
            executable: PathBuf::from(INSTALLED_EXECUTABLE),
            unit: INSTALLED_UNIT.to_owned(),
        }
    }
}

impl Default for ServiceIdentity {
    fn default() -> Self {
        Self::installed()
    }
}

/// Por qué no se confía en el dueño del nombre. Cualquiera de estas significa
/// **no confiar**: la comprobación falla cerrado.
#[derive(Debug)]
pub enum TrustError {
    /// El nombre no tiene dueño: el servicio no está. (El bus no activó a
    /// nadie, o está en la ventana de reinicio.)
    NoOwner,
    /// No se pudo preguntarle al bus quién es el dueño o cuál es su pid.
    Bus(String),
    /// El dueño existe pero su proceso ya no se puede leer (`/proc/<pid>` se
    /// fue entre que el bus dio el pid y que lo miramos).
    ProcessGone(u32),
    /// El dueño es otro proceso, no el servicio: su `exe` no coincide y su
    /// cgroup tampoco lo respalda.
    WrongOwner {
        /// El pid del dueño del nombre.
        pid: u32,
        /// El binario que ese pid está ejecutando, si se pudo leer.
        executable: Option<PathBuf>,
    },
}

impl std::fmt::Display for TrustError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustError::NoOwner => {
                write!(
                    f,
                    "el nombre {SERVICE_NAME} no tiene dueño: el servicio no está"
                )
            }
            TrustError::Bus(detail) => {
                write!(
                    f,
                    "no se pudo preguntar al bus quién tiene {SERVICE_NAME}: {detail}"
                )
            }
            TrustError::ProcessGone(pid) => {
                write!(
                    f,
                    "el dueño de {SERVICE_NAME} (pid {pid}) ya no se puede leer"
                )
            }
            TrustError::WrongOwner { pid, executable } => match executable {
                Some(exe) => write!(
                    f,
                    "{SERVICE_NAME} lo tiene el pid {pid} ({}), que no es {INSTALLED_EXECUTABLE}",
                    exe.display()
                ),
                None => write!(
                    f,
                    "{SERVICE_NAME} lo tiene el pid {pid}, que no es {INSTALLED_EXECUTABLE}"
                ),
            },
        }
    }
}

impl std::error::Error for TrustError {}

/// Lo que hace falta para comprobar al dueño: preguntarle al bus quién lo tiene
/// y cuál es su pid. Un rasgo para poder probar la lógica con un dueño de
/// verdad —un proceso que existe— sin depender de un bus.
pub trait OwnerResolver: Send + Sync {
    /// El nombre único del dueño de un nombre bien conocido, o `None` si nadie
    /// lo tiene.
    fn name_owner<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<String>, String>>;

    /// El pid del proceso que abrió la conexión de un nombre único.
    fn process_id<'a>(&'a self, unique_name: &'a str) -> BoxFuture<'a, Result<u32, String>>;
}

/// El nombre único del dueño de `name`, ya comprobado contra `identity`, o un
/// [`TrustError`] si no se puede confiar. El nombre único que devuelve es al
/// que el consumidor tiene que dirigir las llamadas siguientes.
pub async fn trusted_owner<R>(
    resolver: &R,
    name: &str,
    identity: &ServiceIdentity,
) -> Result<String, TrustError>
where
    R: OwnerResolver + ?Sized,
{
    let owner = resolver
        .name_owner(name)
        .await
        .map_err(TrustError::Bus)?
        .ok_or(TrustError::NoOwner)?;
    let pid = resolver.process_id(&owner).await.map_err(TrustError::Bus)?;
    verify_pid(pid, identity)?;
    Ok(owner)
}

/// La comprobación sobre un pid: primero el `exe`, después el cgroup.
fn verify_pid(pid: u32, identity: &ServiceIdentity) -> Result<(), TrustError> {
    let executable = process_executable(pid);
    if let Some(exe) = &executable {
        if same_executable(exe, &identity.executable) {
            return Ok(());
        }
    }
    match process_in_unit(pid, &identity.unit) {
        Some(true) => Ok(()),
        // El cgroup se leyó y no nombra la unidad: es otro proceso.
        Some(false) => Err(TrustError::WrongOwner { pid, executable }),
        // Ni el `exe` ni el cgroup se pudieron leer: el proceso se fue.
        None if executable.is_none() => Err(TrustError::ProcessGone(pid)),
        // El `exe` se leyó (y no coincidió) pero el cgroup no: es otro proceso.
        None => Err(TrustError::WrongOwner { pid, executable }),
    }
}

/// El binario que un pid está ejecutando, de `/proc/<pid>/exe`. El enlace lo
/// mantiene el núcleo y no se puede falsear. `None` si no se puede leer.
fn process_executable(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

/// Si dos rutas de binario son la misma. Compara tal cual y, si las dos se
/// pueden resolver, por su ruta canónica —así `/usr/bin` y `/bin` (un enlace a
/// `usr/bin`) no se leen como binarios distintos—. Si el binario esperado no
/// existe (el servicio no está instalado), sólo coincide una ruta idéntica, que
/// es lo que se quiere: sin servicio instalado no se confía en nadie.
fn same_executable(found: &Path, expected: &Path) -> bool {
    if found == expected {
        return true;
    }
    match (
        std::fs::canonicalize(found),
        std::fs::canonicalize(expected),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Si el cgroup de un pid nombra a `unit`. `None` si no se puede leer
/// `/proc/<pid>/cgroup`. Respaldo débil: ver la cabecera del módulo.
fn process_in_unit(pid: u32, unit: &str) -> Option<bool> {
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    Some(cgroup.lines().any(|line| line.contains(unit)))
}

/// Resuelve al dueño de un nombre por el bus de sesión, con `GetNameOwner` y
/// `GetConnectionUnixProcessID`.
pub struct DbusOwnerResolver {
    proxy: zbus::fdo::DBusProxy<'static>,
}

impl DbusOwnerResolver {
    /// Un resolvedor sobre una conexión ya abierta.
    pub async fn new(connection: &zbus::Connection) -> zbus::Result<Self> {
        Ok(Self {
            proxy: zbus::fdo::DBusProxy::new(connection).await?,
        })
    }
}

impl OwnerResolver for DbusOwnerResolver {
    fn name_owner<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<String>, String>> {
        Box::pin(async move {
            let bus_name = zbus::names::BusName::try_from(name).map_err(|e| e.to_string())?;
            match self.proxy.get_name_owner(bus_name).await {
                Ok(unique) => Ok(Some(unique.to_string())),
                Err(zbus::fdo::Error::NameHasNoOwner(_)) => Ok(None),
                Err(e) => Err(e.to_string()),
            }
        })
    }

    fn process_id<'a>(&'a self, unique_name: &'a str) -> BoxFuture<'a, Result<u32, String>> {
        Box::pin(async move {
            let bus_name =
                zbus::names::BusName::try_from(unique_name).map_err(|e| e.to_string())?;
            self.proxy
                .get_connection_unix_process_id(bus_name)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

/// El nombre único del dueño de [`SERVICE_NAME`] en esta conexión, ya
/// comprobado contra el servicio instalado. Las aplicaciones lo llaman una vez
/// por conexión y dirigen sus llamadas al nombre único que devuelve.
pub async fn trusted_sync_owner(connection: &zbus::Connection) -> Result<String, TrustError> {
    let resolver = DbusOwnerResolver::new(connection)
        .await
        .map_err(|e| TrustError::Bus(e.to_string()))?;
    trusted_owner(&resolver, SERVICE_NAME, &ServiceIdentity::installed()).await
}

#[cfg(test)]
mod tests;
