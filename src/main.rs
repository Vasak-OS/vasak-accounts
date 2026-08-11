mod auth;
mod permissions;
mod protocols;
mod storage;
use std::collections::HashMap;

use storage::{AccountDatabase, CapabilityType};

use zbus::fdo::DBusProxy;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zbus::message::Header;
use zbus::names::BusName;

/// Decides whether `caller` may use `capability` on `account_id`.
///
/// The answer comes from `vasak-permissions`, a system service, and no longer
/// from a list inside `accounts.json`. That list lived in the user's own
/// configuration directory: any program running as them could rewrite it and
/// grant itself anything, so it protected nothing.
async fn authorize(
    caller: &auth::PinnedCaller,
    db: &AccountDatabase,
    account_id: &str,
    capability: &str,
) -> zbus::fdo::Result<CapabilityType> {
    let cap: CapabilityType = serde_json::from_str(&format!("\"{capability}\""))
        .map_err(|e| FdoError::Failed(format!("Capability inválida '{capability}': {e}")))?;

    let account = db
        .get(account_id)
        .ok_or_else(|| FdoError::Failed(format!("Cuenta '{account_id}' no encontrada")))?;

    // Named so the dialog can say which account is being asked for.
    let granted = permissions::check(caller.pid, &cap, &account.display_name).await?;

    if !granted {
        tracing::warn!(
            "ACCESS DENIED — PID {} no autorizado para '{}' en cuenta {}",
            caller.pid,
            capability,
            account_id,
        );
        return Err(FdoError::AccessDenied(format!(
            "El programa no tiene permiso para '{capability}' en esta cuenta. \
             Podés cambiarlo en Configuración → Privacidad y seguridad."
        )));
    }

    Ok(cap)
}

/// Estructura principal del servicio AccountManager.
/// Los métodos definidos en el bloque `#[interface]` se exponen como
/// métodos D-Bus en la interfaz `ar.net.vasak.os.AccountManager`.
struct AccountManager;

// ---------------------------------------------------------------------------
// Helper: extrae el PID del llamante desde la cabecera D-Bus
// ---------------------------------------------------------------------------

async fn caller_pid_and_uid(
    connection: &zbus::Connection,
    header: &Header<'_>,
) -> zbus::fdo::Result<(u32, u32)> {
    let sender = header
        .sender()
        .ok_or_else(|| FdoError::Failed("Sender no presente en la cabecera".into()))?;

    tracing::debug!("Nombre único del emisor: {}", sender);

    let dbus_proxy = DBusProxy::new(connection)
        .await
        .map_err(|e| FdoError::Failed(format!("Error al crear proxy D-Bus: {}", e)))?;

    let name = BusName::from(sender.clone());
    let pid = dbus_proxy
        .get_connection_unix_process_id(name.clone())
        .await
        .map_err(|e| {
            FdoError::Failed(format!("Error al obtener PID para '{}': {}", sender, e))
        })?;

    // The daemon serves every session on the machine, so the caller's user is
    // what keeps one person's accounts out of another person's requests.
    let uid = dbus_proxy
        .get_connection_unix_user(name)
        .await
        .map_err(|e| {
            FdoError::Failed(format!("Error al obtener usuario para '{}': {}", sender, e))
        })?;

    Ok((pid, uid))
}

/// Obtiene el PID del llamante y lo **fija con un pidfd** de inmediato, para que
/// el binario resuelto no pueda ser suplantado por reciclado de PID mientras se
/// realiza la verificación (cierra la ventana TOCTOU).
async fn caller_identity(
    connection: &zbus::Connection,
    header: &Header<'_>,
) -> zbus::fdo::Result<(auth::PinnedCaller, u32)> {
    let (pid, uid) = caller_pid_and_uid(connection, header).await?;
    let caller = auth::PinnedCaller::capture(pid).map_err(FdoError::Failed)?;
    Ok((caller, uid))
}

#[interface(name = "ar.net.vasak.os.AccountManager")]
impl AccountManager {
    /// Método `Ping` — identifica al cliente llamante (PID + binario).
    async fn ping(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        let (caller, _uid) = caller_identity(connection, &header).await?;

        tracing::info!(
            "Ping recibido del PID: {} (Ruta: {})",
            caller.pid,
            caller.exe.display(),
        );

        Ok(format!(
            "OK: PID {} identificado correctamente (Ruta: {})",
            caller.pid,
            caller.exe.display(),
        ))
    }

    /// Método `GetAccountData` — retorna datos de una cuenta solo si el
    /// proceso llamante tiene permiso en la ACL para la capability solicitada.
    async fn get_account_data(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        account_id: String,
        capability: String,
    ) -> zbus::fdo::Result<String> {
        let (caller, uid) = caller_identity(connection, &header).await?;

        let mut db = AccountDatabase::for_user(uid)
            .map_err(|e| FdoError::Failed(format!("Error al abrir base de datos: {}", e)))?;
        db.load()
            .map_err(|e| FdoError::Failed(format!("Error al cargar cuentas: {}", e)))?;

        let cap = authorize(&caller, &db, &account_id, &capability).await?;

        let account = db
            .get(&account_id)
            .ok_or_else(|| FdoError::Failed(format!("Cuenta '{}' no encontrada", account_id)))?;

        let data = account.capabilities.get(&cap).ok_or_else(|| {
            FdoError::Failed(format!("Capability '{}' no configurada en la cuenta", capability))
        })?;

        let response = serde_json::json!({
            "account_id": account_id,
            "display_name": account.display_name,
            "provider_type": account.provider_type,
            "capability": capability,
            "config": data,
        });

        Ok(serde_json::to_string_pretty(&response)
            .map_err(|e| FdoError::Failed(format!("Error de serialización: {}", e)))?)
    }

    /// Método `ListAccounts` — las cuentas del usuario que llama.
    ///
    /// Metadata only; a token never leaves through here. Listing what accounts
    /// exist is not the same as being allowed to use them, and only the second
    /// needs the user's permission.
    async fn list_accounts(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        let (_caller, uid) = caller_identity(connection, &header).await?;

        let mut db = AccountDatabase::for_user(uid)
            .map_err(|e| FdoError::Failed(format!("Error al abrir base de datos: {}", e)))?;
        db.load()
            .map_err(|e| FdoError::Failed(format!("Error al cargar cuentas: {}", e)))?;

        serde_json::to_string(db.all())
            .map_err(|e| FdoError::Failed(format!("Error de serialización: {e}")))
    }

    /// Método `RegisterAccount` — agrega una cuenta y guarda sus secretos.
    ///
    /// The secrets arrive here and go straight into root-owned storage; the
    /// program that set the account up cannot read them back afterwards without
    /// the user's permission, same as anything else.
    ///
    /// Adding an account to your *own* user needs no extra authorisation — it is
    /// your account. What needs permission is a program getting at the token.
    async fn register_account(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        display_name: String,
        provider_type: String,
        capabilities_json: String,
        secrets_json: String,
    ) -> zbus::fdo::Result<String> {
        let (_caller, uid) = caller_identity(connection, &header).await?;

        let capabilities: HashMap<CapabilityType, serde_json::Value> =
            serde_json::from_str(&capabilities_json).map_err(|e| {
                FdoError::InvalidArgs(format!("capabilities inválidas: {e}"))
            })?;
        let secrets: HashMap<String, String> = serde_json::from_str(&secrets_json)
            .map_err(|e| FdoError::InvalidArgs(format!("secretos inválidos: {e}")))?;

        let mut db = AccountDatabase::for_user(uid)
            .map_err(|e| FdoError::Failed(format!("Error al abrir base de datos: {}", e)))?;
        db.load()
            .map_err(|e| FdoError::Failed(format!("Error al cargar cuentas: {}", e)))?;

        let account = storage::Account::new(&display_name, &provider_type, capabilities);
        let account_id = db
            .add(account)
            .map_err(|e| FdoError::Failed(format!("Error al guardar la cuenta: {e}")))?;

        for (key, value) in secrets {
            storage::SecretStore::store_secret(uid, &account_id, &key, &value)
                .map_err(|e| FdoError::Failed(format!("Error al guardar el secreto: {e}")))?;
        }

        tracing::info!("Cuenta '{account_id}' registrada para el usuario {uid}");
        Ok(account_id)
    }

    /// Método `RemoveAccount` — borra la cuenta y todos sus secretos.
    async fn remove_account(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        account_id: String,
    ) -> zbus::fdo::Result<bool> {
        let (_caller, uid) = caller_identity(connection, &header).await?;

        let mut db = AccountDatabase::for_user(uid)
            .map_err(|e| FdoError::Failed(format!("Error al abrir base de datos: {}", e)))?;
        db.load()
            .map_err(|e| FdoError::Failed(format!("Error al cargar cuentas: {}", e)))?;

        let removed = db
            .remove(&account_id)
            .map_err(|e| FdoError::Failed(format!("Error al eliminar la cuenta: {e}")))?;

        // Always clear the secrets, even if the metadata was already gone:
        // otherwise a live credential stays on disk for an account the user
        // believes no longer exists.
        storage::SecretStore::forget_account(uid, &account_id)
            .map_err(|e| FdoError::Failed(format!("Error al borrar los secretos: {e}")))?;

        Ok(removed)
    }

    /// Método `GetAccessToken` — retorna un access_token **válido** para la
    /// cuenta y capability indicadas. El Motor de Protocolo (Stage 4) verifica
    /// la expiración y refresca automáticamente si es necesario.
    async fn get_access_token(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        account_id: String,
        capability: String,
    ) -> zbus::fdo::Result<String> {
        let (caller, uid) = caller_identity(connection, &header).await?;

        // Verificar ACL (reutilizando Stage 3)
        let mut db = AccountDatabase::for_user(uid)
            .map_err(|e| FdoError::Failed(format!("Error al abrir base de datos: {}", e)))?;
        db.load()
            .map_err(|e| FdoError::Failed(format!("Error al cargar cuentas: {}", e)))?;

        let cap = authorize(&caller, &db, &account_id, &capability).await?;

        // Delegar al Motor de Protocolo OAuth2
        let token = protocols::oauth2::get_valid_access_token(uid, &account_id, &cap)
            .await
            .map_err(|e| FdoError::Failed(format!("Error al obtener token: {}", e)))?;

        Ok(token)
    }
}


/// The system bus, always, in a released build.
///
/// Debug builds can be pointed at a session bus to exercise the whole chain
/// without root. Compiled out of release entirely rather than guarded at
/// runtime: a token broker that could be moved onto a bus the user controls
/// would be handing its requests to whatever claimed the name there.
#[cfg(debug_assertions)]
fn service_bus() -> zbus::Result<zbus::connection::Builder<'static>> {
    if std::env::var_os("VASAK_ACCOUNTS_TEST_ROOT").is_some() {
        tracing::warn!("MODO DE DESARROLLO: usando el bus de sesión");
        return zbus::connection::Builder::session();
    }
    zbus::connection::Builder::system()
}

#[cfg(not(debug_assertions))]
fn service_bus() -> zbus::Result<zbus::connection::Builder<'static>> {
    zbus::connection::Builder::system()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Inicializamos el logging con tracing.
    // La variable de entorno RUST_LOG permite filtrar niveles:
    //   RUST_LOG=info   → mensajes info y superiores (por defecto)
    //   RUST_LOG=debug  → mensajes debug e info
    //   RUST_LOG=trace  → todos los mensajes (más verboso)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    tracing::info!("Iniciando AccountManager…");

    // Construimos la conexión D-Bus en el bus de sesión:
    // 1. Solicitamos el nombre well-known 'ar.net.vasak.os.AccountManager'.
    // 2. Registramos nuestro objeto en la ruta '/ar/net/vasak/os/AccountManager'.
    // The system bus, as root. The tokens live in root-owned files now, so the
    // daemon has to be somewhere a program running as the user cannot be: a
    // service in the session could be replaced by anything that got there
    // first, and would be able to read the files it serves.
    let _connection = service_bus()
        .map_err(|e| format!("Error al conectar al bus del sistema: {}", e))?
        .name("ar.net.vasak.os.AccountManager")
        .map_err(|e| format!("Error al solicitar nombre D-Bus: {}", e))?
        .serve_at("/ar/net/vasak/os/AccountManager", AccountManager)
        .map_err(|e| format!("Error al registrar el servicio: {}", e))?
        .build()
        .await?;

    tracing::info!(
        "AccountManager corriendo en 'ar.net.vasak.os.AccountManager' \
         (objeto en '/ar/net/vasak/os/AccountManager')"
    );

    tracing::info!("Esperando peticiones… (Ctrl+C para detener)");

    // Mantenemos el proceso vivo hasta recibir Ctrl+C
    tokio::signal::ctrl_c().await?;

    tracing::info!("AccountManager detenido");

    Ok(())
}
