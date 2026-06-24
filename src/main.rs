mod auth;
mod protocols;
mod storage;
use storage::{Account, AccountDatabase, CapabilityType, SecureKeyringManager};

use zbus::fdo::DBusProxy;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zbus::message::Header;
use zbus::names::BusName;

/// Estructura principal del servicio AccountManager.
/// Los métodos definidos en el bloque `#[interface]` se exponen como
/// métodos D-Bus en la interfaz `ar.net.vasak.os.AccountManager`.
struct AccountManager;

// ---------------------------------------------------------------------------
// Helper: extrae el PID del llamante desde la cabecera D-Bus
// ---------------------------------------------------------------------------

async fn get_caller_pid(
    connection: &zbus::Connection,
    header: &Header<'_>,
) -> zbus::fdo::Result<u32> {
    let sender = header
        .sender()
        .ok_or_else(|| FdoError::Failed("Sender no presente en la cabecera".into()))?;

    tracing::debug!("Nombre único del emisor: {}", sender);

    let dbus_proxy = DBusProxy::new(connection)
        .await
        .map_err(|e| FdoError::Failed(format!("Error al crear proxy D-Bus: {}", e)))?;

    let pid = dbus_proxy
        .get_connection_unix_process_id(BusName::from(sender.clone()))
        .await
        .map_err(|e| {
            FdoError::Failed(format!("Error al obtener PID para '{}': {}", sender, e))
        })?;

    Ok(pid)
}

#[interface(name = "ar.net.vasak.os.AccountManager")]
impl AccountManager {
    /// Método `Ping` — identifica al cliente llamante (PID + binario).
    async fn ping(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        let pid = get_caller_pid(connection, &header).await?;

        let exe_path = std::fs::read_link(format!("/proc/{}/exe", pid))
            .map_err(|e| {
                FdoError::Failed(format!("No se pudo leer /proc/{}/exe: {}", pid, e))
            })?;

        tracing::info!(
            "Ping recibido del PID: {} (Ruta: {})",
            pid,
            exe_path.display(),
        );

        Ok(format!(
            "OK: PID {} identificado correctamente (Ruta: {})",
            pid,
            exe_path.display(),
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
        let pid = get_caller_pid(connection, &header).await?;

        let mut db = AccountDatabase::new()
            .map_err(|e| FdoError::Failed(format!("Error al abrir base de datos: {}", e)))?;
        db.load()
            .map_err(|e| FdoError::Failed(format!("Error al cargar cuentas: {}", e)))?;

        let account = db
            .get(&account_id)
            .ok_or_else(|| FdoError::Failed(format!("Cuenta '{}' no encontrada", account_id)))?;

        let cap: CapabilityType = serde_json::from_str(&format!("\"{}\"", capability))
            .map_err(|e| FdoError::Failed(format!("Capability inválida '{}': {}", capability, e)))?;

        let allowed = auth::verify_access(account, pid, &cap)
            .map_err(|e| FdoError::Failed(e))?;

        if !allowed {
            tracing::warn!(
                "ACCESS DENIED — PID {} no autorizado para '{}' en cuenta {}",
                pid,
                capability,
                account_id,
            );
            return Err(FdoError::Failed(format!(
                "Acceso denegado: el proceso (PID {}) no está autorizado \
                 para '{}' en esta cuenta",
                pid, capability,
            )));
        }

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
        let pid = get_caller_pid(connection, &header).await?;

        // Verificar ACL (reutilizando Stage 3)
        let mut db = AccountDatabase::new()
            .map_err(|e| FdoError::Failed(format!("Error al abrir base de datos: {}", e)))?;
        db.load()
            .map_err(|e| FdoError::Failed(format!("Error al cargar cuentas: {}", e)))?;

        let account = db
            .get(&account_id)
            .ok_or_else(|| FdoError::Failed(format!("Cuenta '{}' no encontrada", account_id)))?;

        let cap: CapabilityType = serde_json::from_str(&format!("\"{}\"", capability))
            .map_err(|e| FdoError::Failed(format!("Capability inválida '{}': {}", capability, e)))?;

        let allowed = auth::verify_access(account, pid, &cap)
            .map_err(|e| FdoError::Failed(e))?;

        if !allowed {
            tracing::warn!(
                "ACCESS DENIED — PID {} no autorizado para '{}' en cuenta {}",
                pid,
                capability,
                account_id,
            );
            return Err(FdoError::Failed(format!(
                "Acceso denegado: el proceso (PID {}) no está autorizado \
                 para '{}' en esta cuenta",
                pid, capability,
            )));
        }

        // Delegar al Motor de Protocolo OAuth2
        let token = protocols::oauth2::get_valid_access_token(&account_id, &cap)
            .await
            .map_err(|e| FdoError::Failed(format!("Error al obtener token: {}", e)))?;

        Ok(token)
    }
}

fn init_demo_storage() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashMap;
    use storage::AccessControlEntry;

    let mut db = AccountDatabase::new()?;
    db.load()?;

    if !db.is_empty() {
        // Mostramos el ID de la primera cuenta para facilitar pruebas con busctl
        if let Some(acct) = db.accounts.first() {
            tracing::info!("Cuenta existente: id={}", acct.id);
        }
        return Ok(());
    }

    let mut caps = HashMap::new();
    caps.insert(
        CapabilityType::Email,
        serde_json::json!({
            "address": "demo@gmail.com",
            "imap_host": "imap.gmail.com",
            "imap_port": 993,
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "client_id": "123456789012-xxxxx.apps.googleusercontent.com",
            "token_url": "https://oauth2.googleapis.com/token",
            "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "expires_at": null,
        }),
    );
    caps.insert(
        CapabilityType::Drive,
        serde_json::json!({
            "root_folder": "/",
            "max_storage_gb": 15,
        }),
    );

    let mut account = Account::new("Demo Google", "google", caps);
    account.acl = vec![
        AccessControlEntry {
            binary_path: "/usr/bin/vasak-client".into(),
            allowed_capabilities: vec![CapabilityType::Email, CapabilityType::Drive],
        },
        AccessControlEntry {
            binary_path: "/usr/bin/authorized-bridge".into(),
            allowed_capabilities: vec![CapabilityType::Email],
        },
    ];
    let account_id = db.add(account)?;

    tracing::info!("Metadato guardado en ~/.config/vasakos/accounts.json");
    tracing::info!("=== ID DE CUENTA (usar en busctl) ===");
    tracing::info!("{}", account_id);
    tracing::info!("=====================================");
    tracing::info!("ACL configurada: /usr/bin/vasak-client → email, drive");
    tracing::info!("ACL configurada: /usr/bin/authorized-bridge → email");
    tracing::info!("(busctl NO está en la ACL — las llamadas serán denegadas)");

    SecureKeyringManager::store_token(&account_id, "ya29.abc123-secret-demo-token")?;
    SecureKeyringManager::store_secret(&account_id, "refresh", "1//0g-abc123-refresh-token-demo")?;
    SecureKeyringManager::store_secret(
        &account_id,
        "client_secret",
        "GOCSPX-abc123-client-secret-demo",
    )?;
    tracing::info!("Token almacenado en el llavero del sistema (Secret Service)");

    let token = SecureKeyringManager::get_token(&account_id)?;
    tracing::info!(
        "Token recuperado del llavero: {}… (longitud: {})",
        &token[..12],
        token.len(),
    );

    let refresh = SecureKeyringManager::get_secret(&account_id, "refresh")?;
    tracing::info!(
        "Refresh token almacenado: {}… (longitud: {})",
        &refresh[..12],
        refresh.len(),
    );

    let saved = db.get(&account_id).unwrap();
    let pretty = serde_json::to_string_pretty(saved)?;
    tracing::info!("Cuenta persistida:\n{}", pretty);

    tracing::info!("--- Motor de Protocolo OAuth2 (Stage 4) ---");
    tracing::info!("expires_at = null → el token se retorna sin refresco");
    tracing::info!("Para probar refresco automático:");
    tracing::info!("  1. Editar ~/.config/vasakos/accounts.json");
    tracing::info!("  2. Cambiar expires_at a fecha pasada (ISO 8601)");
    tracing::info!("  3. Llamar GetAccessToken desde busctl");
    tracing::info!("  4. El daemon refrescará automáticamente");

    Ok(())
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

    init_demo_storage()?;

    // Construimos la conexión D-Bus en el bus de sesión:
    // 1. Solicitamos el nombre well-known 'ar.net.vasak.os.AccountManager'.
    // 2. Registramos nuestro objeto en la ruta '/ar/net/vasak/os/AccountManager'.
    let _connection = zbus::ConnectionBuilder::session()
        .map_err(|e| format!("Error al conectar al bus de sesión: {}", e))?
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
