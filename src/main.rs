use zbus::fdo::DBusProxy;
use zbus::fdo::Error as FdoError;
use zbus::interface;
use zbus::message::Header;
use zbus::names::BusName;

/// Estructura principal del servicio AccountManager.
/// Los métodos definidos en el bloque `#[interface]` se exponen como
/// métodos D-Bus en la interfaz `ar.net.vasak.os.AccountManager`.
struct AccountManager;

#[interface(name = "ar.net.vasak.os.AccountManager")]
impl AccountManager {
    /// Método `Ping` que identifica al cliente llamante mediante su PID
    /// (consultando las credenciales del bus D-Bus), lee `/proc/{pid}/exe`
    /// para obtener la ruta del binario y retorna un mensaje de confirmación.
    ///
    /// Parámetros inyectados por zbus via `#[zbus(connection)]` y
    /// `#[zbus(header)]`:
    /// - `connection`: referencia a la conexión D-Bus activa del servicio.
    /// - `header`: cabecera del mensaje D-Bus entrante (contiene `sender`).
    async fn ping(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        // Extraemos el nombre único del emisor (p.ej. ":1.42") desde la
        // cabecera del mensaje D-Bus. El sender siempre está presente en
        // las llamadas a método.
        let sender: &zbus::names::UniqueName<'_> = header
            .sender()
            .ok_or_else(|| {
                FdoError::Failed("Sender no presente en la cabecera".into())
            })?;

        tracing::debug!("Nombre único del emisor: {}", sender);

        // Creamos un proxy hacia el bus D-Bus (session bus) para consultar
        // las credenciales del proceso que realizó la llamada.
        let dbus_proxy = DBusProxy::new(connection)
            .await
            .map_err(|e| FdoError::Failed(format!("Error al crear proxy D-Bus: {}", e)))?;

        // Solicitamos el PID del proceso asociado al nombre único del
        // emisor usando el método estándar `GetConnectionUnixProcessID`
        // (org.freedesktop.DBus.GetConnectionUnixProcessID).
        let pid: u32 = dbus_proxy
            .get_connection_unix_process_id(BusName::from(sender.clone()))
            .await
            .map_err(|e| {
                FdoError::Failed(format!(
                    "Error al obtener PID para '{}': {}",
                    sender, e,
                ))
            })?;

        // Leemos el enlace simbólico /proc/{pid}/exe para determinar la
        // ruta absoluta del binario del proceso cliente.
        let exe_path = std::fs::read_link(format!("/proc/{}/exe", pid))
            .map_err(|e| {
                FdoError::Failed(format!(
                    "No se pudo leer /proc/{}/exe: {}",
                    pid, e,
                ))
            })?;

        // Registramos la información en los logs del demonio.
        tracing::info!(
            "Petición recibida del PID: {} (Ruta: {})",
            pid,
            exe_path.display(),
        );

        // Retornamos confirmación al cliente.
        Ok(format!(
            "OK: PID {} identificado correctamente (Ruta: {})",
            pid,
            exe_path.display(),
        ))
    }
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
