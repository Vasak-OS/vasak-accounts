//! `vasak-accounts-sync` — mantiene al día el correo, como servicio del usuario.
//!
//! ── Por qué es un binario aparte ────────────────────────────────────────────
//!
//! Porque habla IMAP con los servidores de correo de la persona, y eso es leer
//! lo que manda un servidor cualquiera. El servicio de cuentas corre **como
//! root** —los tokens están en archivos de root— y meterle ahí un cliente de
//! correo sería poner un parser de red detrás de los permisos más altos del
//! sistema. Es el mismo criterio por el que la prueba de conexión y el
//! autodescubrimiento viven en la ventana de configuración.
//!
//! ── Y por qué no tiene ningún atajo ─────────────────────────────────────────
//!
//! Le pide los tokens al servicio por el mismo método D-Bus que usaría una
//! aplicación de terceros, y la primera vez la persona ve el mismo diálogo de
//! permiso. Estar en el mismo repositorio no le da nada.
//!
//! Eso es a propósito y es media razón de que este binario se haya escrito antes
//! que la aplicación de correo: es el **primer cliente real** del modelo de
//! permisos, así que lo ejercita de punta a punta antes de que dependa de él
//! algo que la gente usa.
//!
//! ── Qué hace hoy, y qué no ──────────────────────────────────────────────────
//!
//! Cuenta el correo sin leer de cada cuenta y lo publica. Nada más.
//!
//! No guarda mensajes. Un caché sería inventarle un formato a una aplicación de
//! correo que todavía no existe, y el día que exista va a querer otro. Contar
//! sin leer, en cambio, sirve hoy —el escritorio puede mostrar que llegó algo— y
//! se apoya en `STATUS`, que devuelve cuatro números: ni una línea de parser
//! sobre lo que escribió un remitente. Ese parser va a llegar, y va a merecer su
//! propia discusión.

mod broker;
mod imap;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use zbus::object_server::SignalContext;
use zbus::interface;

use broker::{Broker, BrokerError};

/// Cada cuánto se vuelve a mirar.
///
/// Cinco minutos, y no algo más frecuente, por dos razones. La primera es que
/// cada vuelta abre una conexión y se autentica contra el servidor de alguien;
/// hacerlo cada treinta segundos es maltratarlo. La segunda es que cada vuelta
/// también le pide el token al servicio de cuentas, que lo refresca si hace
/// falta — así que este intervalo es además lo que mantiene los tokens frescos
/// sin una tarea aparte.
///
/// Lo que falta para que esto sea inmediato es IMAP IDLE, que avisa en vez de
/// preguntar. Es el próximo paso y no cambia nada de lo de acá.
const INTERVALO: Duration = Duration::from_secs(300);

/// Cuánto se espera antes de volver a intentar cuando el servicio de cuentas no
/// está.
///
/// Corto, porque el caso normal es que todavía esté arrancando: este servicio
/// puede levantar antes que el bus del sistema termine de activarlo.
const REINTENTO: Duration = Duration::from_secs(15);

/// Lo que se sabe de una cuenta después de mirarla.
#[derive(Debug, Clone, serde::Serialize)]
struct Resumen {
    account_id: String,
    display_name: String,
    #[serde(flatten)]
    estado: imap::Estado,
    /// Vacío si la última vuelta anduvo. Si no, qué pasó — la aplicación que lo
    /// muestre necesita poder decir «no se pudo» y no un cero que parece «no
    /// tenés correo».
    error: String,
}

#[derive(Default)]
struct Estado {
    por_cuenta: HashMap<String, Resumen>,
    /// Las cuentas cuyo servidor rechazó las credenciales.
    ///
    /// Se dejan de mirar hasta que algo cambie: insistir con una contraseña que
    /// el servidor rechaza es cómo se bloquea una cuenta, y en un bucle de cinco
    /// minutos son casi trescientos intentos por día.
    rechazadas: HashMap<String, String>,
}

#[derive(Clone, Default)]
struct Servicio {
    estado: Arc<Mutex<Estado>>,
}

#[interface(name = "ar.net.vasak.os.AccountsSync")]
impl Servicio {
    /// Cuánto correo sin leer hay, por cuenta.
    ///
    /// Sin pedir permiso: son los mismos números que el servicio de cuentas ya
    /// deja ver por `ListAccounts`, contados. Lo que necesita permiso es llegar
    /// al token, y de eso se ocupa el servicio — este proceso ya pasó por ahí.
    ///
    /// Y esto vive en el bus **de sesión**: es un servicio del usuario y lo que
    /// publica es suyo, así que no hay otra sesión que pueda escucharlo.
    async fn mailbox_status(&self) -> zbus::fdo::Result<String> {
        let estado = self.estado.lock().await;
        let mut resumenes: Vec<&Resumen> = estado.por_cuenta.values().collect();
        // Por identificador, para que la lista no cambie de orden entre lecturas
        // por el recorrido de un mapa.
        resumenes.sort_by(|a, b| a.account_id.cmp(&b.account_id));

        serde_json::to_string(&resumenes)
            .map_err(|e| zbus::fdo::Error::Failed(format!("no se pudo serializar: {e}")))
    }

    /// Señal `MailboxChanged` — cambió el correo sin leer de alguna cuenta.
    ///
    /// Sin detalle, como la del servicio de cuentas y por la misma razón: quien
    /// la recibe vuelve a leer y ve el estado completo, en vez de reconciliar
    /// señales que se pueden perder.
    #[zbus(signal)]
    async fn mailbox_changed(emisor: &SignalContext<'_>) -> zbus::Result<()>;
}

/// Mira una cuenta y devuelve su resumen.
async fn mirar(broker: &Broker, cuenta: &broker::Account) -> Result<imap::Estado, String> {
    let token = broker
        .access_token(&cuenta.id, "email")
        .await
        .map_err(|e| e.to_string())?;

    let config = broker
        .account_data(&cuenta.id, "email")
        .await
        .map_err(|e| e.to_string())?;

    // La configuración viene envuelta: el servicio devuelve la cuenta entera con
    // la capacidad adentro.
    let config = config.get("config").cloned().unwrap_or(config);
    let destino = broker::destino_de(&config, Some(token))?;

    let mut sesion = imap::Sesion::abrir(&destino).await.map_err(|e| e.to_string())?;
    let estado = sesion.estado("INBOX").await.map_err(|e| e.to_string());
    sesion.cerrar().await;
    estado
}

/// Una vuelta: mira todas las cuentas con correo y actualiza el estado.
///
/// Devuelve si algo cambió, para no despertar a las aplicaciones cuando no hay
/// nada nuevo que contarles.
async fn una_vuelta(broker: &Broker, servicio: &Servicio) -> Result<bool, BrokerError> {
    let cuentas = broker.accounts().await?;
    let mut estado = servicio.estado.lock().await;
    let mut cambio = false;

    // Las cuentas que ya no están se olvidan, incluida su marca de rechazo: si
    // la persona la borró y la volvió a conectar, merece un intento limpio.
    let vigentes: Vec<String> = cuentas.iter().map(|c| c.id.clone()).collect();
    let antes = estado.por_cuenta.len();
    estado.por_cuenta.retain(|id, _| vigentes.contains(id));
    estado.rechazadas.retain(|id, _| vigentes.contains(id));
    cambio |= estado.por_cuenta.len() != antes;

    for cuenta in cuentas.iter().filter(|c| c.hay_correo_que_sincronizar()) {
        if let Some(motivo) = estado.rechazadas.get(&cuenta.id) {
            tracing::debug!("'{}' sigue rechazada ({motivo}); no se reintenta", cuenta.id);
            continue;
        }

        let resultado = mirar(broker, cuenta).await;
        let nuevo = match resultado {
            Ok(imap_estado) => Resumen {
                account_id: cuenta.id.clone(),
                display_name: cuenta.display_name.clone(),
                estado: imap_estado,
                error: String::new(),
            },
            Err(detalle) => {
                // Un rechazo de credenciales se anota para no volver a intentar.
                // El resto —red caída, servidor apagado— se reintenta solo en la
                // vuelta siguiente, que es lo que corresponde.
                if detalle.contains("rechazó las credenciales") || detalle.contains("sin permiso")
                {
                    tracing::warn!("'{}' deja de mirarse: {detalle}", cuenta.id);
                    estado.rechazadas.insert(cuenta.id.clone(), detalle.clone());
                } else {
                    tracing::info!("'{}' falló esta vuelta: {detalle}", cuenta.id);
                }
                Resumen {
                    account_id: cuenta.id.clone(),
                    display_name: cuenta.display_name.clone(),
                    estado: imap::Estado::default(),
                    error: detalle,
                }
            }
        };

        let anterior = estado.por_cuenta.get(&cuenta.id);
        if anterior.map(|a| (a.estado, a.error.clone())) != Some((nuevo.estado, nuevo.error.clone()))
        {
            cambio = true;
        }
        estado.por_cuenta.insert(cuenta.id.clone(), nuevo);
    }

    Ok(cambio)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    tracing::info!("Iniciando vasak-accounts-sync…");

    let servicio = Servicio::default();

    // El bus de **sesión**: es un servicio del usuario y lo que publica es suyo.
    let conexion = zbus::connection::Builder::session()?
        .name("ar.net.vasak.os.AccountsSync")?
        .serve_at("/ar/net/vasak/os/AccountsSync", servicio.clone())?
        .build()
        .await?;

    let emisor = SignalContext::new(&conexion, "/ar/net/vasak/os/AccountsSync")?;

    // Una señal del servicio de cuentas —una cuenta agregada, quitada o
    // reconectada— despierta una vuelta sin esperar el intervalo. Es lo que hace
    // que conectar una cuenta muestre su correo en el momento y no en cinco
    // minutos.
    let (despertar, mut despertador) = tokio::sync::mpsc::channel::<()>(1);

    tokio::spawn(async move {
        loop {
            match escuchar_al_servicio(&despertar).await {
                Ok(()) => tracing::warn!("se cortó la escucha del servicio de cuentas"),
                Err(e) => tracing::warn!("no se pudo escuchar al servicio de cuentas: {e}"),
            }
            tokio::time::sleep(REINTENTO).await;
        }
    });

    loop {
        match Broker::connect().await {
            Ok(broker) => match una_vuelta(&broker, &servicio).await {
                Ok(true) => {
                    tracing::debug!("cambió algo; avisando");
                    let _ = Servicio::mailbox_changed(&emisor).await;
                }
                Ok(false) => tracing::debug!("sin novedades"),
                Err(BrokerError::Unavailable(detalle)) => {
                    tracing::info!("el servicio de cuentas no está todavía: {detalle}");
                }
                Err(e) => tracing::warn!("no se pudo mirar las cuentas: {e}"),
            },
            Err(e) => tracing::info!("esperando al servicio de cuentas: {e}"),
        }

        // Lo que pase primero: el intervalo, o una señal de que algo cambió.
        tokio::select! {
            _ = tokio::time::sleep(INTERVALO) => {}
            _ = despertador.recv() => tracing::debug!("algo cambió en las cuentas"),
        }
    }
}

/// Escucha `AccountsChanged` del servicio de cuentas y avisa al bucle.
async fn escuchar_al_servicio(despertar: &tokio::sync::mpsc::Sender<()>) -> zbus::Result<()> {
    use futures_util::StreamExt;

    let conexion = zbus::Connection::system().await?;
    let mut señales = zbus::MessageStream::for_match_rule(
        zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface("ar.net.vasak.os.AccountManager")?
            .member("AccountsChanged")?
            .build(),
        &conexion,
        None,
    )
    .await?;

    while let Some(Ok(_)) = señales.next().await {
        // Sin esperar si el bucle está ocupado: una vuelta ya en curso va a ver
        // el cambio igual, y encolar varias no aporta nada.
        let _ = despertar.try_send(());
    }
    Ok(())
}
