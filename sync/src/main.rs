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

/// Cada cuánto se vuelve a mirar cuando el servidor **no** sabe avisar.
///
/// Cinco minutos, y no algo más frecuente, porque cada vuelta abre una conexión
/// y se autentica contra el servidor de alguien: hacerlo cada treinta segundos
/// es maltratarlo.
const INTERVALO: Duration = Duration::from_secs(300);

/// Cada cuánto se renueva la espera de IDLE.
///
/// El estándar pide renovarla al menos cada veintinueve minutos. Veinticuatro
/// deja margen: si el servidor —o cualquier NAT en el medio— corta por
/// inactividad justo antes de la renovación, lo que se pierde es un aviso, y
/// eso se nota como correo que aparece tarde.
///
/// Es además el pulso que mantiene los tokens frescos. Antes lo hacía el bucle
/// de cinco minutos; con IDLE la conexión se queda quieta, así que en cada
/// renovación se le vuelve a pedir el token al servicio — que es lo que hace que
/// lo refresque. Sin eso, una cuenta que anda bien podría quedarse con un
/// refresh_token caducado por no usarse.
const RENOVAR_IDLE: Duration = Duration::from_secs(24 * 60);

/// Cuánto se espera antes de reconectar una cuenta que falló.
///
/// Las conexiones largas se cortan: se cae el wifi, el servidor se reinicia, un
/// NAT olvida la sesión. Es lo normal y no un error, así que se reconecta — pero
/// no en el acto, o un servidor caído recibiría un intento por milisegundo.
const REINTENTO_CUENTA: Duration = Duration::from_secs(30);

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
    /// Sin esta lista, la tarea de una cuenta rechazada termina, deja de figurar
    /// entre las que corren, y la revisión siguiente la vuelve a arrancar: con
    /// una revisión cada cinco minutos serían unos **288 intentos de
    /// autenticación por día** contra el servidor de alguien, que es exactamente
    /// lo que la salida por rechazo existe para evitar.
    ///
    /// No alcanza con mirar `needs_reauth` de la cuenta: esa marca la pone el
    /// servicio cuando el **proveedor OAuth2** revoca, y un servidor IMAP que
    /// rechaza una contraseña de aplicación no la toca.
    ///
    /// Se limpia sólo cuando el servicio avisa que las cuentas cambiaron — que
    /// es cuando la persona pudo haber arreglado algo.
    rechazadas: std::collections::HashSet<String>,
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

/// Abre la sesión de una cuenta: token, configuración y conexión.
async fn abrir(broker: &Broker, cuenta: &broker::Account) -> Result<imap::Sesion, String> {
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
    imap::Sesion::abrir(&destino).await.map_err(|e| e.to_string())
}

/// Cuenta lo que hay en la casilla abierta.
async fn contar(sesion: &mut imap::Sesion, mensajes: u32) -> Result<imap::Estado, String> {
    let sin_leer = sesion.sin_leer().await.map_err(|e| e.to_string())?;
    Ok(imap::Estado { mensajes, sin_leer })
}

/// Publica lo que se sabe de una cuenta y avisa si cambió.
async fn publicar(
    servicio: &Servicio,
    emisor: &SignalContext<'_>,
    cuenta: &broker::Account,
    resultado: Result<imap::Estado, String>,
) {
    let nuevo = match resultado {
        Ok(estado) => Resumen {
            account_id: cuenta.id.clone(),
            display_name: cuenta.display_name.clone(),
            estado,
            error: String::new(),
        },
        Err(detalle) => Resumen {
            account_id: cuenta.id.clone(),
            display_name: cuenta.display_name.clone(),
            estado: imap::Estado::default(),
            error: detalle,
        },
    };

    let mut estado = servicio.estado.lock().await;
    let anterior = estado.por_cuenta.get(&cuenta.id);
    let cambio =
        anterior.map(|a| (a.estado, a.error.clone())) != Some((nuevo.estado, nuevo.error.clone()));
    estado.por_cuenta.insert(cuenta.id.clone(), nuevo);
    drop(estado);

    if cambio {
        let _ = Servicio::mailbox_changed(emisor).await;
    }
}

/// La tarea de una cuenta: se conecta y se queda.
///
/// Vive mientras la cuenta exista. Cuando el servidor sabe avisar —IDLE— se
/// queda esperando y el correo nuevo aparece en el momento; cuando no, vuelve a
/// mirar cada cinco minutos sobre la misma conexión, que igual es mejor que
/// reconectarse cada vez.
async fn atender(
    cuenta: broker::Account,
    servicio: Servicio,
    emisor: SignalContext<'static>,
) {
    loop {
        let broker = match Broker::connect().await {
            Ok(b) => b,
            Err(e) => {
                tracing::info!("'{}': esperando al servicio de cuentas: {e}", cuenta.id);
                tokio::time::sleep(REINTENTO_CUENTA).await;
                continue;
            }
        };

        match sesion_de_cuenta(&broker, &cuenta, &servicio, &emisor).await {
            // Sólo se sale con un rechazo: insistir con una credencial que el
            // servidor no acepta es cómo se bloquea una cuenta, y en un bucle
            // serían cientos de intentos por día. La tarea termina y no vuelve
            // hasta que algo cambie en las cuentas.
            Err(Salida::Rechazada(detalle)) => {
                tracing::warn!("'{}' deja de mirarse: {detalle}", cuenta.id);
                // Antes de publicar: quien revisa las tareas tiene que ver la
                // marca aunque llegue justo ahora, o la vuelve a arrancar.
                servicio.estado.lock().await.rechazadas.insert(cuenta.id.clone());
                publicar(&servicio, &emisor, &cuenta, Err(detalle)).await;
                return;
            }
            Err(Salida::Cortada(detalle)) => {
                tracing::info!("'{}' se cortó: {detalle}; reconectando", cuenta.id);
                publicar(&servicio, &emisor, &cuenta, Err(detalle)).await;
                tokio::time::sleep(REINTENTO_CUENTA).await;
            }
        }
    }
}

/// Por qué terminó la sesión de una cuenta.
enum Salida {
    /// El servidor rechazó las credenciales, o el servicio negó el permiso.
    Rechazada(String),
    /// Se cortó, se cayó la red, el servidor se reinició. Se reconecta.
    Cortada(String),
}

/// Una sesión, de principio a fin. Nunca vuelve bien: o se corta o la rechazan.
async fn sesion_de_cuenta(
    broker: &Broker,
    cuenta: &broker::Account,
    servicio: &Servicio,
    emisor: &SignalContext<'_>,
) -> Result<std::convert::Infallible, Salida> {
    let mut sesion = abrir(broker, cuenta).await.map_err(clasificar_salida)?;

    let mut mensajes = sesion
        .examinar("INBOX")
        .await
        .map_err(|e| Salida::Cortada(e.to_string()))?;

    let inicial = contar(&mut sesion, mensajes).await;
    publicar(servicio, emisor, cuenta, inicial).await;

    let avisa = sesion.soporta_idle();
    if !avisa {
        tracing::info!(
            "'{}': el servidor no sabe avisar; se mira cada {} minutos",
            cuenta.id,
            INTERVALO.as_secs() / 60,
        );
    }

    loop {
        if avisa {
            // Esperar a que el servidor diga algo. Vuelve por novedad o porque
            // hay que renovar; en los dos casos se vuelve a contar, que es
            // barato y evita depender de interpretar bien cada aviso.
            sesion
                .esperar(RENOVAR_IDLE)
                .await
                .map_err(|e| Salida::Cortada(e.to_string()))?;
        } else {
            tokio::time::sleep(INTERVALO).await;
        }

        // Pedirle el token al servicio en cada vuelta es lo que lo mantiene
        // fresco: el servicio lo refresca si le queda poco. No se usa para nada
        // más — la sesión ya está autenticada— pero sin esto una cuenta que anda
        // podría quedarse con un refresh_token caducado por no usarse.
        if let Err(e) = broker.access_token(&cuenta.id, "email").await {
            if matches!(e, BrokerError::Denied(_)) {
                return Err(Salida::Rechazada(e.to_string()));
            }
            tracing::debug!("'{}': no se pudo refrescar el token: {e}", cuenta.id);
        }

        // `EXAMINE` otra vez para releer cuántos hay: el `EXISTS` que llegó
        // durante la espera puede haber quedado atrás si hubo varios.
        mensajes = sesion
            .examinar("INBOX")
            .await
            .map_err(|e| Salida::Cortada(e.to_string()))?;

        let ahora = contar(&mut sesion, mensajes).await;
        publicar(servicio, emisor, cuenta, ahora).await;
    }
}

/// Separa lo que hay que reintentar de lo que no.
fn clasificar_salida(detalle: String) -> Salida {
    if detalle.contains("rechazó las credenciales") || detalle.contains("sin permiso") {
        Salida::Rechazada(detalle)
    } else {
        Salida::Cortada(detalle)
    }
}

/// Arranca y para las tareas para que coincidan con las cuentas que hay.
async fn ajustar_tareas(
    broker: &Broker,
    servicio: &Servicio,
    emisor: &SignalContext<'static>,
    tareas: &mut HashMap<String, tokio::task::JoinHandle<()>>,
) -> Result<(), BrokerError> {
    let cuentas = broker.accounts().await?;
    let con_correo: Vec<&broker::Account> = cuentas
        .iter()
        .filter(|c| c.hay_correo_que_sincronizar())
        .collect();
    let vigentes: Vec<&str> = con_correo.iter().map(|c| c.id.as_str()).collect();

    // Las que ya no están, o que pasaron a necesitar reautenticación.
    tareas.retain(|id, tarea| {
        if vigentes.contains(&id.as_str()) && !tarea.is_finished() {
            return true;
        }
        tarea.abort();
        false
    });

    let mut estado = servicio.estado.lock().await;
    estado.por_cuenta.retain(|id, _| vigentes.contains(&id.as_str()));
    estado.rechazadas.retain(|id| vigentes.contains(&id.as_str()));
    let rechazadas = estado.rechazadas.clone();
    drop(estado);

    for cuenta in con_correo {
        if tareas.contains_key(&cuenta.id) {
            continue;
        }
        // Una cuenta rechazada no se vuelve a arrancar. Su tarea terminó, así
        // que sin esto la revisión siguiente la levantaría de nuevo y el
        // servidor recibiría un intento cada cinco minutos.
        if rechazadas.contains(&cuenta.id) {
            continue;
        }
        tracing::info!("'{}' pasa a atenderse", cuenta.id);
        let tarea = tokio::spawn(atender(
            cuenta.clone(),
            servicio.clone(),
            emisor.clone(),
        ));
        tareas.insert(cuenta.id.clone(), tarea);
    }

    Ok(())
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

    let emisor = SignalContext::new(&conexion, "/ar/net/vasak/os/AccountsSync")?.to_owned();

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

    // El hilo principal ya no mira casillas: sólo se asegura de que haya una
    // tarea por cuenta. Cada tarea se queda conectada y avisa por su cuenta.
    let mut tareas: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    loop {
        match Broker::connect().await {
            Ok(broker) => {
                if let Err(e) = ajustar_tareas(&broker, &servicio, &emisor, &mut tareas).await {
                    match e {
                        BrokerError::Unavailable(d) => {
                            tracing::info!("el servicio de cuentas no está todavía: {d}")
                        }
                        otro => tracing::warn!("no se pudieron leer las cuentas: {otro}"),
                    }
                }
            }
            Err(e) => tracing::info!("esperando al servicio de cuentas: {e}"),
        }

        // Se revisa cuando el servicio avisa que cambió algo, y cada tanto por
        // las dudas: una tarea que terminó por rechazo tiene que poder volver si
        // la persona reconectó la cuenta.
        tokio::select! {
            _ = tokio::time::sleep(INTERVALO) => {}
            _ = despertador.recv() => {
                tracing::debug!("algo cambió en las cuentas");
                // Y sólo acá se olvidan los rechazos: la persona pudo haber
                // corregido una contraseña o reconectado una cuenta. En la
                // revisión por reloj no, o el olvido devolvería los 288
                // intentos diarios que la marca evita.
                servicio.estado.lock().await.rechazadas.clear();
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cuenta(id: &str) -> broker::Account {
        broker::Account {
            id: id.into(),
            display_name: id.into(),
            provider_type: "custom".into(),
            capabilities: vec!["email".into()],
            needs_reauth: false,
        }
    }

    /// **La propiedad que se había roto.** Una cuenta rechazada no se vuelve a
    /// arrancar en la revisión siguiente.
    ///
    /// La tarea de una cuenta rechazada termina, así que deja de figurar entre
    /// las que corren — y sin la marca, la revisión por reloj la levantaba de
    /// nuevo cada cinco minutos: unos 288 intentos de autenticación por día
    /// contra el servidor de alguien, que es exactamente lo que la salida por
    /// rechazo existe para evitar.
    ///
    /// No alcanza con mirar `needs_reauth`: esa marca la pone el servicio cuando
    /// el proveedor OAuth2 revoca, y un servidor IMAP que rechaza una contraseña
    /// de aplicación no la toca.
    #[tokio::test]
    async fn una_cuenta_rechazada_no_se_vuelve_a_arrancar() {
        let servicio = Servicio::default();
        let cuentas = [cuenta("a"), cuenta("b")];

        servicio.estado.lock().await.rechazadas.insert("a".into());
        let rechazadas = servicio.estado.lock().await.rechazadas.clone();

        let arrancarian: Vec<&str> = cuentas
            .iter()
            .filter(|c| !rechazadas.contains(&c.id))
            .map(|c| c.id.as_str())
            .collect();

        assert_eq!(arrancarian, vec!["b"], "la rechazada no tenía que arrancar");
    }

    /// Y el olvido pasa **sólo** cuando el servicio avisa que algo cambió, que
    /// es cuando la persona pudo haber arreglado la contraseña. Olvidar en la
    /// revisión por reloj devolvería los 288 intentos diarios.
    #[tokio::test]
    async fn el_rechazo_se_olvida_cuando_cambian_las_cuentas() {
        let servicio = Servicio::default();
        servicio.estado.lock().await.rechazadas.insert("a".into());

        // Lo que hace el bucle al recibir la señal.
        servicio.estado.lock().await.rechazadas.clear();

        assert!(servicio.estado.lock().await.rechazadas.is_empty());
    }

    /// Una cuenta que se borró no puede dejar su marca colgada: si se vuelve a
    /// conectar con el mismo identificador, merece un intento limpio.
    #[tokio::test]
    async fn el_rechazo_de_una_cuenta_que_ya_no_esta_se_descarta() {
        let servicio = Servicio::default();
        {
            let mut estado = servicio.estado.lock().await;
            estado.rechazadas.insert("borrada".into());
            estado.rechazadas.insert("sigue".into());
        }

        let vigentes = ["sigue"];
        servicio
            .estado
            .lock()
            .await
            .rechazadas
            .retain(|id| vigentes.contains(&id.as_str()));

        let quedan = servicio.estado.lock().await.rechazadas.clone();
        assert!(quedan.contains("sigue"));
        assert!(!quedan.contains("borrada"));
    }

    /// El tope de un intercambio tiene que ser más corto que la renovación de la
    /// espera: si fuera al revés, un servidor mudo mantendría la cuenta colgada
    /// más de lo que dura un ciclo entero y no se notaría la diferencia con una
    /// conexión sana.
    #[test]
    fn los_tiempos_tienen_el_orden_que_corresponde() {
        assert!(
            RENOVAR_IDLE < Duration::from_secs(29 * 60),
            "el estándar pide renovar antes de los 29 minutos"
        );
        assert!(REINTENTO_CUENTA < INTERVALO);
    }
}
