//! Mostrar los recordatorios de los eventos del calendario cuando llega su
//! hora, con la ventana del calendario cerrada.
//!
//! El `VALARM` de cada evento **ya se parsea y se guarda** —cada ocurrencia con
//! sus disparos en segundos UTC, en la tabla `alarms`—, pero hasta acá nada los
//! disparaba: guardados y nunca mostrados. Esto es la pieza que los lee, los
//! agenda por su hora y **avisa aunque la aplicación de calendario esté
//! cerrada**. Lo hace el servicio y no la ventana, porque el servicio es lo que
//! sigue corriendo (decisión de producto #6, `vasak-calendar#11`): es él quien
//! responde con los datos de la copia local y quien muestra los recordatorios.
//!
//! El transporte es [`crate::notifications`], el mismo que el aviso de correo
//! nuevo: `org.freedesktop.Notifications` por el bus de sesión, al que el
//! servicio ya está conectado, así que no suma ninguna dependencia.
//!
//! # Lo que decide si esto sirve o molesta
//!
//! Son los dos errores clásicos que ya resuelve el correo (`just_arrived` y «no
//! avisar sin lista previa»), acá puestos en el tiempo en vez de en una lista:
//!
//! - **Nada viejo al arrancar.** El planificador empieza a mirar con un borde
//!   (`since`) en la hora de encender. Un recordatorio cuya hora ya pasó cae
//!   antes de ese borde y no dispara: encender el servicio no desentierra los
//!   recordatorios de la mañana. Es la misma idea que «sin una lista anterior no
//!   hay novedad», con la marca en el reloj.
//! - **Sin repetir al resincronizar.** Cada pasada avisa sólo lo que cae en la
//!   franja nueva `(since, now]` y después corre el borde hasta `now`. Un
//!   recordatorio avisado queda detrás del borde; que el sync vuelva a traer el
//!   mismo `VALARM` no lo repite, porque su hora de disparo no cambió.
//!
//! La zona horaria no se mira acá: la expansión ya la resolvió al guardar, así
//! que `fires_at` es un instante UTC y alcanza con compararlo contra la hora de
//! ahora.
//!
//! # Cómo se despierta
//!
//! Duerme hasta el próximo disparo (con un techo, [`MAX_SLEEP`], por si el reloj
//! salta —suspender, un ajuste de NTP— que un temporizador monótono no ve), y
//! además lo despierta la señal `Changed("calendar", …)`: cuando el sync escribe
//! un lote de calendario puede haber aparecido un recordatorio más cercano, y
//! hay que reprogramar sin esperar al techo.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use crate::calendar_sync::Clock;
use crate::notifications;
use crate::store::calendar_read::{self, DueReminder};
use crate::store::key::KeySource;
use crate::store::lifecycle::{StoreManager, CALENDAR_AREA};
use crate::store::StoreError;

/// Cuánto, como mucho, se vuelve a mirar aunque no toque ningún recordatorio ni
/// llegue un `Changed`. Es la red para un reloj que saltó.
const MAX_SLEEP: Duration = Duration::from_secs(15 * 60);

/// Cuántos recordatorios vencidos se atienden de una pasada. Una
/// resincronización puede dejar muchos a la vez; más que esto espera la
/// siguiente vuelta en lugar de tapar la pantalla de carteles.
const BATCH: usize = 50;

/// Cómo se presenta el cartel de un recordatorio.
const APP_NAME: &str = "VasakOS Calendario";
/// El ícono estándar de «cita próxima» del tema, no una ruta: lo resuelve el
/// tema del escritorio.
const ICON: &str = "appointment-soon";
/// La entrada de menú (`.desktop`) de la aplicación de calendario.
const DESKTOP_ENTRY: &str = "vasak-calendar";

/// De dónde salen los recordatorios que toca mirar. Una implementación en
/// producción —el almacén local— y otra en las pruebas —una lista en memoria
/// con horas simuladas—, así que la lógica del planificador se prueba sin bus ni
/// base.
pub trait ReminderSource: Send + Sync {
    /// Los que disparan en la franja `(since, now]`, hasta `limit`.
    fn due(
        &self,
        since: i64,
        now: i64,
        limit: usize,
    ) -> impl std::future::Future<Output = Vec<DueReminder>> + Send;

    /// La próxima hora de disparo después de `now`, o nada si no queda ninguna.
    fn next_after(&self, now: i64) -> impl std::future::Future<Output = Option<i64>> + Send;
}

/// A dónde van los carteles. El escritorio en producción; una lista que se
/// revisa, en las pruebas.
pub trait ReminderSink: Send + Sync {
    fn show(&self, reminder: &DueReminder) -> impl std::future::Future<Output = ()> + Send;
}

/// El reloj de pared de producción.
pub fn system_clock() -> Clock {
    Arc::new(Utc::now)
}

/// El bucle del planificador: avisa lo vencido, duerme hasta el próximo disparo,
/// y se despierta también cuando `wake` lo toca (una señal `Changed` del
/// calendario).
pub async fn run<Src, Snk>(source: Src, sink: Snk, clock: Clock, wake: Arc<tokio::sync::Notify>)
where
    Src: ReminderSource,
    Snk: ReminderSink,
{
    // El borde arranca en la hora de encender: por eso el primer arranque no
    // desentierra los recordatorios de antes.
    let mut since = clock().timestamp();
    loop {
        let now = clock().timestamp();
        let sleep = step(&mut since, now, &source, &sink).await;
        tokio::select! {
            _ = tokio::time::sleep(sleep) => {}
            _ = wake.notified() => {}
        }
    }
}

/// Una pasada: avisa los recordatorios de la franja `(since, now]`, corre el
/// borde hasta `now` y devuelve cuánto dormir hasta el próximo.
///
/// Separada del bucle para poder probarla con horas dadas a mano, sin
/// temporizadores: es donde viven las dos reglas (nada viejo al arrancar, nada
/// repetido al resincronizar).
async fn step<Src, Snk>(since: &mut i64, now: i64, source: &Src, sink: &Snk) -> Duration
where
    Src: ReminderSource + ?Sized,
    Snk: ReminderSink + ?Sized,
{
    for reminder in source.due(*since, now, BATCH).await {
        sink.show(&reminder).await;
    }
    // Sólo hacia adelante: un reloj que retrocede no vuelve a abrir una franja ya
    // atendida, que avisaría de nuevo lo mismo.
    if now > *since {
        *since = now;
    }

    match source.next_after(now).await {
        Some(next) => {
            let seconds = (next - now).clamp(0, MAX_SLEEP.as_secs() as i64);
            Duration::from_secs(seconds as u64)
        }
        None => MAX_SLEEP,
    }
}

/// Lo que dice un cartel de recordatorio: el título «Recordatorio» y, en el
/// cuerpo, el nombre del evento y cuánto falta para que empiece.
///
/// El nombre lo escribió quien creó el evento —puede venir de un servidor—, así
/// que pasa por el mismo saneado que el correo: se escapa el marcado y se acorta.
pub fn reminder_text(title: &str, starts_at: i64, now: i64, all_day: bool) -> (String, String) {
    let trimmed = title.trim();
    let name = if trimmed.is_empty() {
        "(sin título)".to_string()
    } else {
        notifications::for_notification(trimmed)
    };
    (
        "Recordatorio".to_string(),
        format!("{name} — {}", relative_when(starts_at, now, all_day)),
    )
}

/// Cuánto falta para el evento, en palabras.
fn relative_when(starts_at: i64, now: i64, all_day: bool) -> String {
    if all_day {
        return "todo el día".to_string();
    }
    let delta = starts_at - now;
    if delta > 60 {
        format!("en {}", humanize(delta))
    } else if delta < -60 {
        format!("empezó hace {}", humanize(-delta))
    } else {
        "ahora".to_string()
    }
}

/// Un lapso en segundos, en la unidad más grande que no da cero.
fn humanize(seconds: i64) -> String {
    let minutes = seconds / 60;
    if minutes < 60 {
        return unit(minutes.max(1), "minuto", "minutos");
    }
    let hours = minutes / 60;
    if hours < 24 {
        return unit(hours, "hora", "horas");
    }
    unit(hours / 24, "día", "días")
}

fn unit(value: i64, singular: &str, plural: &str) -> String {
    if value == 1 {
        format!("1 {singular}")
    } else {
        format!("{value} {plural}")
    }
}

// ---------------------------------------------------------------------------
// Las implementaciones de producción
// ---------------------------------------------------------------------------

/// Los recordatorios, leídos del almacén local de cada cuenta con calendario
/// encendido. Es el servicio mirando sus propias bases: no pasa por el permiso
/// por aplicación —ese es para quien lee desde afuera—, porque es él quien
/// decide mostrar el recordatorio (decisión #6).
pub struct StoreSource<K: KeySource> {
    manager: Arc<StoreManager<K>>,
}

impl<K: KeySource> StoreSource<K> {
    pub fn new(manager: Arc<StoreManager<K>>) -> Self {
        Self { manager }
    }
}

/// Un error de lectura que no es «la base está cerrada» ni «el llavero está
/// bloqueado»: esos dos son el estado normal mientras nadie desbloqueó la
/// sesión, y llenarían el diario. Los demás sí quedan anotados.
fn log_unless_closed(account_id: &str, error: StoreError) {
    if !matches!(error, StoreError::Missing | StoreError::Key(_)) {
        tracing::debug!("recordatorios de «{account_id}»: {error}");
    }
}

impl<K: KeySource> ReminderSource for StoreSource<K> {
    async fn due(&self, since: i64, now: i64, limit: usize) -> Vec<DueReminder> {
        let mut out = Vec::new();
        for (account_id, account) in self.manager.area_accounts(CALENDAR_AREA).await {
            if !account.active {
                continue;
            }
            let who = account_id.clone();
            match self
                .manager
                .read(&account_id, move |connection| {
                    calendar_read::due_reminders(connection, &who, since, now, limit)
                })
                .await
            {
                Ok(mut found) => out.append(&mut found),
                Err(error) => log_unless_closed(&account_id, error),
            }
        }
        out.sort_by_key(|reminder| reminder.fires_at);
        out.truncate(limit);
        out
    }

    async fn next_after(&self, now: i64) -> Option<i64> {
        let mut soonest: Option<i64> = None;
        for (account_id, account) in self.manager.area_accounts(CALENDAR_AREA).await {
            if !account.active {
                continue;
            }
            match self
                .manager
                .read(&account_id, move |connection| {
                    calendar_read::next_reminder_at(connection, now)
                })
                .await
            {
                Ok(Some(at)) => soonest = Some(soonest.map_or(at, |s| s.min(at))),
                Ok(None) => {}
                Err(error) => log_unless_closed(&account_id, error),
            }
        }
        soonest
    }
}

/// Los carteles van al escritorio por el bus de sesión. Cada recordatorio es su
/// propio cartel —no se colapsan como el correo—: son eventos distintos, y uno
/// que pisa al anterior perdería el de hace cinco minutos.
pub struct DesktopSink {
    connection: zbus::Connection,
}

impl DesktopSink {
    pub fn new(connection: zbus::Connection) -> Self {
        Self { connection }
    }
}

/// La tarjeta de un recordatorio: de qué aplicación es, su ícono y su entrada de
/// menú, con el texto ya armado. Separada del envío real para poder comprobar
/// cómo se presenta sin un bus detrás. Cada recordatorio es nuevo
/// (`replaces: 0`) y no lleva botones.
fn reminder_card<'a>(title: &'a str, body: &'a str) -> notifications::Card<'a> {
    notifications::Card {
        app_name: APP_NAME,
        icon: ICON,
        desktop_entry: DESKTOP_ENTRY,
        replaces: 0,
        title,
        body,
        actions: &[],
    }
}

impl ReminderSink for DesktopSink {
    async fn show(&self, reminder: &DueReminder) {
        let (title, body) = reminder_text(
            &reminder.title,
            reminder.starts_at,
            Utc::now().timestamp(),
            reminder.all_day,
        );
        let _ = notifications::show(&self.connection, &reminder_card(&title, &body)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn reminder(fires_at: i64, action: &str) -> DueReminder {
        DueReminder {
            account_id: "cuenta".to_string(),
            object_id: fires_at, // basta con que sean distintos en las pruebas
            recurrence_id: 0,
            position: 0,
            fires_at,
            action: action.to_string(),
            title: "Reunión".to_string(),
            starts_at: fires_at + 900,
            all_day: false,
            floating: false,
        }
    }

    /// Una fuente en memoria que aplica la misma franja que el almacén: sirve
    /// para probar el planificador con horas dadas a mano.
    struct FakeSource {
        alarms: Vec<DueReminder>,
    }

    impl ReminderSource for FakeSource {
        async fn due(&self, since: i64, now: i64, limit: usize) -> Vec<DueReminder> {
            let mut found: Vec<DueReminder> = self
                .alarms
                .iter()
                .filter(|a| a.fires_at > since && a.fires_at <= now)
                .filter(|a| matches!(a.action.as_str(), "DISPLAY" | "AUDIO"))
                .cloned()
                .collect();
            found.sort_by_key(|a| a.fires_at);
            found.truncate(limit);
            found
        }

        async fn next_after(&self, now: i64) -> Option<i64> {
            self.alarms
                .iter()
                .filter(|a| a.fires_at > now && matches!(a.action.as_str(), "DISPLAY" | "AUDIO"))
                .map(|a| a.fires_at)
                .min()
        }
    }

    #[derive(Default)]
    struct RecordingSink(Mutex<Vec<DueReminder>>);

    impl ReminderSink for RecordingSink {
        async fn show(&self, reminder: &DueReminder) {
            self.0.lock().unwrap().push(reminder.clone());
        }
    }

    impl RecordingSink {
        fn fired(&self) -> Vec<DueReminder> {
            self.0.lock().unwrap().clone()
        }
    }

    // Para compartir el sink con la tarea del bucle y mirarlo desde afuera.
    impl ReminderSink for Arc<RecordingSink> {
        async fn show(&self, reminder: &DueReminder) {
            (**self).show(reminder).await;
        }
    }

    /// Deja correr a las demás tareas unas cuantas veces: con el reloj pausado,
    /// una sola cesión no alcanza para que el bucle complete una pasada.
    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    /// Cero al arrancar: tres recordatorios cuya hora ya pasó cuando el servicio
    /// enciende no disparan ninguno.
    #[tokio::test]
    async fn el_primer_arranque_no_desentierra_los_viejos() {
        let source = FakeSource {
            alarms: vec![
                reminder(100, "DISPLAY"),
                reminder(200, "DISPLAY"),
                reminder(300, "DISPLAY"),
            ],
        };
        let sink = RecordingSink::default();
        // Encendido a las 1000: el borde arranca ahí, y la primera pasada mira
        // (1000, 1000].
        let mut since = 1000;
        step(&mut since, 1000, &source, &sink).await;

        assert!(
            sink.fired().is_empty(),
            "disparó recordatorios de antes de encender"
        );
        assert_eq!(since, 1000);
    }

    /// Un aviso por ocurrencia, y una resincronización no repite los ya
    /// avisados.
    #[tokio::test]
    async fn un_aviso_por_ocurrencia_sin_repetir_al_resincronizar() {
        let source = FakeSource {
            alarms: vec![
                reminder(1100, "DISPLAY"),
                reminder(1200, "DISPLAY"),
                reminder(1300, "DISPLAY"),
            ],
        };
        let sink = RecordingSink::default();
        let mut since = 1000;

        // Antes de la primera: nada.
        step(&mut since, 1050, &source, &sink).await;
        assert_eq!(sink.fired().len(), 0);

        // Cruza la de 1100: un aviso.
        step(&mut since, 1150, &source, &sink).await;
        assert_eq!(sink.fired().len(), 1);
        assert_eq!(sink.fired()[0].fires_at, 1100);

        // Una resincronización vuelve a traer los mismos, pero sin avanzar la
        // hora la franja (1150, 1150] está vacía: no se repite.
        step(&mut since, 1150, &source, &sink).await;
        assert_eq!(sink.fired().len(), 1);

        // Cada ocurrencia siguiente, un aviso y uno solo.
        step(&mut since, 1250, &source, &sink).await;
        step(&mut since, 9999, &source, &sink).await;
        let times: Vec<i64> = sink.fired().iter().map(|r| r.fires_at).collect();
        assert_eq!(times, vec![1100, 1200, 1300]);
    }

    /// Un `VALARM` de tipo `EMAIL` no se dibuja: pide mandar un correo, no poner
    /// un cartel.
    #[tokio::test]
    async fn el_recordatorio_de_correo_no_se_dibuja() {
        let source = FakeSource {
            alarms: vec![reminder(1100, "EMAIL")],
        };
        let sink = RecordingSink::default();
        let mut since = 1000;
        step(&mut since, 9999, &source, &sink).await;
        assert!(sink.fired().is_empty());
    }

    /// El sueño va hasta el próximo disparo, con el techo de [`MAX_SLEEP`].
    #[tokio::test]
    async fn el_sueno_llega_al_proximo_disparo() {
        let source = FakeSource {
            alarms: vec![reminder(1100, "DISPLAY"), reminder(100_000, "DISPLAY")],
        };
        let sink = RecordingSink::default();
        let mut since = 1000;

        // Falta poco para la de 1100.
        let sleep = step(&mut since, 1050, &source, &sink).await;
        assert_eq!(sleep, Duration::from_secs(50));

        // Pasada la de 1100, la siguiente está lejísimos: manda el techo.
        let sleep = step(&mut since, 1150, &source, &sink).await;
        assert_eq!(sleep, MAX_SLEEP);
    }

    /// Sin nada por delante, se duerme el techo y no se despierta por gusto.
    #[tokio::test]
    async fn sin_recordatorios_duerme_el_techo() {
        let source = FakeSource { alarms: vec![] };
        let sink = RecordingSink::default();
        let mut since = 1000;
        assert_eq!(step(&mut since, 1000, &source, &sink).await, MAX_SLEEP);
    }

    #[test]
    fn el_texto_dice_el_evento_y_cuanto_falta() {
        let (title, body) = reminder_text("Dentista", 10_900, 10_000, false);
        assert_eq!(title, "Recordatorio");
        assert_eq!(body, "Dentista — en 15 minutos");
    }

    #[test]
    fn el_texto_singulariza_y_sube_de_unidad() {
        assert_eq!(reminder_text("X", 1_090, 1_000, false).1, "X — en 1 minuto");
        assert_eq!(
            reminder_text("X", 1_000 + 3600, 1_000, false).1,
            "X — en 1 hora"
        );
        assert_eq!(
            reminder_text("X", 1_000 + 2 * 86_400, 1_000, false).1,
            "X — en 2 días"
        );
    }

    #[test]
    fn el_texto_de_un_evento_que_ya_empezo() {
        let (_, body) = reminder_text("Clase", 1_000, 2_800, false);
        assert_eq!(body, "Clase — empezó hace 30 minutos");
    }

    #[test]
    fn el_texto_de_todo_el_dia() {
        let (_, body) = reminder_text("Feriado", 0, 1_000, true);
        assert_eq!(body, "Feriado — todo el día");
    }

    /// El nombre lo escribió un desconocido: su marcado no se interpreta.
    #[test]
    fn el_texto_escapa_el_nombre_del_evento() {
        let (_, body) = reminder_text("<b>Banco</b>", 10_900, 10_000, false);
        assert!(!body.contains("<b>"));
        assert!(body.contains("&lt;b&gt;"));
    }

    #[test]
    fn un_evento_sin_titulo_no_deja_el_cuerpo_cojo() {
        let (_, body) = reminder_text("   ", 10_900, 10_000, false);
        assert!(body.starts_with("(sin título) —"));
    }

    /// Un evento que empieza dentro del minuto se dice «ahora», no «en 0».
    #[test]
    fn el_texto_de_un_evento_que_empieza_ahora() {
        assert_eq!(
            reminder_text("Standup", 1_000, 1_000, false).1,
            "Standup — ahora"
        );
        // El borde de un minuto todavía cuenta como ahora.
        assert_eq!(reminder_text("X", 1_060, 1_000, false).1, "X — ahora");
    }

    /// La tarjeta dice de qué aplicación es el cartel, su ícono y su entrada de
    /// menú, y no lleva botones ni reemplaza a ninguno.
    #[test]
    fn la_tarjeta_dice_de_que_aplicacion_es() {
        let card = reminder_card("Recordatorio", "Reunión — en 15 minutos");
        assert_eq!(card.app_name, "VasakOS Calendario");
        assert_eq!(card.icon, "appointment-soon");
        assert_eq!(card.desktop_entry, "vasak-calendar");
        assert_eq!(card.replaces, 0);
        assert!(card.actions.is_empty());
        assert_eq!(card.title, "Recordatorio");
        assert_eq!(card.body, "Reunión — en 15 minutos");
    }

    #[test]
    fn el_reloj_de_sistema_da_una_hora() {
        let clock = system_clock();
        assert!(clock().timestamp() > 0);
    }

    /// El sink de escritorio manda el cartel por el bus: contra un servidor de
    /// notificaciones falso por una conexión punto a punto, se comprueba que
    /// llega con el nombre de la aplicación y el texto del recordatorio. Cubre
    /// también `notifications::show`, que es a donde delega.
    #[tokio::test]
    async fn el_sink_de_escritorio_manda_el_cartel_al_bus() {
        use std::collections::HashMap;
        use std::sync::Mutex as StdMutex;
        use zbus::zvariant::OwnedValue;

        #[derive(Clone)]
        struct Received {
            app_name: String,
            summary: String,
            body: String,
        }

        struct FakeNotifications {
            last: Arc<StdMutex<Option<Received>>>,
        }

        #[zbus::interface(name = "org.freedesktop.Notifications")]
        impl FakeNotifications {
            #[allow(clippy::too_many_arguments)]
            async fn notify(
                &self,
                app_name: String,
                _replaces_id: u32,
                _app_icon: String,
                summary: String,
                body: String,
                _actions: Vec<String>,
                _hints: HashMap<String, OwnedValue>,
                _expire_timeout: i32,
            ) -> u32 {
                *self.last.lock().unwrap() = Some(Received {
                    app_name,
                    summary,
                    body,
                });
                88
            }
        }

        let (server_end, client_end) = tokio::net::UnixStream::pair().unwrap();
        let server = zbus::connection::Builder::unix_stream(server_end)
            .server(zbus::Guid::generate())
            .unwrap()
            .p2p()
            .build();
        let client = zbus::connection::Builder::unix_stream(client_end)
            .p2p()
            .build();
        let (server, client) = tokio::join!(server, client);
        let (server, client) = (server.unwrap(), client.unwrap());

        let last = Arc::new(StdMutex::new(None));
        server
            .object_server()
            .at(
                "/org/freedesktop/Notifications",
                FakeNotifications {
                    last: Arc::clone(&last),
                },
            )
            .await
            .unwrap();

        let sink = DesktopSink::new(client);
        sink.show(&reminder(1000, "DISPLAY")).await;

        let got = last
            .lock()
            .unwrap()
            .clone()
            .expect("no llegó ningún cartel al servidor de notificaciones");
        assert_eq!(got.app_name, "VasakOS Calendario");
        assert_eq!(got.summary, "Recordatorio");
        assert!(got.body.contains("Reunión"), "cuerpo: {}", got.body);
    }

    /// El bucle entero, con el reloj pausado: avisa cuando el sueño vence al
    /// cruzar un disparo, y también cuando lo despierta un `Changed` (el `wake`),
    /// sin esperar al sueño.
    #[tokio::test(start_paused = true)]
    async fn el_bucle_avisa_al_vencer_el_sueno_y_al_despertarlo() {
        use std::sync::atomic::{AtomicI64, Ordering};

        let now = Arc::new(AtomicI64::new(1000));
        let reading = Arc::clone(&now);
        let clock: Clock = Arc::new(move || {
            chrono::DateTime::from_timestamp(reading.load(Ordering::SeqCst), 0).unwrap()
        });

        let source = FakeSource {
            alarms: vec![reminder(1100, "DISPLAY"), reminder(5000, "DISPLAY")],
        };
        let sink = Arc::new(RecordingSink::default());
        let wake = Arc::new(tokio::sync::Notify::new());

        let handle = tokio::spawn(run(
            source,
            Arc::clone(&sink),
            Arc::clone(&clock),
            Arc::clone(&wake),
        ));

        // Primera pasada: el borde arranca en 1000, nada vence, duerme hasta el
        // primer disparo (1100, o sea 100 s).
        settle().await;
        assert!(sink.fired().is_empty(), "disparó algo antes de tiempo");

        // El reloj avanza más allá del primer disparo y el sueño vence: la pasada
        // lo avisa, una sola vez.
        now.store(1200, Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(200)).await;
        settle().await;
        assert_eq!(sink.fired().len(), 1);
        assert_eq!(sink.fired()[0].fires_at, 1100);

        // Un `Changed` despierta al bucle sin esperar al sueño: movemos el reloj
        // más allá del segundo disparo y lo tocamos.
        now.store(6000, Ordering::SeqCst);
        wake.notify_one();
        settle().await;
        assert_eq!(sink.fired().len(), 2);
        assert_eq!(sink.fired()[1].fires_at, 5000);

        handle.abort();
    }
}
