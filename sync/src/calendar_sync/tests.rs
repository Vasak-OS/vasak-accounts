//! La sincronización del calendario contra un servidor CalDAV de mentira en
//! `127.0.0.1`, sin red, sin bus y con el llavero falso, y con un reloj
//! inyectado para la ventana.

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use chrono::TimeZone;
use rusqlite::OptionalExtension;
use zeroize::Zeroizing;

use super::*;
use crate::dav::fake::{event, task, FakeDav, RecordedRequest};
use crate::dav::webdav::AuthKind;
use crate::store::key::fake::FakeKeys;
use crate::store::lifecycle::{AccountListing, Consent, ListedAccount, Locations};
use crate::store::paths::tests::TempDir;

const ACCOUNT: &str = "cuenta";

struct CredentialState {
    result: Result<DavCredential, CredentialError>,
    calls: usize,
    asked: Vec<&'static str>,
}

#[derive(Clone)]
struct FakeCredentials(Arc<std::sync::Mutex<CredentialState>>);

impl FakeCredentials {
    fn calls(&self) -> usize {
        self.0.lock().unwrap().calls
    }

    fn set(&self, result: Result<DavCredential, CredentialError>) {
        self.0.lock().unwrap().result = result;
    }
}

impl CredentialSource for FakeCredentials {
    async fn credential(
        &self,
        _account_id: &str,
        capability: &'static str,
    ) -> Result<DavCredential, CredentialError> {
        let mut state = self.0.lock().unwrap();
        state.calls += 1;
        state.asked.push(capability);
        state.result.clone()
    }
}

/// El nombre de la variante, sin lo que lleva adentro: lo que sale de una
/// vuelta no se escribe en la salida de una prueba que falla.
fn outcome_kind(outcome: &CalendarOutcome) -> &'static str {
    match outcome {
        CalendarOutcome::StoreClosed => "StoreClosed",
        CalendarOutcome::Denied => "Denied",
        CalendarOutcome::Synced(_) => "Synced",
        CalendarOutcome::Failed(_) => "Failed",
    }
}

/// El 26 de septiembre de 2026 al mediodía, UTC.
const TODAY: i64 = 1_790_424_000;

struct Fixture {
    _temp: TempDir,
    keys: FakeKeys,
    manager: Arc<StoreManager<FakeKeys>>,
    server: FakeDav,
    credentials: FakeCredentials,
    sync: CalendarSync<FakeKeys, FakeCredentials>,
    notified: Arc<AtomicUsize>,
    /// El reloj de la ventana, en segundos: sólo avanza cuando la prueba lo
    /// pide.
    now: Arc<AtomicI64>,
}

impl Fixture {
    async fn new(label: &str) -> Self {
        Self::with(label, Limits::DEFAULT, ExpansionLimits::DEFAULT).await
    }

    async fn with(label: &str, limits: Limits, expansion: ExpansionLimits) -> Self {
        let temp = TempDir::new(label);
        let keys = FakeKeys::default();
        let manager = Arc::new(StoreManager::new(
            keys.clone(),
            Ok(Locations {
                stores: temp.0.join("data/stores"),
                settings: temp.0.join("config/stores.json"),
            }),
        ));
        manager
            .accounts_listed(
                AccountListing::Listed(vec![ListedAccount {
                    id: ACCOUNT.into(),
                    display_name: "Trabajo".into(),
                    capabilities: vec!["calendar".into()],
                    needs_reauth: false,
                }]),
                Instant::now(),
            )
            .await;
        assert!(manager
            .activate_area(CALENDAR_AREA, ACCOUNT, Consent::Granted)
            .await
            .unwrap());

        let server = FakeDav::start_caldav().await;
        let credentials = FakeCredentials(Arc::new(std::sync::Mutex::new(CredentialState {
            result: Ok(DavCredential {
                home: server.home_url(),
                username: "ana".into(),
                secret: Zeroizing::new("la-clave".into()),
                auth: AuthKind::Password,
            }),
            calls: 0,
            asked: Vec::new(),
        })));
        let notified = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&notified);
        let now = Arc::new(AtomicI64::new(TODAY));
        let clock = Arc::clone(&now);
        let sync = CalendarSync::new(
            Arc::clone(&manager),
            credentials.clone(),
            limits,
            HttpPolicy::plain_loopback(),
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        )
        .with_clock(Arc::new(move || {
            Utc.timestamp_opt(clock.load(Ordering::SeqCst), 0).unwrap()
        }))
        .with_expansion(expansion);
        Self {
            _temp: temp,
            keys,
            manager,
            server,
            credentials,
            sync,
            notified,
            now,
        }
    }

    async fn sync(&self) -> CalendarOutcome {
        self.sync.sync_account(ACCOUNT).await
    }

    async fn synced(&self) -> CalendarReport {
        match self.sync().await {
            CalendarOutcome::Synced(report) => report,
            other => panic!("la vuelta no terminó bien: {}", outcome_kind(&other)),
        }
    }

    async fn query<T, F>(&self, read: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(&rusqlite::Connection) -> T + Send + 'static,
    {
        self.manager
            .with_store(ACCOUNT, move |store| Ok(read(store.connection())))
            .await
            .expect("la base tenía que estar abierta")
    }

    async fn count(&self, sql: &'static str) -> i64 {
        self.query(move |c| c.query_row(sql, [], |row| row.get(0)).unwrap())
            .await
    }

    async fn summaries(&self) -> Vec<String> {
        self.query(|c| {
            let mut statement = c
                .prepare("SELECT summary FROM calendar_objects ORDER BY summary")
                .unwrap();
            statement
                .query_map([], |row| row.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        })
        .await
    }

    async fn token(&self, calendar: usize) -> Option<String> {
        let href = self.server.collection_url(calendar).to_string();
        self.query(move |c| {
            c.query_row(
                "SELECT token FROM sync_state WHERE area = 'calendar' AND collection = ?1",
                [href],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .unwrap()
            .flatten()
        })
        .await
    }

    fn server_token(&self) -> String {
        format!("t{}", self.server.state().version)
    }

    fn requests_since(&self, before: usize) -> Vec<RecordedRequest> {
        self.server.requests()[before..].to_vec()
    }

    async fn calendar_status(&self) -> serde_json::Value {
        let status = serde_json::to_value(self.manager.status().await).unwrap();
        status["accounts"][0]["calendar"].clone()
    }

    fn advance_days(&self, days: i64) {
        self.now.fetch_add(days * 86_400, Ordering::SeqCst);
    }
}

fn daily(uid: &str, start: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nSUMMARY:Diario {uid}\r\n\
         DTSTART:{start}\r\nDURATION:PT30M\r\nRRULE:FREQ=DAILY\r\n\
         BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

// ── La capacidad ────────────────────────────────────────────────────────────

/// **Lo que pide esta parte del sincronizador: `calendar`, y nada más** —el
/// nombre de la capacidad, no el del recurso: el servicio de cuentas arma
/// `account.calendar` él mismo—. Las tareas van con el calendario (supuesto 8).
#[tokio::test]
async fn el_calendario_solo_pide_la_capacidad_de_calendario() {
    assert_eq!(CALENDAR_AREA, "calendar");
    let f = Fixture::new("calendario-capacidad").await;
    f.synced().await;
    assert_eq!(f.credentials.0.lock().unwrap().asked, vec!["calendar"]);
}

// ── La carga inicial ────────────────────────────────────────────────────────

/// La primera vez no hay token: `sync-collection` vacío trae todo —eventos y
/// tareas—, se pide por `calendar-multiget`, el token queda guardado, el
/// calendario con su color y sus componentes, y cada evento con sus
/// ocurrencias. Con la credencial en `Basic`, y nada más que `PROPFIND` y
/// `REPORT`.
#[tokio::test]
async fn la_carga_inicial_trae_eventos_y_tareas_y_guarda_el_token() {
    let f = Fixture::new("calendario-inicial").await;
    f.server
        .put(0, "reunion.ics", &event("r", "Reunión", "20260928T140000Z"));
    f.server
        .put(0, "pan.ics", &task("t", "Comprar pan", "20261001T180000Z"));
    f.server
        .put(0, "diario.ics", &daily("d", "20260901T080000Z"));

    let report = f.synced().await;
    assert_eq!(report.calendars, 1);
    assert_eq!(report.fetched, 3);
    assert_eq!(
        f.summaries().await,
        vec!["Comprar pan", "Diario d", "Reunión"]
    );
    assert_eq!(f.token(0).await, Some(f.server_token()));

    let (name, color, components): (String, Option<String>, String) = f
        .query(|c| {
            c.query_row(
                "SELECT display_name, color, components FROM calendars",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
        })
        .await;
    assert_eq!(name, "Personal");
    assert_eq!(color.as_deref(), Some("#FF5733"));
    assert_eq!(components, "VEVENT,VTODO");

    // La tarea no tiene ocurrencias; la reunión, una; la diaria, las de su
    // ventana, cada una con su recordatorio.
    assert_eq!(
        f.count(
            "SELECT count(*) FROM occurrences o JOIN calendar_objects c ON c.id = o.object_id
              WHERE c.component = 'VTODO'"
        )
        .await,
        0
    );
    let daily_count = f
        .count(
            "SELECT count(*) FROM occurrences o JOIN calendar_objects c ON c.id = o.object_id
              WHERE c.uid = 'd'",
        )
        .await;
    assert!(
        (750..=760).contains(&daily_count),
        "{daily_count} días desde el 1 de septiembre hasta la ventana"
    );
    assert_eq!(f.count("SELECT count(*) FROM alarms").await, daily_count);

    let raw: String = f
        .query(|c| {
            c.query_row(
                "SELECT raw_ical FROM calendar_objects WHERE uid = 'r'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        })
        .await;
    assert_eq!(
        raw,
        event("r", "Reunión", "20260928T140000Z").replace("\r\n", "\n")
    );

    let requests = f.server.requests();
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("ana:la-clave")
    );
    assert!(requests.iter().any(|r| r.is_multiget()));
    assert!(requests
        .iter()
        .filter(|r| r.is_multiget())
        .all(|r| r.body.contains("calendar-multiget")));
    for request in &requests {
        assert!(matches!(request.method.as_str(), "PROPFIND" | "REPORT"));
        assert_eq!(request.authorization, expected);
    }
    assert_eq!(f.calendar_status().await["state"], "synced");
    assert!(f.notified.load(Ordering::SeqCst) > 0);
}

// ── Las diferencias ─────────────────────────────────────────────────────────

/// Con token, se pide desde ahí y se trae **sólo** lo que cambió.
#[tokio::test]
async fn la_diferencia_trae_solo_lo_que_cambio() {
    let f = Fixture::new("calendario-diferencia").await;
    f.server
        .put(0, "a.ics", &event("a", "Uno", "20260928T140000Z"));
    f.server
        .put(0, "b.ics", &event("b", "Dos", "20260929T140000Z"));
    f.synced().await;
    let first = f.token(0).await.unwrap();

    f.server
        .put(0, "b.ics", &event("b", "Dos, movido", "20260930T140000Z"));
    let before = f.server.requests().len();
    let report = f.synced().await;
    assert_eq!(report.fetched, 1);
    let multiget: Vec<_> = f
        .requests_since(before)
        .into_iter()
        .filter(|r| r.is_multiget())
        .collect();
    assert_eq!(multiget.len(), 1);
    assert!(multiget[0].body.contains("b.ics"));
    assert!(!multiget[0].body.contains("a.ics"));
    assert_ne!(f.token(0).await.unwrap(), first);
    assert_eq!(f.summaries().await, vec!["Dos, movido", "Uno"]);
    let start: i64 = f
        .query(|c| {
            c.query_row(
                "SELECT o.starts_at FROM occurrences o JOIN calendar_objects c ON c.id = o.object_id
                  WHERE c.uid = 'b'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        })
        .await;
    assert_eq!(crate::ical::rfc3339(start), "2026-09-30T14:00:00+00:00");
}

/// **Un token inválido lleva a la carga completa**, que borra lo que ya no
/// está y guarda el token nuevo.
#[tokio::test]
async fn un_token_invalido_lleva_a_la_sincronizacion_completa() {
    let f = Fixture::new("calendario-token-vencido").await;
    f.server
        .put(0, "a.ics", &event("a", "Uno", "20260928T140000Z"));
    f.server
        .put(0, "b.ics", &event("b", "Dos", "20260929T140000Z"));
    f.synced().await;
    {
        let mut state = f.server.state();
        state.min_valid_token = state.version + 1;
    }
    f.server.remove(0, "b.ics");
    f.server
        .put(0, "c.ics", &event("c", "Tres", "20261001T140000Z"));

    let report = f.synced().await;
    assert_eq!(report.full_resyncs, 1);
    assert_eq!(f.summaries().await, vec!["Tres", "Uno"]);
    assert_eq!(f.token(0).await, Some(f.server_token()));
}

/// **Lo que viene con `404` se borra**, con sus ocurrencias y sus
/// recordatorios.
#[tokio::test]
async fn un_404_borra_el_objeto_sus_ocurrencias_y_sus_recordatorios() {
    let f = Fixture::new("calendario-404").await;
    f.server.put(0, "d.ics", &daily("d", "20260901T080000Z"));
    f.server
        .put(0, "a.ics", &event("a", "Uno", "20260928T140000Z"));
    f.synced().await;
    assert!(f.count("SELECT count(*) FROM alarms").await > 0);

    f.server.remove(0, "d.ics");
    let report = f.synced().await;
    assert_eq!(report.removed, 1);
    assert_eq!(f.summaries().await, vec!["Uno"]);
    assert_eq!(f.count("SELECT count(*) FROM occurrences").await, 1);
    assert_eq!(f.count("SELECT count(*) FROM alarms").await, 0);
}

/// Sin `sync-collection`, por ETag: lo nuevo y lo cambiado se traen, lo que
/// no está se borra, y no se pide ningún `sync-collection`.
#[tokio::test]
async fn sin_sync_collection_se_compara_por_etag() {
    let f = Fixture::new("calendario-etag").await;
    f.server.state().collections[0].supports_sync = false;
    f.server
        .put(0, "a.ics", &event("a", "Uno", "20260928T140000Z"));
    f.server
        .put(0, "b.ics", &event("b", "Dos", "20260929T140000Z"));
    let report = f.synced().await;
    assert_eq!(report.etag_calendars, 1);
    assert_eq!(report.fetched, 2);

    f.server.remove(0, "a.ics");
    f.server
        .put(0, "b.ics", &event("b", "Dos bis", "20260929T140000Z"));
    f.server
        .put(0, "c.ics", &event("c", "Tres", "20260930T140000Z"));
    let report = f.synced().await;
    assert_eq!(report.fetched, 2);
    assert_eq!(report.removed, 1);
    assert_eq!(f.summaries().await, vec!["Dos bis", "Tres"]);
    assert!(!f.server.requests().iter().any(|r| r.is_sync_collection()));
    assert_eq!(f.token(0).await, None);
}

/// Un calendario que desaparece se va con sus objetos, sus ocurrencias y su
/// token; el otro queda.
#[tokio::test]
async fn un_calendario_que_desaparece_se_va_con_lo_suyo() {
    let f = Fixture::new("calendario-desaparece").await;
    let work = f.server.add_collection("/dav/ana/trabajo/", "Trabajo");
    f.server
        .put(0, "a.ics", &event("a", "Personal", "20260928T140000Z"));
    f.server.put(work, "b.ics", &daily("b", "20260901T080000Z"));
    f.synced().await;
    assert_eq!(f.count("SELECT count(*) FROM calendars").await, 2);

    f.server.state().collections.remove(work);
    let report = f.synced().await;
    assert_eq!(report.calendars, 1);
    assert_eq!(f.count("SELECT count(*) FROM calendars").await, 1);
    assert_eq!(f.summaries().await, vec!["Personal"]);
    assert_eq!(f.count("SELECT count(*) FROM occurrences").await, 1);
    assert_eq!(
        f.count("SELECT count(*) FROM sync_state WHERE area = 'calendar'")
            .await,
        1
    );
}

/// Un calendario de sólo tareas se guarda con sus tareas y sin ocurrencias.
#[tokio::test]
async fn un_calendario_de_solo_tareas_se_guarda() {
    let f = Fixture::new("calendario-tareas").await;
    f.server.state().collections[0].components = vec!["VTODO".into()];
    f.server
        .put(0, "t.ics", &task("t", "Comprar pan", "20261001T180000Z"));
    f.synced().await;
    let components: String = f
        .query(|c| {
            c.query_row("SELECT components FROM calendars", [], |r| r.get(0))
                .unwrap()
        })
        .await;
    assert_eq!(components, "VTODO");
    assert_eq!(f.summaries().await, vec!["Comprar pan"]);
    assert_eq!(f.count("SELECT count(*) FROM occurrences").await, 0);
}

/// **Una dirección de otro origen no se pide ni se guarda**, y el otro
/// servidor no recibe nada.
#[tokio::test]
async fn una_direccion_de_otro_origen_no_se_pide_ni_se_guarda() {
    let f = Fixture::new("calendario-otro-origen").await;
    let other = FakeDav::start_caldav().await;
    f.server
        .put(0, "a.ics", &event("a", "Uno", "20260928T140000Z"));
    {
        let mut state = f.server.state();
        state.extra_listing_xml = format!(
            "<d:response><d:href>{}/dav/ana/ajeno/</d:href><d:propstat><d:prop>\
             <d:resourcetype><d:collection/><c:calendar/></d:resourcetype>\
             <d:displayname>Ajeno</d:displayname></d:prop>\
             <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
            other.origin()
        );
        state.extra_sync_xml = format!(
            "<d:response><d:href>{}/dav/ana/personal/ajeno.ics</d:href><d:propstat><d:prop>\
             <d:getetag>\"x\"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status>\
             </d:propstat></d:response>",
            other.origin()
        );
    }
    let report = f.synced().await;
    assert!(report.foreign >= 2, "{}", report.foreign);
    assert_eq!(f.summaries().await, vec!["Uno"]);
    assert_eq!(f.count("SELECT count(*) FROM calendars").await, 1);
    assert!(
        other.requests().is_empty(),
        "el otro servidor no recibió nada"
    );
}

// ── El llavero ──────────────────────────────────────────────────────────────

/// **Con el llavero bloqueado no se pide ni se escribe nada**: ni al
/// servidor, ni la credencial.
#[tokio::test]
async fn con_el_llavero_bloqueado_no_se_pide_ni_se_escribe_nada() {
    let f = Fixture::new("calendario-bloqueado").await;
    f.server
        .put(0, "a.ics", &event("a", "Uno", "20260928T140000Z"));
    f.keys.state().locked = true;

    assert_eq!(f.sync().await, CalendarOutcome::StoreClosed);
    assert_eq!(f.server.requests().len(), 0, "el servidor no recibió nada");
    assert_eq!(f.credentials.calls(), 0, "ni se pidió la credencial");
    assert_eq!(f.calendar_status().await["state"], "pending");

    f.keys.state().locked = false;
    assert!(f.manager.prepare_for_sync(CALENDAR_AREA, ACCOUNT).await);
    assert_eq!(f.count("SELECT count(*) FROM calendar_objects").await, 0);
}

/// **Bloqueado a mitad**: lo que llegó después no se escribe, y no se pide
/// nada más.
#[tokio::test]
async fn si_el_llavero_se_bloquea_a_mitad_no_se_escribe_lo_que_llego() {
    let f = Fixture::new("calendario-bloqueo-a-mitad").await;
    f.server
        .put(0, "a.ics", &event("a", "Uno", "20260928T140000Z"));
    let keys = f.keys.clone();
    f.server.state().on_request = Some(Box::new(move |request| {
        if request.is_multiget() {
            keys.state().locked = true;
        }
    }));

    assert_eq!(f.sync().await, CalendarOutcome::StoreClosed);
    let multigets = f
        .server
        .requests()
        .iter()
        .filter(|r| r.is_multiget())
        .count();
    assert_eq!(multigets, 1, "después del bloqueo no se pidió nada más");

    f.server.state().on_request = None;
    f.keys.state().locked = false;
    assert!(f.manager.prepare_for_sync(CALENDAR_AREA, ACCOUNT).await);
    assert_eq!(f.count("SELECT count(*) FROM calendar_objects").await, 0);
    assert_eq!(f.token(0).await, None);
}

/// Sin permiso del servicio de cuentas, `unavailable` con el motivo, y nada
/// pedido al servidor.
#[tokio::test]
async fn sin_permiso_se_ve_no_disponible() {
    let f = Fixture::new("calendario-sin-permiso").await;
    f.credentials.set(Err(CredentialError::Denied));
    assert_eq!(f.sync().await, CalendarOutcome::Denied);
    let status = f.calendar_status().await;
    assert_eq!(status["state"], "unavailable");
    assert!(status["detail"]
        .as_str()
        .unwrap()
        .contains("vasak-permissions 0.15.0"));
    assert!(f.server.requests().is_empty());
}

// ── Los lotes ───────────────────────────────────────────────────────────────

/// **Más de quinientos objetos van en varios lotes**, el token con el último,
/// y cada lote que cambió algo sale una vez como cambio del área.
#[tokio::test]
async fn mas_de_quinientos_objetos_van_en_varios_lotes_con_el_token_en_el_ultimo() {
    let f = Fixture::new("calendario-lotes").await;
    for i in 0..1203 {
        f.server.put(
            0,
            &format!("{i:05}.ics"),
            &event(
                &format!("{i:05}"),
                &format!("Evento {i:05}"),
                "20261010T100000Z",
            ),
        );
    }
    let mut changes = f.manager.subscribe_changes();
    let report = f.synced().await;
    assert_eq!(report.fetched, 1203);
    assert_eq!(report.batches, 3);
    assert_eq!(f.count("SELECT count(*) FROM calendar_objects").await, 1203);
    assert_eq!(f.count("SELECT count(*) FROM occurrences").await, 1203);
    assert_eq!(f.token(0).await, Some(f.server_token()));
    let mut calendar_changes = 0;
    while let Ok(change) = changes.try_recv() {
        assert_eq!(change.area, CALENDAR_AREA);
        calendar_changes += 1;
    }
    // El calendario nuevo y los tres lotes.
    assert_eq!(calendar_changes, 4);
}

/// **Un corte a mitad no pierde el token viejo**: el primer lote queda
/// escrito, el token no se guarda —va con el último—, y la vuelta siguiente
/// sigue desde ahí y termina.
#[tokio::test]
async fn un_corte_a_mitad_no_pierde_el_token_viejo() {
    let f = Fixture::new("calendario-corte").await;
    for i in 0..1203 {
        f.server.put(
            0,
            &format!("{i:05}.ics"),
            &event(
                &format!("{i:05}"),
                &format!("Evento {i:05}"),
                "20261010T100000Z",
            ),
        );
    }
    // Diez `multiget` de cincuenta son el primer lote de quinientos; el
    // duodécimo falla.
    f.server.state().fail_multiget_from = Some(12);
    assert!(matches!(f.sync().await, CalendarOutcome::Failed(_)));
    assert_eq!(f.count("SELECT count(*) FROM calendar_objects").await, 500);
    assert_eq!(f.token(0).await, None, "el token va con el último lote");

    f.server.state().fail_multiget_from = None;
    let report = f.synced().await;
    // Lo que quedó escrito no se vuelve a pedir: su ETag es el mismo.
    assert_eq!(report.fetched, 703);
    assert_eq!(report.batches, 2);
    assert_eq!(f.count("SELECT count(*) FROM calendar_objects").await, 1203);
    assert_eq!(f.token(0).await, Some(f.server_token()));
}

/// Una cuenta que pasaría el tope de ocurrencias no escribe ese lote ni
/// guarda el token.
#[tokio::test]
async fn una_cuenta_que_pasa_el_tope_de_ocurrencias_no_sigue_escribiendo() {
    let limits = Limits {
        max_account_occurrences: 100,
        ..Limits::DEFAULT
    };
    let f = Fixture::with(
        "calendario-tope-ocurrencias",
        limits,
        ExpansionLimits::DEFAULT,
    )
    .await;
    f.server.put(0, "d.ics", &daily("d", "20260901T080000Z"));
    let outcome = f.sync().await;
    assert!(
        matches!(outcome, CalendarOutcome::Failed(_)),
        "{}",
        outcome_kind(&outcome)
    );
    assert_eq!(f.count("SELECT count(*) FROM occurrences").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM calendar_objects").await, 0);
    assert_eq!(f.token(0).await, None);
    assert_eq!(f.calendar_status().await["state"], "failed");
}

/// Una cuenta que pasaría el tope de recordatorios —diez por ocurrencia en un
/// diario— tampoco escribe ese lote ni guarda el token, aunque sus
/// ocurrencias entren.
#[tokio::test]
async fn una_cuenta_que_pasa_el_tope_de_recordatorios_no_sigue_escribiendo() {
    let limits = Limits {
        max_account_alarms: 1000,
        ..Limits::DEFAULT
    };
    let f = Fixture::with(
        "calendario-tope-recordatorios",
        limits,
        ExpansionLimits::DEFAULT,
    )
    .await;
    let alarms: String = (1..=10)
        .map(|m| format!("BEGIN:VALARM\r\nTRIGGER:-PT{m}M\r\nEND:VALARM\r\n"))
        .collect();
    f.server.put(
        0,
        "d.ics",
        &format!(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:d\r\nSUMMARY:Diario\r\n\
             DTSTART:20260901T080000Z\r\nDURATION:PT30M\r\nRRULE:FREQ=DAILY\r\n\
             {alarms}END:VEVENT\r\nEND:VCALENDAR\r\n"
        ),
    );
    let outcome = f.sync().await;
    assert!(
        matches!(outcome, CalendarOutcome::Failed(_)),
        "{}",
        outcome_kind(&outcome)
    );
    assert_eq!(f.count("SELECT count(*) FROM alarms").await, 0);
    assert_eq!(f.count("SELECT count(*) FROM calendar_objects").await, 0);
    assert_eq!(f.token(0).await, None);
    assert_eq!(f.calendar_status().await["state"], "failed");
}

// ── La expansión y la ventana ───────────────────────────────────────────────

/// **Una regla que se dispara no cuelga la vuelta ni llena la base**: una por
/// segundo sin fin, una con `COUNT` de diez millones y miles de `RDATE`
/// terminan enseguida, con el tope de ocurrencias por objeto, marcadas.
#[tokio::test]
async fn una_regla_desmedida_no_cuelga_la_vuelta_ni_llena_la_base() {
    let f = Fixture::new("calendario-desmedido").await;
    let rdates: Vec<String> = (0..5000)
        .map(|i| {
            crate::ical::rfc3339(TODAY + i * 60)
                .replace(['-', ':'], "")
                .replace("+0000", "Z")
        })
        .collect();
    for (name, rule) in [
        ("segundos", "RRULE:FREQ=SECONDLY".to_string()),
        ("cuenta", "RRULE:FREQ=SECONDLY;COUNT=10000000".to_string()),
        ("fechas", format!("RDATE:{}", rdates.join(","))),
    ] {
        f.server.put(
            0,
            &format!("{name}.ics"),
            &format!(
                "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:{name}\r\nSUMMARY:{name}\r\n\
                 DTSTART:20250101T000000Z\r\n{rule}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
            ),
        );
    }
    let report = tokio::time::timeout(Duration::from_secs(20), f.synced())
        .await
        .expect("la vuelta no terminó a tiempo");
    assert_eq!(report.capped_series, 3);
    let per_object: i64 = f
        .count("SELECT max(n) FROM (SELECT count(*) AS n FROM occurrences GROUP BY object_id)")
        .await;
    assert!(per_object <= ExpansionLimits::DEFAULT.max_occurrences as i64);
    assert_eq!(
        f.count("SELECT count(*) FROM calendar_objects WHERE expansion = 'truncated'")
            .await,
        3
    );
    // Y queda anotado en la bitácora de la base, sin nada del evento.
    let logged: String = f
        .query(|c| {
            c.query_row(
                "SELECT message FROM sync_log WHERE area = 'calendar'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        })
        .await;
    assert!(logged.starts_with("3 objetos"), "{logged}");
}

/// **La zona desconocida no pierde el evento**: queda a la hora de la sesión y
/// marcado `unknown`.
#[tokio::test]
async fn un_evento_con_zona_desconocida_se_guarda_marcado() {
    let f = Fixture::new("calendario-zona").await;
    f.server.put(
        0,
        "m.ics",
        "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:m\r\nSUMMARY:En Marte\r\n\
         DTSTART;TZID=Hora de Marte:20261010T100000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
    );
    f.synced().await;
    let (zone, start): (String, i64) = f
        .query(|c| {
            c.query_row(
                "SELECT c.zone, o.starts_at FROM calendar_objects c
                   JOIN occurrences o ON o.object_id = c.id",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
        })
        .await;
    assert_eq!(zone, "unknown");
    let local = chrono::Local
        .from_local_datetime(
            &chrono::NaiveDate::from_ymd_opt(2026, 10, 10)
                .unwrap()
                .and_hms_opt(10, 0, 0)
                .unwrap(),
        )
        .earliest()
        .unwrap();
    assert_eq!(start, local.timestamp());
}

/// **La ventana que se corre, sin volver a la red.** Con el reloj diez días
/// adelante, la revisión saca las ocurrencias de antes del comienzo nuevo,
/// suma las del final nuevo y deja la ventana nueva en la base, sin un solo
/// pedido al servidor ni a la credencial; y lo anuncia.
#[tokio::test]
async fn la_ventana_se_corre_sin_volver_a_la_red() {
    let f = Fixture::new("calendario-ventana").await;
    f.server.put(0, "d.ics", &daily("d", "20200101T080000Z"));
    f.server
        .put(0, "a.ics", &event("a", "Suelto", "20100101T080000Z"));
    f.synced().await;
    let window = Window::around(Utc.timestamp_opt(TODAY, 0).unwrap());
    let first: i64 = f
        .count("SELECT min(starts_at) FROM occurrences WHERE object_id = (SELECT id FROM calendar_objects WHERE uid = 'd')")
        .await;
    assert_eq!(crate::ical::rfc3339(first), "2025-09-26T08:00:00+00:00");
    let before_count = f.count("SELECT count(*) FROM occurrences").await;
    let requests = f.server.requests().len();
    let credentials = f.credentials.calls();

    // El mismo día, nada.
    assert!(!f.sync.shift_window(ACCOUNT).await);

    f.advance_days(10);
    let mut changes = f.manager.subscribe_changes();
    assert!(f.sync.shift_window(ACCOUNT).await);
    let moved = Window::around(Utc.timestamp_opt(TODAY + 10 * 86_400, 0).unwrap());
    assert_ne!(moved, window);

    let (first, last): (i64, i64) = f
        .query(|c| {
            c.query_row(
                "SELECT min(starts_at), max(starts_at) FROM occurrences WHERE object_id = (SELECT id FROM calendar_objects WHERE uid = 'd')",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
        })
        .await;
    assert_eq!(crate::ical::rfc3339(first), "2025-10-06T08:00:00+00:00");
    assert_eq!(crate::ical::rfc3339(last), "2028-10-05T08:00:00+00:00");
    assert_eq!(
        f.count("SELECT count(*) FROM occurrences").await,
        before_count
    );
    assert_eq!(
        f.count(
            "SELECT count(*) FROM occurrences
              WHERE object_id = (SELECT id FROM calendar_objects WHERE uid = 'a')"
        )
        .await,
        1,
        "el suelto de 2010 sigue"
    );
    assert_eq!(
        f.query(|c| {
            c.query_row(
                "SELECT value FROM store_meta WHERE key = 'calendar.window'",
                [],
                |r| r.get::<_, String>(0),
            )
            .unwrap()
        })
        .await,
        format!("{},{}", moved.start, moved.end)
    );
    assert_eq!(
        f.server.requests().len(),
        requests,
        "ningún pedido a la red"
    );
    assert_eq!(f.credentials.calls(), credentials);
    assert_eq!(changes.try_recv().unwrap().area, CALENDAR_AREA);

    // La vuelta siguiente escribe con la ventana nueva.
    f.server.put(0, "e.ics", &daily("e", "20200101T090000Z"));
    f.synced().await;
    let from: i64 = f
        .query(|c| {
            c.query_row(
                "SELECT expanded_from FROM calendar_objects WHERE uid = 'e'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        })
        .await;
    assert_eq!(from, moved.start);
}

/// La revisión del programador corre la ventana antes de las vueltas.
#[tokio::test]
async fn la_revision_corre_la_ventana() {
    let f = Fixture::new("calendario-revision").await;
    f.server.put(0, "d.ics", &daily("d", "20200101T080000Z"));
    f.synced().await;
    f.advance_days(1);
    let scheduler = CalendarScheduler::new(f.sync);
    scheduler.run_due(Instant::now()).await;
    let from: i64 = f
        .manager
        .with_store(ACCOUNT, |s| {
            Ok(s.connection()
                .query_row(
                    "SELECT expanded_from FROM calendar_objects WHERE uid = 'd'",
                    [],
                    |r| r.get(0),
                )
                .unwrap())
        })
        .await
        .unwrap();
    assert_eq!(
        from,
        Window::around(Utc.timestamp_opt(TODAY + 86_400, 0).unwrap()).start
    );
}

/// El estado del área no lleva nada del calendario ni direcciones.
#[tokio::test]
async fn el_estado_del_area_no_lleva_datos_ni_direcciones() {
    let f = Fixture::new("calendario-estado").await;
    f.server.put(
        0,
        "a.ics",
        &event("a", "Reunión secreta", "20260928T140000Z"),
    );
    f.synced().await;
    let status = serde_json::to_string(&f.manager.status().await).unwrap();
    for forbidden in ["Reunión", "127.0.0.1", "/dav/", "la-clave", "Personal"] {
        assert!(!status.contains(forbidden), "el estado lleva «{forbidden}»");
    }
}

/// **El plazo de la vuelta se mira entre objeto y objeto.** Una tanda son
/// cincuenta objetos y cada uno puede gastar el plazo de su expansión entero:
/// derivados todos de una vez, la vuelta no se podía cortar en ese rato. Con el
/// plazo ya pasado no se deriva ninguno; con tiempo, todos.
#[test]
fn derivar_una_tanda_mira_el_plazo_de_la_vuelta() {
    let window = Window::around(Utc.timestamp_opt(TODAY, 0).unwrap());
    let objects = || -> Vec<CalendarResource> {
        (0..50)
            .map(|i| CalendarResource {
                href: url::Url::parse(&format!("https://x/c/{i}.ics")).unwrap(),
                etag: None,
                data: daily(&format!("d{i}"), "20260901T080000Z"),
            })
            .collect()
    };
    let expansion = ExpansionLimits::DEFAULT;
    let past = std::time::Instant::now();
    let (rows, _) = rows_from(objects(), 512 * 1024, window, &expansion, past);
    assert!(rows.is_empty(), "derivó {} con el plazo pasado", rows.len());
    let later = std::time::Instant::now() + Duration::from_secs(600);
    let (rows, _) = rows_from(objects(), 512 * 1024, window, &expansion, later);
    assert_eq!(rows.len(), 50);
}

/// Lo mismo al correr la ventana: con el plazo pasado, la tanda no se
/// expande ni se escribe.
#[test]
fn correr_una_tanda_de_la_ventana_mira_el_plazo() {
    let target = Window::around(Utc.timestamp_opt(TODAY, 0).unwrap());
    let stale: Vec<StaleSeries> = (0..100)
        .map(|i| StaleSeries {
            id: i + 1,
            calendar_id: 1,
            raw_ical: daily(&format!("d{i}"), "20260901T080000Z"),
            expanded: None,
            truncated: false,
        })
        .collect();
    let expansion = ExpansionLimits::DEFAULT;
    assert!(shifts_until(&stale, target, &expansion, std::time::Instant::now()).is_none());
    let later = std::time::Instant::now() + Duration::from_secs(600);
    assert_eq!(
        shifts_until(&stale, target, &expansion, later).map(|s| s.len()),
        Some(100)
    );
}

// ── Lo que pasa el tope, al leerlo (N8) ─────────────────────────────────────

/// **N8**: `fetch_objects` no devuelve —ni retiene hasta el final de la
/// tanda— ningún objeto que pase el tope de tamaño: se descarta al leer cada
/// respuesta y queda contado en `too_large`. Antes se miraba en `rows_from`,
/// después de juntar la tanda entera: con objetos de 15 MiB, que parten la
/// tanda hasta uno por pedido, eran ~30 MB de pico por objeto y ~1,5 GB por
/// tanda de 50.
#[tokio::test]
async fn una_tanda_del_calendario_no_retiene_lo_que_pasa_el_tope() {
    let limits = Limits {
        max_ical_bytes: 1024,
        ..Limits::DEFAULT
    };
    let f = Fixture::with("calendario-tanda-de-mas", limits, ExpansionLimits::DEFAULT).await;
    let big = format!(
        "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:g\r\nDESCRIPTION:{}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        "d".repeat(4096)
    );
    for i in 0..20 {
        f.server.put(0, &format!("grande{i}.ics"), &big);
    }
    f.server
        .put(0, "chico.ics", &event("c", "Chico", "20260928T140000Z"));

    let credential = f.credentials.0.lock().unwrap().result.clone().unwrap();
    let client = DavClient::new(&credential, limits, HttpPolicy::plain_loopback()).unwrap();
    let (calendars, _) = caldav::list_calendars(&client).await.unwrap();
    let base = &calendars[0].href;
    let mut hrefs: Vec<url::Url> = (0..20)
        .map(|i| base.join(&format!("grande{i}.ics")).unwrap())
        .collect();
    hrefs.push(base.join("chico.ics").unwrap());
    let mut round = Round {
        report: CalendarReport::default(),
        deadline: tokio::time::Instant::now() + Duration::from_secs(60),
        stored_bytes: 0,
        stored_occurrences: 0,
        stored_alarms: 0,
        window: Window::around(Utc.timestamp_opt(TODAY, 0).unwrap()),
    };
    let objects = f
        .sync
        .fetch_objects(&client, &calendars[0], &hrefs, &mut round)
        .await
        .unwrap();
    assert_eq!(objects.len(), 1, "se retuvieron los de más");
    assert!(objects.iter().all(|o| o.data.len() <= 1024));
    assert_eq!(round.report.too_large, 20);

    // Y de punta a punta: el chico se guarda, los grandes quedan contados, y
    // el token se guarda —un objeto de más no traba el calendario—.
    let report = f.synced().await;
    assert_eq!((report.fetched, report.too_large), (1, 20));
    assert_eq!(f.summaries().await, vec!["Chico"]);
    assert_eq!(f.token(0).await, Some(f.server_token()));
}
