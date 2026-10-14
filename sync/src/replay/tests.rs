//! El empuje de la cola contra un servidor CalDAV de mentira en `127.0.0.1`,
//! sin red de verdad, sin bus y con el llavero falso.
//!
//! Son pruebas de borrador: `qa` las reescribe y las amplía. Cada una monta un
//! almacén de verdad, encola una op y la drena contra el servidor, y mira que la
//! base quede como tiene que quedar según lo que el servidor contestó.

use std::sync::Arc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::*;
use crate::dav::fake::{event, FakeDav};
use crate::dav::webdav::{AuthKind, DavClient, DavCredential, HttpPolicy, Limits};
use crate::ical::recurrence::ExpansionLimits;
use crate::store::calendar::{derive_with_occurrences, ObjectRow, StoredCalendar, Window};
use crate::store::key::fake::FakeKeys;
use crate::store::lifecycle::{
    AccountListing, Consent, ListedAccount, Locations, StoreManager, CALENDAR_AREA,
};
use crate::store::paths::tests::TempDir;

const ACCOUNT: &str = "cuenta";
const TODAY: i64 = 1_790_424_000;

struct Fixture {
    _temp: TempDir,
    manager: Arc<StoreManager<FakeKeys>>,
    server: FakeDav,
    calendar: StoredCalendar,
}

impl Fixture {
    async fn new(label: &str) -> Self {
        let temp = TempDir::new(label);
        let keys = FakeKeys::default();
        let manager = Arc::new(StoreManager::new(
            keys,
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
        manager
            .activate_area(CALENDAR_AREA, ACCOUNT, Consent::Granted)
            .await
            .unwrap();
        assert!(
            manager.prepare_for_sync(CALENDAR_AREA, ACCOUNT).await,
            "la base tenía que quedar abierta"
        );

        let server = FakeDav::start_caldav().await;
        let collection = server.collection_url(0).to_string();
        let calendar = manager
            .with_store(ACCOUNT, move |store| {
                let stored =
                    store.upsert_calendars(&[crate::store::calendar::CalendarListing {
                        href: collection,
                        display_name: "Personal".into(),
                        color: None,
                        components: vec!["VEVENT".into()],
                    }])?;
                Ok(stored.into_iter().next().unwrap())
            })
            .await
            .unwrap();

        Self {
            _temp: temp,
            manager,
            server,
            calendar,
        }
    }

    fn client(&self) -> DavClient {
        let credential = DavCredential {
            home: self.server.home_url(),
            username: "ana".into(),
            secret: Zeroizing::new("la-clave".into()),
            auth: AuthKind::Password,
        };
        DavClient::new(&credential, Limits::DEFAULT, HttpPolicy::plain_loopback()).unwrap()
    }

    fn object_url(&self, name: &str) -> String {
        self.server
            .collection_url(0)
            .join(name)
            .unwrap()
            .to_string()
    }

    fn row(&self, name: &str, raw: &str, base_etag: Option<&str>) -> ObjectRow {
        let window = Window::around(chrono::DateTime::from_timestamp(TODAY, 0).unwrap());
        let (index, occurrences) = derive_with_occurrences(raw, window, &ExpansionLimits::DEFAULT);
        ObjectRow {
            href: self.object_url(name),
            etag: base_etag.map(str::to_string),
            raw_ical: raw.to_string(),
            index,
            occurrences,
        }
    }

    async fn enqueue_put(&self, name: &str, raw: &str, base_etag: Option<&str>) {
        let row = self.row(name, raw, base_etag);
        let calendar = self.calendar.clone();
        let window = Window::around(chrono::DateTime::from_timestamp(TODAY, 0).unwrap());
        self.manager
            .with_store(ACCOUNT, move |store| {
                store.enqueue_calendar_put(&calendar, &row, window)
            })
            .await
            .unwrap();
    }

    async fn enqueue_delete(&self, name: &str, base_etag: Option<&str>) {
        let collection = self.calendar.href.clone();
        let object = self.object_url(name);
        let base = base_etag.map(str::to_string);
        self.manager
            .with_store(ACCOUNT, move |store| {
                store.enqueue_delete(CALENDAR_AREA, &collection, &object, base.as_deref())
            })
            .await
            .unwrap();
    }

    async fn replay(&self) -> ReplayReport {
        let client = self.client();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        replay_area(
            &self.manager,
            ACCOUNT,
            CALENDAR_AREA,
            &client,
            CALENDAR_CONTENT_TYPE,
            deadline,
        )
        .await
        .unwrap()
    }

    async fn pending(&self) -> i64 {
        self.manager
            .with_store(ACCOUNT, |store| store.pending_count(CALENDAR_AREA))
            .await
            .unwrap()
    }

    async fn stored_etag(&self, name: &str) -> Option<Option<String>> {
        let href = self.object_url(name);
        self.manager
            .with_store(ACCOUNT, move |store| {
                Ok(store
                    .connection()
                    .query_row(
                        "SELECT etag FROM calendar_objects WHERE href = ?1",
                        [href],
                        |row| row.get::<_, Option<String>>(0),
                    )
                    .ok())
            })
            .await
            .unwrap()
    }

    async fn stored_raw(&self, name: &str) -> Option<String> {
        let href = self.object_url(name);
        self.manager
            .with_store(ACCOUNT, move |store| {
                Ok(store
                    .connection()
                    .query_row(
                        "SELECT raw_ical FROM calendar_objects WHERE href = ?1",
                        [href],
                        |row| row.get::<_, String>(0),
                    )
                    .ok())
            })
            .await
            .unwrap()
    }

    /// El estado de la op de un objeto (`ready`/`conflict`), o `None` si ya no
    /// hay op.
    async fn op_state(&self, name: &str) -> Option<String> {
        let href = self.object_url(name);
        self.manager
            .with_store(ACCOUNT, move |store| {
                Ok(store
                    .connection()
                    .query_row(
                        "SELECT state FROM pending_dav_ops WHERE object_href = ?1",
                        [href],
                        |row| row.get::<_, String>(0),
                    )
                    .ok())
            })
            .await
            .unwrap()
    }

    async fn pending_collections(&self) -> Vec<String> {
        self.manager
            .with_store(ACCOUNT, |store| store.pending_collections(CALENDAR_AREA))
            .await
            .unwrap()
    }
}

/// Un `PUT` que crea algo nuevo: el servidor lo escribe, la op se cierra y el
/// ETag del servidor queda en la fila.
#[tokio::test]
async fn un_put_que_crea_sube_y_cierra_la_op() {
    let f = Fixture::new("replay-crea").await;
    f.enqueue_put("a.ics", &event("a", "Reunión", "20260928T140000Z"), None)
        .await;
    assert_eq!(f.pending().await, 1);

    let report = f.replay().await;
    assert_eq!(report.pushed, 1);
    assert_eq!(report.remaining, 0);
    assert_eq!(f.pending().await, 0);

    // El servidor lo tiene, y la fila quedó con su ETag (no nulo).
    assert!(f.server.state().collections[0]
        .resources
        .contains_key("a.ics"));
    let server_etag = f.server.state().collections[0].resources["a.ics"]
        .etag
        .clone();
    assert_eq!(f.stored_etag("a.ics").await, Some(Some(server_etag)));
}

/// Un `PUT` cuya respuesta no trae `ETag` cierra la op igual, pero deja el ETag
/// local en `NULL` para que la bajada traiga el suyo.
#[tokio::test]
async fn un_put_sin_etag_de_respuesta_pide_refetch() {
    let f = Fixture::new("replay-refetch").await;
    f.server.state().omit_put_etag = true;
    f.enqueue_put("a.ics", &event("a", "Reunión", "20260928T140000Z"), None)
        .await;

    let report = f.replay().await;
    assert_eq!(report.pushed, 1);
    assert_eq!(f.pending().await, 0);
    assert_eq!(f.stored_etag("a.ics").await, Some(None));
}

/// Un `412` en un reemplazo es un conflicto: la op queda viva, **no se pisa el
/// crudo local**, y el servidor sigue con lo suyo.
#[tokio::test]
async fn un_412_deja_la_op_en_conflicto_y_no_pierde_lo_local() {
    let f = Fixture::new("replay-conflicto").await;
    // El servidor tiene otra versión del recurso.
    f.server
        .put(0, "a.ics", &event("a", "Del servidor", "20260928T150000Z"));
    // Local cree que el ETag es otro: un reemplazo que va a chocar.
    let local = event("a", "Mía", "20260928T140000Z");
    f.enqueue_put("a.ics", &local, Some("\"viejo\"")).await;

    let report = f.replay().await;
    assert_eq!(report.conflicts, 1);
    assert_eq!(report.pushed, 0);
    // La op sigue en la cola (en conflicto) y el crudo local es el mío.
    assert_eq!(f.pending().await, 1);
    assert_eq!(f.stored_raw("a.ics").await, Some(local));
    // El servidor no se tocó.
    assert_eq!(
        f.server.state().collections[0].resources["a.ics"].data,
        event("a", "Del servidor", "20260928T150000Z")
    );
}

/// **H2**: un `Create` que choca con un `412` **no** se da por hecho: no se puede
/// distinguir «mi creación ya llegó» de «hay OTRO recurso en ese href». Va a
/// conflicto, y la creación local se conserva —no se pisa con lo ajeno en la
/// próxima bajada—.
#[tokio::test]
async fn un_create_que_choca_412_no_se_pierde_va_a_conflicto() {
    let f = Fixture::new("replay-create-412").await;
    // En ese href ya hay OTRO recurso (otro cliente, o mi intento anterior con
    // contenido distinto).
    f.server
        .put(0, "a.ics", &event("a", "Del servidor", "20260928T150000Z"));
    // La creación local, distinta, como Create (sin base_etag).
    let local = event("a", "Mía", "20260928T140000Z");
    f.enqueue_put("a.ics", &local, None).await;

    let report = f.replay().await;
    assert_eq!(
        report.conflicts, 1,
        "un 412 en create es conflicto, no éxito"
    );
    assert_eq!(report.pushed, 0);
    // La creación local sobrevive, en conflicto, con su crudo intacto.
    assert_eq!(f.pending().await, 1);
    assert_eq!(f.op_state("a.ics").await.as_deref(), Some("conflict"));
    assert_eq!(f.stored_raw("a.ics").await, Some(local));
}

/// Un `DELETE` con el ETag correcto borra en el servidor y cierra la op; la fila
/// guardada se va.
#[tokio::test]
async fn un_delete_borra_y_cierra_la_op() {
    let f = Fixture::new("replay-borra").await;
    // Una fila guardada, al día con el servidor, que después se borra.
    f.server
        .put(0, "a.ics", &event("a", "Reunión", "20260928T140000Z"));
    let etag = f.server.state().collections[0].resources["a.ics"]
        .etag
        .clone();
    f.enqueue_put(
        "a.ics",
        &event("a", "Reunión", "20260928T140000Z"),
        Some(&etag),
    )
    .await;
    f.replay().await; // sube el put: la fila queda al día
    assert_eq!(f.pending().await, 0);
    let etag = f.server.state().collections[0].resources["a.ics"]
        .etag
        .clone();

    f.enqueue_delete("a.ics", Some(&etag)).await;
    let report = f.replay().await;
    assert_eq!(report.pushed, 1);
    assert_eq!(f.pending().await, 0);
    assert!(!f.server.state().collections[0]
        .resources
        .contains_key("a.ics"));
    assert_eq!(f.stored_raw("a.ics").await, None);
}

/// Un `DELETE` de algo que ya no está en el servidor (`404`) es éxito
/// idempotente: la op se cierra igual.
#[tokio::test]
async fn un_delete_de_lo_que_ya_no_esta_es_exito() {
    let f = Fixture::new("replay-borra-404").await;
    f.enqueue_delete("fantasma.ics", Some("\"v9\"")).await;

    let report = f.replay().await;
    assert_eq!(report.pushed, 1);
    assert_eq!(f.pending().await, 0);
}

/// Un error reintentable (`507`) deja la op en la cola, en `ready`, con un
/// reintento más: vuelve a intentarse en la próxima vuelta.
#[tokio::test]
async fn un_error_reintentable_deja_la_op_para_despues() {
    let f = Fixture::new("replay-reintento").await;
    f.server.state().force_write_status = Some(507);
    f.enqueue_put("a.ics", &event("a", "Reunión", "20260928T140000Z"), None)
        .await;

    let report = f.replay().await;
    assert_eq!(report.retried, 1);
    assert_eq!(report.remaining, 1);
    assert_eq!(f.pending().await, 1);
    assert_eq!(f.op_state("a.ics").await.as_deref(), Some("ready"));
    // Reintentable: sigue trabando la colección hasta que se resuelva.
    assert_eq!(f.pending_collections().await, vec![f.calendar.href.clone()]);
}

/// **H4**: un error **permanente** (un `400` persistente) **no se reintenta para
/// siempre**: escala a `conflict` en la primera vuelta, así deja de trabar el
/// token de la colección (disponibilidad). La op no queda en `ready`, y la
/// colección deja de contar como «no al día».
#[tokio::test]
async fn un_error_permanente_escala_a_conflicto_y_no_traba_el_token() {
    let f = Fixture::new("replay-veneno").await;
    f.server.state().force_write_status = Some(400);
    f.enqueue_put("a.ics", &event("a", "Mía", "20260928T140000Z"), None)
        .await;

    let report = f.replay().await;
    assert_eq!(report.conflicts, 1);
    assert_eq!(report.retried, 0);
    // No sigue en `ready` bloqueando el token.
    assert_eq!(f.op_state("a.ics").await.as_deref(), Some("conflict"));
    assert!(
        f.pending_collections().await.is_empty(),
        "una op en conflicto no traba la colección"
    );
}

/// Un `PUT` que falla deja la op viva y el objeto marcado; una bajada posterior
/// **no lo borra** aunque el servidor no lo tenga.
#[tokio::test]
async fn un_put_fallido_sobrevive_a_una_bajada() {
    let f = Fixture::new("replay-sobrevive").await;
    f.server.state().force_write_status = Some(507);
    let raw = event("a", "Mía", "20260928T140000Z");
    f.enqueue_put("a.ics", &raw, None).await;
    f.replay().await; // falla: la op queda, el objeto marcado
    assert_eq!(f.pending().await, 1);

    // Una bajada completa que no trae el objeto no lo borra (está marcado).
    let calendar = f.calendar.clone();
    f.manager
        .with_store(ACCOUNT, move |store| {
            let window = Window::around(chrono::DateTime::from_timestamp(TODAY, 0).unwrap());
            store.apply_calendar_objects(
                &calendar,
                &[crate::store::calendar::ObjectOp::Delete(
                    "http://example/a.ics".into(),
                )],
                window,
                None,
                crate::store::calendar::CalendarRoom::UNLIMITED,
            )
        })
        .await
        .unwrap();
    assert_eq!(f.stored_raw("a.ics").await, Some(raw));
}

/// **Seguridad**: `ClearStore` vacía la base entera, y con ella la cola. Una op
/// con un cuerpo privado no sobrevive a vaciar la cuenta.
#[tokio::test]
async fn clear_store_vacia_la_cola() {
    let f = Fixture::new("replay-clear").await;
    f.server.state().force_write_status = Some(507);
    f.enqueue_put("a.ics", &event("a", "Mía", "20260928T140000Z"), None)
        .await;
    assert_eq!(f.pending().await, 1);

    f.manager.clear(ACCOUNT).await.unwrap();
    // La base se rehizo vacía (la cuenta sigue encendida): sin ops.
    assert_eq!(f.pending().await, 0);
}

/// **Seguridad**: `SetStoreEnabled(false)` borra la base de la cuenta, y con
/// ella la cola.
#[tokio::test]
async fn apagar_el_almacen_vacia_la_cola() {
    let f = Fixture::new("replay-apaga").await;
    f.server.state().force_write_status = Some(507);
    f.enqueue_put("a.ics", &event("a", "Mía", "20260928T140000Z"), None)
        .await;
    assert_eq!(f.pending().await, 1);

    f.manager.set_enabled(ACCOUNT, false).await.unwrap();
    // Apagada y vuelta a encender: la base se rehace vacía, sin ops.
    f.manager.set_enabled(ACCOUNT, true).await.unwrap();
    assert!(f.manager.prepare_for_sync(CALENDAR_AREA, ACCOUNT).await);
    assert_eq!(f.pending().await, 0);
}
