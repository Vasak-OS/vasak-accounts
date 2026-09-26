//! La sincronización de contactos contra un servidor CardDAV de mentira en
//! `127.0.0.1`, sin red, sin bus y con el llavero falso.

use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine;
use rusqlite::OptionalExtension;

use super::*;
use crate::dav::fake::{card, FakeDav, RecordedRequest};
use crate::dav::webdav::AuthKind;
use crate::store::key::fake::FakeKeys;
use crate::store::lifecycle::{AccountListing, ListedAccount, Locations};
use crate::store::paths::tests::TempDir;

const ACCOUNT: &str = "cuenta";

struct CredentialState {
    result: Result<DavCredential, CredentialError>,
    calls: usize,
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
    async fn contacts_credential(
        &self,
        _account_id: &str,
    ) -> Result<DavCredential, CredentialError> {
        let mut state = self.0.lock().unwrap();
        state.calls += 1;
        state.result.clone()
    }
}

struct Fixture {
    _temp: TempDir,
    keys: FakeKeys,
    manager: Arc<StoreManager<FakeKeys>>,
    server: FakeDav,
    credentials: FakeCredentials,
    sync: ContactsSync<FakeKeys, FakeCredentials>,
    notified: Arc<AtomicUsize>,
}

fn credential_for(server: &FakeDav) -> DavCredential {
    DavCredential {
        home: server.home_url(),
        username: "ana".into(),
        secret: Zeroizing::new("la-clave".into()),
        auth: AuthKind::Password,
    }
}

impl Fixture {
    async fn new(label: &str) -> Self {
        Self::with_limits(label, Limits::DEFAULT).await
    }

    async fn with_limits(label: &str, limits: Limits) -> Self {
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
                    capabilities: vec!["contacts".into()],
                    needs_reauth: false,
                }]),
                Instant::now(),
            )
            .await;
        assert!(manager.activate_contacts(ACCOUNT).await.unwrap());

        let server = FakeDav::start().await;
        let credentials = FakeCredentials(Arc::new(std::sync::Mutex::new(CredentialState {
            result: Ok(credential_for(&server)),
            calls: 0,
        })));
        let notified = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&notified);
        let sync = ContactsSync::new(
            Arc::clone(&manager),
            credentials.clone(),
            limits,
            HttpPolicy::plain_loopback(),
            Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        );
        Self {
            _temp: temp,
            keys,
            manager,
            server,
            credentials,
            sync,
            notified,
        }
    }

    async fn sync(&self) -> SyncOutcome {
        self.sync.sync_account(ACCOUNT).await
    }

    async fn synced(&self) -> SyncReport {
        match self.sync().await {
            SyncOutcome::Synced(report) => report,
            other => panic!("la vuelta no terminó bien: {other:?}"),
        }
    }

    /// Lo que hay en la base, con la base abierta como la dejó la vuelta.
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

    async fn names(&self) -> Vec<String> {
        self.query(|c| {
            let mut statement = c
                .prepare("SELECT display_name FROM contacts ORDER BY sort_key, id")
                .unwrap();
            statement
                .query_map([], |row| row.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        })
        .await
    }

    async fn search(&self, terms: &'static str) -> Vec<String> {
        self.query(move |c| {
            let mut statement = c
                .prepare(
                    "SELECT c.display_name FROM contacts_fts f JOIN contacts c ON c.id = f.rowid
                     WHERE contacts_fts MATCH ?1 ORDER BY c.sort_key",
                )
                .unwrap();
            statement
                .query_map([terms], |row| row.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        })
        .await
    }

    async fn token(&self, book: usize) -> Option<String> {
        let href = self.server.book_url(book).to_string();
        self.query(move |c| {
            c.query_row(
                "SELECT token FROM sync_state WHERE area = 'contacts' AND collection = ?1",
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

    async fn contacts_status(&self) -> serde_json::Value {
        let status = serde_json::to_value(self.manager.status().await).unwrap();
        status["accounts"][0]["contacts"].clone()
    }
}

fn put_many(server: &FakeDav, book: usize, range: std::ops::Range<usize>) {
    for i in range {
        server.put(
            book,
            &format!("{i:05}.vcf"),
            &card(
                &format!("{i:05}"),
                &format!("Persona {i:05}"),
                &format!("p{i}@x.com"),
            ),
        );
    }
}

// ── El límite ───────────────────────────────────────────────────────────────

/// **Lo que pide esta parte del sincronizador: `contacts`, y nada más.** Viene
/// de `vasak-contacts` (`esta_aplicacion_solo_pide_los_contactos`).
///
/// Importa especialmente acá: los contactos y los calendarios viven en el
/// mismo servidor y detrás de la misma contraseña —un Nextcloud entrega los
/// dos con la misma credencial de aplicación—. Que la sincronización de
/// contactos pida otra capacidad tiene que ser una decisión y no un descuido.
/// Y es el nombre de la capacidad, no el del recurso: el servicio de cuentas
/// rechaza `account.contacts` como argumento inválido y le pregunta a
/// `vasak-permissions` por `account.contacts` él mismo.
#[test]
fn los_contactos_solo_piden_la_capacidad_de_contactos() {
    assert_eq!(CONTACTS_AREA, "contacts");
}

// ── La carga inicial ────────────────────────────────────────────────────────

/// La primera vez no hay token: `sync-collection` vacío trae todo, se pide por
/// `multiget` y el token del servidor queda guardado. Con la credencial de la
/// cuenta en `Basic`, y nada más que `PROPFIND` y `REPORT`.
#[tokio::test]
async fn la_carga_inicial_trae_todas_las_tarjetas_y_guarda_el_token() {
    let f = Fixture::new("contactos-inicial").await;
    f.server
        .put(0, "ana.vcf", &card("1", "Ana Pérez", "ana@x.com"));
    f.server
        .put(0, "jose.vcf", &card("2", "José Gómez", "jose@x.com"));
    f.server.put(0, "zoe.vcf", &card("3", "Zoe", "zoe@x.com"));

    let report = f.synced().await;
    assert_eq!(report.books, 1);
    assert_eq!(report.fetched, 3);

    assert_eq!(f.names().await, vec!["Ana Pérez", "José Gómez", "Zoe"]);
    assert_eq!(f.count("SELECT count(*) FROM contact_emails").await, 3);
    assert_eq!(f.count("SELECT count(*) FROM contact_phones").await, 3);
    assert_eq!(f.search("jose gomez").await, vec!["José Gómez"]);
    assert_eq!(f.token(0).await, Some(f.server_token()));
    let raw: String = f
        .query(|c| {
            c.query_row(
                "SELECT raw_vcard FROM contacts WHERE display_name = 'Zoe'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        })
        .await;
    // La tarjeta cruda, tal cual llegó. Los `\r\n` los normaliza el XML en el
    // camino —es la regla de fin de línea del estándar—, así que lo que llega
    // son `\n`, salvo que el servidor los mande escapados.
    assert_eq!(raw, card("3", "Zoe", "zoe@x.com").replace("\r\n", "\n"));

    let requests = f.server.requests();
    let sync = requests.iter().find(|r| r.is_sync_collection()).unwrap();
    assert!(sync.body.contains("<d:sync-token></d:sync-token>"));
    assert_eq!(sync.depth, "0");
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("ana:la-clave")
    );
    for request in &requests {
        assert!(matches!(request.method.as_str(), "PROPFIND" | "REPORT"));
        assert_eq!(request.authorization, expected);
    }
    assert_eq!(f.contacts_status().await["state"], "synced");
    assert!(f.notified.load(Ordering::SeqCst) > 0);
}

// ── Las diferencias ─────────────────────────────────────────────────────────

/// Con token, se pide desde ahí y se trae **sólo** lo que cambió; el token
/// nuevo reemplaza al viejo.
#[tokio::test]
async fn la_diferencia_trae_solo_lo_que_cambio_y_guarda_el_token_nuevo() {
    let f = Fixture::new("contactos-diferencia").await;
    f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));
    f.server
        .put(0, "juan.vcf", &card("2", "Juan", "juan@x.com"));
    f.synced().await;
    let first_token = f.token(0).await.unwrap();

    f.server
        .put(0, "juan.vcf", &card("2", "Juan Carlos", "jc@x.com"));
    f.server.put(0, "zoe.vcf", &card("3", "Zoe", "zoe@x.com"));
    let before = f.server.requests().len();

    let report = f.synced().await;
    assert_eq!(report.fetched, 2);
    assert_eq!(f.names().await, vec!["Ana", "Juan Carlos", "Zoe"]);
    assert_eq!(f.search("jc").await, vec!["Juan Carlos"]);
    assert!(
        f.search("\"juan x com\"").await.is_empty(),
        "el correo viejo ya no está en el índice"
    );

    let requests = f.requests_since(before);
    let sync = requests.iter().find(|r| r.is_sync_collection()).unwrap();
    assert!(sync
        .body
        .contains(&format!("<d:sync-token>{first_token}</d:sync-token>")));
    let multiget = requests.iter().find(|r| r.is_multiget()).unwrap();
    assert!(multiget.body.contains("juan.vcf") && multiget.body.contains("zoe.vcf"));
    assert!(!multiget.body.contains("ana.vcf"), "ana no cambió");
    assert_eq!(f.token(0).await, Some(f.server_token()));
    assert_ne!(f.token(0).await.unwrap(), first_token);
}

/// Sin nada nuevo, no se pide ninguna tarjeta, y el token igual se guarda.
#[tokio::test]
async fn sin_cambios_no_se_pide_ninguna_tarjeta() {
    let f = Fixture::new("contactos-sin-cambios").await;
    f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));
    f.synced().await;
    let before = f.server.requests().len();

    let report = f.synced().await;
    assert_eq!(report.fetched, 0);
    assert!(!f.requests_since(before).iter().any(|r| r.is_multiget()));
    assert_eq!(f.names().await, vec!["Ana"]);
}

/// **Lo que viene con `404` dentro de su `<d:response>` se borra**, y con él
/// sus correos, sus teléfonos y su entrada del índice.
#[tokio::test]
async fn un_404_en_la_respuesta_borra_la_fila_y_todo_lo_suyo() {
    let f = Fixture::new("contactos-404").await;
    f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));
    f.server
        .put(0, "juan.vcf", &card("2", "Juan", "juan@x.com"));
    f.synced().await;
    assert_eq!(f.search("juan").await, vec!["Juan"]);

    f.server.remove(0, "juan.vcf");
    let report = f.synced().await;

    assert_eq!(report.removed, 1);
    assert_eq!(f.names().await, vec!["Ana"]);
    assert_eq!(f.count("SELECT count(*) FROM contact_emails").await, 1);
    assert_eq!(f.count("SELECT count(*) FROM contact_phones").await, 1);
    assert!(f.search("juan").await.is_empty());
}

/// **Un token vencido no es un error**: se tira y se hace la sincronización
/// completa, que además borra lo que ya no está —el `404` de lo borrado
/// mientras tanto no va a llegar nunca— y guarda el token nuevo.
#[tokio::test]
async fn un_token_vencido_lleva_a_la_sincronizacion_completa() {
    let f = Fixture::new("contactos-token-vencido").await;
    f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));
    f.server
        .put(0, "juan.vcf", &card("2", "Juan", "juan@x.com"));
    f.synced().await;
    let old = f.token(0).await.unwrap();

    {
        let mut state = f.server.state();
        state.min_valid_token = state.version + 1;
    }
    f.server.remove(0, "juan.vcf");
    f.server.put(0, "zoe.vcf", &card("3", "Zoe", "zoe@x.com"));

    let report = f.synced().await;
    assert_eq!(report.full_resyncs, 1);
    assert_eq!(f.names().await, vec!["Ana", "Zoe"]);
    let token = f.token(0).await.unwrap();
    assert_ne!(token, old);
    assert_eq!(token, f.server_token());

    // Y la vuelta que sigue ya va por diferencias con el token nuevo.
    let before = f.server.requests().len();
    let report = f.synced().await;
    assert_eq!(report.full_resyncs, 0);
    let sync: Vec<_> = f
        .requests_since(before)
        .into_iter()
        .filter(|r| r.is_sync_collection())
        .collect();
    assert_eq!(sync.len(), 1);
    assert!(sync[0].body.contains(&token));
}

// ── Sin sync-collection ─────────────────────────────────────────────────────

/// El servidor que dice que no sabe `sync-collection` va por ETag: lo nuevo y
/// lo cambiado se trae, lo que ya no está se borra, y no se le pide nunca un
/// `sync-collection`.
#[tokio::test]
async fn sin_sync_collection_se_compara_por_etag() {
    let f = Fixture::new("contactos-etag").await;
    f.server.state().books[0].supports_sync = false;
    f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));
    f.server
        .put(0, "juan.vcf", &card("2", "Juan", "juan@x.com"));
    f.server
        .put(0, "luis.vcf", &card("4", "Luis", "luis@x.com"));
    let report = f.synced().await;
    assert_eq!(report.etag_books, 1);
    assert_eq!(f.names().await, vec!["Ana", "Juan", "Luis"]);
    assert_eq!(f.token(0).await, None, "por ETag no hay token");

    f.server
        .put(0, "juan.vcf", &card("2", "Juan Carlos", "jc@x.com"));
    f.server.put(0, "zoe.vcf", &card("3", "Zoe", "zoe@x.com"));
    f.server.remove(0, "luis.vcf");
    let before = f.server.requests().len();

    let report = f.synced().await;
    assert_eq!(report.fetched, 2);
    assert_eq!(report.removed, 1);
    assert_eq!(f.names().await, vec!["Ana", "Juan Carlos", "Zoe"]);
    assert!(f.search("luis").await.is_empty());
    let requests = f.requests_since(before);
    let multiget = requests.iter().find(|r| r.is_multiget()).unwrap();
    assert!(!multiget.body.contains("ana.vcf"));
    assert!(!f.server.requests().iter().any(|r| r.is_sync_collection()));
}

/// Y el que no dice nada se prueba: si contesta que no sabe (`501`), se va por
/// ETag en la misma vuelta.
#[tokio::test]
async fn un_servidor_que_no_dice_nada_se_prueba_y_se_va_por_etag() {
    let f = Fixture::new("contactos-etag-probado").await;
    {
        let mut state = f.server.state();
        state.books[0].supports_sync = false;
        state.hide_reports = true;
    }
    f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));

    let report = f.synced().await;
    assert_eq!(report.etag_books, 1);
    assert_eq!(f.names().await, vec!["Ana"]);
    assert!(f.server.requests().iter().any(|r| r.is_sync_collection()));
}

/// Con el `getctag` igual al de la última vuelta completa, la libreta no se
/// toca: ni `sync-collection` ni `PROPFIND` de sus tarjetas.
#[tokio::test]
async fn con_el_getctag_igual_la_libreta_no_se_pide() {
    let f = Fixture::new("contactos-ctag").await;
    f.server.state().books[0].ctag = Some("c1".into());
    f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));
    f.synced().await;

    let before = f.server.requests().len();
    let report = f.synced().await;
    assert_eq!(report.unchanged_books, 1);
    let requests = f.requests_since(before);
    assert_eq!(
        requests.len(),
        1,
        "sólo el listado de libretas: {requests:?}"
    );

    f.server.put(0, "zoe.vcf", &card("2", "Zoe", "zoe@x.com"));
    f.server.state().books[0].ctag = Some("c2".into());
    let report = f.synced().await;
    assert_eq!(report.fetched, 1);
    assert_eq!(f.names().await, vec!["Ana", "Zoe"]);
}

/// Una libreta que el servidor ya no lista se borra, de a tandas, con sus
/// contactos y su token.
#[tokio::test]
async fn una_libreta_que_ya_no_esta_se_borra_con_lo_suyo() {
    let f = Fixture::new("contactos-libreta-ida").await;
    let work = f.server.add_book("/dav/ana/trabajo/", "Trabajo");
    f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));
    f.server
        .put(work, "jefe.vcf", &card("2", "La Jefa", "jefa@x.com"));
    f.synced().await;
    assert_eq!(f.names().await, vec!["Ana", "La Jefa"]);
    assert!(f.token(work).await.is_some());
    let work_url = f.server.book_url(work).to_string();

    f.server.state().books.remove(work);
    let report = f.synced().await;
    assert_eq!(report.books, 1);
    assert_eq!(f.names().await, vec!["Ana"]);
    assert!(f.search("jefa").await.is_empty());
    assert_eq!(f.count("SELECT count(*) FROM address_books").await, 1);
    let tokens: i64 = f
        .query(move |c| {
            c.query_row(
                "SELECT count(*) FROM sync_state WHERE collection = ?1",
                [work_url],
                |r| r.get(0),
            )
            .unwrap()
        })
        .await;
    assert_eq!(tokens, 0);
}

// ── El llavero ──────────────────────────────────────────────────────────────

/// **Con el llavero bloqueado no se pide nada a nadie**: ni la credencial al
/// servicio de cuentas ni un solo pedido al servidor.
#[tokio::test]
async fn con_el_llavero_bloqueado_no_se_pide_ni_se_escribe_nada() {
    let f = Fixture::new("contactos-bloqueado").await;
    f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));
    f.keys.state().locked = true;

    assert_eq!(f.sync().await, SyncOutcome::StoreClosed);
    assert_eq!(f.server.requests().len(), 0, "el servidor no recibió nada");
    assert_eq!(f.credentials.calls(), 0, "ni se pidió la credencial");
    assert_eq!(f.contacts_status().await["state"], "pending");

    // Al desbloquear, la base se abre y no tiene nada.
    f.keys.state().locked = false;
    assert!(f.manager.prepare_for_sync(ACCOUNT).await);
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 0);
}

/// Y si se bloquea **a mitad de camino**, lo que llegó del servidor no se
/// escribe y la vuelta se corta ahí: ni tarjetas, ni token.
#[tokio::test]
async fn si_el_llavero_se_bloquea_a_mitad_no_se_escribe_lo_que_llego() {
    let f = Fixture::new("contactos-bloqueo-a-mitad").await;
    f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));
    let keys = f.keys.clone();
    f.server.state().on_request = Some(Box::new(move |request| {
        if request.is_multiget() {
            keys.state().locked = true;
        }
    }));

    assert_eq!(f.sync().await, SyncOutcome::StoreClosed);
    let multigets = f
        .server
        .requests()
        .iter()
        .filter(|r| r.is_multiget())
        .count();
    assert_eq!(multigets, 1, "después del bloqueo no se pidió nada más");

    f.server.state().on_request = None;
    f.keys.state().locked = false;
    assert!(f.manager.prepare_for_sync(ACCOUNT).await);
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 0);
    assert_eq!(f.token(0).await, None);
}

// ── El permiso ──────────────────────────────────────────────────────────────

/// **`AccessDenied` se ve `unavailable` y no se reintenta en bucle**: la
/// revisión de cada cinco minutos no vuelve a preguntar hasta que pasa la
/// hora; un `RequestSync` sí.
#[tokio::test]
async fn sin_permiso_se_ve_no_disponible_y_no_se_reintenta_en_bucle() {
    let f = Fixture::new("contactos-sin-permiso").await;
    f.credentials.set(Err(CredentialError::Denied));
    let Fixture {
        sync,
        credentials,
        server,
        manager,
        _temp,
        ..
    } = f;
    let scheduler = ContactsScheduler::new(sync);
    let start = Instant::now();

    scheduler.run_due(start).await;
    assert_eq!(credentials.calls(), 1);
    let status = serde_json::to_value(manager.status().await).unwrap();
    let contacts = &status["accounts"][0]["contacts"];
    assert_eq!(contacts["state"], "unavailable");
    assert!(
        contacts["detail"]
            .as_str()
            .unwrap()
            .contains("vasak-permissions"),
        "{contacts}"
    );

    for minutes in [5, 10, 30, 59] {
        scheduler
            .run_due(start + Duration::from_secs(minutes * 60))
            .await;
    }
    assert_eq!(
        credentials.calls(),
        1,
        "no se volvió a preguntar antes de la hora"
    );

    scheduler.run_due(start + CONTACTS_INTERVAL).await;
    assert_eq!(credentials.calls(), 2);

    scheduler
        .run_requested(ACCOUNT, start + CONTACTS_INTERVAL + Duration::from_secs(60))
        .await;
    assert_eq!(credentials.calls(), 3, "un RequestSync vuelve a preguntar");
    assert!(
        server.requests().is_empty(),
        "sin credencial no se habló con el servidor"
    );
}

/// Dos `RequestSync` seguidos de la misma cuenta son una vuelta.
#[tokio::test]
async fn dos_pedidos_seguidos_son_una_vuelta() {
    let f = Fixture::new("contactos-pedidos").await;
    let Fixture {
        sync,
        credentials,
        _temp,
        server,
        ..
    } = f;
    let scheduler = ContactsScheduler::new(sync);
    let start = Instant::now();

    scheduler.run_requested(ACCOUNT, start).await;
    scheduler
        .run_requested(ACCOUNT, start + Duration::from_secs(5))
        .await;
    assert_eq!(credentials.calls(), 1);
    scheduler
        .run_requested(ACCOUNT, start + REQUEST_COOLDOWN)
        .await;
    assert_eq!(credentials.calls(), 2);
    drop(server);
}

/// La revisión de cada cinco minutos no cuenta como intento lo que no pidió
/// nada: con el llavero bloqueado, la cuenta entra apenas se desbloquea.
#[tokio::test]
async fn con_el_llavero_bloqueado_la_revision_no_cuenta_como_intento() {
    let f = Fixture::new("contactos-revision").await;
    f.keys.state().locked = true;
    let keys = f.keys.clone();
    let Fixture {
        sync,
        credentials,
        _temp,
        server,
        ..
    } = f;
    let scheduler = ContactsScheduler::new(sync);
    let start = Instant::now();

    scheduler.run_due(start).await;
    assert_eq!(credentials.calls(), 0);
    keys.state().locked = false;
    scheduler.run_due(start + CONTACTS_TICK).await;
    assert_eq!(credentials.calls(), 1);
    drop(server);
}

// ── Lo que llega de la red ──────────────────────────────────────────────────

/// **Una dirección de otro origen no se pide ni se guarda**, y el otro
/// servidor no recibe nada: ni la libreta que el listado dice que vive allá,
/// ni la tarjeta que el `sync-collection` dice que vive allá.
#[tokio::test]
async fn una_direccion_de_otro_origen_no_se_pide_ni_se_guarda() {
    let f = Fixture::new("contactos-otro-origen").await;
    let other = FakeDav::start().await;
    other.put(0, "ana.vcf", &card("9", "Ajena", "ajena@x.com"));
    f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));
    {
        let mut state = f.server.state();
        state.extra_books_xml = format!(
            "<d:response><d:href>{}/dav/ana/personal/</d:href><d:propstat><d:prop>\
             <d:resourcetype><d:collection/><c:addressbook/></d:resourcetype>\
             </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
            other.origin()
        );
        state.extra_sync_xml = format!(
            "<d:response><d:href>{}/dav/ana/personal/ajena.vcf</d:href><d:propstat><d:prop>\
             <d:getetag>\"x\"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status>\
             </d:propstat></d:response>",
            other.origin()
        );
    }

    let report = f.synced().await;
    assert_eq!(report.books, 1);
    assert_eq!(report.foreign, 1);
    assert_eq!(f.names().await, vec!["Ana"]);
    assert!(
        other.requests().is_empty(),
        "al otro servidor no se le pidió nada"
    );
    let multiget = f
        .server
        .requests()
        .into_iter()
        .find(|r| r.is_multiget())
        .unwrap();
    assert!(!multiget.body.contains("ajena.vcf"));
    let foreign = other.origin();
    let stored: i64 = f
        .query(move |c| {
            c.query_row(
                "SELECT (SELECT count(*) FROM contacts WHERE href LIKE ?1 || '%')
                      + (SELECT count(*) FROM address_books WHERE href LIKE ?1 || '%')",
                [foreign],
                |r| r.get(0),
            )
            .unwrap()
        })
        .await;
    assert_eq!(stored, 0);
}

/// **Un `multiget` que trae tarjetas no pedidas no las guarda.** El servidor
/// suma tres con dirección de la misma libreta a cada respuesta: si se
/// guardaran, una sola tarjeta cambiada podía meter ciento cincuenta mil por
/// vuelta, por encima del tope de la libreta, y quedarse para siempre.
#[tokio::test]
async fn un_multiget_que_trae_tarjetas_no_pedidas_no_las_guarda() {
    let f = Fixture::new("contactos-no-pedidas").await;
    f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));
    f.server
        .put(0, "juan.vcf", &card("2", "Juan", "juan@x.com"));
    f.server.state().extra_multiget_xml = (0..3)
        .map(|i| {
            format!(
                "<d:response><d:href>/dav/ana/personal/intrusa{i}.vcf</d:href>\
                 <d:propstat><d:prop><d:getetag>\"i\"</d:getetag><c:address-data>{}\
                 </c:address-data></d:prop><d:status>HTTP/1.1 200 OK</d:status>\
                 </d:propstat></d:response>",
                card(&format!("9{i}"), &format!("Intrusa {i}"), "i@x.com")
            )
        })
        .collect();

    let report = f.synced().await;
    assert_eq!(report.fetched, 2);
    assert_eq!(report.unrequested, 3);
    assert_eq!(f.names().await, vec!["Ana", "Juan"]);
    assert_eq!(
        f.count("SELECT count(*) FROM contacts WHERE href LIKE '%intrusa%'")
            .await,
        0
    );
}

/// **Una respuesta anidada de más no tumba el sincronizador.** Diez mil
/// niveles en el listado de libretas —el primer pedido de cada vuelta— son
/// cien kilobytes; leídos sin tope, desbordan la pila y el proceso aborta, con
/// el correo adentro, y `Restart=on-failure` lo vuelve a levantar para caer
/// igual. Tiene que ser una vuelta fallida y nada más.
#[tokio::test(flavor = "multi_thread")]
async fn una_respuesta_anidada_no_tumba_el_sincronizador() {
    let f = Fixture::new("contactos-anidada").await;
    f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));
    f.server.state().extra_books_xml = format!(
        "<d:response><d:href>/x/</d:href>{}{}</d:response>",
        "<d:x>".repeat(10_000),
        "</d:x>".repeat(10_000)
    );

    let outcome = f.sync().await;
    assert!(matches!(outcome, SyncOutcome::Failed(_)), "{outcome:?}");
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 0);
    assert_eq!(f.contacts_status().await["state"], "failed");
}

/// Una respuesta que pasa el tope no se lee —con `Content-Length` se corta
/// antes de leer, sin él mientras llega— y no se guarda nada.
#[tokio::test]
async fn una_respuesta_que_pasa_el_tope_no_se_lee() {
    for chunked in [false, true] {
        let limits = Limits {
            max_body_bytes: 64 * 1024,
            ..Limits::DEFAULT
        };
        let f = Fixture::with_limits("contactos-tope", limits).await;
        f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));
        {
            let mut state = f.server.state();
            state.padding = 100 * 1024;
            state.chunked = chunked;
        }

        let outcome = f.sync().await;
        let SyncOutcome::Failed(detail) = outcome else {
            panic!("tenía que fallar: {outcome:?}");
        };
        assert!(detail.contains("65536 bytes"), "{detail}");
        assert_eq!(f.count("SELECT count(*) FROM contacts").await, 0);
        assert_eq!(f.contacts_status().await["state"], "failed");
    }
}

/// Una tarjeta enorme no traba la libreta: la tanda se parte hasta aislarla,
/// y ésa se saltea; las demás entran.
#[tokio::test]
async fn una_tarjeta_que_no_entra_se_saltea_y_las_demas_entran() {
    let limits = Limits {
        max_body_bytes: 64 * 1024,
        ..Limits::DEFAULT
    };
    let f = Fixture::with_limits("contactos-tarjeta-enorme", limits).await;
    put_many(&f.server, 0, 0..8);
    let photo = format!(
        "BEGIN:VCARD\r\nFN:Con Foto\r\nPHOTO;ENCODING=b:{}\r\nEND:VCARD\r\n",
        "A".repeat(80 * 1024)
    );
    f.server.put(0, "foto.vcf", &photo);

    let report = f.synced().await;
    assert_eq!(report.too_large, 1);
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 8);
}

/// Y una que entra en la respuesta pero pasa el tope de tamaño por tarjeta,
/// tampoco se guarda.
#[tokio::test]
async fn una_tarjeta_mas_grande_que_su_tope_no_se_guarda() {
    let limits = Limits {
        max_vcard_bytes: 1024,
        ..Limits::DEFAULT
    };
    let f = Fixture::with_limits("contactos-tope-tarjeta", limits).await;
    f.server.put(0, "ana.vcf", &card("1", "Ana", "ana@x.com"));
    f.server.put(
        0,
        "nota.vcf",
        &format!(
            "BEGIN:VCARD\r\nFN:Nota\r\nNOTE:{}\r\nEND:VCARD\r\n",
            "n".repeat(2048)
        ),
    );

    let report = f.synced().await;
    assert_eq!(report.too_large, 1);
    assert_eq!(f.names().await, vec!["Ana"]);
}

/// Una libreta de más tarjetas que el tope no se guarda a medias.
#[tokio::test]
async fn una_libreta_que_pasa_el_tope_de_tarjetas_no_se_guarda() {
    let limits = Limits {
        max_cards_per_book: 5,
        ..Limits::DEFAULT
    };
    let f = Fixture::with_limits("contactos-tope-libreta", limits).await;
    put_many(&f.server, 0, 0..6);

    let SyncOutcome::Failed(detail) = f.sync().await else {
        panic!("tenía que fallar");
    };
    assert!(detail.contains("más de 5 tarjetas"), "{detail}");
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 0);
    assert!(!f.server.requests().iter().any(|r| r.is_multiget()));
}

/// Una cuenta con más libretas que el tope no se sincroniza.
#[tokio::test]
async fn una_cuenta_que_pasa_el_tope_de_libretas_no_se_guarda() {
    let limits = Limits {
        max_address_books: 2,
        ..Limits::DEFAULT
    };
    let f = Fixture::with_limits("contactos-tope-libretas", limits).await;
    f.server.add_book("/dav/ana/b/", "B");
    f.server.add_book("/dav/ana/c/", "C");

    let SyncOutcome::Failed(detail) = f.sync().await else {
        panic!("tenía que fallar");
    };
    assert!(detail.contains("más de 2 libretas"), "{detail}");
    assert_eq!(f.count("SELECT count(*) FROM address_books").await, 0);
}

// ── Los lotes ───────────────────────────────────────────────────────────────

/// **De a quinientas por transacción**: mil doscientas tres son tres lotes, y
/// el último lleva el token.
#[tokio::test]
async fn mas_de_quinientas_tarjetas_van_en_varios_lotes() {
    let f = Fixture::new("contactos-lotes").await;
    put_many(&f.server, 0, 0..1203);

    let report = f.synced().await;
    assert_eq!(report.fetched, 1203);
    assert_eq!(report.batches, 3);
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 1203);
    assert_eq!(f.count("SELECT count(*) FROM contact_emails").await, 1203);
    assert_eq!(f.token(0).await, Some(f.server_token()));
}

/// **Un corte a mitad no pierde el token viejo**: el servidor falla en el
/// segundo lote, lo del primero queda escrito, el token es el de antes, y la
/// vuelta siguiente repite desde ahí y termina igual que si no se hubiera
/// cortado.
#[tokio::test]
async fn un_corte_a_mitad_no_pierde_el_token_viejo() {
    let f = Fixture::new("contactos-corte").await;
    put_many(&f.server, 0, 0..2);
    f.synced().await;
    let old = f.token(0).await.unwrap();

    put_many(&f.server, 0, 2..702);
    // 500 tarjetas son diez `multiget` de cincuenta: el once es del segundo
    // lote.
    {
        let mut state = f.server.state();
        state.fail_multiget_from = Some(state.multigets + 11);
    }
    let outcome = f.sync().await;
    assert!(matches!(outcome, SyncOutcome::Failed(_)), "{outcome:?}");
    assert_eq!(f.token(0).await, Some(old.clone()), "el token no se movió");
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 502);

    f.server.state().fail_multiget_from = None;
    let before = f.server.requests().len();
    f.synced().await;
    let sync = f
        .requests_since(before)
        .into_iter()
        .find(|r| r.is_sync_collection())
        .unwrap();
    assert!(sync.body.contains(&old), "repitió desde el token viejo");
    assert_eq!(f.count("SELECT count(*) FROM contacts").await, 702);
    assert_eq!(f.token(0).await, Some(f.server_token()));
}

// ── El estado ───────────────────────────────────────────────────────────────

/// Lo que se ve en `GetStatus` dice en qué está el área y cuándo terminó
/// bien, **sin datos de los contactos ni direcciones**.
#[tokio::test]
async fn el_estado_del_area_no_lleva_datos_ni_direcciones() {
    let f = Fixture::new("contactos-estado").await;
    f.server
        .put(0, "ana.vcf", &card("1", "Ana Pérez", "ana@x.com"));
    f.synced().await;

    let status = serde_json::to_string(&f.manager.status().await).unwrap();
    let json: serde_json::Value = serde_json::from_str(&status).unwrap();
    let contacts = &json["accounts"][0]["contacts"];
    assert_eq!(contacts["state"], "synced");
    assert!(contacts["last_synced_at"].is_string());
    for secret in ["Ana", "ana@x.com", "127.0.0.1", "/dav/", "la-clave"] {
        assert!(!status.contains(secret), "«{secret}» en {status}");
    }

    // Y un fallo del servidor tampoco lleva la dirección, y conserva cuándo
    // anduvo por última vez.
    f.server.put(0, "x.vcf", &card("2", "X", "x@x.com"));
    f.server.state().fail_multiget_from = Some(1);
    assert!(matches!(f.sync().await, SyncOutcome::Failed(_)));
    let status = serde_json::to_string(&f.manager.status().await).unwrap();
    assert!(!status.contains("127.0.0.1"), "{status}");
    let json: serde_json::Value = serde_json::from_str(&status).unwrap();
    assert_eq!(json["accounts"][0]["contacts"]["state"], "failed");
    assert!(json["accounts"][0]["contacts"]["last_synced_at"].is_string());
}
