//! Pruebas del empuje por Graph: la serialización conservadora a JSON y el
//! alambre (`POST`/`PATCH`/`DELETE` con `If-Match`, idempotencia, conflicto)
//! contra el endpoint falso de [`crate::graph::fake`], el mismo que usan las
//! pruebas de lectura.

use super::*;
use crate::calendar_sync::graph::event_body_from_ical;
use crate::contacts_sync::graph::contact_body_from_vcard;
use crate::graph::fake::{self, FakeGraph};

// ── Serialización del cuerpo (iCal/vCard → JSON de Graph) ─────────────────────

const EVENT_ICAL: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:u1\r\n\
    SUMMARY:Reunión\r\nDESCRIPTION:Repaso\r\nLOCATION:Sala 3\r\n\
    DTSTART:20260105T140000Z\r\nDTEND:20260105T150000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

/// Un evento se serializa al subconjunto conservador, y **al crear** lleva el
/// `transactionId` (idempotencia nativa de Graph).
#[test]
fn el_cuerpo_de_un_evento_al_crear_lleva_transaction_id() {
    let body = event_body_from_ical(EVENT_ICAL, Some("tx-1")).expect("es un VEVENT");
    assert_eq!(body["subject"], "Reunión");
    assert_eq!(body["body"]["content"], "Repaso");
    assert_eq!(body["body"]["contentType"], "text");
    assert_eq!(body["location"]["displayName"], "Sala 3");
    assert_eq!(body["start"]["dateTime"], "2026-01-05T14:00:00");
    assert_eq!(body["start"]["timeZone"], "UTC");
    assert_eq!(body["end"]["dateTime"], "2026-01-05T15:00:00");
    assert_eq!(body["isAllDay"], false);
    assert_eq!(body["transactionId"], "tx-1");
}

/// **Al editar no va `transactionId`**: el `PATCH` no lo lleva.
#[test]
fn el_cuerpo_de_un_evento_al_editar_no_lleva_transaction_id() {
    let body = event_body_from_ical(EVENT_ICAL, None).expect("es un VEVENT");
    assert!(body.get("transactionId").is_none());
}

/// Un evento de día completo (`VALUE=DATE`) sale con `isAllDay` y la fecha a
/// medianoche.
#[test]
fn un_evento_de_dia_completo_sale_con_is_all_day() {
    let ical = "BEGIN:VEVENT\r\nUID:u\r\nSUMMARY:Feriado\r\n\
        DTSTART;VALUE=DATE:20260210\r\nDTEND;VALUE=DATE:20260211\r\nEND:VEVENT\r\n";
    let body = event_body_from_ical(ical, None).expect("es un VEVENT");
    assert_eq!(body["isAllDay"], true);
    assert_eq!(body["start"]["dateTime"], "2026-02-10T00:00:00");
    assert_eq!(body["end"]["dateTime"], "2026-02-11T00:00:00");
}

/// Un crudo que no es un evento (un `VTODO`) no se puede mandar a `/me/events`:
/// devuelve `None` y el empuje lo manda a conflicto en vez de crear algo torcido.
#[test]
fn un_vtodo_no_se_serializa_como_evento() {
    let vtodo = "BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:t\r\nSUMMARY:Tarea\r\nEND:VTODO\r\n\
        END:VCALENDAR\r\n";
    assert!(event_body_from_ical(vtodo, None).is_none());
}

/// **Seguridad: sin inyección.** Un `SUMMARY` con salto de línea y comillas no
/// puede partir el JSON ni fabricar campos: `serde_json` lo escapa, y al parsear
/// de vuelta el valor vuelve entero como un solo campo.
#[test]
fn el_cuerpo_escapa_la_inyeccion_en_el_json() {
    let ical = "BEGIN:VEVENT\r\nUID:u\r\nSUMMARY:Malo\\n\"isAllDay\":true x\r\n\
        DTSTART:20260105T140000Z\r\nEND:VEVENT\r\n";
    let body = event_body_from_ical(ical, None).expect("es un VEVENT");
    // El salto `\n` del iCal se deshace a un salto real dentro del valor; sigue
    // siendo un solo string, no un campo nuevo.
    assert_eq!(body["subject"], "Malo\n\"isAllDay\":true x");
    // `isAllDay` es el que puso la serialización (false), no el del texto.
    assert_eq!(body["isAllDay"], false);
    // Y re-serializado y re-parseado, el objeto es el mismo (JSON válido).
    let text = serde_json::to_string(&body).unwrap();
    let round: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(round["subject"], "Malo\n\"isAllDay\":true x");
}

/// Un evento sin fechas (sólo `SUMMARY`) se serializa sin `start`/`end` y con
/// `isAllDay` en falso, sin romper: `PATCH` fusiona, así que no pisa las fechas del
/// servidor.
#[test]
fn un_evento_sin_fechas_no_pone_start_ni_end() {
    let ical = "BEGIN:VEVENT\r\nUID:u\r\nSUMMARY:Sin fecha\r\nEND:VEVENT\r\n";
    let body = event_body_from_ical(ical, None).expect("es un VEVENT");
    assert_eq!(body["subject"], "Sin fecha");
    assert!(body.get("start").is_none(), "sin start");
    assert!(body.get("end").is_none(), "sin end");
    assert_eq!(body["isAllDay"], false);
}

const CONTACT_VCARD: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:c1\r\nFN:Ana Pérez\r\n\
    EMAIL:ana@x.com\r\nTEL;TYPE=WORK:+5411000\r\nTEL;TYPE=HOME:+5411111\r\n\
    TEL;TYPE=CELL:+5411222\r\nORG:Vasak\r\nNOTE:una nota\r\nEND:VCARD\r\n";

/// Un contacto se serializa al subconjunto conservador, con los teléfonos
/// repartidos por etiqueta en los tres campos de Graph.
#[test]
fn el_cuerpo_de_un_contacto_reparte_los_telefonos() {
    let body = contact_body_from_vcard(CONTACT_VCARD);
    assert_eq!(body["displayName"], "Ana Pérez");
    assert_eq!(body["emailAddresses"][0]["address"], "ana@x.com");
    assert_eq!(body["businessPhones"][0], "+5411000");
    assert_eq!(body["homePhones"][0], "+5411111");
    assert_eq!(body["mobilePhone"], "+5411222");
    assert_eq!(body["companyName"], "Vasak");
    assert_eq!(body["personalNotes"], "una nota");
}

/// Un contacto vacío no rompe: devuelve un objeto vacío (un `PATCH` sin campos no
/// toca nada; un `POST` crea un contacto vacío, borde aceptable).
#[test]
fn un_contacto_sin_campos_da_un_objeto_vacio() {
    let body = contact_body_from_vcard("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:x\r\nEND:VCARD\r\n");
    assert!(body.as_object().expect("es objeto").is_empty());
}

// ── Alambre: método, If-Match, idempotencia y conflicto contra el fake ────────

/// Un cuerpo JSON cualquiera para las pruebas de alambre.
fn body() -> serde_json::Value {
    serde_json::json!({ "subject": "x" })
}

/// Crear hace `POST` a la colección, **sin `If-Match`**, con el token, y devuelve
/// el `id` y el `@odata.etag` que asignó el servidor.
#[tokio::test]
async fn crear_hace_post_y_devuelve_id_y_etag() {
    let server = FakeGraph::start().await;
    server.push_status(201, r#"{"id":"NEW-ID","@odata.etag":"\"e1\""}"#);
    let credential = fake::credential_for(&server);
    let client = fake::client();

    let created = create(&client, &credential, "events", &body())
        .await
        .expect("creó");
    assert_eq!(created.id, "NEW-ID");
    assert_eq!(created.etag.as_deref(), Some("\"e1\""));

    let request = server.requests().remove(0);
    assert_eq!(request.method, "POST");
    assert!(
        request.path.contains("/users/me/events"),
        "{}",
        request.path
    );
    assert!(request.if_match.is_empty(), "un POST no lleva If-Match");
    assert!(request.authorization.contains(fake::TOKEN), "va el token");
    assert!(request.body.contains("\"subject\""), "va el cuerpo JSON");
}

/// Editar hace `PATCH` al objeto **con `If-Match: @odata.etag`**, y devuelve el
/// ETag nuevo.
#[tokio::test]
async fn editar_hace_patch_con_if_match() {
    let server = FakeGraph::start().await;
    server.push_status(200, r#"{"@odata.etag":"\"e2\""}"#);
    let credential = fake::credential_for(&server);
    let client = fake::client();

    let etag = update(&client, &credential, "events", "EV1", "\"e1\"", &body())
        .await
        .expect("editó");
    assert_eq!(etag.as_deref(), Some("\"e2\""));

    let request = server.requests().remove(0);
    assert_eq!(request.method, "PATCH");
    assert!(
        request.path.contains("/users/me/events/EV1"),
        "{}",
        request.path
    );
    assert_eq!(request.if_match, "\"e1\"", "va la precondición");
}

/// Borrar hace `DELETE` al objeto con `If-Match`.
#[tokio::test]
async fn borrar_hace_delete_con_if_match() {
    let server = FakeGraph::start().await;
    server.push_status(204, "");
    let credential = fake::credential_for(&server);
    let client = fake::client();

    delete(&client, &credential, "events", "EV1", "\"e1\"")
        .await
        .expect("borró");

    let request = server.requests().remove(0);
    assert_eq!(request.method, "DELETE");
    assert!(
        request.path.contains("/users/me/events/EV1"),
        "{}",
        request.path
    );
    assert_eq!(request.if_match, "\"e1\"");
}

/// **Idempotencia del borrado**: un `404` es éxito —el recurso ya no está, que es
/// lo que se buscaba—.
#[tokio::test]
async fn borrar_un_404_es_idempotente() {
    let server = FakeGraph::start().await;
    server.push_status(404, "");
    let credential = fake::credential_for(&server);
    let client = fake::client();

    delete(&client, &credential, "events", "EV1", "\"e1\"")
        .await
        .expect("un 404 al borrar es éxito");
}

/// **Conflicto**: un `412` al editar es [`GraphWriteError::Conflict`] —la op irá a
/// `conflict` sin pisar el local—.
#[tokio::test]
async fn editar_un_412_es_conflicto() {
    let server = FakeGraph::start().await;
    server.push_status(412, "");
    let credential = fake::credential_for(&server);
    let client = fake::client();

    let error = update(&client, &credential, "events", "EV1", "\"vieja\"", &body())
        .await
        .expect_err("un 412 es error");
    assert_eq!(error, GraphWriteError::Conflict);
}

/// Un `PATCH` que da `404` (el objeto desapareció en el servidor) también es
/// conflicto, no idempotente: no se pierde el cambio local.
#[tokio::test]
async fn editar_un_404_es_conflicto() {
    let server = FakeGraph::start().await;
    server.push_status(404, "");
    let credential = fake::credential_for(&server);
    let client = fake::client();

    let error = update(&client, &credential, "events", "EV1", "\"e1\"", &body())
        .await
        .expect_err("un 404 al editar es error");
    assert_eq!(error, GraphWriteError::Conflict);
}

/// Un `5xx` es reintentable (no se marca conflicto a la primera).
#[tokio::test]
async fn un_5xx_es_reintentable() {
    let server = FakeGraph::start().await;
    server.push_status(503, "");
    let credential = fake::credential_for(&server);
    let client = fake::client();

    let error = create(&client, &credential, "events", &body())
        .await
        .expect_err("un 503 es error");
    assert!(matches!(error, GraphWriteError::Retryable(_)));
}

/// **Seguridad: un `id` con `/`, `?` o `#` no altera la ruta ni cuela una query.**
/// El `id` entra percent-codificado como un segmento más, y la URL no lleva query.
#[test]
fn el_id_se_percent_codifica_en_la_ruta() {
    let server_origin = "https://graph.example/v1.0";
    let credential = GraphCredential {
        access_token: zeroize::Zeroizing::new("t".into()),
        user_id: "me".into(),
        base_url: server_origin.into(),
    };
    let url = object_url(&credential, "events", "a/b?c#d").expect("url válida");
    assert_eq!(url.query(), None, "sin query");
    assert!(
        url.path().contains("/users/me/events/a%2Fb%3Fc%23d"),
        "el id no se percent-codificó: {}",
        url.path()
    );
}

// ── `href` ↔ `id` del servidor ────────────────────────────────────────────────

/// El `href` guardado y el `id` del servidor se invierten en **las dos áreas**,
/// también con un `id` que se escapa (`;`, `,`, `\`): si no, un `PATCH`/`DELETE`
/// iría a un `id` distinto del que Graph asignó.
#[test]
fn el_href_y_el_id_se_invierten_en_las_dos_areas() {
    use crate::store::lifecycle::CONTACTS_AREA;
    for area in [CALENDAR_AREA, CONTACTS_AREA] {
        for id in ["AAMkAGI2=", "a;b,c\\d"] {
            let href = href_for_id(area, id);
            assert_eq!(id_from_href(area, &href), id, "{area}: {href}");
        }
    }
}

// ── Clasificación del estado HTTP ─────────────────────────────────────────────

/// Un `429` (rate limit) es reintentable, no conflicto: no se pierde el cambio por
/// un límite temporal.
#[test]
fn un_429_es_reintentable() {
    let error = classify(reqwest::StatusCode::TOO_MANY_REQUESTS, false).expect_err("429 es error");
    assert!(matches!(error, GraphWriteError::Retryable(_)));
}

/// Un `409` (conflicto) es [`GraphWriteError::Conflict`], igual que el `412`.
#[test]
fn un_409_es_conflicto() {
    let error = classify(reqwest::StatusCode::CONFLICT, false).expect_err("409 es error");
    assert_eq!(error, GraphWriteError::Conflict);
}

/// Un `4xx` firme que no es `409`/`412`/`404` (p. ej. `400`) es permanente: escala
/// a conflicto para no trabar la colección, no se reintenta en bucle.
#[test]
fn un_400_es_permanente() {
    let error = classify(reqwest::StatusCode::BAD_REQUEST, false).expect_err("400 es error");
    assert!(matches!(error, GraphWriteError::Permanent(_)));
}

/// Un `2xx` es éxito, tanto en un `DELETE` como en el resto.
#[test]
fn un_2xx_es_exito() {
    assert!(classify(reqwest::StatusCode::OK, false).is_ok());
    assert!(classify(reqwest::StatusCode::NO_CONTENT, true).is_ok());
}

// ── Lectura de la respuesta de escritura (`read_response` vía `create`) ────────

/// Un cuerpo que no es JSON válido, tras un `201`, es permanente (respuesta
/// ilegible): no se reintenta un `POST` que ya creó algo, va a conflicto.
#[tokio::test]
async fn un_cuerpo_ilegible_es_permanente() {
    let server = FakeGraph::start().await;
    server.push_status(201, "esto no es json {{{");
    let credential = fake::credential_for(&server);
    let client = fake::client();

    let error = create(&client, &credential, "contacts", &body())
        .await
        .expect_err("un cuerpo ilegible es error");
    assert!(matches!(error, GraphWriteError::Permanent(_)));
}

/// Un cuerpo de respuesta que supera el tope de tamaño es permanente: un servidor
/// roto o adversario no puede hacer leer sin límite.
#[tokio::test]
async fn un_cuerpo_sobredimensionado_es_permanente() {
    let server = FakeGraph::start().await;
    let gordo = format!(
        "{{\"id\":\"X\",\"pad\":\"{}\"}}",
        "a".repeat(super::MAX_WRITE_RESPONSE + 16)
    );
    server.push_status(201, gordo);
    let credential = fake::credential_for(&server);
    let client = fake::client();

    let error = create(&client, &credential, "contacts", &body())
        .await
        .expect_err("un cuerpo gigante es error");
    assert!(matches!(error, GraphWriteError::Permanent(_)));
}

/// Un `201` **sin `id`** es permanente: no hay a qué re-basar el `href`, y
/// reintentar el `POST` duplicaría; va a conflicto.
#[tokio::test]
async fn un_201_sin_id_es_permanente() {
    let server = FakeGraph::start().await;
    server.push_status(201, "{}");
    let credential = fake::credential_for(&server);
    let client = fake::client();

    let error = create(&client, &credential, "contacts", &body())
        .await
        .expect_err("un 201 sin id es error");
    assert!(matches!(error, GraphWriteError::Permanent(_)));
}

// ── De punta a punta: `replay_graph_area` contra el fake y un almacén de verdad ─
//
// Las pruebas de arriba miran el alambre (`create`/`update`/`delete`) y la
// serialización por separado, y `store::queue` prueba los cierres contra la base.
// Falta el **pegamento**: `replay_graph_area` drena la cola contra el servidor y,
// según el estado que contesta, deja la op cerrada, en conflicto o para
// reintentar —**sin perder el crudo local**—. Eso es lo que ve la persona, y es lo
// que ningún test cubría de punta a punta. Se monta un `StoreManager` con el
// llavero falso, se encola una op y se drena contra el `FakeGraph`, igual que las
// pruebas de borrador de `replay` para el camino DAV.
mod end_to_end {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::graph::fake::{self, FakeGraph};
    use crate::graph::GraphCredential;
    use crate::graph_write::replay_graph_area;
    use crate::replay::ReplayReport;
    use crate::store::contacts::{ContactOp, ContactRow, StoredAddressBook};
    use crate::store::key::fake::FakeKeys;
    use crate::store::lifecycle::{
        AccountListing, Consent, ListedAccount, Locations, StoreManager, CONTACTS_AREA,
    };
    use crate::store::paths::tests::TempDir;
    use crate::vcard;

    const ACCOUNT: &str = "cuenta";
    const BOOK: &str = "https://x/a/";

    struct Fixture {
        _temp: TempDir,
        manager: Arc<StoreManager<FakeKeys>>,
        server: FakeGraph,
        book: StoredAddressBook,
    }

    impl Fixture {
        async fn new(label: &str) -> Self {
            let temp = TempDir::new(label);
            let manager = Arc::new(StoreManager::new(
                FakeKeys::default(),
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
                        capabilities: vec!["contacts".into()],
                        needs_reauth: false,
                    }]),
                    Instant::now(),
                )
                .await;
            manager
                .activate_area(CONTACTS_AREA, ACCOUNT, Consent::Granted)
                .await
                .unwrap();
            assert!(
                manager.prepare_for_sync(CONTACTS_AREA, ACCOUNT).await,
                "la base tenía que quedar abierta"
            );
            let book = manager
                .with_store(ACCOUNT, |store| {
                    Ok(store
                        .upsert_address_books(&[(BOOK.into(), "A".into())])?
                        .remove(0))
                })
                .await
                .unwrap();
            Self {
                _temp: temp,
                server: FakeGraph::start().await,
                manager,
                book,
            }
        }

        fn credential(&self) -> GraphCredential {
            fake::credential_for(&self.server)
        }

        fn card(href: &str, name: &str, base_etag: Option<&str>) -> ContactRow {
            let raw = format!("BEGIN:VCARD\r\nFN:{name}\r\nEND:VCARD");
            ContactRow {
                href: href.into(),
                etag: base_etag.map(str::to_string),
                contact: vcard::contact_from(&raw, href).unwrap(),
                raw_vcard: raw,
            }
        }

        /// Encola un `put`: `base_etag` nulo lo hace **crear** (`POST`); con
        /// `base_etag`, **editar** (`PATCH` con `If-Match`).
        async fn enqueue_put(&self, href: &str, name: &str, base_etag: Option<&str>) {
            let book = self.book.clone();
            let row = Self::card(href, name, base_etag);
            self.manager
                .with_store(ACCOUNT, move |store| store.enqueue_contact_put(&book, &row))
                .await
                .unwrap();
        }

        async fn enqueue_delete(&self, href: &str, base_etag: Option<&str>) {
            let href = href.to_string();
            let base = base_etag.map(str::to_string);
            self.manager
                .with_store(ACCOUNT, move |store| {
                    store.enqueue_delete(CONTACTS_AREA, BOOK, &href, base.as_deref())
                })
                .await
                .unwrap();
        }

        /// Una bajada del servidor del mismo objeto, por el camino normal de la
        /// caché (`apply_contacts`): para probar que no duplica tras una creación.
        async fn download(&self, href: &str, name: &str) {
            let book = self.book.clone();
            let row = Self::card(href, name, Some("\"srv\""));
            self.manager
                .with_store(ACCOUNT, move |store| {
                    store
                        .apply_contacts(&book, &[ContactOp::Upsert(Box::new(row))], None, u64::MAX)
                        .map(|_| ())
                })
                .await
                .unwrap();
        }

        async fn replay(&self) -> ReplayReport {
            let credential = self.credential();
            let client = fake::client();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            replay_graph_area(
                &self.manager,
                ACCOUNT,
                CONTACTS_AREA,
                &client,
                &credential,
                deadline,
            )
            .await
            .unwrap()
        }

        async fn op_field(&self, href: &str, column: &'static str) -> Option<String> {
            let href = href.to_string();
            self.manager
                .with_store(ACCOUNT, move |store| {
                    Ok(store
                        .connection()
                        .query_row(
                            &format!("SELECT {column} FROM pending_dav_ops WHERE object_href = ?1"),
                            [href],
                            |r| r.get::<_, String>(0),
                        )
                        .ok())
                })
                .await
                .unwrap()
        }

        async fn op_state(&self, href: &str) -> Option<String> {
            self.op_field(href, "state").await
        }

        async fn op_attempts(&self, href: &str) -> Option<i64> {
            let href = href.to_string();
            self.manager
                .with_store(ACCOUNT, move |store| {
                    Ok(store
                        .connection()
                        .query_row(
                            "SELECT attempts FROM pending_dav_ops WHERE object_href = ?1",
                            [href],
                            |r| r.get::<_, i64>(0),
                        )
                        .ok())
                })
                .await
                .unwrap()
        }

        async fn stored(&self, href: &str, column: &'static str) -> Option<String> {
            let href = href.to_string();
            self.manager
                .with_store(ACCOUNT, move |store| {
                    Ok(store
                        .connection()
                        .query_row(
                            &format!("SELECT {column} FROM contacts WHERE href = ?1"),
                            [href],
                            |r| r.get::<_, Option<String>>(0),
                        )
                        .ok()
                        .flatten())
                })
                .await
                .unwrap()
        }

        async fn pending(&self) -> i64 {
            self.manager
                .with_store(ACCOUNT, |store| store.pending_count(CONTACTS_AREA))
                .await
                .unwrap()
        }

        async fn row_count(&self, href: &str) -> i64 {
            let href = href.to_string();
            self.manager
                .with_store(ACCOUNT, move |store| {
                    Ok(store
                        .connection()
                        .query_row(
                            "SELECT count(*) FROM contacts WHERE href = ?1",
                            [href],
                            |r| r.get::<_, i64>(0),
                        )
                        .unwrap())
                })
                .await
                .unwrap()
        }
    }

    /// **`412` en un `PATCH`**: la op queda en `conflict` y **el crudo local no se
    /// pierde** —sigue la fila, re-leíble y re-intentable por la superficie de
    /// conflicto—.
    #[tokio::test]
    async fn un_412_deja_la_op_en_conflicto_y_conserva_el_crudo_local() {
        let f = Fixture::new("graph-e2e-412").await;
        f.enqueue_put("SRV-ID", "Mía", Some("\"vieja\"")).await;
        f.server.push_status(412, "");

        let report = f.replay().await;

        assert_eq!(report.conflicts, 1);
        assert_eq!(f.op_state("SRV-ID").await.as_deref(), Some("conflict"));
        assert_eq!(f.pending().await, 1, "la op sigue para resolverse");
        assert!(
            f.stored("SRV-ID", "raw_vcard")
                .await
                .is_some_and(|r| r.contains("Mía")),
            "el crudo local no se perdió"
        );
    }

    /// **`DELETE` con `404`**: es éxito idempotente —el recurso ya no está, que es
    /// lo que se buscaba—. La op se completa, no queda colgada.
    #[tokio::test]
    async fn borrar_con_404_completa_la_op_idempotente() {
        let f = Fixture::new("graph-e2e-del404").await;
        f.download("SRV-ID", "Ana").await; // una fila al día que después se borra
        f.enqueue_delete("SRV-ID", Some("\"e1\"")).await;
        f.server.push_status(404, "");

        let report = f.replay().await;

        assert_eq!(report.pushed, 1, "un 404 al borrar cuenta como éxito");
        assert_eq!(f.pending().await, 0, "la op no queda colgada");
        assert_eq!(
            f.stored("SRV-ID", "raw_vcard").await,
            None,
            "la fila se borró"
        );
    }

    /// **`PATCH` con `404`**: el objeto desapareció en el servidor → conflicto, no
    /// éxito. No se pierde el cambio local.
    #[tokio::test]
    async fn editar_con_404_queda_en_conflicto() {
        let f = Fixture::new("graph-e2e-patch404").await;
        f.enqueue_put("SRV-ID", "Mía", Some("\"e1\"")).await;
        f.server.push_status(404, "");

        let report = f.replay().await;

        assert_eq!(report.conflicts, 1);
        assert_eq!(f.op_state("SRV-ID").await.as_deref(), Some("conflict"));
        assert!(
            f.stored("SRV-ID", "raw_vcard")
                .await
                .is_some_and(|r| r.contains("Mía")),
            "el cambio local no se perdió"
        );
    }

    /// **Creación por `POST`**: tras el `POST`, el `href` local se re-basa al `id`
    /// del servidor y el ETag queda guardado; una bajada posterior del mismo objeto
    /// **no lo duplica**.
    #[tokio::test]
    async fn crear_rebasa_el_href_al_id_del_servidor_y_no_duplica() {
        const LOCAL: &str = "graph://default/nuevo.vcf";
        let f = Fixture::new("graph-e2e-create").await;
        f.enqueue_put(LOCAL, "Local", None).await; // base_etag nulo → crear
        f.server
            .push_status(201, r#"{"id":"SRV-ID","@odata.etag":"\"e1\""}"#);

        let report = f.replay().await;
        assert_eq!(report.pushed, 1);

        let server_href = crate::vcard::escape_vcard_public("SRV-ID");
        assert_eq!(
            f.stored(LOCAL, "raw_vcard").await,
            None,
            "el href sintético se fue"
        );
        assert!(
            f.stored(&server_href, "raw_vcard")
                .await
                .is_some_and(|r| r.contains("Local")),
            "la fila vive bajo el id del servidor con el crudo local"
        );
        assert_eq!(
            f.stored(&server_href, "etag").await.as_deref(),
            Some("\"e1\""),
            "el ETag del servidor quedó guardado"
        );
        assert_eq!(f.pending().await, 0);

        // Una bajada posterior del mismo objeto, por su id del servidor, no lo
        // duplica: sigue habiendo una sola fila.
        f.download(&server_href, "Local").await;
        assert_eq!(f.row_count(&server_href).await, 1, "no se duplicó");
    }

    /// **`5xx`**: transitorio → se reintenta (`retry_later`), la op sigue en
    /// `ready` con un intento más. **No** se marca conflicto firme a la primera.
    #[tokio::test]
    async fn un_5xx_reintenta_y_no_marca_conflicto() {
        let f = Fixture::new("graph-e2e-5xx").await;
        f.enqueue_put("SRV-ID", "Mía", Some("\"e1\"")).await;
        f.server.push_status(503, "");

        let report = f.replay().await;

        assert_eq!(report.retried, 1);
        assert_eq!(report.conflicts, 0, "un 5xx no es conflicto firme");
        assert_eq!(
            f.op_state("SRV-ID").await.as_deref(),
            Some("ready"),
            "sigue reintentable"
        );
        assert_eq!(f.op_attempts("SRV-ID").await, Some(1));
    }

    /// **`If-Match` correcto**: el `PATCH` manda el `@odata.etag` capturado —el
    /// `base_etag` de la op— y **no vacío**: la precondición que dispara el `412`.
    #[tokio::test]
    async fn el_patch_manda_el_etag_capturado_no_vacio() {
        let f = Fixture::new("graph-e2e-ifmatch").await;
        f.enqueue_put("SRV-ID", "Mía", Some("W/\"cap\"")).await;
        f.server
            .push_status(200, r#"{"@odata.etag":"W/\"nuevo\""}"#);

        f.replay().await;

        let request = f.server.requests().remove(0);
        assert_eq!(request.method, "PATCH");
        assert!(
            !request.if_match.is_empty(),
            "la precondición no viaja vacía"
        );
        assert_eq!(
            request.if_match, "W/\"cap\"",
            "manda el etag capturado, no otro"
        );
    }

    /// **`DELETE` sin `base_etag`**: nunca hubo recurso en el servidor (se creó y se
    /// borró local sin subir), así que el borrado se cierra **sin tocar la red**.
    #[tokio::test]
    async fn borrar_sin_etag_cierra_sin_tocar_la_red() {
        let f = Fixture::new("graph-e2e-del-sin-etag").await;
        f.download("SRV-ID", "Ana").await;
        f.enqueue_delete("SRV-ID", None).await;
        // No se encola ninguna respuesta: si tocara la red, el fake daría 500 y la
        // op no se completaría.

        let report = f.replay().await;

        assert_eq!(report.pushed, 1);
        assert_eq!(f.pending().await, 0, "el borrado se cerró");
        assert_eq!(f.stored("SRV-ID", "raw_vcard").await, None);
        assert!(
            f.server.requests().is_empty(),
            "no se mandó ningún pedido a la red"
        );
    }

    /// **`POST` que no devuelve `id`**: es permanente (no hay a qué re-basar el
    /// `href`; reintentar duplicaría) → la op escala a `conflict` **sin perder el
    /// crudo local** ni duplicar.
    #[tokio::test]
    async fn crear_sin_id_escala_a_conflicto_sin_perder_el_local() {
        const LOCAL: &str = "graph://default/nuevo.vcf";
        let f = Fixture::new("graph-e2e-create-sin-id").await;
        f.enqueue_put(LOCAL, "Local", None).await;
        f.server.push_status(201, "{}");

        let report = f.replay().await;

        assert_eq!(report.conflicts, 1);
        assert_eq!(f.op_state(LOCAL).await.as_deref(), Some("conflict"));
        assert!(
            f.stored(LOCAL, "raw_vcard")
                .await
                .is_some_and(|r| r.contains("Local")),
            "el crudo local sigue en su href sintético"
        );
    }

    /// Deja la op de un objeto con `attempts` reintentos ya contados, como si
    /// hubiera fallado por red esas veces en vueltas anteriores.
    async fn burn_attempts(f: &Fixture, href: &str, attempts: i64) {
        let href = href.to_string();
        f.manager
            .with_store(ACCOUNT, move |store| {
                let op = store
                    .pending_ops(CONTACTS_AREA)?
                    .into_iter()
                    .find(|o| o.object_href == href)
                    .expect("la op está encolada");
                for _ in 0..attempts {
                    store.retry_later(&op, "red caída")?;
                }
                Ok(())
            })
            .await
            .unwrap();
    }

    /// **Escalada por tope**: una op que ya agotó sus reintentos y vuelve a fallar
    /// por algo transitorio (`503`) **escala a `conflict`** en vez de reintentarse
    /// para siempre y trabar la colección. El crudo local no se pierde.
    #[tokio::test]
    async fn una_op_que_agoto_los_reintentos_escala_a_conflicto() {
        let f = Fixture::new("graph-e2e-escalada").await;
        f.enqueue_put("SRV-ID", "Mía", Some("\"e1\"")).await;
        burn_attempts(&f, "SRV-ID", super::super::MAX_REPLAY_ATTEMPTS - 1).await;
        f.server.push_status(503, "");

        let report = f.replay().await;

        assert_eq!(report.conflicts, 1, "pasó el tope: escala");
        assert_eq!(report.retried, 0);
        assert_eq!(f.op_state("SRV-ID").await.as_deref(), Some("conflict"));
        assert!(f
            .stored("SRV-ID", "raw_vcard")
            .await
            .is_some_and(|r| r.contains("Mía")));
    }

    /// El borde de abajo: con un intento menos del tope, el mismo `503` todavía
    /// **reintenta** —no escala antes de tiempo—.
    #[tokio::test]
    async fn una_op_un_intento_antes_del_tope_todavia_reintenta() {
        let f = Fixture::new("graph-e2e-antes-del-tope").await;
        f.enqueue_put("SRV-ID", "Mía", Some("\"e1\"")).await;
        burn_attempts(&f, "SRV-ID", super::super::MAX_REPLAY_ATTEMPTS - 2).await;
        f.server.push_status(503, "");

        let report = f.replay().await;

        assert_eq!(report.retried, 1);
        assert_eq!(report.conflicts, 0);
        assert_eq!(f.op_state("SRV-ID").await.as_deref(), Some("ready"));
    }
}

// ── De punta a punta por el camino de **calendario** (`/me/events`) ───────────
//
// Espejo de `end_to_end` de contactos: ejerce la rama `CALENDAR_AREA` de
// `segment`, `build_body`, `href_for_id` e `id_from_href` por `replay_graph_area`.
mod end_to_end_calendar {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::graph::fake::{self, FakeGraph};
    use crate::graph_write::replay_graph_area;
    use crate::ical::recurrence::ExpansionLimits;
    use crate::replay::ReplayReport;
    use crate::store::calendar::{
        derive_with_occurrences, CalendarListing, ObjectRow, StoredCalendar, Window,
    };
    use crate::store::key::fake::FakeKeys;
    use crate::store::lifecycle::{
        AccountListing, Consent, ListedAccount, Locations, StoreManager, CALENDAR_AREA,
    };
    use crate::store::paths::tests::TempDir;

    const ACCOUNT: &str = "cuenta";
    const COLLECTION: &str = "https://x/cal/";
    const TODAY: i64 = 1_790_424_000;
    const ICAL: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:u1\r\n\
        SUMMARY:Reunión\r\nDTSTART:20260105T140000Z\r\nDTEND:20260105T150000Z\r\n\
        END:VEVENT\r\nEND:VCALENDAR\r\n";

    struct Fixture {
        _temp: TempDir,
        manager: Arc<StoreManager<FakeKeys>>,
        server: FakeGraph,
        calendar: StoredCalendar,
    }

    impl Fixture {
        async fn new(label: &str) -> Self {
            let temp = TempDir::new(label);
            let manager = Arc::new(StoreManager::new(
                FakeKeys::default(),
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
            assert!(manager.prepare_for_sync(CALENDAR_AREA, ACCOUNT).await);
            let calendar = manager
                .with_store(ACCOUNT, |store| {
                    Ok(store
                        .upsert_calendars(&[CalendarListing {
                            href: COLLECTION.into(),
                            display_name: "Personal".into(),
                            color: None,
                            components: vec!["VEVENT".into()],
                        }])?
                        .remove(0))
                })
                .await
                .unwrap();
            Self {
                _temp: temp,
                server: FakeGraph::start().await,
                manager,
                calendar,
            }
        }

        fn window() -> Window {
            Window::around(chrono::DateTime::from_timestamp(TODAY, 0).unwrap())
        }

        async fn enqueue_put(&self, href: &str, base_etag: Option<&str>) {
            let (index, occurrences) =
                derive_with_occurrences(ICAL, Self::window(), &ExpansionLimits::DEFAULT);
            let row = ObjectRow {
                href: href.into(),
                etag: base_etag.map(str::to_string),
                raw_ical: ICAL.into(),
                index,
                occurrences,
            };
            let calendar = self.calendar.clone();
            self.manager
                .with_store(ACCOUNT, move |store| {
                    store.enqueue_calendar_put(&calendar, &row, Self::window())
                })
                .await
                .unwrap();
        }

        async fn replay(&self) -> ReplayReport {
            let credential = fake::credential_for(&self.server);
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            replay_graph_area(
                &self.manager,
                ACCOUNT,
                CALENDAR_AREA,
                &fake::client(),
                &credential,
                deadline,
            )
            .await
            .unwrap()
        }

        /// Una columna de la fila guardada del evento, o `None` si no hay fila.
        async fn stored(&self, href: &str, column: &'static str) -> Option<String> {
            let href = href.to_string();
            self.manager
                .with_store(ACCOUNT, move |store| {
                    Ok(store
                        .connection()
                        .query_row(
                            &format!("SELECT {column} FROM calendar_objects WHERE href = ?1"),
                            [href],
                            |r| r.get::<_, Option<String>>(0),
                        )
                        .ok()
                        .flatten())
                })
                .await
                .unwrap()
        }

        async fn op_state(&self, href: &str) -> Option<String> {
            let href = href.to_string();
            self.manager
                .with_store(ACCOUNT, move |store| {
                    Ok(store
                        .connection()
                        .query_row(
                            "SELECT state FROM pending_dav_ops WHERE object_href = ?1",
                            [href],
                            |r| r.get::<_, String>(0),
                        )
                        .ok())
                })
                .await
                .unwrap()
        }

        async fn pending(&self) -> i64 {
            self.manager
                .with_store(ACCOUNT, |store| store.pending_count(CALENDAR_AREA))
                .await
                .unwrap()
        }
    }

    /// **Crear**: `POST /me/events` con `transactionId` (idempotencia de Graph) sacado
    /// del `href` local, sin `If-Match`; el `href` se re-basa al `id` del servidor y
    /// el ETag queda guardado.
    #[tokio::test]
    async fn crear_un_evento_hace_post_con_transaction_id_y_rebasa_el_href() {
        const LOCAL: &str = "graph://default/nuevo.ics";
        let f = Fixture::new("graph-cal-create").await;
        f.enqueue_put(LOCAL, None).await;
        f.server
            .push_status(201, r#"{"id":"SRV-ID","@odata.etag":"W/\"e1\""}"#);

        let report = f.replay().await;
        assert_eq!(report.pushed, 1);

        let request = f.server.requests().remove(0);
        assert_eq!(request.method, "POST");
        assert!(
            request.path.contains("/users/me/events"),
            "{}",
            request.path
        );
        assert!(request.if_match.is_empty());
        let sent: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        assert_eq!(sent["subject"], "Reunión");
        assert_eq!(sent["transactionId"], LOCAL, "idempotencia estable");

        assert_eq!(f.stored(LOCAL, "raw_ical").await, None, "se re-basó");
        assert!(f
            .stored("SRV-ID", "raw_ical")
            .await
            .is_some_and(|r| r.contains("Reunión")));
        assert_eq!(
            f.stored("SRV-ID", "etag").await.as_deref(),
            Some("W/\"e1\"")
        );
        assert_eq!(f.pending().await, 0);
    }

    /// **Editar**: `PATCH /me/events/{id}` con el `If-Match` capturado, **sin**
    /// `transactionId`; con la respuesta se guarda el ETag nuevo.
    #[tokio::test]
    async fn editar_un_evento_hace_patch_con_if_match_y_sin_transaction_id() {
        let f = Fixture::new("graph-cal-patch").await;
        f.enqueue_put("SRV-ID", Some("W/\"cap\"")).await;
        f.server
            .push_status(200, r#"{"@odata.etag":"W/\"nuevo\""}"#);

        let report = f.replay().await;
        assert_eq!(report.pushed, 1);

        let request = f.server.requests().remove(0);
        assert_eq!(request.method, "PATCH");
        assert!(
            request.path.contains("/users/me/events/SRV-ID"),
            "{}",
            request.path
        );
        assert_eq!(request.if_match, "W/\"cap\"");
        let sent: serde_json::Value = serde_json::from_str(&request.body).unwrap();
        assert!(sent.get("transactionId").is_none());
        assert_eq!(
            f.stored("SRV-ID", "etag").await.as_deref(),
            Some("W/\"nuevo\"")
        );
        assert_eq!(f.pending().await, 0);
    }

    /// **`412` en un evento**: la op queda en `conflict` y el crudo local no se
    /// pierde.
    #[tokio::test]
    async fn un_412_en_un_evento_deja_conflicto_y_conserva_el_local() {
        let f = Fixture::new("graph-cal-412").await;
        f.enqueue_put("SRV-ID", Some("W/\"vieja\"")).await;
        f.server.push_status(412, "");

        let report = f.replay().await;

        assert_eq!(report.conflicts, 1);
        assert_eq!(f.op_state("SRV-ID").await.as_deref(), Some("conflict"));
        assert!(f
            .stored("SRV-ID", "raw_ical")
            .await
            .is_some_and(|r| r.contains("Reunión")));
    }
}
