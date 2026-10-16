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
