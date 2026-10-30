//! Recordatorios de seguimiento (`vasak-accounts#22`, PR 4): **todo lo que se
//! puede probar sin un compositor ni un servidor de verdad**.
//!
//! - Los cores de `store_api::followup_*_in` y la decisión de
//!   [`crate::apply_followup_in`], sobre un almacén de prueba (llavero falso y
//!   una base real en un directorio temporal) y mirando el almacén, no lo que
//!   devuelven.
//! - `Reader::check_followup` contra un servidor IMAP de mentira por TLS (el de
//!   `snooze_tests`): qué comandos manda y qué contesta según lo que encuentra.
//! - El productor del bucle de punta a punta (IMAP de mentira + servidor de
//!   notificaciones falso): el cartel sale cuando tiene que salir.
//! - El enganche de `SendMessage` y los métodos D-Bus, sin almacén (el
//!   `LIVE_STORE` sólo lo fija el arranque del servicio, así que acá es el estado
//!   de «el almacén no está disponible»).
//! - La forma del JSON (`Followup`, `Draft`) y el texto del cartel.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use zbus::zvariant::OwnedValue;

use crate::compose::Draft;
use crate::followup_notify::FollowupNotifier;
use crate::notifications::{self, ShownNotifications};
use crate::snooze_core_tests::{store_with, store_with_keys};
use crate::snooze_tests::{after_open, client, finish, imap_server, ACCOUNT, ADDRESS};
use crate::store::key::fake::FakeKeys;
use crate::store::lifecycle::StoreManager;
use crate::store::snooze::Followup;
use crate::test_bus::{captured_logs, error_of, Fixture};
use crate::test_support::json_keys;
use crate::{apply_followup_in, store_api, ServiceFollowupNotifier};

fn row(message_id: &str, remind_at: i64) -> Followup {
    Followup {
        id: remind_at,
        message_id: message_id.into(),
        recipients: "ana@x.com".into(),
        remind_at,
        created_at: 1,
    }
}

async fn put(manager: &StoreManager<FakeKeys>, account_id: &str, message_id: &str, at: i64) {
    store_api::followup_upsert_in(manager, account_id, message_id, "ana@x.com", at)
        .await
        .unwrap();
}

async fn ids(manager: &StoreManager<FakeKeys>, account_id: &str) -> Vec<String> {
    store_api::followup_list_in(manager, account_id)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.message_id)
        .collect()
}

// ---------------------------------------------------------------------------
// apply_followup_in: qué se hace con la fila según lo que dijo la comprobación
// ---------------------------------------------------------------------------

/// Cuenta cuántas veces se avisó. El aviso entra por closure para ejercer la
/// decisión sin un bus de notificaciones detrás.
async fn apply(
    manager: Option<&StoreManager<FakeKeys>>,
    message_id: &str,
    checked: Result<bool, String>,
) -> usize {
    let calls = AtomicUsize::new(0);
    apply_followup_in(manager, "cta", &row(message_id, 100), checked, || async {
        calls.fetch_add(1, Ordering::SeqCst);
    })
    .await;
    calls.load(Ordering::SeqCst)
}

#[tokio::test]
async fn si_ya_respondieron_se_borra_la_fila_y_no_se_avisa() {
    let (_t, manager) = store_with("seg-respondido", &["cta"], &["cta"]).await;
    put(&manager, "cta", "<m@x>", 100).await;
    put(&manager, "cta", "<otro@x>", 200).await;

    let notified = apply(Some(&manager), "<m@x>", Ok(true)).await;

    assert_eq!(notified, 0, "avisó «sin respuesta» habiendo respuesta");
    assert_eq!(
        ids(&manager, "cta").await,
        ["<otro@x>"],
        "sólo se va la fila atendida"
    );
}

#[tokio::test]
async fn si_no_hubo_respuesta_se_avisa_una_sola_vez_y_se_borra_la_fila() {
    let (_t, manager) = store_with("seg-sin-respuesta", &["cta"], &["cta"]).await;
    put(&manager, "cta", "<m@x>", 100).await;
    put(&manager, "cta", "<otro@x>", 200).await;

    let notified = apply(Some(&manager), "<m@x>", Ok(false)).await;

    assert_eq!(notified, 1);
    assert_eq!(
        ids(&manager, "cta").await,
        ["<otro@x>"],
        "el recordatorio es de un solo disparo"
    );
}

#[tokio::test]
async fn si_la_comprobacion_falla_ni_se_avisa_ni_se_borra_la_fila() {
    let (_t, manager) = store_with("seg-falla", &["cta"], &["cta"]).await;
    put(&manager, "cta", "<m@x>", 100).await;

    let notified = apply(Some(&manager), "<m@x>", Err("sin red".into())).await;

    assert_eq!(notified, 0, "avisó «sin respuesta» sólo porque no hubo red");
    assert_eq!(
        ids(&manager, "cta").await,
        ["<m@x>"],
        "la fila queda para reintentar en la próxima vuelta"
    );
}

/// Sin almacén no hay fila que borrar, pero el aviso sí corresponde: no explota.
#[tokio::test]
async fn sin_almacen_el_aviso_sale_igual_y_nada_explota() {
    assert_eq!(apply(None, "<m@x>", Ok(false)).await, 1);
    assert_eq!(apply(None, "<m@x>", Ok(true)).await, 0);
    assert_eq!(apply(None, "<m@x>", Err("sin red".into())).await, 0);
}

/// Con el llavero bloqueado la fila no se puede borrar: el aviso ya salió y la
/// función no falla; la fila sigue ahí cuando se desbloquea.
#[tokio::test]
async fn si_no_se_puede_borrar_la_fila_no_falla_y_sigue_cuando_se_desbloquea() {
    let keys = FakeKeys::default();
    let (_t, manager) = store_with_keys("seg-bloqueado", &["cta"], &["cta"], keys.clone()).await;
    put(&manager, "cta", "<m@x>", 100).await;

    keys.state().locked = true;
    assert_eq!(apply(Some(&manager), "<m@x>", Ok(false)).await, 1);

    keys.state().locked = false;
    manager.refresh().await;
    assert_eq!(ids(&manager, "cta").await, ["<m@x>"]);
}

// ---------------------------------------------------------------------------
// store_api::followup_*_in
// ---------------------------------------------------------------------------

#[tokio::test]
async fn el_seguimiento_se_anota_y_se_lista_con_sus_datos() {
    let (_t, manager) = store_with("seg-anotar", &["cta"], &["cta"]).await;
    assert!(store_api::followup_list_in(&manager, "cta")
        .await
        .unwrap()
        .is_empty());

    store_api::followup_upsert_in(&manager, "cta", "<a@x>", "ana@x.com, bo@x.com", 5_000)
        .await
        .unwrap();

    let rows = store_api::followup_list_in(&manager, "cta").await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].message_id, "<a@x>");
    assert_eq!(rows[0].recipients, "ana@x.com, bo@x.com");
    assert_eq!(rows[0].remind_at, 5_000);

    // Reponer el mismo mensaje no lo duplica: actualiza la hora.
    put(&manager, "cta", "<a@x>", 9_000).await;
    let rows = store_api::followup_list_in(&manager, "cta").await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].remind_at, 9_000);
}

#[tokio::test]
async fn el_listado_sale_por_hora_de_aviso() {
    let (_t, manager) = store_with("seg-orden", &["cta"], &["cta"]).await;
    put(&manager, "cta", "<tarde@x>", 900).await;
    put(&manager, "cta", "<temprano@x>", 100).await;

    assert_eq!(ids(&manager, "cta").await, ["<temprano@x>", "<tarde@x>"]);
}

#[tokio::test]
async fn borrar_un_seguimiento_dice_si_habia_fila() {
    let (_t, manager) = store_with("seg-borrar", &["cta"], &["cta"]).await;
    put(&manager, "cta", "<a@x>", 100).await;
    put(&manager, "cta", "<b@x>", 200).await;

    assert!(store_api::followup_delete_in(&manager, "cta", "<a@x>")
        .await
        .unwrap());
    assert!(!store_api::followup_delete_in(&manager, "cta", "<a@x>")
        .await
        .unwrap());
    assert_eq!(ids(&manager, "cta").await, ["<b@x>"]);
}

#[tokio::test]
async fn una_cuenta_sin_almacen_da_error_y_no_una_lista_vacia() {
    let (_t, manager) = store_with("seg-sin-cuenta", &["cta"], &["cta"]).await;

    assert!(
        store_api::followup_upsert_in(&manager, "ajena", "<a@x>", "ana@x.com", 1)
            .await
            .is_err()
    );
    assert!(store_api::followup_list_in(&manager, "ajena")
        .await
        .is_err());
    assert!(store_api::followup_delete_in(&manager, "ajena", "<a@x>")
        .await
        .is_err());
}

#[tokio::test]
async fn los_vencidos_salen_ordenados_respetan_la_tanda_y_saltan_la_cuenta_apagada() {
    let (_t, manager) = store_with("seg-vencidos", &["a", "b", "off"], &["a", "b"]).await;
    put(&manager, "a", "<a3@x>", 300).await;
    put(&manager, "b", "<b1@x>", 100).await;
    put(&manager, "a", "<a2@x>", 200).await;
    put(&manager, "b", "<b-futuro@x>", 5_000).await; // todavía no vence
    put(&manager, "off", "<off@x>", 50).await; // cuenta apagada: se salta

    let all = store_api::followup_due_all_in(&manager, 1_000, 10).await;
    let order: Vec<(&str, &str)> = all
        .iter()
        .map(|(a, r)| (a.as_str(), r.message_id.as_str()))
        .collect();
    assert_eq!(order, [("b", "<b1@x>"), ("a", "<a2@x>"), ("a", "<a3@x>")]);

    // La tanda corta por el límite, quedándose con los más viejos.
    let batch = store_api::followup_due_all_in(&manager, 1_000, 2).await;
    let order: Vec<&str> = batch.iter().map(|(_, r)| r.message_id.as_str()).collect();
    assert_eq!(order, ["<b1@x>", "<a2@x>"]);

    // El borde es inclusivo: vence justo ahora.
    let at_the_edge = store_api::followup_due_all_in(&manager, 100, 10).await;
    assert_eq!(at_the_edge.len(), 1);
    assert!(store_api::followup_due_all_in(&manager, 10, 10)
        .await
        .is_empty());
}

#[tokio::test]
async fn el_proximo_aviso_es_el_mas_cercano_de_todas_las_cuentas() {
    let (_t, manager) = store_with("seg-proximo", &["a", "b", "off"], &["a", "b"]).await;
    assert_eq!(store_api::followup_next_after_in(&manager, 0).await, None);

    put(&manager, "a", "<a@x>", 500).await;
    put(&manager, "b", "<b@x>", 300).await;
    put(&manager, "off", "<off@x>", 150).await; // apagada: no cuenta

    assert_eq!(
        store_api::followup_next_after_in(&manager, 0).await,
        Some(300)
    );
    assert_eq!(
        store_api::followup_next_after_in(&manager, 300).await,
        Some(500)
    );
    assert_eq!(store_api::followup_next_after_in(&manager, 500).await, None);
}

/// Con el llavero bloqueado el almacén no se puede leer: el bucle no ve nada que
/// avisar ni techo de sueño (en vez de caerse), y las filas siguen al desbloquear.
#[tokio::test]
async fn con_el_llavero_bloqueado_no_hay_vencidos_y_al_desbloquear_siguen() {
    let keys = FakeKeys::default();
    let (_t, manager) = store_with_keys("seg-llavero", &["cta"], &["cta"], keys.clone()).await;
    put(&manager, "cta", "<a@x>", 100).await;

    keys.state().locked = true;
    assert!(store_api::followup_due_all_in(&manager, 1_000, 10)
        .await
        .is_empty());
    assert_eq!(store_api::followup_next_after_in(&manager, 0).await, None);
    assert!(store_api::followup_list_in(&manager, "cta").await.is_err());

    keys.state().locked = false;
    manager.refresh().await;
    assert_eq!(
        store_api::followup_due_all_in(&manager, 1_000, 10)
            .await
            .len(),
        1
    );
    assert_eq!(
        store_api::followup_next_after_in(&manager, 0).await,
        Some(100)
    );
}

/// Un error de lectura que no es «cerrado» ni «bloqueado» (acá, la tabla
/// desaparecida) va al diario y se salta esa cuenta: las otras se siguen leyendo.
#[tokio::test]
async fn si_una_cuenta_no_se_puede_leer_las_otras_siguen_y_nada_explota() {
    let (_t, manager) = store_with("seg-rota", &["rota", "sana"], &["rota", "sana"]).await;
    put(&manager, "rota", "<r@x>", 100).await;
    put(&manager, "sana", "<s@x>", 200).await;
    manager
        .with_store("rota", |store| {
            store
                .connection()
                .execute_batch("DROP TABLE followups")
                .map_err(|e| crate::store::StoreError::Sqlite(e.to_string()))
        })
        .await
        .unwrap();

    let due = store_api::followup_due_all_in(&manager, 1_000, 10).await;
    let order: Vec<&str> = due.iter().map(|(_, r)| r.message_id.as_str()).collect();
    assert_eq!(order, ["<s@x>"]);
    assert_eq!(
        store_api::followup_next_after_in(&manager, 0).await,
        Some(200)
    );
}

/// Las funciones libres, antes de que el servicio de almacén arranque (o sin
/// cuenta con correo): nada se anota, nada vence y nadie explota.
#[tokio::test]
async fn los_seguimientos_sin_almacen_no_hacen_nada_ni_fallan() {
    assert!(
        store_api::followup_upsert(ACCOUNT, "<a@x>", "ana@x.com", 1_000)
            .await
            .is_err()
    );
    assert!(store_api::followup_delete(ACCOUNT, "<a@x>").await.is_err());
    assert!(store_api::followup_list(ACCOUNT).await.is_err());
    assert!(store_api::followup_due_all(1_000, 50).await.is_empty());
    assert_eq!(store_api::followup_next_after(1_000).await, None);
}

// ---------------------------------------------------------------------------
// La forma del JSON
// ---------------------------------------------------------------------------

/// Lo que ve la ventana en `ListFollowups`: sólo las tres claves, con esos
/// nombres. El `id` de fila y el `created_at` son de adentro y no salen.
#[test]
fn un_seguimiento_se_serializa_con_las_claves_de_la_ventana_y_sin_las_internas() {
    let json = serde_json::to_value(row("<a@x>", 7_000)).unwrap();

    assert_eq!(
        json_keys(&json),
        ["destinatarios", "message_id", "recordar_en"]
    );
    assert_eq!(json["message_id"], "<a@x>");
    assert_eq!(json["destinatarios"], "ana@x.com");
    assert_eq!(json["recordar_en"], 7_000);
}

fn draft_from(json: &str) -> Draft {
    serde_json::from_str(json).unwrap()
}

/// Un borrador de antes del seguimiento (la cola vieja, o una ventana que no lo
/// manda) se lee igual: sin seguimiento.
#[test]
fn un_borrador_sin_el_campo_de_seguimiento_se_lee_sin_seguimiento() {
    let legacy = r#"{"de":"a@b.c","nombre":"","para":["d@e.f"],"cc":[],"asunto":"x","cuerpo":"y","en_respuesta_a":"","referencias":[],"adjuntos":[]}"#;

    assert_eq!(draft_from(legacy).followup_at, None);
}

#[test]
fn un_borrador_con_seguimiento_lo_lee_y_lo_escribe_con_el_nombre_del_bus() {
    let draft =
        draft_from(r#"{"para":["d@e.f"],"asunto":"x","cuerpo":"y","recordar_en":4102444800}"#);
    assert_eq!(draft.followup_at, Some(4_102_444_800));

    let json = serde_json::to_value(&draft).unwrap();
    assert_eq!(json["recordar_en"], 4_102_444_800_i64);
    let back: Draft = serde_json::from_value(json).unwrap();
    assert_eq!(back.followup_at, Some(4_102_444_800));
}

/// **La cola vieja no cambia de bytes**: sin seguimiento el campo no se escribe.
#[test]
fn sin_seguimiento_el_borrador_no_escribe_el_campo() {
    let draft = draft_from(r#"{"para":["d@e.f"],"asunto":"x","cuerpo":"y"}"#);

    let json = serde_json::to_value(&draft).unwrap();

    assert!(
        !json_keys(&json).contains(&"recordar_en".to_string()),
        "{json}"
    );
}

// ---------------------------------------------------------------------------
// El cartel
// ---------------------------------------------------------------------------

#[test]
fn el_cartel_dice_a_quien_se_le_escribio_y_nada_del_contenido() {
    let (title, body) = notifications::followup_text("ana@x.com, bo@x.com");

    assert_eq!(title, "Sin respuesta todavía");
    assert_eq!(body, "Tu mensaje a ana@x.com, bo@x.com sigue sin respuesta");
}

#[test]
fn sin_destinatarios_el_cartel_no_deja_un_hueco() {
    for recipients in ["", "   "] {
        let (_, body) = notifications::followup_text(recipients);
        assert_eq!(body, "Tu mensaje sigue sin respuesta", "«{recipients}»");
    }
}

#[test]
fn el_cartel_escapa_el_marcado_de_los_destinatarios() {
    let (_, body) = notifications::followup_text("<b>Ana</b> & co <ana@x.com>");

    assert!(!body.contains("<b>"), "{body}");
    assert!(
        body.contains("&lt;b&gt;Ana&lt;/b&gt; &amp; co &lt;ana@x.com&gt;"),
        "{body}"
    );
}

#[test]
fn un_destinatario_larguisimo_se_acorta_en_el_cartel() {
    let long = "a".repeat(5_000);

    let (_, body) = notifications::followup_text(&long);

    assert!(body.contains('…'), "no se acortó");
    assert!(body.len() < 1_000, "{} bytes", body.len());
}

/// La clave es propia de la cuenta y no pisa la del correo nuevo ni al revés; y
/// el botón «Ver» sigue andando porque `is_ours` mira todos los carteles.
#[test]
fn el_cartel_de_seguimiento_no_pisa_el_de_correo_nuevo_de_la_cuenta() {
    let key = notifications::followup_key("cta");
    assert_ne!(key, "cta");
    assert_ne!(key, notifications::followup_key("otra"));
    assert!(key.contains("cta"));

    let mut shown = ShownNotifications::default();
    shown.remember("cta", 9); // «llegaron N mensajes»
    shown.remember(&key, 5); // seguimiento

    assert_eq!(shown.previous("cta"), 9);
    assert_eq!(shown.previous(&key), 5);
    assert!(shown.is_ours(5) && shown.is_ours(9));
}

// ---------------------------------------------------------------------------
// D-Bus sin almacén: ListFollowups, CancelFollowup y el enganche de SendMessage
// ---------------------------------------------------------------------------

/// `ListFollowups` sin almacén dice que no está disponible; no devuelve una
/// lista vacía, que la ventana leería como «no hay seguimientos».
#[tokio::test]
async fn listar_seguimientos_sin_almacen_no_es_una_lista_vacia() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;

    let (name, text) = error_of(f.call("ListFollowups", &(ACCOUNT,)).await);

    assert_eq!(name, "org.freedesktop.DBus.Error.Failed");
    assert!(text.contains("el almacén no está disponible"), "{text}");
}

/// `CancelFollowup` sin almacén es un error y **no** `no_estaba`: no poder mirar
/// la cola no es lo mismo que no haber pedido nunca el seguimiento.
#[tokio::test]
async fn cancelar_un_seguimiento_sin_almacen_es_un_error_y_no_un_no_estaba() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;

    let (name, text) = error_of(f.call("CancelFollowup", &(ACCOUNT, "<a@x>")).await);

    assert_eq!(name, "org.freedesktop.DBus.Error.Failed");
    assert!(text.contains("el almacén no está disponible"), "{text}");
}

fn draft_json(followup_at: Option<i64>) -> String {
    let mut draft = serde_json::json!({
        "para": ["dest@otro.test", "otra@otro.test"],
        "cc": ["copia@otro.test"],
        "asunto": "Hola",
        "cuerpo": "Un mensaje.",
    });
    if let Some(at) = followup_at {
        draft["recordar_en"] = at.into();
    }
    draft.to_string()
}

async fn send(f: &Fixture, followup_at: Option<i64>) -> zbus::Result<zbus::Message> {
    f.call("SendMessage", &(ACCOUNT, draft_json(followup_at), ""))
        .await
}

fn queued() -> Vec<crate::outbox::Outgoing> {
    crate::outbox::Outbox::open(crate::outbox::outbox_dir())
        .unwrap()
        .all()
        .unwrap()
}

/// El recordatorio es secundario: si el almacén no está, el mensaje **se encola
/// igual** y la falla queda en el diario con el `Message-ID` que se le generó
/// (el mismo con el que se encoló, que es el que el seguimiento buscaría).
#[tokio::test]
async fn enviar_con_seguimiento_sin_almacen_encola_igual_y_deja_el_aviso_en_el_diario() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;

    send(&f, Some(4_102_444_800)).await.unwrap();

    let queue = queued();
    assert_eq!(queue.len(), 1, "el envío no se encoló");
    assert_eq!(queue[0].draft.followup_at, Some(4_102_444_800));
    let logs = captured_logs();
    assert!(
        logs.contains(&format!(
            "no se anotó el seguimiento de «{}»",
            queue[0].message_id
        )),
        "no quedó registrado con el Message-ID del envío: {logs}"
    );
}

/// Sin pedir seguimiento, `SendMessage` ni lo intenta.
#[tokio::test]
async fn enviar_sin_seguimiento_no_intenta_anotarlo() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;

    send(&f, None).await.unwrap();

    let queue = queued();
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].draft.followup_at, None);
    assert!(
        !captured_logs().contains("no se anotó el seguimiento"),
        "intentó anotar un seguimiento que nadie pidió"
    );
}

// ---------------------------------------------------------------------------
// Reader::check_followup contra un servidor IMAP de mentira
// ---------------------------------------------------------------------------

const MESSAGE_ID: &str = "<abc@x>";

fn examine() -> (&'static str, Vec<&'static str>) {
    (
        "EXAMINE \"INBOX\"",
        vec![
            "* 3 EXISTS",
            "* OK [UIDVALIDITY 1] ok",
            "{tag} OK [READ-ONLY] EXAMINE completado",
        ],
    )
}

fn references(found: &'static str) -> (&'static str, Vec<&'static str>) {
    (
        "HEADER References \"<abc@x>\"",
        vec![found, "{tag} OK SEARCH completado"],
    )
}

fn in_reply_to(found: &'static str) -> (&'static str, Vec<&'static str>) {
    (
        "HEADER In-Reply-To \"<abc@x>\"",
        vec![found, "{tag} OK SEARCH completado"],
    )
}

fn rejected(what: &'static str) -> (&'static str, Vec<&'static str>) {
    (what, vec!["{tag} NO servidor ocupado"])
}

async fn check(
    script: Vec<(&'static str, Vec<&'static str>)>,
) -> (Result<bool, String>, Vec<String>) {
    let (port, task) = imap_server("", script).await;
    let c = client(port).await;
    let reader = c.service.reader(ACCOUNT).await;
    let result = reader
        .lock()
        .await
        .check_followup(&c.broker, &c.account, MESSAGE_ID)
        .await;
    (result, finish(task).await)
}

/// Una respuesta que lo cita en `References` es una respuesta. Se abre la casilla
/// en **solo lectura** (`EXAMINE`): sólo se busca.
#[tokio::test]
async fn si_una_respuesta_lo_cita_en_references_hubo_respuesta() {
    let (result, received) = check(vec![examine(), references("* SEARCH 9")]).await;

    assert_eq!(result, Ok(true));
    let sent = after_open(&received);
    assert!(sent[0].starts_with("EXAMINE"), "{sent:?}");
    assert!(sent[1].contains("SEARCH"), "{sent:?}");
}

/// Y una que sólo lo cita en `In-Reply-To` también: hay **dos** búsquedas, no
/// una. Con sólo `References` esta respuesta se perdería y se avisaría «sin
/// respuesta» habiéndola.
#[tokio::test]
async fn si_una_respuesta_lo_cita_en_in_reply_to_hubo_respuesta() {
    let (result, received) = check(vec![
        examine(),
        references("* SEARCH"),
        in_reply_to("* SEARCH 12"),
    ])
    .await;

    assert_eq!(result, Ok(true));
    assert_eq!(after_open(&received).len(), 3, "{received:?}");
}

/// La búsqueda anduvo y las dos volvieron vacías: no hubo respuesta.
#[tokio::test]
async fn si_ninguna_de_las_dos_busquedas_encuentra_nada_no_hubo_respuesta() {
    let (result, received) = check(vec![
        examine(),
        references("* SEARCH"),
        in_reply_to("* SEARCH"),
    ])
    .await;

    assert_eq!(result, Ok(false));
    assert_eq!(after_open(&received).len(), 3, "{received:?}");
}

/// Sin INBOX no se puede comprobar nada: es un fallo, **no** «sin respuesta».
#[tokio::test]
async fn sin_bandeja_de_entrada_la_comprobacion_falla() {
    let (result, _) = check(vec![(
        "EXAMINE \"INBOX\"",
        vec!["{tag} NO [NONEXISTENT] no hay INBOX"],
    )])
    .await;

    assert!(result.is_err(), "dio {result:?}");
}

/// Una búsqueda que el servidor rechaza es un fallo, no un vacío: si fuera
/// `Ok(false)` se avisaría «sin respuesta» sólo porque el servidor estaba
/// ocupado. Vale para cada una de las dos.
#[tokio::test]
async fn una_busqueda_rechazada_es_un_fallo_y_no_un_sin_respuesta() {
    let (first, _) = check(vec![examine(), rejected("HEADER References")]).await;
    assert!(first.is_err(), "References: dio {first:?}");

    let (second, _) = check(vec![
        examine(),
        references("* SEARCH"),
        rejected("HEADER In-Reply-To"),
    ])
    .await;
    assert!(second.is_err(), "In-Reply-To: dio {second:?}");
}

/// Con el servidor caído (nadie escucha en el puerto) también es un fallo.
#[tokio::test]
async fn con_el_servidor_caido_la_comprobacion_falla() {
    let port = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let c = client(port).await;

    let result = c.service.check_followup(ACCOUNT, MESSAGE_ID).await;

    assert!(result.is_err(), "dio {result:?}");
}

/// Y con una cuenta que ya no existe, con el motivo.
#[tokio::test]
async fn comprobar_el_seguimiento_de_una_cuenta_que_ya_no_existe_da_error() {
    let _f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;

    let error = crate::Service::default()
        .check_followup("borrada", MESSAGE_ID)
        .await
        .unwrap_err();

    assert!(error.contains("ya no existe"), "{error}");
}

/// `Service::check_followup` llega por la conexión de lectura de la cuenta.
#[tokio::test]
async fn el_servicio_comprueba_el_seguimiento_por_imap() {
    let (port, task) = imap_server("", vec![examine(), references("* SEARCH 4")]).await;
    let c = client(port).await;

    assert_eq!(
        c.service.check_followup(ACCOUNT, MESSAGE_ID).await,
        Ok(true)
    );
    finish(task).await;
}

// ---------------------------------------------------------------------------
// El productor del bucle, de punta a punta: IMAP de mentira + cartel
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Shown {
    app_name: String,
    replaces: u32,
    title: String,
    body: String,
    actions: Vec<String>,
}

/// El servidor de notificaciones de mentira: anota lo que se le muestra y
/// anuncia (o no) la capacidad `actions`.
struct FakeNotifications {
    shown: Arc<StdMutex<Vec<Shown>>>,
    actions: bool,
}

#[zbus::interface(name = "org.freedesktop.Notifications")]
impl FakeNotifications {
    async fn get_capabilities(&self) -> Vec<String> {
        if self.actions {
            vec!["actions".into(), "body".into()]
        } else {
            vec!["body".into()]
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn notify(
        &self,
        app_name: String,
        replaces_id: u32,
        _app_icon: String,
        summary: String,
        body: String,
        actions: Vec<String>,
        _hints: HashMap<String, OwnedValue>,
        _expire_timeout: i32,
    ) -> u32 {
        self.shown.lock().unwrap().push(Shown {
            app_name,
            replaces: replaces_id,
            title: summary,
            body,
            actions,
        });
        88
    }
}

/// Una conexión punto a punta con el servidor de notificaciones de mentira, que
/// es la que usa el cartel (la del bus de sesión no tiene ninguno).
async fn notification_server(actions: bool) -> (zbus::Connection, Arc<StdMutex<Vec<Shown>>>) {
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

    let shown = Arc::new(StdMutex::new(Vec::new()));
    server
        .object_server()
        .at(
            "/org/freedesktop/Notifications",
            FakeNotifications {
                shown: Arc::clone(&shown),
                actions,
            },
        )
        .await
        .unwrap();
    // El servidor tiene que seguir vivo mientras dure la prueba.
    std::mem::forget(server);
    (client, shown)
}

async fn notifier(
    c: &crate::snooze_tests::Client,
    actions: bool,
) -> (ServiceFollowupNotifier, Arc<StdMutex<Vec<Shown>>>) {
    let (connection, shown) = notification_server(actions).await;
    (
        ServiceFollowupNotifier {
            service: c.service.clone(),
            connection,
        },
        shown,
    )
}

fn no_reply_script() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![examine(), references("* SEARCH"), in_reply_to("* SEARCH")]
}

/// Sin respuesta: el cartel sale con el texto del seguimiento, a nombre del
/// correo y con el botón «Ver»; y queda registrado como nuestro (para que «Ver»
/// abra el correo).
#[tokio::test]
async fn sin_respuesta_el_productor_muestra_el_cartel_con_el_boton_ver() {
    let (port, task) = imap_server("", no_reply_script()).await;
    let c = client(port).await;
    let (notifier, shown) = notifier(&c, true).await;

    notifier.notify_due(ACCOUNT, &row(MESSAGE_ID, 100)).await;

    finish(task).await;
    let shown = shown.lock().unwrap().clone();
    assert_eq!(shown.len(), 1, "{shown:?}");
    assert_eq!(shown[0].app_name, notifications::MAIL_APP_NAME);
    assert_eq!(shown[0].title, "Sin respuesta todavía");
    assert_eq!(shown[0].body, "Tu mensaje a ana@x.com sigue sin respuesta");
    assert_eq!(shown[0].actions, [notifications::OPEN_ACTION, "Ver"]);
    assert!(c.service.shown_notifications.lock().await.is_ours(88));
}

/// El servidor de notificaciones que no sabe dibujar botones recibe el cartel
/// sin pedírselos.
#[tokio::test]
async fn sin_soporte_de_botones_el_cartel_va_sin_boton() {
    let (port, task) = imap_server("", no_reply_script()).await;
    let c = client(port).await;
    let (notifier, shown) = notifier(&c, false).await;

    notifier.notify_due(ACCOUNT, &row(MESSAGE_ID, 100)).await;

    finish(task).await;
    let shown = shown.lock().unwrap().clone();
    assert_eq!(shown.len(), 1);
    assert!(shown[0].actions.is_empty(), "{:?}", shown[0].actions);
}

/// El segundo seguimiento de la cuenta reemplaza al primer cartel de
/// seguimiento, y con su clave propia: el cartel de correo nuevo de la misma
/// cuenta ni se entera.
#[tokio::test]
async fn el_segundo_cartel_reemplaza_al_de_seguimiento_y_no_toca_el_de_correo_nuevo() {
    let mut script = no_reply_script();
    script.extend(no_reply_script());
    let (port, task) = imap_server("", script).await;
    let c = client(port).await;
    let (notifier, shown) = notifier(&c, true).await;

    notifier.notify_due(ACCOUNT, &row(MESSAGE_ID, 100)).await;
    notifier.notify_due(ACCOUNT, &row(MESSAGE_ID, 100)).await;

    finish(task).await;
    let shown = shown.lock().unwrap().clone();
    assert_eq!(shown.len(), 2);
    assert_eq!(shown[0].replaces, 0);
    assert_eq!(shown[1].replaces, 88, "no reemplazó al cartel anterior");
    assert_eq!(
        c.service.shown_notifications.lock().await.previous(ACCOUNT),
        0,
        "pisó la clave del cartel de correo nuevo"
    );
}

/// Con respuesta no se avisa nada.
#[tokio::test]
async fn con_respuesta_el_productor_no_muestra_ningun_cartel() {
    let (port, task) = imap_server("", vec![examine(), references("* SEARCH 9")]).await;
    let c = client(port).await;
    let (notifier, shown) = notifier(&c, true).await;

    notifier.notify_due(ACCOUNT, &row(MESSAGE_ID, 100)).await;

    finish(task).await;
    assert!(shown.lock().unwrap().is_empty());
}

/// Si el servidor no contesta no se avisa «sin respuesta»: la fila queda para la
/// próxima vuelta (acá no hay almacén, así que lo observable es que no hay
/// cartel).
#[tokio::test]
async fn si_el_servidor_falla_el_productor_no_muestra_ningun_cartel() {
    let (port, task) = imap_server("", vec![examine(), rejected("HEADER References")]).await;
    let c = client(port).await;
    let (notifier, shown) = notifier(&c, true).await;

    notifier.notify_due(ACCOUNT, &row(MESSAGE_ID, 100)).await;

    finish(task).await;
    assert!(shown.lock().unwrap().is_empty());
}
