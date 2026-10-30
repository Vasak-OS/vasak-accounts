//! Posponer mensajes (`vasak-accounts#22`): **los cuerpos que sí tienen
//! almacén**. `snooze_tests.rs` prueba el camino sin almacén (el global
//! `LIVE_STORE` sólo lo fija el arranque del servicio); acá se ejercen los
//! cores genéricos que reciben el `StoreManager` por parámetro, con el llavero
//! falso y una base real en un directorio temporal, y se mira el resultado
//! leyendo el almacén y no el valor que devuelve la función.

use crate::broker::Account;
use crate::imap::MoveOutcome;
use crate::store::key::fake::FakeKeys;
use crate::store::lifecycle::{Consent, Locations, StoreManager, EMAIL_AREA};
use crate::store::paths::tests::TempDir;
use crate::store::snooze::SnoozedMessage;
use crate::store_api::{self, listing_from};
use crate::{apply_return_in, cancel_snooze_in, drop_inbox_message, snooze_commit_in, State};
use std::time::Instant;

fn account(id: &str) -> Account {
    Account {
        id: id.into(),
        display_name: id.into(),
        provider_type: "custom".into(),
        capabilities: vec!["email".into()],
        needs_reauth: false,
    }
}

/// Un almacén de prueba con las cuentas dadas. Las de `active` tienen el área de
/// correo encendida (las que el bucle de vuelta recorre); las otras existen pero
/// están apagadas. El directorio vive mientras viva el almacén.
pub(crate) async fn store_with(
    label: &str,
    accounts: &[&str],
    active: &[&str],
) -> (TempDir, StoreManager<FakeKeys>) {
    store_with_keys(label, accounts, active, FakeKeys::default()).await
}

/// Lo mismo con el llavero falso en mano, para poder bloquearlo.
pub(crate) async fn store_with_keys(
    label: &str,
    accounts: &[&str],
    active: &[&str],
    keys: FakeKeys,
) -> (TempDir, StoreManager<FakeKeys>) {
    let temp = TempDir::new(label);
    let manager = StoreManager::new(
        keys,
        Ok(Locations {
            stores: temp.0.join("stores"),
            settings: temp.0.join("stores.json"),
        }),
    );
    let listed: Vec<Account> = accounts.iter().map(|id| account(id)).collect();
    manager
        .accounts_listed(listing_from(&Ok(listed)), Instant::now())
        .await;
    for id in active {
        assert!(manager
            .activate_area(EMAIL_AREA, id, Consent::Granted)
            .await
            .unwrap());
    }
    (temp, manager)
}

async fn snoozed(manager: &StoreManager<FakeKeys>, account_id: &str) -> Vec<SnoozedMessage> {
    store_api::snooze_list_in(manager, account_id)
        .await
        .unwrap()
}

async fn put(manager: &StoreManager<FakeKeys>, account_id: &str, message_id: &str, at: i64) {
    store_api::snooze_upsert_in(
        manager,
        account_id,
        message_id,
        "INBOX",
        Some(5),
        Some(9),
        at,
    )
    .await
    .unwrap();
}

// ---------------------------------------------------------------------------
// store_api: los cuerpos sobre un almacén dado
// ---------------------------------------------------------------------------

#[tokio::test]
async fn con_almacen_el_pospuesto_se_anota_y_se_lista() {
    let (_t, manager) = store_with("snooze-anotar", &["cta"], &["cta"]).await;
    assert!(store_api::snooze_store_ready_in(&manager, "cta").await);
    assert!(snoozed(&manager, "cta").await.is_empty());

    store_api::snooze_upsert_in(&manager, "cta", "<a@x>", "Trabajo", Some(7), Some(3), 5_000)
        .await
        .unwrap();

    let rows = snoozed(&manager, "cta").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].message_id, "<a@x>");
    assert_eq!(rows[0].origin_mailbox, "Trabajo");
    assert_eq!(rows[0].new_uid, Some(7));
    assert_eq!(rows[0].uidvalidity, Some(3));
    assert_eq!(rows[0].return_at, 5_000);

    // Reponer el mismo mensaje no lo duplica: actualiza la hora.
    put(&manager, "cta", "<a@x>", 9_000).await;
    let rows = snoozed(&manager, "cta").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].return_at, 9_000);
}

#[tokio::test]
async fn un_almacen_sin_esa_cuenta_no_esta_listo_ni_deja_anotar() {
    let (_t, manager) = store_with("snooze-sin-cuenta", &["cta"], &["cta"]).await;

    assert!(!store_api::snooze_store_ready_in(&manager, "ajena").await);
    assert!(
        store_api::snooze_upsert_in(&manager, "ajena", "<a@x>", "INBOX", None, None, 1)
            .await
            .is_err()
    );
    assert!(store_api::snooze_list_in(&manager, "ajena").await.is_err());
}

#[tokio::test]
async fn borrar_un_pospuesto_dice_si_habia_fila() {
    let (_t, manager) = store_with("snooze-borrar", &["cta"], &["cta"]).await;
    put(&manager, "cta", "<a@x>", 100).await;
    put(&manager, "cta", "<b@x>", 200).await;

    assert!(store_api::snooze_delete_in(&manager, "cta", "<a@x>")
        .await
        .unwrap());
    assert!(!store_api::snooze_delete_in(&manager, "cta", "<a@x>")
        .await
        .unwrap());

    let left: Vec<String> = snoozed(&manager, "cta")
        .await
        .into_iter()
        .map(|r| r.message_id)
        .collect();
    assert_eq!(left, ["<b@x>"]);
}

#[tokio::test]
async fn los_vencidos_salen_ordenados_por_hora_y_respetan_la_tanda() {
    let (_t, manager) = store_with("snooze-vencidos", &["a", "b", "off"], &["a", "b"]).await;
    put(&manager, "a", "<a3@x>", 300).await;
    put(&manager, "b", "<b1@x>", 100).await;
    put(&manager, "a", "<a2@x>", 200).await;
    put(&manager, "b", "<b-futuro@x>", 5_000).await; // todavía no vence
    put(&manager, "off", "<off@x>", 50).await; // cuenta apagada: se salta

    let all = store_api::snooze_due_all_in(&manager, 1_000, 10).await;
    let order: Vec<(&str, &str)> = all
        .iter()
        .map(|(a, r)| (a.as_str(), r.message_id.as_str()))
        .collect();
    assert_eq!(order, [("b", "<b1@x>"), ("a", "<a2@x>"), ("a", "<a3@x>")]);

    // La tanda corta por el límite, quedándose con los más viejos.
    let batch = store_api::snooze_due_all_in(&manager, 1_000, 2).await;
    let order: Vec<&str> = batch.iter().map(|(_, r)| r.message_id.as_str()).collect();
    assert_eq!(order, ["<b1@x>", "<a2@x>"]);

    assert!(store_api::snooze_due_all_in(&manager, 10, 10)
        .await
        .is_empty());
}

#[tokio::test]
async fn el_proximo_pospuesto_es_el_mas_cercano_de_todas_las_cuentas() {
    let (_t, manager) = store_with("snooze-proximo", &["a", "b", "off"], &["a", "b"]).await;
    assert_eq!(store_api::snooze_next_after_in(&manager, 0).await, None);

    put(&manager, "a", "<a@x>", 500).await;
    put(&manager, "b", "<b@x>", 300).await;
    put(&manager, "off", "<off@x>", 150).await; // apagada: no cuenta

    assert_eq!(
        store_api::snooze_next_after_in(&manager, 0).await,
        Some(300)
    );
    assert_eq!(
        store_api::snooze_next_after_in(&manager, 300).await,
        Some(500)
    );
    assert_eq!(store_api::snooze_next_after_in(&manager, 500).await, None);
}

/// Con el llavero bloqueado el almacén no se puede leer: el bucle de vuelta no
/// ve nada que devolver ni techo de sueño (en vez de caerse), y la cuenta no
/// está lista para posponer. Cuando se desbloquea, las filas siguen ahí.
#[tokio::test]
async fn con_el_llavero_bloqueado_no_hay_vencidos_y_al_desbloquear_siguen() {
    let keys = FakeKeys::default();
    let (_t, manager) = store_with_keys("snooze-bloqueado", &["cta"], &["cta"], keys.clone()).await;
    put(&manager, "cta", "<a@x>", 100).await;

    keys.state().locked = true;
    assert!(!store_api::snooze_store_ready_in(&manager, "cta").await);
    assert!(store_api::snooze_due_all_in(&manager, 1_000, 10)
        .await
        .is_empty());
    assert_eq!(store_api::snooze_next_after_in(&manager, 0).await, None);

    // Al desbloquear, la tabla de almacenes reabre la base (como al cambiar el
    // llavero en producción).
    keys.state().locked = false;
    manager.refresh().await;
    assert_eq!(
        store_api::snooze_due_all_in(&manager, 1_000, 10)
            .await
            .len(),
        1
    );
    assert_eq!(
        store_api::snooze_next_after_in(&manager, 0).await,
        Some(100)
    );
}

// ---------------------------------------------------------------------------
// main.rs: snooze_commit_in
// ---------------------------------------------------------------------------

#[tokio::test]
async fn al_mover_completo_la_fila_queda_en_el_almacen() {
    let (_t, manager) = store_with("commit-ok", &["cta"], &["cta"]).await;

    snooze_commit_in(
        &manager,
        "cta",
        "INBOX",
        42,
        "<m@x>",
        &MoveOutcome::Complete {
            new_uid: Some(77),
            uidvalidity: Some(4),
        },
        8_000,
    )
    .await
    .unwrap();

    let rows = snoozed(&manager, "cta").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].message_id, "<m@x>");
    assert_eq!(rows[0].origin_mailbox, "INBOX");
    assert_eq!(rows[0].new_uid, Some(77));
    assert_eq!(rows[0].uidvalidity, Some(4));
    assert_eq!(rows[0].return_at, 8_000);
}

#[tokio::test]
async fn si_el_servidor_dejo_copia_en_el_origen_no_se_pospone() {
    let (_t, manager) = store_with("commit-copia", &["cta"], &["cta"]).await;

    let error = snooze_commit_in(
        &manager,
        "cta",
        "INBOX",
        42,
        "<m@x>",
        &MoveOutcome::OldCopyKept,
        8_000,
    )
    .await
    .unwrap_err();

    assert!(error.contains("no se pospuso"), "{error}");
    assert!(snoozed(&manager, "cta").await.is_empty());
}

#[tokio::test]
async fn si_no_se_puede_anotar_la_fila_el_error_lo_dice() {
    let (_t, manager) = store_with("commit-sin-fila", &["cta"], &["cta"]).await;

    let error = snooze_commit_in(
        &manager,
        "ajena",
        "INBOX",
        42,
        "<m@x>",
        &MoveOutcome::Complete {
            new_uid: None,
            uidvalidity: None,
        },
        8_000,
    )
    .await
    .unwrap_err();

    assert!(
        error.contains("se movió a pospuestos pero no se pudo registrar"),
        "{error}"
    );
}

// ---------------------------------------------------------------------------
// main.rs: drop_inbox_message
// ---------------------------------------------------------------------------

fn summary(uid: u32) -> crate::message::MessageSummary {
    crate::message::MessageSummary {
        uid,
        ..Default::default()
    }
}

fn state_with_inbox(uids: &[u32]) -> State {
    let mut state = State::default();
    state
        .messages
        .insert("cta".into(), uids.iter().map(|u| summary(*u)).collect());
    state
}

fn uids(state: &State) -> Vec<u32> {
    state.messages["cta"].iter().map(|m| m.uid).collect()
}

#[test]
fn el_mensaje_que_sale_de_la_entrada_desaparece_de_la_lista_y_avisa() {
    let mut state = state_with_inbox(&[1, 2, 3]);

    assert!(drop_inbox_message(&mut state, "cta", "INBOX", 2));
    assert_eq!(uids(&state), [1, 3]);

    // La casilla de entrada se reconoce sin mirar mayúsculas.
    assert!(drop_inbox_message(&mut state, "cta", "inbox", 3));
    assert_eq!(uids(&state), [1]);
}

#[test]
fn el_mensaje_de_otra_casilla_no_toca_la_lista_ni_avisa() {
    let mut state = state_with_inbox(&[1, 2, 3]);

    assert!(!drop_inbox_message(&mut state, "cta", "Trabajo", 2));
    assert_eq!(
        uids(&state),
        [1, 2, 3],
        "el uid 2 de otra casilla no es el de la entrada"
    );
}

#[test]
fn sacar_de_una_cuenta_sin_lista_no_falla() {
    let mut state = State::default();

    assert!(drop_inbox_message(&mut state, "sin-lista", "INBOX", 1));
    assert!(state.messages.is_empty());
}

// ---------------------------------------------------------------------------
// main.rs: cancel_snooze_in
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cancelar_lo_que_no_estaba_pospuesto_no_mueve_nada() {
    let (_t, manager) = store_with("cancel-nada", &["cta"], &["cta"]).await;
    put(&manager, "cta", "<otro@x>", 100).await;

    let outcome = cancel_snooze_in(&manager, "cta", "<m@x>", |_| async {
        panic!("sin fila no hay nada que devolver")
    })
    .await
    .unwrap();

    assert_eq!(outcome, "no_estaba");
    assert_eq!(
        snoozed(&manager, "cta").await.len(),
        1,
        "la fila ajena sigue"
    );
}

#[tokio::test]
async fn cancelar_devuelve_el_mensaje_a_su_casilla_y_borra_la_fila() {
    let (_t, manager) = store_with("cancel-devuelto", &["cta"], &["cta"]).await;
    put(&manager, "cta", "<m@x>", 100).await;
    put(&manager, "cta", "<otro@x>", 200).await;

    let outcome = cancel_snooze_in(&manager, "cta", "<m@x>", |row| async move {
        assert_eq!(row.message_id, "<m@x>");
        assert_eq!(row.new_uid, Some(5));
        Ok(true)
    })
    .await
    .unwrap();

    assert_eq!(outcome, "devuelto");
    let left: Vec<String> = snoozed(&manager, "cta")
        .await
        .into_iter()
        .map(|r| r.message_id)
        .collect();
    assert_eq!(left, ["<otro@x>"], "sólo se va la fila cancelada");
}

#[tokio::test]
async fn cancelar_lo_que_ya_no_estaba_en_pospuestos_tambien_borra_la_fila() {
    let (_t, manager) = store_with("cancel-ya-no", &["cta"], &["cta"]).await;
    put(&manager, "cta", "<m@x>", 100).await;

    let outcome = cancel_snooze_in(&manager, "cta", "<m@x>", |_| async { Ok(false) })
        .await
        .unwrap();

    assert_eq!(outcome, "ya_no_estaba");
    assert!(snoozed(&manager, "cta").await.is_empty());
}

#[tokio::test]
async fn si_no_se_pudo_devolver_la_fila_se_conserva_para_reintentar() {
    let (_t, manager) = store_with("cancel-error", &["cta"], &["cta"]).await;
    put(&manager, "cta", "<m@x>", 100).await;

    let error = cancel_snooze_in(&manager, "cta", "<m@x>", |_| async {
        Err("el servidor no contesta".to_string())
    })
    .await
    .unwrap_err();

    assert_eq!(error, "el servidor no contesta");
    assert_eq!(snoozed(&manager, "cta").await.len(), 1);
}

#[tokio::test]
async fn cancelar_con_el_almacen_caido_es_un_error_y_no_un_no_estaba() {
    let (_t, manager) = store_with("cancel-caido", &["cta"], &["cta"]).await;

    let result = cancel_snooze_in(&manager, "ajena", "<m@x>", |_| async { Ok(true) }).await;

    assert!(result.is_err(), "no poder mirar la cola no es «no estaba»");
}

// ---------------------------------------------------------------------------
// main.rs: apply_return_in (el productor del bucle de vuelta)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn devuelto_el_pospuesto_su_fila_se_borra() {
    let (_t, manager) = store_with("return-ok", &["cta"], &["cta"]).await;
    put(&manager, "cta", "<m@x>", 100).await;
    put(&manager, "cta", "<otro@x>", 200).await;

    apply_return_in(Some(&manager), "cta", "<m@x>", Ok(true)).await;

    let left: Vec<String> = snoozed(&manager, "cta")
        .await
        .into_iter()
        .map(|r| r.message_id)
        .collect();
    assert_eq!(left, ["<otro@x>"]);
}

#[tokio::test]
async fn si_ya_no_estaba_en_pospuestos_tambien_se_borra_la_fila() {
    let (_t, manager) = store_with("return-ya-no", &["cta"], &["cta"]).await;
    put(&manager, "cta", "<m@x>", 100).await;

    apply_return_in(Some(&manager), "cta", "<m@x>", Ok(false)).await;

    assert!(snoozed(&manager, "cta").await.is_empty());
}

#[tokio::test]
async fn si_la_vuelta_falla_la_fila_queda_para_la_proxima() {
    let (_t, manager) = store_with("return-error", &["cta"], &["cta"]).await;
    put(&manager, "cta", "<m@x>", 100).await;

    apply_return_in(Some(&manager), "cta", "<m@x>", Err("sin red".into())).await;

    assert_eq!(snoozed(&manager, "cta").await.len(), 1);
}

#[tokio::test]
async fn sin_almacen_la_vuelta_exitosa_no_explota() {
    apply_return_in::<FakeKeys>(None, "cta", "<m@x>", Ok(true)).await;
}
