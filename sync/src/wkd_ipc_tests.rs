//! `ResolveRecipientKey` (`vasak-accounts#21`, PR6): la puerta de permisos y las
//! respuestas de error por D-Bus, de punta a punta (calca `pgp_ipc_tests`), y la
//! lógica pura que arma el estado de clave (`pgp_key_state`, `resolve_key_json`).
//!
//! Lo que **no** se ejerce por el bus: las ramas peerstate y WKD del método. El
//! almacén lo da `store_api::live_store()`, un global que sólo fija el arranque del
//! servicio, y el cliente WKD resuelve DNS y conecta por HTTPS (a loopback lo veta, a
//! propósito). Esas ramas se cubren por sus piezas: el estado y el JSON acá, el
//! peerstate con un almacén real, y el veto de red en `wkd::tests`.

use crate::access::tests::Answer;
use crate::ipc_test_support::short_name;
use crate::pgp::tests::{
    clave_completa, clave_vieja, con_primaria_con_vencimiento_en_el_uid, con_primaria_revocada,
    generar, publica, subclave_de_firma,
};
use crate::pgp_send_tests::{ACCOUNT, ADDRESS};
use crate::test_bus::{error_of, Fixture};
use crate::{pgp_key_state, resolve_key_json, PgpKeyState};
use pgp::ser::Serialize;

const DESTINATARIO: &str = "beto@vasak.test";

async fn resolve(f: &Fixture, address: &str) -> zbus::Result<zbus::Message> {
    f.call("ResolveRecipientKey", &(ACCOUNT, address)).await
}

fn bytes_of(key: &pgp::composed::SignedPublicKey) -> Vec<u8> {
    key.to_bytes().unwrap()
}

fn json(source: &str, state: PgpKeyState) -> serde_json::Value {
    serde_json::from_str(&resolve_key_json(source, state).unwrap()).unwrap()
}

// ── La puerta de permisos ───────────────────────────────────────────────

#[tokio::test]
async fn resolver_sin_permiso_da_accessdenied() {
    let f = Fixture::start_with_permission(&[(ACCOUNT, ADDRESS)], Answer::Deny).await;
    assert_eq!(short_name(resolve(&f, DESTINATARIO).await), "AccessDenied");
}

#[tokio::test]
async fn resolver_con_el_servicio_de_permisos_caido_da_accessdenied() {
    // Falla cerrado: no poder preguntar es no tener permiso.
    let f = Fixture::start_with_permission(&[(ACCOUNT, ADDRESS)], Answer::Fail).await;
    assert_eq!(short_name(resolve(&f, DESTINATARIO).await), "AccessDenied");
}

#[tokio::test]
async fn sin_permiso_no_se_llega_ni_a_validar_la_direccion() {
    // Una dirección vacía con permiso da `Failed`; sin permiso tiene que dar
    // `AccessDenied`: la puerta va antes que cualquier otra comprobación (y que la red).
    let f = Fixture::start_with_permission(&[(ACCOUNT, ADDRESS)], Answer::Deny).await;
    assert_eq!(short_name(resolve(&f, "   ").await), "AccessDenied");
}

// ── Lo que pasa con permiso ─────────────────────────────────────────────

#[tokio::test]
async fn una_direccion_vacia_tras_normalizar_da_failed() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;
    let (name, text) = error_of(resolve(&f, "   ").await);
    assert_eq!(name.rsplit('.').next().unwrap(), "Failed");
    assert!(text.contains("vacía"), "{text}");
}

#[tokio::test]
async fn sin_almacen_vivo_da_failed_y_no_toca_la_red() {
    // En las pruebas `live_store()` es `None` (lo fija sólo el arranque).
    assert!(crate::store_api::live_store().is_none());
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;
    let (name, text) = error_of(resolve(&f, DESTINATARIO).await);
    assert_eq!(name.rsplit('.').next().unwrap(), "Failed");
    assert!(text.contains("almacén"), "{text}");
}

// ── El estado de la clave ───────────────────────────────────────────────

#[test]
fn una_clave_con_subclave_de_cifrado_viva_esta_presente() {
    let secret = clave_completa("Beto <beto@vasak.test>");
    let key = publica(&secret);
    let state = pgp_key_state(&bytes_of(&key));
    assert!(state.present);
    assert!(!state.expired && !state.revoked);
    assert_eq!(
        state.fingerprint.as_deref(),
        Some(crate::pgp::fingerprint(&key).as_str())
    );
}

#[test]
fn una_clave_solo_de_firma_existe_pero_no_esta_presente() {
    let secret = generar("Beto <beto@vasak.test>", vec![subclave_de_firma()]);
    let key = publica(&secret);
    let state = pgp_key_state(&bytes_of(&key));
    assert!(!state.present, "no hay a qué cifrar");
    assert!(state.fingerprint.is_some());
    assert!(!state.expired && !state.revoked);
}

#[test]
fn una_clave_guardada_que_hoy_esta_expirada_no_esta_presente_y_dice_expired() {
    let vivo = clave_vieja("Beto <beto@vasak.test>");
    let key = con_primaria_con_vencimiento_en_el_uid(&vivo, 24 * 3600);
    let state = pgp_key_state(&bytes_of(&key));
    assert!(!state.present);
    assert!(state.expired);
    assert!(!state.revoked);
    assert!(state.fingerprint.is_some());
}

#[test]
fn una_clave_revocada_no_esta_presente_y_dice_revoked() {
    let vivo = clave_vieja("Beto <beto@vasak.test>");
    let key = con_primaria_revocada(&vivo);
    let state = pgp_key_state(&bytes_of(&key));
    assert!(!state.present);
    assert!(state.revoked);
    assert!(!state.expired, "revocada manda sobre expirada");
}

#[test]
fn bytes_que_no_son_una_clave_dan_sin_clave_sin_filtrar_el_motivo() {
    let state = pgp_key_state(b"esto no es una clave");
    assert!(!state.present && !state.expired && !state.revoked);
    assert!(state.fingerprint.is_none());
}

// ── El JSON ─────────────────────────────────────────────────────────────

#[test]
fn el_json_lleva_exactamente_los_cinco_campos_de_la_interfaz() {
    let v = json(
        "peerstate",
        PgpKeyState {
            present: true,
            fingerprint: Some("ABCD".into()),
            expired: false,
            revoked: false,
        },
    );
    let mut campos: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
    campos.sort();
    assert_eq!(
        campos,
        ["expired", "fingerprint", "present", "revoked", "source"]
    );
    assert_eq!(v["source"], "peerstate");
    assert_eq!(v["present"], true);
    assert_eq!(v["fingerprint"], "ABCD");
}

#[test]
fn sin_huella_la_fuente_se_degrada_a_none_y_la_huella_es_null() {
    // No decir «peerstate» o «wkd» cuando no hay clave que mostrar.
    for fuente in ["peerstate", "wkd", "none"] {
        let v = json(fuente, PgpKeyState::absent());
        assert_eq!(v["source"], "none", "{fuente}");
        assert_eq!(v["present"], false);
        assert!(v["fingerprint"].is_null());
        assert_eq!(v["expired"], false);
        assert_eq!(v["revoked"], false);
    }
}

#[test]
fn una_clave_muerta_conserva_la_fuente_y_la_huella() {
    let v = json(
        "peerstate",
        PgpKeyState {
            present: false,
            fingerprint: Some("ABCD".into()),
            expired: true,
            revoked: false,
        },
    );
    assert_eq!(v["source"], "peerstate");
    assert_eq!(v["present"], false);
    assert_eq!(v["expired"], true);
}

// ── Peerstate real: lo que guarda WKD lo ve la 2ª llamada como peerstate ─

#[test]
fn la_clave_guardada_por_wkd_se_relee_del_peerstate_con_la_misma_huella() {
    use crate::store::contacts::tests::open_store;
    use crate::store::paths::tests::TempDir;

    let temp = TempDir::new("wkd-peerstate");
    let store = open_store(&temp);
    let key = publica(&clave_completa("Beto <beto@vasak.test>"));
    let bytes = bytes_of(&key);

    // Lo mismo que hace el método tras un acierto de WKD.
    crate::pgp_import::ingest_peer_key(&store, DESTINATARIO, &bytes, 1_000).unwrap();

    let peer = store
        .find_peer(DESTINATARIO)
        .unwrap()
        .expect("quedó guardada");
    let v = json("peerstate", pgp_key_state(&peer.public_key));
    assert_eq!(v["source"], "peerstate");
    assert_eq!(v["present"], true);
    assert_eq!(v["fingerprint"], crate::pgp::fingerprint(&key));
}
