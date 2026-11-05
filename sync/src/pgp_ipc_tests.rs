//! La gestión de la identidad OpenPGP por D-Bus (`ImportPgpIdentity`,
//! `GetPgpIdentity`, `RemovePgpIdentity` y el `SendMessage` con `metodo_firma`),
//! **de punta a punta**: un servicio `AccountsSync` de verdad, un servicio de
//! cuentas falso y el llavero falso en un bus privado (ver `test_bus.rs`), y la
//! ventana llamando por el bus. Calca `smime_ipc_tests`. Lo que se mira es lo que
//! ve la ventana: el nombre del error D-Bus, lo que queda en el llavero y el JSON.

use crate::access::tests::Answer;
use crate::pgp::tests::{clave_vieja, con_primaria_muerta, con_primaria_revocada};
use crate::pgp_send_tests::{
    armored, dead_keys, fingerprint, protected_key, ACCOUNT, ADDRESS, PASSPHRASE,
};
use crate::store::key::tests::lock_and_announce;
use crate::test_bus::{error_of, Fixture};
use pgp::types::KeyDetails as _;

const NAME_PREFIX: &str = "ar.net.vasak.os.AccountsSync.";
const WRONG_PASSPHRASE: &[u8] = b"contrasena-equivocada-9f3a-no-filtrar";
const MAX_KEY: usize = 1024 * 1024;
const MAX_PASSPHRASE: usize = 4096;
const UID: &str = "Ana <ana@vasak.test>";
const PASSPHRASE_STR: &str = "frase-de-paso-de-prueba";

/// Un memfd sellado con estos bytes, como lo manda el cliente.
pub(crate) fn sealed_fd(bytes: &[u8]) -> zbus::zvariant::OwnedFd {
    use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};
    use std::io::Write;

    let fd = memfd_create(
        "pgp-prueba",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .unwrap();
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes).unwrap();
    fcntl_add_seals(
        &file,
        SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
    )
    .unwrap();
    std::os::fd::OwnedFd::from(file).into()
}

/// Un memfd con estos bytes pero **sin sellar** (TOCTOU).
fn unsealed_fd(bytes: &[u8]) -> zbus::zvariant::OwnedFd {
    use rustix::fs::{memfd_create, MemfdFlags};
    use std::io::Write;

    let fd = memfd_create(
        "pgp-prueba-sin-sello",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .unwrap();
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes).unwrap();
    std::os::fd::OwnedFd::from(file).into()
}

/// El extremo de lectura de un pipe con estos bytes; el de escritura se cierra.
fn pipe_fd(bytes: &[u8]) -> zbus::zvariant::OwnedFd {
    use std::io::Write;

    let (reader, mut writer) = std::io::pipe().unwrap();
    writer.write_all(bytes).unwrap();
    drop(writer);
    std::os::fd::OwnedFd::from(reader).into()
}

/// Un archivo común en disco (no un memfd): no admite sellos.
fn regular_file_fd(bytes: &[u8]) -> zbus::zvariant::OwnedFd {
    use std::io::Write;

    let path = std::env::temp_dir().join(format!("vasak-pgp-prueba-{}", std::process::id()));
    let mut file = std::fs::File::create_new(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    file.write_all(bytes).unwrap();
    std::os::fd::OwnedFd::from(file).into()
}

async fn import_fds(
    f: &Fixture,
    account: &str,
    key: zbus::zvariant::OwnedFd,
    passphrase: zbus::zvariant::OwnedFd,
) -> zbus::Result<zbus::Message> {
    f.call("ImportPgpIdentity", &(account, key, passphrase))
        .await
}

pub(crate) async fn import(
    f: &Fixture,
    account: &str,
    key: &[u8],
    passphrase: &[u8],
) -> zbus::Result<zbus::Message> {
    import_fds(f, account, sealed_fd(key), sealed_fd(passphrase)).await
}

fn short_name(result: zbus::Result<zbus::Message>) -> String {
    let (name, _) = error_of(result);
    name.strip_prefix(NAME_PREFIX)
        .unwrap_or_else(|| panic!("el nombre del error no es del servicio"))
        .to_string()
}

async fn identity_reply(f: &Fixture, account: &str) -> String {
    f.call("GetPgpIdentity", &(account,))
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap()
}

async fn identity(f: &Fixture, account: &str) -> serde_json::Value {
    serde_json::from_str(&identity_reply(f, account).await).unwrap()
}

/// Que no haya nada guardado para esa cuenta (ni la clave ni la contraseña).
async fn assert_nothing_stored(f: &Fixture, account: &str) {
    let keys = f.keys();
    assert!(
        keys.find_pgp_secret_key(account).await.unwrap().is_none(),
        "quedó una clave guardada"
    );
    assert!(
        keys.find_pgp_passphrase(account).await.unwrap().is_none(),
        "quedó una contraseña guardada"
    );
}

/// La clave armada de la identidad de prueba para ese UID.
fn key_for(uid: &str) -> Vec<u8> {
    armored(&protected_key(uid, PASSPHRASE_STR))
}

/// Una cuenta de prueba y la clave armada que liga su dirección.
async fn account_and_key() -> (Fixture, Vec<u8>) {
    (account().await, key_for(UID))
}

/// La cuenta de prueba con la identidad de `UID` ya importada, y su clave.
async fn account_with_identity() -> (Fixture, pgp::composed::SignedSecretKey) {
    let f = account().await;
    let key = protected_key(UID, PASSPHRASE_STR);
    import(&f, ACCOUNT, &armored(&key), PASSPHRASE)
        .await
        .unwrap();
    (f, key)
}

/// La cuenta de prueba, sin identidad.
async fn account() -> Fixture {
    Fixture::start(&[(ACCOUNT, ADDRESS)]).await
}

/// `RemovePgpIdentity` de la cuenta de prueba, que tiene que salir bien.
async fn remove(f: &Fixture) {
    f.call("RemovePgpIdentity", &(ACCOUNT,)).await.unwrap();
}

/// ¿Hay identidad en la cuenta de prueba, según `GetPgpIdentity`?
async fn is_present(f: &Fixture) -> bool {
    identity(f, ACCOUNT).await["present"] == true
}

/// Importa la clave de prueba de ese UID en esa cuenta, con la contraseña buena.
async fn import_identity(f: &Fixture, account: &str, uid: &str) {
    import(f, account, &key_for(uid), PASSPHRASE).await.unwrap();
}

/// El nombre corto del error de importar la cuenta de prueba.
async fn import_error(f: &Fixture, key: &[u8], passphrase: &[u8]) -> String {
    short_name(import(f, ACCOUNT, key, passphrase).await)
}

/// Importar con estos descriptores se rechaza como `Malformed` y no guarda nada.
async fn assert_fds_rejected(key: zbus::zvariant::OwnedFd, passphrase: zbus::zvariant::OwnedFd) {
    let f = account().await;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        import_fds(&f, ACCOUNT, key, passphrase),
    )
    .await
    .expect("el servicio se colgó");
    assert_eq!(short_name(result), "Malformed");
    assert_nothing_stored(&f, ACCOUNT).await;
}

/// Que el texto de un rechazo de envío sea `InvalidArgs` y diga `needle`.
fn assert_invalid_args(result: zbus::Result<zbus::Message>, needle: &str) {
    let (name, text) = error_of(result);
    assert_eq!(name, "org.freedesktop.DBus.Error.InvalidArgs");
    assert!(text.contains(needle), "falta lo esperado en el rechazo");
}

// ── Importar ────────────────────────────────────────────────────────────

#[tokio::test]
async fn importar_una_clave_que_liga_la_direccion_de_la_cuenta_la_guarda() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS), ("otra", "otra@vasak.test")]).await;
    let key = key_for(UID);

    import(&f, ACCOUNT, &key, PASSPHRASE).await.unwrap();

    let keys = f.keys();
    // Se guarda la clave saneada y re-serializada (binaria), no el blob armado
    // que mandó la ventana: tiene que ser la misma identidad.
    let stored = keys.find_pgp_secret_key(ACCOUNT).await.unwrap().unwrap();
    let stored = crate::pgp::parse_secret_key(&stored).expect("la clave guardada se relee");
    let sent = crate::pgp::parse_secret_key(&key).unwrap();
    assert_eq!(
        stored.primary_key.fingerprint().to_string(),
        sent.primary_key.fingerprint().to_string()
    );
    let pass = keys.find_pgp_passphrase(ACCOUNT).await.unwrap().unwrap();
    assert_eq!(pass.as_slice(), PASSPHRASE);
    assert_nothing_stored(&f, "otra").await;
}

#[tokio::test]
async fn la_direccion_sale_de_la_cuenta_y_no_de_lo_que_mande_la_ventana() {
    let f = Fixture::start(&[(ACCOUNT, "otra@vasak.test")]).await;
    let key = key_for(UID);

    // La clave liga `ana@…`, pero la cuenta es `otra@…`: aunque la ventana pase
    // la dirección de la clave como identificador, la cuenta no existe, y con el
    // identificador real la dirección que cuenta es la de la cuenta.
    assert_eq!(
        short_name(import(&f, ADDRESS, &key, PASSPHRASE).await),
        "Failed"
    );
    assert_eq!(import_error(&f, &key, PASSPHRASE).await, "AddressMismatch");
    assert_nothing_stored(&f, ACCOUNT).await;
    assert_nothing_stored(&f, ADDRESS).await;
}

#[tokio::test]
async fn una_clave_cuyo_uid_no_liga_la_direccion_de_la_cuenta_da_addressmismatch() {
    let (f, _) = account_and_key().await;
    let key = key_for("Beto <beto@vasak.test>");

    assert_eq!(import_error(&f, &key, PASSPHRASE).await, "AddressMismatch");
    assert_nothing_stored(&f, ACCOUNT).await;
}

#[tokio::test]
async fn el_correo_del_uid_se_compara_sin_distinguir_mayusculas() {
    let f = Fixture::start(&[(ACCOUNT, "Ana@VASAK.test")]).await;

    import_identity(&f, ACCOUNT, UID).await;

    assert!(f
        .keys()
        .find_pgp_secret_key(ACCOUNT)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn una_clave_ilegible_da_malformed_y_no_importa_nada() {
    let (f, key) = account_and_key().await;

    for (what, blob) in [
        ("basura", &b"esto no es una clave"[..]),
        ("vacío", &b""[..]),
        ("truncado", &key[..key.len() / 2]),
    ] {
        assert_eq!(
            import_error(&f, blob, PASSPHRASE).await,
            "Malformed",
            "{what}"
        );
    }
    assert_nothing_stored(&f, ACCOUNT).await;
}

#[tokio::test]
async fn una_contrasena_equivocada_da_wrongpassword_y_no_importa_nada() {
    let (f, key) = account_and_key().await;

    assert_eq!(
        import_error(&f, &key, WRONG_PASSPHRASE).await,
        "WrongPassword"
    );
    assert_nothing_stored(&f, ACCOUNT).await;
    // Y la correcta, sobre la misma clave, sí entra: la rechazada era la contraseña.
    import(&f, ACCOUNT, &key, PASSPHRASE).await.unwrap();
}

#[tokio::test]
async fn una_clave_sin_componente_de_firma_se_importa_igual() {
    // Una primaria revocada no puede firmar (`NoSigningKey`): no se puede sondear
    // la contraseña con una firma de prueba, y se acepta. Sirve para descifrar.
    let (f, _) = account_and_key().await;
    let vivo = clave_vieja(UID);
    let revocada = con_primaria_muerta(&vivo, con_primaria_revocada(&vivo));

    import(&f, ACCOUNT, &armored(&revocada), b"").await.unwrap();

    assert!(f
        .keys()
        .find_pgp_secret_key(ACCOUNT)
        .await
        .unwrap()
        .is_some());
}

// ── Los descriptores: sello, tipo y tope ────────────────────────────────

#[tokio::test]
async fn una_clave_sin_sellar_se_rechaza_aunque_sea_valida() {
    assert_fds_rejected(unsealed_fd(&key_for(UID)), sealed_fd(PASSPHRASE)).await;
}

#[tokio::test]
async fn una_contrasena_sin_sellar_se_rechaza_aunque_sea_la_correcta() {
    assert_fds_rejected(sealed_fd(&key_for(UID)), unsealed_fd(PASSPHRASE)).await;
}

#[tokio::test]
async fn una_clave_que_es_un_archivo_comun_no_se_acepta_aunque_sea_valida() {
    assert_fds_rejected(regular_file_fd(&key_for(UID)), sealed_fd(PASSPHRASE)).await;
}

#[tokio::test]
async fn un_pipe_como_clave_se_rechaza_sin_colgarse() {
    assert_fds_rejected(pipe_fd(&key_for(UID)), sealed_fd(PASSPHRASE)).await;
}

#[tokio::test]
async fn una_clave_de_mas_de_1_mib_da_toobig_y_una_de_justo_1_mib_se_lee() {
    // Sin ninguna cuenta: si se buscara primero daría `Failed`.
    {
        let f = Fixture::start(&[]).await;
        let too_big = vec![0u8; MAX_KEY + 1];
        assert_eq!(
            short_name(import(&f, "no-existe", &too_big, PASSPHRASE).await),
            "TooBig"
        );
    }
    // En el tope exacto se lee entera y falla después, por no ser una clave.
    let (f, _) = account_and_key().await;
    assert_eq!(
        import_error(&f, &vec![0u8; MAX_KEY], PASSPHRASE).await,
        "Malformed"
    );
}

#[tokio::test]
async fn una_contrasena_de_mas_de_4096_bytes_da_toobig_y_una_de_justo_4096_se_lee() {
    let (f, key) = account_and_key().await;

    assert_eq!(
        import_error(&f, &key, &vec![b'x'; MAX_PASSPHRASE + 1]).await,
        "TooBig"
    );
    // En el tope exacto se lee entera y falla después, por incorrecta.
    assert_eq!(
        import_error(&f, &key, &vec![b'x'; MAX_PASSPHRASE]).await,
        "WrongPassword"
    );
    assert_nothing_stored(&f, ACCOUNT).await;
}

#[tokio::test]
async fn el_tope_de_la_contrasena_se_mira_antes_de_buscar_la_cuenta() {
    let f = Fixture::start(&[]).await;
    let too_long = vec![b'x'; MAX_PASSPHRASE + 1];

    assert_eq!(
        short_name(import(&f, "no-existe", &key_for(UID), &too_long).await),
        "TooBig"
    );
}

#[tokio::test]
async fn con_el_llavero_bloqueado_importar_da_keyringlocked_y_al_desbloquear_se_reintenta() {
    let (f, key) = account_and_key().await;
    lock_and_announce(&f.keyring_server, &f.keyring)
        .await
        .unwrap();

    assert_eq!(import_error(&f, &key, PASSPHRASE).await, "KeyringLocked");
    assert_eq!(
        short_name(f.call("GetPgpIdentity", &(ACCOUNT,)).await),
        "KeyringLocked"
    );
}

#[tokio::test]
async fn los_tres_metodos_dan_failed_con_una_cuenta_que_no_existe() {
    let (f, key) = account_and_key().await;

    assert_eq!(
        short_name(import(&f, "borrada", &key, PASSPHRASE).await),
        "Failed"
    );
    assert_eq!(
        short_name(f.call("RemovePgpIdentity", &("borrada",)).await),
        "Failed"
    );
}

// ── La contraseña no sale de ahí ────────────────────────────────────────

#[tokio::test]
async fn la_contrasena_no_aparece_en_ningun_error_ni_en_las_trazas() {
    let (f, key) = account_and_key().await;
    let wrong = std::str::from_utf8(WRONG_PASSPHRASE).unwrap();

    for blob in [&key[..], b"basura"] {
        let (_, text) = error_of(import(&f, ACCOUNT, blob, WRONG_PASSPHRASE).await);
        assert!(!text.contains(wrong), "el error filtra la contraseña");
    }
    assert!(!crate::test_bus::captured_logs().contains(wrong));
}

// ── Consultar y borrar ──────────────────────────────────────────────────

#[tokio::test]
async fn consultar_con_identidad_da_present_huella_y_uids() {
    let (f, key) = account_with_identity().await;

    let value = identity(&f, ACCOUNT).await;

    assert_eq!(value["present"], true);
    assert_eq!(value["fingerprint"], fingerprint(&key));
    assert_eq!(value["uids"], serde_json::json!([ADDRESS]));
}

#[tokio::test]
async fn consultar_sin_identidad_da_present_false_y_vacios() {
    let f = account().await;

    let value = identity(&f, ACCOUNT).await;

    assert_eq!(
        value,
        serde_json::json!({ "present": false, "fingerprint": null, "uids": [] })
    );
}

#[tokio::test]
async fn consultar_nunca_devuelve_material_secreto() {
    let (f, key) = account_with_identity().await;

    let reply = identity_reply(&f, ACCOUNT).await;

    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let mut keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["fingerprint", "present", "uids"]);
    assert!(
        !reply.contains("PRIVATE KEY"),
        "el texto no cumple lo esperado"
    );
    assert!(
        !reply.contains(PASSPHRASE_STR),
        "el texto no cumple lo esperado"
    );
    // Ni un trozo del armor de la clave guardada.
    let armor = String::from_utf8(armored(&key)).unwrap();
    let body_line = armor.lines().nth(3).unwrap();
    assert!(!reply.contains(body_line), "el texto no cumple lo esperado");
}

#[tokio::test]
async fn consultar_una_clave_guardada_que_no_parsea_da_present_false() {
    let f = account().await;
    f.keys()
        .store_pgp_identity(ACCOUNT, b"no es una clave", b"x")
        .await
        .unwrap();

    assert!(!is_present(&f).await);
}

#[tokio::test]
async fn borrar_la_identidad_la_saca_del_llavero_y_consultar_da_present_false() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS), ("otra", "otra@vasak.test")]).await;
    import_identity(&f, ACCOUNT, UID).await;
    import_identity(&f, "otra", "Otra <otra@vasak.test>").await;
    assert!(is_present(&f).await);

    remove(&f).await;

    assert!(!is_present(&f).await);
    assert_nothing_stored(&f, ACCOUNT).await;
    // La de la otra cuenta no se toca.
    assert_eq!(identity(&f, "otra").await["present"], true);
}

#[tokio::test]
async fn borrar_cuando_no_hay_identidad_no_es_un_error() {
    let f = account().await;
    remove(&f).await;
    remove(&f).await;
}

// ── Quién puede mutar la identidad ──────────────────────────────────────

#[tokio::test]
async fn importar_sin_permiso_da_accessdenied_y_no_guarda_nada() {
    let f = Fixture::start_with_permission(&[(ACCOUNT, ADDRESS)], Answer::Deny).await;
    let key = key_for(UID);

    let name = short_name(import(&f, ACCOUNT, &key, PASSPHRASE).await);

    assert_eq!(name, "AccessDenied");
    assert_nothing_stored(&f, ACCOUNT).await;
}

#[tokio::test]
async fn borrar_sin_permiso_da_accessdenied_y_no_borra() {
    let f = Fixture::start_with_permission(&[(ACCOUNT, ADDRESS)], Answer::Deny).await;
    f.keys()
        .store_pgp_identity(ACCOUNT, &key_for(UID), PASSPHRASE)
        .await
        .unwrap();

    let name = short_name(f.call("RemovePgpIdentity", &(ACCOUNT,)).await);

    assert_eq!(name, "AccessDenied");
    assert!(is_present(&f).await);
}

// ── El error IPC no filtra material ─────────────────────────────────────

#[test]
fn los_errores_de_pgp_se_traducen_a_nombres_estables_sin_filtrar_el_detalle() {
    use crate::pgp::PgpError;
    use crate::SmimeIpcError as E;

    assert!(matches!(
        crate::pgp_ipc_from_parse(PgpError::BadKey("la clave no liga ningún UID a x".into())),
        E::AddressMismatch
    ));
    assert!(matches!(
        crate::pgp_ipc_from_parse(PgpError::BadKey("paquete ilegible".into())),
        E::Malformed
    ));
    for error in [
        PgpError::Crypto("DETALLE-SECRETO".into()),
        PgpError::NoSigningKey,
        PgpError::NoEncryptionKey("DETALLE-SECRETO".into()),
    ] {
        match crate::pgp_ipc_from_parse(error) {
            E::Failed(text) => assert!(
                !text.contains("DETALLE-SECRETO"),
                "el texto no cumple lo esperado"
            ),
            other => {
                let _ = other;
                panic!("se esperaba Failed")
            }
        }
    }
}

// ── Enviar firmado con PGP: se rechaza al encolar, no tarde ─────────────

fn draft_json(sign: Option<bool>, method: Option<&str>) -> String {
    let mut draft = serde_json::json!({
        "para": ["dest@otro.test"],
        "asunto": "Hola",
        "cuerpo": "Un mensaje.",
    });
    if let Some(sign) = sign {
        draft["firmar"] = sign.into();
    }
    if let Some(method) = method {
        draft["metodo_firma"] = method.into();
    }
    draft.to_string()
}

async fn send(
    f: &Fixture,
    sign: Option<bool>,
    method: Option<&str>,
) -> zbus::Result<zbus::Message> {
    f.call("SendMessage", &(ACCOUNT, draft_json(sign, method), ""))
        .await
}

async fn queued(f: &Fixture) -> usize {
    let reply: String = f
        .call("ListOutbox", &())
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    serde_json::from_str::<serde_json::Value>(&reply)
        .unwrap()
        .as_array()
        .unwrap()
        .len()
}

#[tokio::test]
async fn pedir_firma_pgp_sin_identidad_se_rechaza_al_encolar_con_invalidargs() {
    let f = account().await;

    assert_invalid_args(send(&f, None, Some("pgp")).await, "OpenPGP");
    // No quedó nada en la cola: no hay mensaje trabado.
    assert_eq!(queued(&f).await, 0);
}

#[tokio::test]
async fn pedir_firma_pgp_con_identidad_encola_normal() {
    let f = account().await;
    import_identity(&f, ACCOUNT, UID).await;

    let id: String = send(&f, None, Some("pgp"))
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();

    assert!(!id.is_empty());
    assert_eq!(queued(&f).await, 1);
}

#[tokio::test]
async fn la_identidad_de_otra_cuenta_no_alcanza_para_firmar_con_pgp_desde_esta() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS), ("otra", "otra@vasak.test")]).await;
    import_identity(&f, "otra", "Otra <otra@vasak.test>").await;

    assert_invalid_args(send(&f, None, Some("pgp")).await, "OpenPGP");
    assert_eq!(queued(&f).await, 0);
}

#[tokio::test]
async fn sin_pedir_firma_se_encola_aunque_no_haya_identidad() {
    let f = account().await;

    send(&f, None, None).await.unwrap();
    send(&f, Some(false), None).await.unwrap();
    // «none» explícito pisa al `firmar` viejo: no pide identidad.
    send(&f, Some(true), Some("none")).await.unwrap();

    assert_eq!(queued(&f).await, 3);
}

#[tokio::test]
async fn la_identidad_pgp_no_alcanza_para_pedir_smime_ni_al_reves() {
    let f = account().await;
    import_identity(&f, ACCOUNT, UID).await;

    // Hay PGP pero no S/MIME: el `firmar` viejo (S/MIME) se rechaza.
    assert_invalid_args(send(&f, Some(true), None).await, "S/MIME");
    assert_invalid_args(send(&f, None, Some("smime")).await, "S/MIME");
    assert_eq!(queued(&f).await, 0);
}

#[tokio::test]
async fn borrar_la_identidad_pgp_vuelve_a_rechazar_el_envio_firmado() {
    let f = account().await;
    import_identity(&f, ACCOUNT, UID).await;
    send(&f, None, Some("pgp")).await.unwrap();
    remove(&f).await;

    assert_invalid_args(send(&f, None, Some("pgp")).await, "OpenPGP");
    assert_eq!(queued(&f).await, 1, "sólo el que se encoló con identidad");
}

#[tokio::test]
async fn la_identidad_smime_no_alcanza_para_pedir_pgp() {
    use crate::smime_sign::test_support::{PASSWORD, RSA_ADDRESS, RSA_P12};
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;
    let imported = crate::store::smime_key::parse_pkcs12(RSA_P12, PASSWORD).unwrap();
    f.keys()
        .store_smime_identity(RSA_ADDRESS, &imported)
        .await
        .unwrap();

    // Con S/MIME sí se puede firmar con S/MIME…
    send(&f, Some(true), None).await.unwrap();
    // …pero PGP pide **su** identidad, no «la que haya».
    assert_invalid_args(send(&f, None, Some("pgp")).await, "OpenPGP");
    assert_eq!(queued(&f).await, 1);
}

#[tokio::test]
async fn pedir_firma_pgp_con_una_clave_que_no_puede_firmar_se_rechaza_al_encolar() {
    // Una identidad que existe pero cuya primaria está muerta (revocada o
    // expirada) no firmaría: se rechaza al encolar, no recién al enviar.
    for (what, key) in dead_keys(UID) {
        let f = account().await;
        f.keys()
            .store_pgp_identity(ACCOUNT, &armored(&key), b"")
            .await
            .unwrap();

        assert_invalid_args(send(&f, None, Some("pgp")).await, "OpenPGP");
        assert_eq!(queued(&f).await, 0, "{what}");
    }
}

#[tokio::test]
async fn pedir_firma_pgp_con_una_clave_viva_sin_contrasena_guardada_encola() {
    // Control de la anterior: la misma clave sin matar sí encola.
    let f = account().await;
    f.keys()
        .store_pgp_identity(ACCOUNT, &armored(&clave_vieja(UID)), b"")
        .await
        .unwrap();

    send(&f, None, Some("pgp")).await.unwrap();

    assert_eq!(queued(&f).await, 1);
}
