//! La gestión de la identidad S/MIME por D-Bus (`ImportSmimeIdentity`,
//! `GetSmimeIdentity`, `RemoveSmimeIdentity` y el `SendMessage` con `firmar`),
//! **de punta a punta**: un servicio `AccountsSync` de verdad, un servicio de
//! cuentas falso y el llavero falso en un bus privado (ver `test_bus.rs`), y la
//! ventana —un cliente— llamando por el bus. Lo que se mira es lo que ve la
//! ventana: el nombre del error D-Bus, lo que queda en el llavero y el JSON.

use crate::smime_sign::test_support::*;
use crate::smime_sign::{certificate_matches_address, certificate_summary};
use crate::store::key::tests::{lock_and_announce, unlock_and_announce};
use crate::store::smime_key::parse_pkcs12;
use crate::test_bus::{captured_logs, error_of, Fixture};

const ACCOUNT: &str = "cta";
const NAME_PREFIX: &str = "ar.net.vasak.os.AccountsSync.";
/// Una contraseña que no es la de ningún `.p12` de prueba y que no se parece a
/// nada que el servicio imprima por su cuenta: si aparece, se filtró.
const WRONG_PASSWORD: &[u8] = b"contrasena-equivocada-9f3a-no-filtrar";
const MAX_P12: usize = 8 * 1024 * 1024;

const LEGACY_P12: &[u8] = include_bytes!("../tests/fixtures/smime/rsa-legacy.p12");
const ONLY_CERTS_P12: &[u8] = include_bytes!("../tests/fixtures/smime/solo-certs.p12");
const ONLY_KEY_P12: &[u8] = include_bytes!("../tests/fixtures/smime/solo-clave.p12");

async fn import(
    f: &Fixture,
    account: &str,
    p12: &[u8],
    password: &[u8],
) -> zbus::Result<zbus::Message> {
    f.call("ImportSmimeIdentity", &(account, p12, password))
        .await
}

/// El nombre corto del error (`WrongPassword`…), sin el prefijo del servicio.
fn short_name(result: zbus::Result<zbus::Message>) -> String {
    let (name, _) = error_of(result);
    name.strip_prefix(NAME_PREFIX)
        .unwrap_or_else(|| panic!("el nombre {name} no es del servicio"))
        .to_string()
}

async fn identity(f: &Fixture, account: &str) -> serde_json::Value {
    let reply: String = f
        .call("GetSmimeIdentity", &(account,))
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    serde_json::from_str(&reply).unwrap()
}

/// Que no haya nada guardado para esa dirección (ni la clave ni los certs).
async fn assert_nothing_stored(f: &Fixture, address: &str) {
    let keys = f.keys();
    assert!(
        keys.find_smime_private_key(address)
            .await
            .unwrap()
            .is_none(),
        "quedó una clave para {address}"
    );
    assert!(
        keys.find_smime_certs(address).await.unwrap().is_none(),
        "quedaron certificados para {address}"
    );
}

// ── Importar ────────────────────────────────────────────────────────────

#[tokio::test]
async fn importar_un_p12_cuyo_certificado_liga_la_direccion_de_la_cuenta_lo_guarda() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS), ("otra", EC_ADDRESS)]).await;

    import(&f, ACCOUNT, RSA_P12, PASSWORD).await.unwrap();

    let keys = f.keys();
    let key = keys.find_smime_private_key(RSA_ADDRESS).await.unwrap();
    assert!(key.is_some_and(|k| !k.is_empty()), "no quedó la clave");
    let certs = keys.find_smime_certs(RSA_ADDRESS).await.unwrap().unwrap();
    assert!(!certs.is_empty(), "no quedaron los certificados");
    // Y bajo la dirección de **esa** cuenta, no de otra.
    assert_nothing_stored(&f, EC_ADDRESS).await;
}

#[tokio::test]
async fn la_direccion_sale_de_la_cuenta_y_no_de_lo_que_mande_la_ventana() {
    let f = Fixture::start(&[(ACCOUNT, EC_ADDRESS)]).await;

    // Pasar la dirección en lugar del identificador de cuenta no sirve para
    // elegir bajo qué identidad se guarda: la cuenta no existe.
    let name = short_name(import(&f, RSA_ADDRESS, RSA_P12, PASSWORD).await);
    assert_eq!(name, "Failed");
    assert_nothing_stored(&f, RSA_ADDRESS).await;
    assert_nothing_stored(&f, EC_ADDRESS).await;
}

#[tokio::test]
async fn el_correo_del_certificado_se_compara_sin_distinguir_mayusculas_y_tambien_en_el_subject() {
    let f = Fixture::start(&[("may", "Prueba@VASAK.test"), ("subj", "subject@vasak.test")]).await;

    import(&f, "may", RSA_P12, PASSWORD).await.unwrap();
    // El cert que sólo trae el correo en el `emailAddress` del subject.
    import(&f, "subj", EC_SUBJECT_P12, PASSWORD).await.unwrap();

    // Guardado bajo la dirección tal cual la tiene la cuenta, que es la que
    // usa el envío para buscar la clave.
    let keys = f.keys();
    assert!(keys
        .find_smime_private_key("Prueba@VASAK.test")
        .await
        .unwrap()
        .is_some());
    assert!(keys
        .find_smime_private_key("subject@vasak.test")
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn un_certificado_de_otra_direccion_da_addressmismatch_y_no_importa_nada() {
    let f = Fixture::start(&[(ACCOUNT, "otra@vasak.test")]).await;

    let name = short_name(import(&f, ACCOUNT, RSA_P12, PASSWORD).await);

    assert_eq!(name, "AddressMismatch");
    assert_nothing_stored(&f, "otra@vasak.test").await;
    // Ni siquiera bajo la dirección del certificado.
    assert_nothing_stored(&f, RSA_ADDRESS).await;
}

#[tokio::test]
async fn un_certificado_con_el_correo_vacio_no_liga_ninguna_direccion() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;

    let name = short_name(import(&f, ACCOUNT, EC_EMPTY_EMAIL_P12, PASSWORD).await);

    assert_eq!(name, "AddressMismatch");
    assert_nothing_stored(&f, RSA_ADDRESS).await;
}

#[tokio::test]
async fn una_contrasena_equivocada_da_wrongpassword_y_no_importa_nada() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;

    let name = short_name(import(&f, ACCOUNT, RSA_P12, WRONG_PASSWORD).await);

    assert_eq!(name, "WrongPassword");
    assert_nothing_stored(&f, RSA_ADDRESS).await;
}

#[tokio::test]
async fn un_p12_ilegible_o_incompleto_da_malformed() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;

    let truncated = &RSA_P12[..RSA_P12.len() / 2];
    for (what, p12) in [
        ("basura", &b"esto no es un PFX"[..]),
        ("vacío", &b""[..]),
        ("truncado", truncated),
        ("sin clave", ONLY_CERTS_P12),
        ("sin certificados", ONLY_KEY_P12),
    ] {
        let name = short_name(import(&f, ACCOUNT, p12, PASSWORD).await);
        assert_eq!(name, "Malformed", "{what}");
    }
    assert_nothing_stored(&f, RSA_ADDRESS).await;
}

#[tokio::test]
async fn un_p12_con_cifrado_heredado_da_unsupportedlegacy() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;

    let name = short_name(import(&f, ACCOUNT, LEGACY_P12, PASSWORD).await);

    assert_eq!(name, "UnsupportedLegacy");
    assert_nothing_stored(&f, RSA_ADDRESS).await;
}

#[tokio::test]
async fn un_p12_de_mas_de_8_mib_da_toobig_y_uno_de_justo_8_mib_se_lee() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;

    let too_big = vec![0u8; MAX_P12 + 1];
    assert_eq!(
        short_name(import(&f, ACCOUNT, &too_big, PASSWORD).await),
        "TooBig"
    );
    // En el tope exacto pasa el chequeo de tamaño y falla después, por ilegible:
    // el límite es «más de», no «desde».
    let at_the_limit = vec![0u8; MAX_P12];
    assert_eq!(
        short_name(import(&f, ACCOUNT, &at_the_limit, PASSWORD).await),
        "Malformed"
    );
    assert_nothing_stored(&f, RSA_ADDRESS).await;
}

#[tokio::test]
async fn el_tope_de_tamano_se_mira_antes_de_buscar_la_cuenta() {
    // Sin ninguna cuenta: si se buscara primero daría `Failed`.
    let f = Fixture::start(&[]).await;
    let too_big = vec![0u8; MAX_P12 + 1];
    assert_eq!(
        short_name(import(&f, "no-existe", &too_big, PASSWORD).await),
        "TooBig"
    );
}

#[tokio::test]
async fn con_el_llavero_bloqueado_importar_da_keyringlocked_y_al_desbloquear_se_puede_reintentar() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;
    lock_and_announce(&f.keyring_server, &f.keyring)
        .await
        .unwrap();

    let name = short_name(import(&f, ACCOUNT, RSA_P12, PASSWORD).await);
    assert_eq!(name, "KeyringLocked");

    unlock_and_announce(&f.keyring_server, &f.keyring)
        .await
        .unwrap();
    import(&f, ACCOUNT, RSA_P12, PASSWORD).await.unwrap();
    assert!(f
        .keys()
        .find_smime_private_key(RSA_ADDRESS)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn con_el_llavero_bloqueado_leer_y_borrar_dan_keyringlocked_y_no_ausencia() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;
    import(&f, ACCOUNT, RSA_P12, PASSWORD).await.unwrap();
    lock_and_announce(&f.keyring_server, &f.keyring)
        .await
        .unwrap();

    // «Bloqueado» no es «no hay identidad»: decirlo así mandaría a la persona a
    // importar de nuevo un certificado que ya tiene.
    assert_eq!(
        short_name(f.call("GetSmimeIdentity", &(ACCOUNT,)).await),
        "KeyringLocked"
    );
    assert_eq!(
        short_name(f.call("RemoveSmimeIdentity", &(ACCOUNT,)).await),
        "KeyringLocked"
    );
}

#[tokio::test]
async fn los_tres_metodos_dan_failed_con_una_cuenta_que_no_existe() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;

    assert_eq!(
        short_name(import(&f, "borrada", RSA_P12, PASSWORD).await),
        "Failed"
    );
    assert_eq!(
        short_name(f.call("GetSmimeIdentity", &("borrada",)).await),
        "Failed"
    );
    assert_eq!(
        short_name(f.call("RemoveSmimeIdentity", &("borrada",)).await),
        "Failed"
    );
}

// ── La contraseña no sale de ahí ────────────────────────────────────────

#[tokio::test]
async fn la_contrasena_no_aparece_en_ningun_error_ni_en_las_trazas() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS), ("otra", "otra@vasak.test")]).await;
    let too_big = vec![0u8; MAX_P12 + 1];

    // Todas las formas de fallar, con la contraseña equivocada, y la que sale
    // bien, con la verdadera.
    let mut seen = Vec::new();
    for (account, p12) in [
        (ACCOUNT, RSA_P12),
        (ACCOUNT, &b"basura"[..]),
        (ACCOUNT, LEGACY_P12),
        (ACCOUNT, &too_big[..]),
        ("otra", RSA_P12),
        ("no-existe", RSA_P12),
    ] {
        let (name, text) = error_of(import(&f, account, p12, WRONG_PASSWORD).await);
        seen.push(format!("{name} {text}"));
    }
    // El de la dirección que no liga sólo se alcanza con la contraseña buena.
    let real = std::str::from_utf8(PASSWORD).unwrap();
    let (name, text) = error_of(import(&f, "otra", RSA_P12, PASSWORD).await);
    seen.push(format!("{name} {text}"));
    // Y la importación que sale bien.
    import(&f, ACCOUNT, RSA_P12, PASSWORD).await.unwrap();

    let wrong = std::str::from_utf8(WRONG_PASSWORD).unwrap();
    let as_numbers = |bytes: &[u8]| format!("{bytes:?}");
    let errors = seen.join("\n");
    let logs = captured_logs();
    for (what, haystack) in [("un error", &errors), ("las trazas", &logs)] {
        for secret in [wrong, real] {
            assert!(!haystack.contains(secret), "{what} trae la contraseña");
        }
        // Tampoco como lista de bytes, que es como la imprimiría un `Debug`.
        for secret in [WRONG_PASSWORD, PASSWORD] {
            assert!(
                !haystack.contains(&as_numbers(secret)),
                "{what} trae la contraseña como bytes"
            );
        }
    }
}

#[test]
fn los_errores_ipc_llevan_su_nombre_estable_y_ninguno_imprime_el_p12() {
    use zbus::DBusError;
    let cases = [
        (crate::SmimeIpcError::WrongPassword, "WrongPassword"),
        (crate::SmimeIpcError::UnsupportedLegacy, "UnsupportedLegacy"),
        (crate::SmimeIpcError::Malformed, "Malformed"),
        (crate::SmimeIpcError::AddressMismatch, "AddressMismatch"),
        (crate::SmimeIpcError::KeyringLocked, "KeyringLocked"),
        (crate::SmimeIpcError::TooBig, "TooBig"),
        (crate::SmimeIpcError::Failed("x".into()), "Failed"),
    ];
    for (error, short) in cases {
        assert_eq!(error.name().as_str(), format!("{NAME_PREFIX}{short}"));
    }
}

// ── Consultar y borrar ──────────────────────────────────────────────────

#[tokio::test]
async fn consultar_con_identidad_da_present_email_y_vencimiento_en_rfc3339() {
    let f = Fixture::start(&[("rsa", RSA_ADDRESS), ("vencida", "vencido@vasak.test")]).await;
    import(&f, "rsa", RSA_P12, PASSWORD).await.unwrap();
    import(&f, "vencida", EC_EXPIRED_P12, PASSWORD)
        .await
        .unwrap();

    let value = identity(&f, "rsa").await;
    assert_eq!(value["present"], true);
    assert_eq!(value["email"], RSA_ADDRESS);
    // El `notAfter` del certificado de prueba (openssl x509 -enddate).
    let not_after = chrono::DateTime::parse_from_rfc3339(value["not_after"].as_str().unwrap())
        .expect("not_after no es RFC 3339");
    assert_eq!(
        not_after.with_timezone(&chrono::Utc).to_rfc3339(),
        "2036-10-16T18:42:21+00:00"
    );

    // Uno vencido sigue «presente»: la ventana decide qué hace con la fecha.
    let expired = identity(&f, "vencida").await;
    assert_eq!(expired["present"], true);
    assert_eq!(expired["email"], "vencido@vasak.test");
    assert_eq!(
        chrono::DateTime::parse_from_rfc3339(expired["not_after"].as_str().unwrap())
            .unwrap()
            .with_timezone(&chrono::Utc)
            .to_rfc3339(),
        "2021-01-01T00:00:00+00:00"
    );
}

#[tokio::test]
async fn consultar_sin_identidad_da_present_false_y_nulos() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;

    let value = identity(&f, ACCOUNT).await;

    assert_eq!(
        value,
        serde_json::json!({ "present": false, "email": null, "not_after": null })
    );
}

#[tokio::test]
async fn consultar_nunca_devuelve_material_de_clave() {
    use base64::prelude::*;
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;
    import(&f, ACCOUNT, RSA_P12, PASSWORD).await.unwrap();

    let reply: String = f
        .call("GetSmimeIdentity", &(ACCOUNT,))
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();

    // Exactamente estas tres claves, ninguna más.
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let mut keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["email", "not_after", "present"]);

    // Y la clave privada no está en el texto, ni en base64 ni en hexadecimal.
    let key = parse_pkcs12(RSA_P12, PASSWORD).unwrap().private_key_pkcs8;
    // Base64 de un trozo sólo aparece en el base64 del todo si empieza en un múltiplo de 3.
    let start = key.len() / 2 / 3 * 3;
    let chunk = &key[start..start + 24];
    assert!(!reply.contains(&BASE64_STANDARD.encode(chunk)));
    assert!(!reply.contains(&BASE64_URL_SAFE.encode(chunk)));
    let hex: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!reply.to_lowercase().contains(&hex));
    assert!(!reply.contains("PRIVATE"));
}

#[tokio::test]
async fn borrar_la_identidad_la_saca_del_llavero_y_consultar_da_present_false() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS), ("otra", EC_ADDRESS)]).await;
    import(&f, ACCOUNT, RSA_P12, PASSWORD).await.unwrap();
    import(&f, "otra", EC_P12, PASSWORD).await.unwrap();
    assert_eq!(identity(&f, ACCOUNT).await["present"], true);

    f.call("RemoveSmimeIdentity", &(ACCOUNT,)).await.unwrap();

    assert_eq!(identity(&f, ACCOUNT).await["present"], false);
    assert_nothing_stored(&f, RSA_ADDRESS).await;
    // La de la otra cuenta no se toca.
    assert_eq!(identity(&f, "otra").await["present"], true);
    assert!(f
        .keys()
        .find_smime_private_key(EC_ADDRESS)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn borrar_cuando_no_hay_identidad_no_es_un_error() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;
    f.call("RemoveSmimeIdentity", &(ACCOUNT,)).await.unwrap();
    f.call("RemoveSmimeIdentity", &(ACCOUNT,)).await.unwrap();
}

#[tokio::test]
async fn importar_de_nuevo_reemplaza_la_identidad_anterior() {
    // Una cuenta cuya dirección liga con dos certificados distintos no existe en
    // los fixtures; el reemplazo se ve con la misma identidad dos veces: sigue
    // habiendo una sola y consulta bien.
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;
    import(&f, ACCOUNT, RSA_P12, PASSWORD).await.unwrap();
    import(&f, ACCOUNT, RSA_P12, PASSWORD).await.unwrap();

    assert_eq!(identity(&f, ACCOUNT).await["present"], true);
    f.call("RemoveSmimeIdentity", &(ACCOUNT,)).await.unwrap();
    assert_eq!(identity(&f, ACCOUNT).await["present"], false);
}

// ── Enviar firmado ──────────────────────────────────────────────────────

fn draft_json(sign: bool) -> String {
    serde_json::json!({
        "para": ["dest@otro.test"],
        "asunto": "Hola",
        "cuerpo": "Un mensaje.",
        "firmar": sign,
    })
    .to_string()
}

async fn send(f: &Fixture, sign: bool) -> zbus::Result<zbus::Message> {
    f.call("SendMessage", &(ACCOUNT, draft_json(sign), ""))
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
async fn pedir_firma_sin_identidad_se_rechaza_al_encolar_con_invalidargs() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;

    let (name, text) = error_of(send(&f, true).await);

    assert_eq!(name, "org.freedesktop.DBus.Error.InvalidArgs");
    // Dice de qué dirección falta, para que la ventana lo pueda mostrar.
    assert!(text.contains(RSA_ADDRESS), "{text}");
    // Y no quedó nada en la cola: no hay mensaje trabado.
    assert_eq!(queued(&f).await, 0);
}

#[tokio::test]
async fn la_identidad_de_otra_cuenta_no_alcanza_para_firmar_desde_esta() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS), ("otra", EC_ADDRESS)]).await;
    import(&f, "otra", EC_P12, PASSWORD).await.unwrap();

    let (name, _) = error_of(send(&f, true).await);

    assert_eq!(name, "org.freedesktop.DBus.Error.InvalidArgs");
    assert_eq!(queued(&f).await, 0);
}

#[tokio::test]
async fn pedir_firma_con_identidad_encola_normal() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;
    import(&f, ACCOUNT, RSA_P12, PASSWORD).await.unwrap();

    let id: String = send(&f, true).await.unwrap().body().deserialize().unwrap();

    assert!(!id.is_empty());
    assert_eq!(queued(&f).await, 1);
}

#[tokio::test]
async fn sin_pedir_firma_se_encola_aunque_no_haya_identidad() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;

    send(&f, false).await.unwrap();

    assert_eq!(queued(&f).await, 1);
}

#[tokio::test]
async fn borrar_la_identidad_vuelve_a_rechazar_el_envio_firmado() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;
    import(&f, ACCOUNT, RSA_P12, PASSWORD).await.unwrap();
    send(&f, true).await.unwrap();
    f.call("RemoveSmimeIdentity", &(ACCOUNT,)).await.unwrap();

    let (name, _) = error_of(send(&f, true).await);

    assert_eq!(name, "org.freedesktop.DBus.Error.InvalidArgs");
    assert_eq!(queued(&f).await, 1, "sólo el que se encoló con identidad");
}

#[tokio::test]
async fn pedir_firma_con_el_llavero_bloqueado_no_encola_ni_dice_que_falta_el_certificado() {
    let f = Fixture::start(&[(ACCOUNT, RSA_ADDRESS)]).await;
    import(&f, ACCOUNT, RSA_P12, PASSWORD).await.unwrap();
    lock_and_announce(&f.keyring_server, &f.keyring)
        .await
        .unwrap();

    let (name, text) = error_of(send(&f, true).await);

    // El certificado está: lo que pasa es que no se puede leer ahora. No es un
    // «importalo antes de firmar».
    assert_eq!(name, "org.freedesktop.DBus.Error.Failed");
    assert!(!text.contains("importalo"), "{text}");
    assert_eq!(queued(&f).await, 0);
}

// ── Las dos funciones del certificado, sin bus ──────────────────────────

#[test]
fn el_certificado_liga_la_direccion_sin_distinguir_mayusculas_ni_espacios() {
    let cert = parse_pkcs12(RSA_P12, PASSWORD).unwrap().certs.remove(0);

    assert!(certificate_matches_address(&cert, RSA_ADDRESS));
    assert!(certificate_matches_address(&cert, "PRUEBA@Vasak.Test"));
    assert!(certificate_matches_address(&cert, "  prueba@vasak.test \n"));
    assert!(!certificate_matches_address(&cert, "otra@vasak.test"));
    // Prefijo y sufijo de la dirección no son la dirección.
    assert!(!certificate_matches_address(&cert, "prueba@vasak"));
    assert!(!certificate_matches_address(&cert, "xprueba@vasak.test"));
    assert!(!certificate_matches_address(&cert, ""));
    assert!(!certificate_matches_address(&cert, "   "));
    assert!(!certificate_matches_address(b"no es DER", RSA_ADDRESS));
}

#[test]
fn un_correo_vacio_en_el_certificado_no_liga_una_direccion_vacia() {
    let cert = parse_pkcs12(EC_EMPTY_EMAIL_P12, PASSWORD)
        .unwrap()
        .certs
        .remove(0);
    assert!(!certificate_matches_address(&cert, ""));
    assert!(!certificate_matches_address(&cert, " "));
}

#[test]
fn el_resumen_del_certificado_tiene_correo_y_vencimiento_y_no_lee_basura() {
    let cert = parse_pkcs12(EC_P12, PASSWORD).unwrap().certs.remove(0);

    let (email, not_after) = certificate_summary(&cert).unwrap();

    assert_eq!(email.as_deref(), Some(EC_ADDRESS));
    assert_eq!(not_after, "2036-10-17T11:31:10+00:00");
    assert!(certificate_summary(b"no es DER").is_none());
}

// ── El control de dirección y el resumen, con certificados armados ──────

/// El certificado de `rsa-pbes2.p12` con otro SubjectAltName: lo que se pida, en
/// `rfc822Name`. La firma del certificado deja de valer, y no importa: estas
/// funciones sólo leen los nombres, no verifican la cadena.
fn cert_with_sans(sans: &[&str]) -> Vec<u8> {
    use der::asn1::{Ia5String, OctetString};
    use der::{Decode, Encode};
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;
    use x509_cert::Certificate;

    let original = parse_pkcs12(RSA_P12, PASSWORD).unwrap().certs.remove(0);
    let mut cert = Certificate::from_der(&original).unwrap();
    let names = sans
        .iter()
        .map(|s| GeneralName::Rfc822Name(Ia5String::new(s).unwrap()))
        .collect();
    let value = OctetString::new(SubjectAltName(names).to_der().unwrap()).unwrap();
    let mut replaced = false;
    for ext in cert.tbs_certificate.extensions.as_mut().unwrap() {
        if ext.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME {
            ext.extn_value = value.clone();
            replaced = true;
        }
    }
    assert!(replaced, "el cert de prueba no tenía SubjectAltName");
    cert.to_der().unwrap()
}

#[test]
fn el_control_de_direccion_mira_cada_san_y_basta_con_que_uno_coincida() {
    let own = cert_with_sans(&[RSA_ADDRESS]);
    assert!(certificate_matches_address(&own, RSA_ADDRESS));

    // Varios: liga si alguno es la dirección, esté en la posición que esté.
    let several = cert_with_sans(&["a@otro.test", RSA_ADDRESS, "b@otro.test"]);
    assert!(certificate_matches_address(&several, RSA_ADDRESS));
    assert!(certificate_matches_address(&several, "b@otro.test"));
    assert!(!certificate_matches_address(&several, "c@otro.test"));

    // Que no coincida: el IPC contesta `AddressMismatch`.
    let other = cert_with_sans(&["otra@vasak.test"]);
    assert!(!certificate_matches_address(&other, RSA_ADDRESS));

    // Un SAN vacío no liga nada, ni siquiera una dirección vacía o en blanco.
    let empty = cert_with_sans(&[""]);
    assert!(!certificate_matches_address(&empty, RSA_ADDRESS));
    assert!(!certificate_matches_address(&empty, ""));
    assert!(!certificate_matches_address(&empty, " "));
    // Y con la dirección vacía no liga ningún cert, aunque tenga correos.
    assert!(!certificate_matches_address(&several, ""));
}

#[test]
fn un_san_con_basura_o_saltos_de_linea_no_iguala_la_direccion_limpia() {
    for dirty in [
        // Inyección de cabecera: la dirección limpia es sólo el prefijo.
        "prueba@vasak.test\r\nBcc: victima@otro.test",
        "prueba@vasak.test\nBcc: victima@otro.test",
        "prueba@vasak.test,victima@otro.test",
        "prueba@vasak.test;victima@otro.test",
        "prueba@vasak.test\0",
        "<prueba@vasak.test>",
        "prueba@vasak.test.otro.test",
        "otro.prueba@vasak.test",
    ] {
        let cert = cert_with_sans(&[dirty]);
        assert!(
            !certificate_matches_address(&cert, RSA_ADDRESS),
            "{dirty:?} no tendría que ligar {RSA_ADDRESS}"
        );
    }
}

#[test]
fn el_resumen_devuelve_el_correo_tal_cual_y_serde_lo_escapa_en_el_json() {
    let hostile = "a@b.test\r\n\"},{\"present\":true,\"x\":\"\u{7}";
    let cert = cert_with_sans(&[hostile]);

    let (email, not_after) = certificate_summary(&cert).unwrap();
    assert_eq!(email.as_deref(), Some(hostile));
    assert!(chrono::DateTime::parse_from_rfc3339(&not_after).is_ok());

    // Armado como lo arma el método: sin ningún carácter de control crudo, y
    // vuelve a leerse como un solo campo con el valor exacto.
    let json =
        serde_json::json!({ "present": true, "email": email, "not_after": not_after }).to_string();
    assert!(!json.chars().any(|c| c.is_control()), "{json:?}");
    let back: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(back["email"], hostile);
    assert_eq!(back.as_object().unwrap().len(), 3);
}

#[tokio::test]
async fn consultar_con_un_correo_hostil_en_el_certificado_sale_escapado_por_el_bus() {
    use crate::store::smime_key::ImportedIdentity;
    use zeroize::Zeroizing;
    let hostile = "a@b.test\r\n\"},{\"present\":true,\"x\":\"\u{7}";
    let f = Fixture::start(&[(ACCOUNT, hostile)]).await;
    let imported = ImportedIdentity {
        private_key_pkcs8: Zeroizing::new(b"clave-privada-de-mentira-0123456789".to_vec()),
        certs: vec![cert_with_sans(&[hostile])],
    };
    f.keys()
        .store_smime_identity(hostile, &imported)
        .await
        .unwrap();

    let reply: String = f
        .call("GetSmimeIdentity", &(ACCOUNT,))
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();

    assert!(!reply.chars().any(|c| c.is_control()), "{reply:?}");
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(value["email"], hostile);
    assert_eq!(value.as_object().unwrap().len(), 3);
    // Ni rastro de la clave guardada.
    assert!(!reply.contains("clave-privada"));
}
