//! El camino de envío con S/MIME: pedir firma y no poder firmar **falla**, no
//! manda el mensaje sin firmar. Va contra el llavero falso de `store::key`, que
//! habla el protocolo de Secret Service de verdad.

use crate::compose::{self, Draft};
use crate::smime_sign::test_support::*;
use crate::smime_sign::{verify_message, Verification};
use crate::smtp::SmtpError;
use crate::store::key::tests::{fake_keyring, lock_and_announce};
use crate::store::smime_key::import_pkcs12;

fn permanent(result: Result<String, SmtpError>) -> String {
    match result {
        Err(SmtpError::Permanent(detail)) => detail,
        other => panic!("se esperaba un fallo permanente, dio {other:?}"),
    }
}

#[tokio::test]
async fn pedir_firma_sin_certificado_para_el_from_falla_con_un_error_claro() {
    let (keys, _server, _shared) = fake_keyring().await;
    let result =
        crate::compose_outgoing(&keys, &draft(RSA_ADDRESS, "hola"), MESSAGE_ID, DATE).await;

    // No se manda sin firmar: no hay mensaje, hay un error que dice qué falta.
    let detail = permanent(result);
    assert!(detail.contains(RSA_ADDRESS), "{detail}");
    assert!(detail.contains("S/MIME"), "{detail}");
}

#[tokio::test]
async fn el_certificado_de_otra_direccion_no_sirve_para_este_from() {
    let (keys, _server, _shared) = fake_keyring().await;
    import_pkcs12(&keys, "otra@vasak.test", RSA_P12, PASSWORD)
        .await
        .unwrap();
    let result =
        crate::compose_outgoing(&keys, &draft(RSA_ADDRESS, "hola"), MESSAGE_ID, DATE).await;
    assert!(permanent(result).contains(RSA_ADDRESS));
}

#[tokio::test]
async fn con_certificado_firma_con_el_de_su_from_y_la_firma_verifica() {
    let (keys, _server, _shared) = fake_keyring().await;
    import_pkcs12(&keys, RSA_ADDRESS, RSA_P12, PASSWORD)
        .await
        .unwrap();
    import_pkcs12(&keys, EC_ADDRESS, EC_P12, PASSWORD)
        .await
        .unwrap();

    for (from, algorithm) in [(RSA_ADDRESS, "RSA"), (EC_ADDRESS, "ECDSA")] {
        let message = crate::compose_outgoing(&keys, &draft(from, "hola"), MESSAGE_ID, DATE)
            .await
            .unwrap_or_else(|e| panic!("{algorithm}: {e}"));
        assert!(message.contains("multipart/signed"), "{algorithm}");
        // Que verifique contra su From quiere decir que se eligió el certificado
        // de esa dirección y no otro.
        assert_eq!(
            verify_message(message.as_bytes()),
            Verification::SignedUntrusted(from.into()),
            "{algorithm}"
        );
    }
}

#[tokio::test]
async fn sin_pedir_firma_el_mensaje_sale_como_siempre_haya_o_no_certificado() {
    let plain = Draft {
        sign: false,
        ..draft(RSA_ADDRESS, "hola")
    };
    let expected = compose::build_message(&plain, MESSAGE_ID, DATE).unwrap();

    let (empty, _server, _shared) = fake_keyring().await;
    let (loaded, _server2, _shared2) = fake_keyring().await;
    import_pkcs12(&loaded, RSA_ADDRESS, RSA_P12, PASSWORD)
        .await
        .unwrap();

    for keys in [&empty, &loaded] {
        let message = crate::compose_outgoing(keys, &plain, MESSAGE_ID, DATE)
            .await
            .unwrap();
        assert_eq!(message, expected);
        assert_eq!(verify_message(message.as_bytes()), Verification::NotSigned);
    }
}

#[tokio::test]
async fn con_el_llavero_bloqueado_el_envio_firmado_se_reintenta_y_no_sale_sin_firmar() {
    let (keys, server, shared) = fake_keyring().await;
    import_pkcs12(&keys, RSA_ADDRESS, RSA_P12, PASSWORD)
        .await
        .unwrap();
    lock_and_announce(&server, &shared).await.unwrap();

    let result =
        crate::compose_outgoing(&keys, &draft(RSA_ADDRESS, "hola"), MESSAGE_ID, DATE).await;
    // Bloqueado no es «no hay certificado»: se desbloquea y sale. Reintentable.
    assert!(
        matches!(result, Err(SmtpError::Temporary(_))),
        "dio {result:?}"
    );
}
