//! Los bordes de firmar y verificar S/MIME, escritos por `qa` aparte del
//! round-trip de `round_trip` (que sólo prueba que lo que se firma se verifica).
//!
//! Cada prueba mira **por qué** falla lo que falla: un `Unverified` por la razón
//! equivocada (por ejemplo, una firma rota cuando se quería probar el `From`)
//! es una prueba que no prueba lo que dice.

use super::test_support::*;
use super::*;
use crate::compose::Draft;
use crate::store::smime_key::parse_pkcs12;

// ── Los bytes firmados son los transmitidos ───────────────────────────

/// El contenido de la parte 1 del mensaje armado, sacado **a mano** del texto
/// transmitido, sin pasar por `split_parts` ni por el verificador: es la vara
/// contra la que se mide lo que se firmó.
fn wire_content(message: &str) -> &str {
    let start = message.find("boundary=\"").expect("hay frontera") + "boundary=\"".len();
    let boundary = message[start..].split('"').next().unwrap();
    let first = message
        .find(&format!("--{boundary}\r\n"))
        .expect("primera frontera")
        + boundary.len()
        + 4;
    let last = message[first..]
        .find(&format!("\r\n--{boundary}\r\n"))
        .expect("frontera de la firma")
        + first;
    &message[first..last]
}

/// Reescribe la firma (su DER) de un `multipart/signed` ya armado.
fn rewrite_signature(message: &str, change: impl FnOnce(Vec<u8>) -> Vec<u8>) -> String {
    let marker = "filename=\"smime.p7s\"\r\n\r\n";
    let from = message.find(marker).expect("parte de la firma") + marker.len();
    let to = message[from..].find("\r\n--").expect("cierre") + from;
    let der = BASE64_STANDARD
        .decode(strip_whitespace(&message.as_bytes()[from..to]))
        .expect("base64 de la firma");
    let wrapped = crate::compose::wrap_base64(&BASE64_STANDARD.encode(change(der)));
    format!("{}{}{}", &message[..from], wrapped, &message[to..])
}

fn replace_header(message: &str, name: &str, value: &str) -> String {
    let prefix = format!("{name}: ");
    message
        .split("\r\n")
        .map(|line| {
            if line.starts_with(&prefix) {
                format!("{prefix}{value}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

#[test]
fn con_adjuntos_la_firma_cubre_los_bytes_exactos_que_se_transmiten() {
    for (p12, from) in [(RSA_P12, RSA_ADDRESS), (EC_P12, EC_ADDRESS)] {
        let signed = sign(p12, &draft_with_attachments(from));

        // Es un árbol de verdad: el firmado envuelve a un multipart/mixed con los
        // dos adjuntos adentro.
        assert!(
            signed.content.contains("multipart/mixed"),
            "{}",
            signed.content
        );
        assert!(signed.content.contains("datos.bin"));
        assert!(!signed.content.contains("smime.p7s"));
        assert!(signed.message.contains("smime.p7s"));

        // Lo que viaja en la parte 1 es, byte por byte, lo que se firmó…
        assert_eq!(wire_content(&signed.message), signed.content);
        // …y el digest firmado es el de esos bytes transmitidos.
        let content_info = ContentInfo::from_der(&signed.signature).unwrap();
        let signed_data = SignedData::from_der(&content_info.content.to_der().unwrap()).unwrap();
        let attrs = signed_data
            .signer_infos
            .0
            .iter()
            .next()
            .unwrap()
            .signed_attrs
            .as_ref()
            .unwrap();
        let digest =
            OctetString::from_der(&signed_attribute(attrs, ID_MESSAGE_DIGEST).unwrap()).unwrap();
        assert_eq!(
            digest.as_bytes(),
            Sha256::digest(wire_content(&signed.message).as_bytes()).as_slice()
        );

        assert_eq!(
            verify_message(signed.message.as_bytes()),
            Verification::SignedUntrusted(from.into())
        );
    }
}

#[test]
fn el_mensaje_firmado_declara_sha256_y_la_firma_va_separada() {
    let signed = sign(RSA_P12, &draft(RSA_ADDRESS, "hola"));
    let message = &signed.message;
    assert!(
        message.contains(
            "multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=\"sha-256\""
        ),
        "{message}"
    );
    assert!(message.contains("Content-Type: application/pkcs7-signature; name=\"smime.p7s\""));
    // Firma separada: el SignedData no lleva el contenido adentro.
    let content_info = ContentInfo::from_der(&signed.signature).unwrap();
    let signed_data = SignedData::from_der(&content_info.content.to_der().unwrap()).unwrap();
    assert!(signed_data.encap_content_info.econtent.is_none());
    // El cuerpo se lee aunque el cliente no entienda S/MIME.
    assert!(wire_content(message).contains("hola"));
}

#[test]
fn los_bordes_del_cuerpo_no_rompen_la_firma() {
    // Los saltos del final del cuerpo son los que se pierden si el verificador
    // recorta de más o de menos al sacar el CRLF de la frontera.
    for body in [
        "",
        "\n",
        "\r\n\r\n",
        "hola\n",
        "hola\n\n\n",
        "  con espacios al final  ",
        "línea con acentos ñ é y un euro €",
        "una línea larga ".repeat(40).as_str(),
        "igual = a otro",
    ] {
        let signed = sign(RSA_P12, &draft(RSA_ADDRESS, body));
        assert_eq!(wire_content(&signed.message), signed.content, "{body:?}");
        assert_eq!(
            verify_message(signed.message.as_bytes()),
            Verification::SignedUntrusted(RSA_ADDRESS.into()),
            "{body:?}"
        );
    }
}

#[test]
fn una_linea_que_empieza_con_punto_sobrevive_al_dot_stuffing_de_smtp() {
    // SMTP le agrega un punto a esas líneas al mandar y el servidor se lo saca:
    // lo que llega tiene que ser lo firmado, y lo que sale no es lo firmado.
    let signed = sign(
        EC_P12,
        &Draft {
            body: ".primera\n.\n..tres".into(),
            ..draft_with_attachments(EC_ADDRESS)
        },
    );
    let on_the_wire = crate::smtp::dot_stuff(&signed.message);
    assert_ne!(on_the_wire, signed.message, "la prueba no estresa nada");

    let delivered = on_the_wire
        .split("\r\n")
        .map(|line| {
            line.strip_prefix('.')
                .filter(|_| line.starts_with(".."))
                .unwrap_or(line)
        })
        .collect::<Vec<_>>()
        .join("\r\n");
    assert_eq!(delivered, signed.message);
    assert_eq!(
        verify_message(delivered.as_bytes()),
        Verification::SignedUntrusted(EC_ADDRESS.into())
    );
}

// ── El From tiene que ligar al certificado ────────────────────────────

#[test]
fn un_from_que_no_liga_al_certificado_es_firmado_no_verificado() {
    for (p12, cert_address) in [(RSA_P12, RSA_ADDRESS), (EC_P12, EC_ADDRESS)] {
        // Se firma con un cert que es de otra dirección: la firma es perfecta,
        // pero no es de quien dice el From.
        let signed = sign(p12, &draft("otro@vasak.test", "hola"));
        let reason = unverified_reason(verify_message(signed.message.as_bytes()));
        assert!(
            reason.contains("From"),
            "tenía que fallar por el From y falló por: {reason}"
        );

        // Y al revés: el mensaje bien firmado, al que le cambian el From de
        // afuera (que no está firmado) por otro.
        let honest = sign(p12, &draft(cert_address, "hola"));
        assert!(matches!(
            verify_message(honest.message.as_bytes()),
            Verification::SignedUntrusted(_)
        ));
        let swapped = replace_header(&honest.message, "From", "otro@vasak.test");
        let reason = unverified_reason(verify_message(swapped.as_bytes()));
        assert!(reason.contains("From"), "{reason}");
    }
}

#[test]
fn un_nombre_que_parece_la_direccion_no_engana_al_verificador() {
    let honest = sign(RSA_P12, &draft(RSA_ADDRESS, "hola"));
    // La dirección real es la de adentro de los `<>`; el nombre es decoración.
    let spoofed = replace_header(
        &honest.message,
        "From",
        &format!("\"{RSA_ADDRESS}\" <atacante@otro.test>"),
    );
    let reason = unverified_reason(verify_message(spoofed.as_bytes()));
    assert!(reason.contains("From"), "{reason}");

    // Y con el nombre decorativo y la dirección verdadera, sí liga.
    let named = replace_header(
        &honest.message,
        "From",
        &format!("Prueba Vasak <{RSA_ADDRESS}>"),
    );
    assert_eq!(
        verify_message(named.as_bytes()),
        Verification::SignedUntrusted(RSA_ADDRESS.into())
    );
}

#[test]
fn sin_from_no_hay_a_quien_ligar_la_firma() {
    let honest = sign(RSA_P12, &draft(RSA_ADDRESS, "hola"));
    let without_from = honest
        .message
        .split("\r\n")
        .filter(|line| !line.starts_with("From: "))
        .collect::<Vec<_>>()
        .join("\r\n");
    let reason = unverified_reason(verify_message(without_from.as_bytes()));
    assert!(reason.contains("From"), "{reason}");
}

#[test]
fn el_from_liga_sin_distinguir_mayusculas_y_tambien_por_el_email_del_subject() {
    // Mayúsculas: las direcciones se comparan sin distinguirlas.
    let signed = sign(RSA_P12, &draft("PRUEBA@Vasak.TEST", "hola"));
    assert!(matches!(
        verify_message(signed.message.as_bytes()),
        Verification::SignedUntrusted(_)
    ));

    // Un cert sin SubjectAltName: el correo está sólo en el `emailAddress`.
    let by_subject = sign(EC_SUBJECT_P12, &draft("subject@vasak.test", "hola"));
    assert_eq!(
        verify_message(by_subject.message.as_bytes()),
        Verification::SignedUntrusted("subject@vasak.test".into())
    );
    // …y con otro From, no.
    let other = sign(EC_SUBJECT_P12, &draft("otro@vasak.test", "hola"));
    assert!(unverified_reason(verify_message(other.message.as_bytes())).contains("From"));
}

// ── Una firma entrante manipulada ─────────────────────────────────────

#[test]
fn un_contenido_cambiado_despues_de_firmar_no_verifica() {
    for (p12, from) in [(RSA_P12, RSA_ADDRESS), (EC_P12, EC_ADDRESS)] {
        let signed = sign(p12, &draft(from, "transfiere 100 a Ana"));
        let tampered = signed.message.replace("transfiere 100", "transfiere 900");
        assert_ne!(tampered, signed.message);
        // La firma en sí es buena: lo que no coincide es el digest del contenido.
        let reason = unverified_reason(verify_message(tampered.as_bytes()));
        assert!(reason.contains("messageDigest"), "{reason}");
    }
}

#[test]
fn un_adjunto_cambiado_despues_de_firmar_no_verifica() {
    let signed = sign(RSA_P12, &draft_with_attachments(RSA_ADDRESS));
    // Un carácter del base64 del adjunto binario, adentro de la parte firmada.
    let marker = "Content-Transfer-Encoding: base64\r\n\r\n";
    let at = signed.message.find(marker).unwrap() + marker.len();
    let mut bytes = signed.message.clone().into_bytes();
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    let reason = unverified_reason(verify_message(&bytes));
    assert!(reason.contains("messageDigest"), "{reason}");
}

#[test]
fn una_firma_alterada_no_verifica() {
    for (p12, from) in [(RSA_P12, RSA_ADDRESS), (EC_P12, EC_ADDRESS)] {
        let signed = sign(p12, &draft(from, "hola"));
        // El último byte del DER es del valor de la firma del firmante.
        let tampered = rewrite_signature(&signed.message, |mut der| {
            *der.last_mut().unwrap() ^= 0x01;
            der
        });
        assert_ne!(tampered, signed.message);
        let reason = unverified_reason(verify_message(tampered.as_bytes()));
        assert!(reason.contains("inválida"), "{reason}");
    }
}

#[test]
fn la_firma_de_otro_mensaje_no_sirve_para_este() {
    // Una firma perfecta, pero de un mensaje con otro contenido.
    let mine = sign(RSA_P12, &draft(RSA_ADDRESS, "el mensaje de verdad"));
    let other = sign(RSA_P12, &draft(RSA_ADDRESS, "otro mensaje distinto"));
    let grafted = rewrite_signature(&mine.message, |_| other.signature.clone());
    let reason = unverified_reason(verify_message(grafted.as_bytes()));
    assert!(reason.contains("messageDigest"), "{reason}");
}

#[test]
fn una_firma_hecha_con_otra_clave_no_verifica_con_el_cert_que_se_declara() {
    // El cert viaja adentro del mensaje, así que quien lo arma puede declarar el
    // de otro y firmar con su propia clave. `detached_signature` toma el cert
    // de la cabeza de la cadena que se le pase y la clave que se le pase, y no
    // las cruza: sirve para armar exactamente ese engaño.
    let rsa = parse_pkcs12(RSA_P12, PASSWORD).unwrap();
    let ec = parse_pkcs12(EC_P12, PASSWORD).unwrap();
    let ec_subject = parse_pkcs12(EC_SUBJECT_P12, PASSWORD).unwrap();

    for (key, certs, from) in [
        // Clave EC, cert RSA: ni el algoritmo es el mismo.
        (&ec, &rsa, RSA_ADDRESS),
        // Clave EC, cert de otra clave EC: mismo algoritmo, otra clave.
        (&ec, &ec_subject, "subject@vasak.test"),
    ] {
        let draft = draft(from, "hola");
        let headers = crate::compose::build_message_headers(&draft, MESSAGE_ID, DATE).unwrap();
        let content = crate::compose::build_content_entity(&draft);
        let signature =
            detached_signature(content.as_bytes(), &key.private_key_pkcs8, &certs.certs).unwrap();
        let message = build_signed_message(&headers, &content, &signature);

        // El From liga al cert declarado, así que lo único que puede parar esto
        // es la firma.
        let reason = unverified_reason(verify_message(message.as_bytes()));
        assert!(reason.contains("firma"), "{reason}");
    }
}

// ── La forma opaca ────────────────────────────────────────────────────

#[test]
fn la_forma_opaca_se_verifica_igual_que_multipart_signed() {
    for (p12, from) in [(RSA_P12, RSA_ADDRESS), (EC_P12, EC_ADDRESS)] {
        let signed = sign(p12, &draft_with_attachments(from));
        for media_type in ["application/pkcs7-mime", "application/x-pkcs7-mime"] {
            let message = opaque(&signed, media_type);
            // Es opaca de verdad: no hay `multipart/signed` y el cuerpo no se lee.
            assert!(!message.contains("multipart/signed"));
            assert!(!message.contains("Va el informe"));
            assert_eq!(
                verify_message(message.as_bytes()),
                Verification::SignedUntrusted(from.into()),
                "{media_type}"
            );
        }
    }
}

#[test]
fn la_forma_opaca_tambien_exige_el_from_y_el_contenido() {
    let signed = sign(RSA_P12, &draft(RSA_ADDRESS, "contenido de verdad"));

    // From que no liga.
    let message = opaque(&signed, "application/pkcs7-mime");
    let swapped = replace_header(&message, "From", "otro@vasak.test");
    assert!(unverified_reason(verify_message(swapped.as_bytes())).contains("From"));

    // Contenido embebido distinto del firmado (mismo largo): el DER es válido y
    // lo que falla es el digest.
    let tampered = Signed {
        headers: signed.headers.clone(),
        signature: signed.signature.clone(),
        content: signed.content.replace("de verdad", "de falso!"),
        message: String::new(),
    };
    assert_eq!(tampered.content.len(), signed.content.len());
    let message = opaque(&tampered, "application/pkcs7-mime");
    let reason = unverified_reason(verify_message(message.as_bytes()));
    assert!(reason.contains("messageDigest"), "{reason}");
}

// ── Truncado y basura ─────────────────────────────────────────────────

#[test]
fn un_mensaje_truncado_no_verifica_ni_entra_en_panico() {
    let signed = sign(RSA_P12, &draft_with_attachments(RSA_ADDRESS));
    let message = signed.message.as_bytes();
    // Hasta dónde llega la firma: lo que sigue es la frontera de cierre, que no
    // forma parte de nada firmado.
    let signature_end = signed.message.rfind("\r\n--").unwrap();

    for cut in 0..message.len() {
        let result = verify_message(&message[..cut]);
        if cut < signature_end {
            assert!(
                !matches!(result, Verification::SignedUntrusted(_)),
                "un mensaje cortado en {cut} de {} no puede verificar",
                message.len()
            );
        }
    }

    // El opaco, cortado en cada byte: el DER incompleto no verifica.
    let opaque = opaque(&signed, "application/pkcs7-mime");
    let body_end = opaque.trim_end().len();
    for cut in 0..body_end {
        assert!(
            !matches!(
                verify_message(&opaque.as_bytes()[..cut]),
                Verification::SignedUntrusted(_)
            ),
            "el opaco cortado en {cut} no puede verificar"
        );
    }
}

#[test]
fn un_multipart_signed_mal_armado_no_verifica_ni_entra_en_panico() {
    let headers = "From: prueba@vasak.test\r\nMIME-Version: 1.0\r\n";
    let cases = [
        // Sin frontera.
        "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"\r\n\r\ncuerpo\r\n",
        // Con frontera pero sin partes.
        "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"b\"\r\n\r\n--b--\r\n",
        // Una sola parte.
        "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"b\"\r\n\r\n--b\r\n\r\nsolo contenido\r\n--b--\r\n",
        // La segunda parte no es base64.
        "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"b\"\r\n\r\n--b\r\n\r\nhola\r\n--b\r\n\r\n%%%\r\n--b--\r\n",
        // La segunda parte es base64 pero no es un PKCS#7.
        "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=\"b\"\r\n\r\n--b\r\n\r\nhola\r\n--b\r\n\r\naG9sYQ==\r\n--b--\r\n",
        // Un opaco que no es base64 ni DER.
        "Content-Type: application/pkcs7-mime; smime-type=signed-data\r\n\r\n%%%\r\n",
        "Content-Type: application/pkcs7-mime; smime-type=signed-data\r\n\r\naG9sYQ==\r\n",
        "Content-Type: application/pkcs7-mime; smime-type=signed-data\r\n\r\n",
    ];
    for case in cases {
        let message = format!("{headers}{case}");
        let result = verify_message(message.as_bytes());
        assert!(
            matches!(result, Verification::Unverified(_)),
            "{case:?} dio {result:?}"
        );
    }
    // Vacío y basura binaria: no es S/MIME y no se cae.
    assert_eq!(verify_message(b""), Verification::NotSigned);
    assert_eq!(
        verify_message(&[0xff, 0x00, 0xfe, 0x30]),
        Verification::NotSigned
    );
}

#[test]
fn lo_que_no_es_smime_no_es_firmado() {
    let plain = crate::compose::build_message(
        &Draft {
            sign: false,
            ..draft_with_attachments(RSA_ADDRESS)
        },
        MESSAGE_ID,
        DATE,
    )
    .unwrap();
    assert_eq!(verify_message(plain.as_bytes()), Verification::NotSigned);
}

// ── Sin validación de confianza, nunca «válido» ───────────────────────

/// Lo que `opened_rows` guarda de este crudo: (estado, firmante).
fn stored(raw: &[u8], truncated: bool) -> (Option<i64>, Option<String>) {
    let (body, _) = crate::email_sync::opened_rows(1, raw, truncated);
    (body.smime_status, body.smime_signer)
}

/// **Regresión del crítico.** Un cert autofirmado con `rfc822 = X` y un
/// `From: X` pasa la firma, el digest y la ligadura al From; sin cadena de
/// confianza eso es un correo falsificable por cualquiera. Lo más que se dice
/// es «firmado, no verificado», y lo que se guarda nunca es el estado 1.
#[test]
fn un_cert_autofirmado_con_el_san_del_from_se_guarda_firmado_no_verificado_nunca_valido() {
    for (p12, from) in [(RSA_P12, RSA_ADDRESS), (EC_P12, EC_ADDRESS)] {
        let signed = sign(p12, &draft(from, "hola"));
        for raw in [
            signed.message.clone(),
            opaque(&signed, "application/pkcs7-mime"),
        ] {
            assert_eq!(
                verify_message(raw.as_bytes()),
                Verification::SignedUntrusted(from.into())
            );
            assert_eq!(stored(raw.as_bytes(), false), (Some(0), Some(from.into())));
        }
    }
}

/// Vencido tampoco es «válido» ni «roto»: es el mismo «firmado, no verificado».
#[test]
fn un_cert_vencido_es_firmado_no_verificado_y_no_valido_ni_roto() {
    let signed = sign(EC_EXPIRED_P12, &draft("vencido@vasak.test", "hola"));
    assert_eq!(
        verify_message(signed.message.as_bytes()),
        Verification::SignedUntrusted("vencido@vasak.test".into())
    );
    assert_eq!(
        stored(signed.message.as_bytes(), false),
        (Some(0), Some("vencido@vasak.test".into()))
    );
}

// ── multipart/signed son exactamente dos partes ───────────────────────

/// El ataque de la parte de más: lo firmado es un adjunto, pero la vista
/// mostraría el texto de una tercera parte que la firma no cubre.
#[test]
fn un_multipart_signed_con_una_tercera_parte_se_rechaza() {
    let identity = parse_pkcs12(RSA_P12, PASSWORD).unwrap();
    let draft = draft(RSA_ADDRESS, "x");
    let headers = crate::compose::build_message_headers(&draft, MESSAGE_ID, DATE).unwrap();
    let signed_entity = "Content-Type: application/octet-stream\r\n\
                         Content-Disposition: attachment; filename=\"a.txt\"\r\n\
                         Content-Transfer-Encoding: base64\r\n\r\nQUJD";
    let signature = detached_signature(
        signed_entity.as_bytes(),
        &identity.private_key_pkcs8,
        &identity.certs,
    )
    .unwrap();
    let honest = build_signed_message(&headers, signed_entity, &signature);
    assert_eq!(
        verify_message(honest.as_bytes()),
        Verification::SignedUntrusted(RSA_ADDRESS.into()),
        "el control: de dos partes sí liga"
    );

    let boundary = {
        let at = honest.find("boundary=\"").unwrap() + "boundary=\"".len();
        honest[at..].split('"').next().unwrap().to_string()
    };
    let closing = format!("--{boundary}--\r\n");
    let forged = honest.replace(
        &closing,
        &format!(
            "--{boundary}\r\nContent-Type: text/plain\r\n\r\nTEXTO QUE LA FIRMA NO CUBRE\r\n{closing}"
        ),
    );
    assert_ne!(forged, honest);
    let reason = unverified_reason(verify_message(forged.as_bytes()));
    assert!(reason.contains("dos partes"), "{reason}");
    assert_eq!(stored(forged.as_bytes(), false), (None, None));
}

// ── Lo que no es S/MIME ───────────────────────────────────────────────

#[test]
fn un_multipart_signed_de_pgp_no_es_smime() {
    let pgp = "From: a@b.test\r\n\
        Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"b\"\r\n\r\n\
        --b\r\nContent-Type: text/plain\r\n\r\nhola\r\n\
        --b\r\nContent-Type: application/pgp-signature\r\n\r\n\
        -----BEGIN PGP SIGNATURE-----\r\nabc\r\n-----END PGP SIGNATURE-----\r\n--b--\r\n";
    assert_eq!(verify_message(pgp.as_bytes()), Verification::NotSigned);
    assert_eq!(stored(pgp.as_bytes(), false), (None, None));
}

#[test]
fn el_protocolo_de_s_mime_se_reconoce_en_sus_dos_nombres_y_sin_mayusculas() {
    let signed = sign(RSA_P12, &draft(RSA_ADDRESS, "hola"));
    for protocol in [
        "application/x-pkcs7-signature",
        "Application/PKCS7-Signature",
    ] {
        let message = signed.message.replace(
            "application/pkcs7-signature\"; micalg",
            &format!("{protocol}\"; micalg"),
        );
        assert_ne!(message, signed.message);
        assert_eq!(
            verify_message(message.as_bytes()),
            Verification::SignedUntrusted(RSA_ADDRESS.into()),
            "{protocol}"
        );
    }
}

/// El tipo lo dice el OID del CMS, no el parámetro `smime-type` del header: un
/// mensaje cifrado no es «firmado» aunque el header diga `signed-data`.
#[test]
fn un_mensaje_cifrado_entrante_no_es_firmado() {
    let headers = vec!["From: a@b.test".to_string()];
    for oid in [ID_ENVELOPED_DATA, ID_DATA] {
        let content_info = ContentInfo {
            content_type: oid,
            content: der::Any::new(der::Tag::Sequence, Vec::<u8>::new()).unwrap(),
        };
        let message = opaque_from_der(
            &headers,
            "application/pkcs7-mime",
            &content_info.to_der().unwrap(),
        );
        assert_eq!(
            verify_message(message.as_bytes()),
            Verification::NotSigned,
            "{oid}"
        );
        assert_eq!(stored(message.as_bytes(), false), (None, None), "{oid}");
    }
}

// ── El opaque se muestra ──────────────────────────────────────────────

/// En el opaque el cuerpo está **adentro** del PKCS#7: sin desenvolverlo, la
/// ventana mostraría un mensaje en blanco y sin adjuntos.
#[test]
fn el_opaque_firmado_se_muestra_con_su_texto_y_sus_adjuntos() {
    let signed = sign(RSA_P12, &draft_with_attachments(RSA_ADDRESS));
    let message = opaque(&signed, "application/pkcs7-mime");

    let (body, attachments) = crate::email_sync::opened_rows(7, message.as_bytes(), false);
    let text = body.text_body.unwrap_or_default();
    assert!(text.contains("Va el informe"), "{text:?}");
    let names: Vec<_> = attachments.iter().filter_map(|a| a.name.clone()).collect();
    assert!(names.iter().any(|n| n == "datos.bin"), "{names:?}");
    assert_eq!(body.smime_status, Some(0));
    assert_eq!(body.smime_signer.as_deref(), Some(RSA_ADDRESS));
}

// ── Lo que no se pudo comprobar no deja estado ────────────────────────

/// Cada una falla por **su** motivo y ninguna deja estado guardado: ni
/// «firmado» ni firmante. (No se confunde con el cert vencido, que sí se guarda.)
#[test]
fn lo_que_no_se_pudo_comprobar_queda_sin_estado_ni_firmante() {
    let honest = sign(RSA_P12, &draft_with_attachments(RSA_ADDRESS));
    let by_from = sign(RSA_P12, &draft("otro@vasak.test", "hola"));
    let digest = honest.message.replace("Va el informe", "Va el enorme!");
    let altered = rewrite_signature(&honest.message, |mut der| {
        *der.last_mut().unwrap() ^= 1;
        der
    });
    let cut = &honest.message[..honest.message.rfind("\r\n--").unwrap() - 40];

    for (raw, reason) in [
        (by_from.message.as_str(), "From"),
        (digest.as_str(), "messageDigest"),
        (altered.as_str(), "inválida"),
        (cut, ""),
    ] {
        let found = unverified_reason(verify_message(raw.as_bytes()));
        assert!(found.contains(reason), "esperaba «{reason}», dio «{found}»");
        assert_eq!(stored(raw.as_bytes(), false), (None, None), "{reason}");
    }

    // Y un crudo bien firmado pero cortado por el tope de descarga.
    let truncated = &honest.message.as_bytes()[..honest.message.len() / 2];
    assert_eq!(stored(truncated, true), (None, None));
}

// ── Ligar con vacíos ──────────────────────────────────────────────────

/// `"" == ""` no liga nada: sin `From` y con un cert de correo vacío, la firma
/// es buena y aun así no es de nadie.
#[test]
fn un_from_vacio_y_un_cert_de_correo_vacio_no_se_ligan() {
    let signed = sign(EC_EMPTY_EMAIL_P12, &draft("x@vasak.test", "hola"));

    let without_from = signed
        .message
        .split("\r\n")
        .filter(|line| !line.starts_with("From: "))
        .collect::<Vec<_>>()
        .join("\r\n");
    let empty_from = replace_header(&signed.message, "From", "");

    for (what, raw) in [
        ("con un From de verdad", signed.message.as_str()),
        ("sin From", without_from.as_str()),
        ("con el From vacío", empty_from.as_str()),
    ] {
        let reason = unverified_reason(verify_message(raw.as_bytes()));
        assert!(reason.contains("From"), "{what}: {reason}");
        assert_eq!(stored(raw.as_bytes(), false), (None, None), "{what}");
    }
}
