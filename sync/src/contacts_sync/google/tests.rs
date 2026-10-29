//! El enriquecimiento de contactos de Google por la People API, contra un
//! endpoint de People de mentira en `127.0.0.1` (el `FakeGraph` compartido, que
//! sirve una cola de JSON y anota los pedidos), sin red, sin bus y con el llavero
//! falso.
//!
//! La descarga de la foto NO va por acá: en producción pasa por `images::fetch`,
//! que rechaza el loopback del endpoint falso a propósito (es el guard
//! anti-SSRF). Por eso [`enrich_photos`] recibe el fetcher como parámetro y las
//! pruebas le dan uno de mentira que devuelve los bytes sin tocar la red; el
//! guard en sí lo prueban `images` (loopback/privadas) y
//! [`is_google_photo_host`] acá abajo.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use base64::Engine;

use super::{
    check_photo_size, enrich_photos, fetch_connections, fetch_contact_groups, fetch_photo,
    is_google_photo_host, GoogleBackend, PeopleError, PeopleLimits, MAX_GROUPS_PER_CONTACT,
    MAX_GROUP_NAME_CHARS, PHOTO_MAX_BYTES,
};
use crate::contacts_sync::backend::{SyncContext, SyncResult};
use crate::dav::fake::{card, FakeDav};
use crate::dav::webdav::{AuthKind, DavCredential, HttpPolicy};
use crate::graph::fake::{client, FakeGraph, TOKEN};
use crate::store::contacts::tests::row;
use crate::store::contacts::{ContactEnrichment, ContactOp};
use crate::store::key::fake::FakeKeys;
use crate::store::lifecycle::{
    AccountListing, Consent, ListedAccount, Locations, StoreManager, CONTACTS_AREA,
};
use crate::store::paths::tests::TempDir;

const ACCOUNT: &str = "cuenta";

/// Un almacén listo, con la cuenta dada de alta y el área de contactos activa.
async fn store(label: &str) -> (TempDir, Arc<StoreManager<FakeKeys>>) {
    let temp = TempDir::new(label);
    let keys = FakeKeys::default();
    let manager = Arc::new(StoreManager::new(
        keys,
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
    assert!(manager
        .activate_area(CONTACTS_AREA, ACCOUNT, Consent::Granted)
        .await
        .unwrap());
    (temp, manager)
}

/// Deja un contacto con su correo en el almacén y devuelve su `id`.
async fn seed(manager: &Arc<StoreManager<FakeKeys>>, name: &str, email: &str) -> i64 {
    let book = manager
        .with_store(ACCOUNT, |s| {
            s.upsert_address_books(&[("book://1".into(), "Libreta".into())])
        })
        .await
        .unwrap()
        .pop()
        .unwrap();
    let href = format!("https://x/a/{name}.vcf");
    let name_owned = name.to_string();
    let email_owned = email.to_string();
    manager
        .with_store(ACCOUNT, move |s| {
            s.apply_contacts(
                &book,
                &[ContactOp::Upsert(row(&href, &name_owned, &email_owned))],
                None,
                u64::MAX,
            )
        })
        .await
        .unwrap();
    let name_q = name.to_string();
    manager
        .with_store(ACCOUNT, move |s| {
            Ok(s.connection()
                .query_row(
                    "SELECT id FROM contacts WHERE display_name = ?1",
                    [name_q],
                    |r| r.get(0),
                )
                .unwrap())
        })
        .await
        .unwrap()
}

/// Un fetcher de fotos de mentira que cuenta cuántas veces se lo llamó y
/// devuelve bytes fijos. Sustituye a `images::fetch`, que no puede hablar con el
/// loopback del endpoint falso.
fn stub_fetcher(
    calls: Arc<AtomicUsize>,
) -> impl Fn(String) -> std::future::Ready<Result<(Vec<u8>, String), String>> {
    move |_url: String| {
        calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok((b"JPEGBYTES".to_vec(), "image/jpeg".to_string())))
    }
}

/// De punta a punta: una persona de People casa por email con el contacto local,
/// se persiste el enlace (`resourceName`/`etag`/`photo_etag`) y se guarda la foto.
/// El casamiento es insensible a mayúsculas.
#[tokio::test]
async fn casa_por_email_persiste_el_enlace_y_guarda_la_foto() {
    let (_temp, manager) = store("google_match").await;
    let id = seed(&manager, "Ana", "ana@x.com").await;

    let server = FakeGraph::start().await;
    server.push(
        r#"{"connections":[{"resourceName":"people/c1","etag":"\"e1\"",
            "emailAddresses":[{"value":"ANA@x.com"}],
            "photos":[{"url":"https://lh3.googleusercontent.com/p1"}]}]}"#,
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let (fetched, unchanged) = enrich_photos(
        &manager,
        ACCOUNT,
        TOKEN,
        &server.base_url(),
        PeopleLimits::DEFAULT,
        stub_fetcher(calls.clone()),
    )
    .await
    .unwrap();

    assert_eq!((fetched, unchanged), (1, 0));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let link = manager
        .with_store(ACCOUNT, move |s| s.contact_enrichment(id))
        .await
        .unwrap()
        .expect("el enlace se tiene que haber guardado");
    assert_eq!(link.resource_name, "people/c1");
    assert_eq!(link.etag.as_deref(), Some("\"e1\""));
    assert_eq!(
        link.photo_etag.as_deref(),
        Some("https://lh3.googleusercontent.com/p1")
    );

    let photo = manager
        .with_store(ACCOUNT, move |s| s.contact_photo(id))
        .await
        .unwrap()
        .expect("la foto se tiene que haber guardado");
    assert_eq!(photo, (b"JPEGBYTES".to_vec(), "image/jpeg".to_string()));

    // El token viajó al endpoint de People, y nada más.
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].authorization, format!("Bearer {TOKEN}"));
    assert!(requests[0].path.contains("/people/me/connections"));
}

/// La segunda corrida es incremental: con el mismo `resourceName` y la misma url
/// de foto no se vuelve a bajar; si la foto cambia, sí.
#[tokio::test]
async fn la_segunda_corrida_no_rebaja_si_no_cambio_la_foto() {
    let (_temp, manager) = store("google_incremental").await;
    seed(&manager, "Ana", "ana@x.com").await;

    let calls = Arc::new(AtomicUsize::new(0));
    let page = |url: &str| {
        format!(
            r#"{{"connections":[{{"resourceName":"people/c1","etag":"\"e1\"",
                "emailAddresses":[{{"value":"ana@x.com"}}],
                "photos":[{{"url":"{url}"}}]}}]}}"#
        )
    };

    // Primera corrida: baja.
    let server = FakeGraph::start().await;
    server.push(page("https://lh3.googleusercontent.com/p1"));
    let (fetched, unchanged) = enrich_photos(
        &manager,
        ACCOUNT,
        TOKEN,
        &server.base_url(),
        PeopleLimits::DEFAULT,
        stub_fetcher(calls.clone()),
    )
    .await
    .unwrap();
    assert_eq!((fetched, unchanged), (1, 0));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // Segunda corrida, misma foto: no baja.
    let server = FakeGraph::start().await;
    server.push(page("https://lh3.googleusercontent.com/p1"));
    let (fetched, unchanged) = enrich_photos(
        &manager,
        ACCOUNT,
        TOKEN,
        &server.base_url(),
        PeopleLimits::DEFAULT,
        stub_fetcher(calls.clone()),
    )
    .await
    .unwrap();
    assert_eq!((fetched, unchanged), (0, 1));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "no se llamó al fetcher de nuevo"
    );

    // Tercera corrida, foto distinta: baja de nuevo.
    let server = FakeGraph::start().await;
    server.push(page("https://lh3.googleusercontent.com/p2"));
    let (fetched, unchanged) = enrich_photos(
        &manager,
        ACCOUNT,
        TOKEN,
        &server.base_url(),
        PeopleLimits::DEFAULT,
        stub_fetcher(calls.clone()),
    )
    .await
    .unwrap();
    assert_eq!((fetched, unchanged), (1, 0));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// Una persona sin un email que case con la agenda local no se enriquece: es el
/// trade-off aceptado en #111.
#[tokio::test]
async fn una_persona_sin_email_que_case_no_se_enriquece() {
    let (_temp, manager) = store("google_sin_match").await;
    let id = seed(&manager, "Ana", "ana@x.com").await;

    let server = FakeGraph::start().await;
    server.push(
        r#"{"connections":[{"resourceName":"people/c9",
            "emailAddresses":[{"value":"otro@x.com"}],
            "photos":[{"url":"https://lh3.googleusercontent.com/p9"}]}]}"#,
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let (fetched, unchanged) = enrich_photos(
        &manager,
        ACCOUNT,
        TOKEN,
        &server.base_url(),
        PeopleLimits::DEFAULT,
        stub_fetcher(calls.clone()),
    )
    .await
    .unwrap();

    assert_eq!((fetched, unchanged), (0, 0));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(manager
        .with_store(ACCOUNT, move |s| s.contact_photo(id))
        .await
        .unwrap()
        .is_none());
}

/// No se enriquece un contacto con una op pendiente: una edición local sin
/// confirmar queda fuera del casamiento, igual que el guard de `apply_contacts`.
#[tokio::test]
async fn no_se_enriquece_un_contacto_con_op_pendiente() {
    let (_temp, manager) = store("google_pending").await;
    let id = seed(&manager, "Ana", "ana@x.com").await;
    // Marcar la edición local sin confirmar.
    manager
        .with_store(ACCOUNT, move |s| {
            s.connection()
                .execute("UPDATE contacts SET pending_op = 'put' WHERE id = ?1", [id])
                .unwrap();
            Ok(())
        })
        .await
        .unwrap();

    let server = FakeGraph::start().await;
    server.push(
        r#"{"connections":[{"resourceName":"people/c1",
            "emailAddresses":[{"value":"ana@x.com"}],
            "photos":[{"url":"https://lh3.googleusercontent.com/p1"}]}]}"#,
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let (fetched, unchanged) = enrich_photos(
        &manager,
        ACCOUNT,
        TOKEN,
        &server.base_url(),
        PeopleLimits::DEFAULT,
        stub_fetcher(calls.clone()),
    )
    .await
    .unwrap();

    assert_eq!((fetched, unchanged), (0, 0));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no se tocó el contacto pendiente"
    );
    assert!(manager
        .with_store(ACCOUNT, move |s| s.contact_photo(id))
        .await
        .unwrap()
        .is_none());
}

/// La foto entra al vCard **de la lectura** (no al crudo guardado), antes del
/// `END:VCARD`, y sólo cuando el contacto no tiene op pendiente.
#[tokio::test]
async fn la_foto_entra_en_la_lectura_pero_no_con_op_pendiente() {
    let (_temp, manager) = store("google_lectura").await;
    let id = seed(&manager, "Ana", "ana@x.com").await;
    manager
        .with_store(ACCOUNT, move |s| {
            s.upsert_contact_enrichment(&ContactEnrichment {
                contact_id: id,
                resource_name: "people/c1".into(),
                etag: None,
                photo_etag: Some("u".into()),
            })?;
            s.set_contact_photo(id, b"hello", "image/png")
        })
        .await
        .unwrap();

    // El crudo guardado NO lleva la foto.
    let raw: String = manager
        .with_store(ACCOUNT, move |s| {
            Ok(s.connection()
                .query_row("SELECT raw_vcard FROM contacts WHERE id = ?1", [id], |r| {
                    r.get(0)
                })
                .unwrap())
        })
        .await
        .unwrap();
    assert!(!raw.contains("PHOTO"), "el crudo no se tocó");

    // La lectura sí la inyecta, antes del cierre.
    let card = manager
        .with_store(ACCOUNT, |s| {
            Ok(crate::store::contacts_read::list_cards(s.connection(), None, None, 100).unwrap())
        })
        .await
        .unwrap()
        .items
        .pop()
        .expect("hay una tarjeta");
    let expected = base64::engine::general_purpose::STANDARD.encode(b"hello");
    assert!(
        card.vcard
            .contains(&format!("PHOTO;ENCODING=b;TYPE=PNG:{expected}")),
        "la foto entra en la lectura: {}",
        card.vcard
    );
    assert!(card.vcard.find("PHOTO").unwrap() < card.vcard.find("END:VCARD").unwrap());

    // Con una op pendiente, la lectura no inyecta la foto.
    manager
        .with_store(ACCOUNT, move |s| {
            s.connection()
                .execute("UPDATE contacts SET pending_op = 'put' WHERE id = ?1", [id])
                .unwrap();
            Ok(())
        })
        .await
        .unwrap();
    let card = manager
        .with_store(ACCOUNT, |s| {
            Ok(crate::store::contacts_read::list_cards(s.connection(), None, None, 100).unwrap())
        })
        .await
        .unwrap()
        .items
        .pop()
        .expect("sigue habiendo una tarjeta");
    assert!(
        !card.vcard.contains("PHOTO"),
        "con op pendiente no se inyecta la foto"
    );
}

/// El paginador acota: deduplica el `pageToken` (bucle), tope de páginas y tope
/// de personas. Todas abortan sin mandar nada a otro host (la url la construimos
/// nosotros sobre la base).
#[tokio::test]
async fn el_paginador_corta_un_token_repetido() {
    let server = FakeGraph::start().await;
    // Dos páginas con el MISMO token: la segunda vez ya se vio.
    server.push(r#"{"connections":[],"nextPageToken":"t1"}"#);
    server.push(r#"{"connections":[],"nextPageToken":"t1"}"#);
    let result =
        fetch_connections(&client(), TOKEN, &server.base_url(), &PeopleLimits::DEFAULT).await;
    assert!(matches!(result, Err(PeopleError::PaginationLoop)));
}

#[tokio::test]
async fn el_paginador_corta_por_tope_de_paginas() {
    let server = FakeGraph::start().await;
    server.push(r#"{"connections":[],"nextPageToken":"t1"}"#);
    let limits = PeopleLimits {
        max_pages: 1,
        ..PeopleLimits::DEFAULT
    };
    let result = fetch_connections(&client(), TOKEN, &server.base_url(), &limits).await;
    assert!(matches!(result, Err(PeopleError::TooManyPages)));
}

#[tokio::test]
async fn el_paginador_corta_por_tope_de_personas() {
    let server = FakeGraph::start().await;
    server.push(r#"{"connections":[{"resourceName":"people/c1"},{"resourceName":"people/c2"}]}"#);
    let limits = PeopleLimits {
        max_people: 1,
        ..PeopleLimits::DEFAULT
    };
    let result = fetch_connections(&client(), TOKEN, &server.base_url(), &limits).await;
    assert!(matches!(result, Err(PeopleError::TooManyItems)));
}

/// El allowlist del host de la foto: sólo `googleusercontent.com` y sus
/// subdominios; nada de un host que lo imite ni de otro cualquiera.
#[test]
fn solo_se_baja_la_foto_de_un_host_de_google() {
    assert!(is_google_photo_host("lh3.googleusercontent.com"));
    assert!(is_google_photo_host("googleusercontent.com"));
    assert!(is_google_photo_host("GOOGLEUSERCONTENT.COM"));
    for bad in [
        "evil.com",
        "googleusercontent.com.evil.com",
        "notgoogleusercontent.com",
        "lh3.googleusercontent.com.attacker.net",
        "",
    ] {
        assert!(!is_google_photo_host(bad), "{bad} no es de Google");
    }
}

// ── Pruebas de qa: bordes de la pasada de fotos ─────────────────────────────

/// Un contacto SIN email no se casa, ni siquiera con una persona de People cuyo
/// correo viene vacío: el `''` no es una clave (trade-off aceptado en #111).
#[tokio::test]
async fn un_contacto_sin_email_no_se_casa_ni_con_un_correo_vacio() {
    let (_temp, manager) = store("google_contacto_sin_email").await;
    let id = seed(&manager, "Sin", "").await;
    // Por si una fila con correo vacío llegara al almacén (no debería): igual no
    // es una clave de casamiento.
    manager
        .with_store(ACCOUNT, move |s| {
            s.connection()
                .execute(
                    "INSERT OR REPLACE INTO contact_emails (contact_id, position, label, value)
                     VALUES (?1, 0, '', '')",
                    [id],
                )
                .unwrap();
            Ok(())
        })
        .await
        .unwrap();

    let server = FakeGraph::start().await;
    server.push(
        r#"{"connections":[{"resourceName":"people/c1",
            "emailAddresses":[{"value":""},{}],
            "photos":[{"url":"https://lh3.googleusercontent.com/p1"}]}]}"#,
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let (fetched, unchanged) = enrich_photos(
        &manager,
        ACCOUNT,
        TOKEN,
        &server.base_url(),
        PeopleLimits::DEFAULT,
        stub_fetcher(calls.clone()),
    )
    .await
    .unwrap();

    assert_eq!((fetched, unchanged), (0, 0));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(manager
        .with_store(ACCOUNT, move |s| s.contact_enrichment(id))
        .await
        .unwrap()
        .is_none());
}

/// El monograma que Google genera solo (`"default": true`) no se baja.
#[tokio::test]
async fn la_foto_por_defecto_de_google_no_se_baja() {
    let (_temp, manager) = store("google_monograma").await;
    let id = seed(&manager, "Ana", "ana@x.com").await;

    let server = FakeGraph::start().await;
    server.push(
        r#"{"connections":[{"resourceName":"people/c1",
            "emailAddresses":[{"value":"ana@x.com"}],
            "photos":[{"url":"https://lh3.googleusercontent.com/mono","default":true}]}]}"#,
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let (fetched, _) = enrich_photos(
        &manager,
        ACCOUNT,
        TOKEN,
        &server.base_url(),
        PeopleLimits::DEFAULT,
        stub_fetcher(calls.clone()),
    )
    .await
    .unwrap();

    assert_eq!(fetched, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(manager
        .with_store(ACCOUNT, move |s| s.contact_photo(id))
        .await
        .unwrap()
        .is_none());
}

/// La segunda corrida, contra el endpoint falso, **no pide la foto otra vez**: el
/// fetcher cuenta cero llamadas nuevas y People recibe un solo pedido por
/// corrida (el listado), nunca uno por la foto.
#[tokio::test]
async fn la_segunda_corrida_con_los_mismos_testigos_no_vuelve_a_bajar() {
    let (_temp, manager) = store("google_incremental_fetch").await;
    seed(&manager, "Ana", "ana@x.com").await;
    let page = r#"{"connections":[{"resourceName":"people/c1","etag":"\"e1\"",
        "emailAddresses":[{"value":"ana@x.com"}],
        "photos":[{"url":"https://lh3.googleusercontent.com/p1"}]}]}"#;

    let calls = Arc::new(AtomicUsize::new(0));
    let server = FakeGraph::start().await;
    server.push(page);
    server.push(page);
    for _ in 0..2 {
        enrich_photos(
            &manager,
            ACCOUNT,
            TOKEN,
            &server.base_url(),
            PeopleLimits::DEFAULT,
            stub_fetcher(calls.clone()),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "dos corridas con los mismos testigos, una sola descarga"
    );
    assert_eq!(server.requests().len(), 2, "un listado por corrida");
}

/// Un servidor que repite el `pageToken` para siempre **termina**: con un token
/// repetido corta en el segundo pedido (no consume la cola entera), y con tokens
/// siempre nuevos corta exactamente en `max_pages` pedidos.
#[tokio::test]
async fn el_paginador_termina_con_un_servidor_que_no_corta() {
    // Token repetido: cola con 50 páginas iguales; tiene que parar en la 2.ª.
    let server = FakeGraph::start().await;
    for _ in 0..50 {
        server.push(r#"{"connections":[],"nextPageToken":"t1"}"#);
    }
    let result =
        fetch_connections(&client(), TOKEN, &server.base_url(), &PeopleLimits::DEFAULT).await;
    assert!(matches!(result, Err(PeopleError::PaginationLoop)));
    assert_eq!(
        server.requests().len(),
        2,
        "el token repetido se corta apenas se ve por segunda vez"
    );

    // Tokens siempre nuevos: para exactamente en el tope de páginas.
    let server = FakeGraph::start().await;
    for n in 0..50 {
        server.push(format!(r#"{{"connections":[],"nextPageToken":"n{n}"}}"#));
    }
    let limits = PeopleLimits {
        max_pages: 3,
        ..PeopleLimits::DEFAULT
    };
    let result = fetch_connections(&client(), TOKEN, &server.base_url(), &limits).await;
    assert!(matches!(result, Err(PeopleError::TooManyPages)));
    assert_eq!(server.requests().len(), 3, "ni un pedido más que el tope");
}

/// El `nextPageToken` es opaco: viaja como parámetro de NUESTRA url, y el token
/// de acceso sólo va al endpoint de People.
#[tokio::test]
async fn el_page_token_se_pega_a_nuestra_url_y_no_se_sigue_ninguna_otra() {
    let server = FakeGraph::start().await;
    server.push(r#"{"connections":[],"nextPageToken":"http://evil.example/steal"}"#);
    server.push(r#"{"connections":[{"resourceName":"people/c1"}]}"#);
    let people = fetch_connections(&client(), TOKEN, &server.base_url(), &PeopleLimits::DEFAULT)
        .await
        .unwrap();
    assert_eq!(people.len(), 1);
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].path.contains("/people/me/connections"));
    assert!(requests[1].path.contains("pageToken="));
}

/// El allowlist está **cableado** en la descarga real: una url que no es de
/// Google se rechaza antes de tocar la red (la loopback, el host imitador y el
/// esquema que no es web).
#[tokio::test]
async fn la_descarga_real_rechaza_un_host_que_no_es_de_google() {
    for bad in [
        "http://127.0.0.1:1/p.jpg",
        "https://googleusercontent.com.evil.com/p.jpg",
        "https://evilgoogleusercontent.com/p.jpg",
        "file:///etc/passwd",
        "no es una url",
    ] {
        let result = fetch_photo(bad).await;
        assert!(result.is_err(), "{bad} no debería bajarse");
    }
    let err = fetch_photo("https://googleusercontent.com.evil.com/p.jpg")
        .await
        .unwrap_err();
    assert!(
        err.contains("host de Google"),
        "rechazo por el allowlist: {err}"
    );
}

/// El tope de 2 MB: una foto justo en el límite entra, una de un byte más se
/// rechaza. Sin esta guardia, una foto gigante pasaría derecho al guardado.
#[test]
fn el_tope_de_la_foto_deja_pasar_el_limite_y_rechaza_lo_que_lo_supera() {
    assert!(
        check_photo_size(&vec![0u8; PHOTO_MAX_BYTES]),
        "2 MB justo entra"
    );
    assert!(
        !check_photo_size(&vec![0u8; PHOTO_MAX_BYTES + 1]),
        "un byte de más se rechaza"
    );
}

/// Imitaciones del host que un `ends_with` descuidado dejaría pasar.
#[test]
fn el_allowlist_rechaza_imitaciones_del_host() {
    for bad in [
        "googleusercontent.com.evil.com",
        "evilgoogleusercontent.com",
        "lh3.googleusercontent.com.evil.com",
        "googleusercontent.comx",
        "xgoogleusercontent.com",
        "lh3.googleusercontent.com@evil.com",
    ] {
        assert!(!is_google_photo_host(bad), "{bad}");
    }
    for good in ["lh3.googleusercontent.com", "lh3.googleusercontent.com."] {
        assert!(is_google_photo_host(good), "{good}");
    }
}

/// Guardar una foto sube la generación de los contactos; sin fila de enlace no
/// toca nada ni la sube.
#[tokio::test]
async fn guardar_una_foto_sube_la_generacion_y_sin_enlace_no_toca_nada() {
    let (_temp, manager) = store("google_generacion").await;
    let id = seed(&manager, "Ana", "ana@x.com").await;
    let generation = |m: Arc<StoreManager<FakeKeys>>| async move {
        m.with_store(ACCOUNT, |s| {
            crate::store::read_generation(s.connection(), CONTACTS_AREA)
        })
        .await
        .unwrap()
    };

    // Sin fila de enlace: nada que enriquecer.
    let before = generation(manager.clone()).await;
    manager
        .with_store(ACCOUNT, move |s| s.set_contact_photo(id, b"x", "image/png"))
        .await
        .unwrap();
    assert_eq!(generation(manager.clone()).await, before);
    assert!(manager
        .with_store(ACCOUNT, move |s| s.contact_photo(id))
        .await
        .unwrap()
        .is_none());

    // Con enlace: sube.
    manager
        .with_store(ACCOUNT, move |s| {
            s.upsert_contact_enrichment(&ContactEnrichment {
                contact_id: id,
                resource_name: "people/c1".into(),
                etag: None,
                photo_etag: Some("u".into()),
            })?;
            s.set_contact_photo(id, b"x", "image/png")
        })
        .await
        .unwrap();
    assert!(generation(manager.clone()).await > before);
}

/// La inyección es **sólo de lectura**: el `raw_vcard` guardado queda
/// byte por byte igual antes y después de leer, con y sin op pendiente, y con op
/// pendiente la tarjeta servida es exactamente el crudo.
#[tokio::test]
async fn la_lectura_no_toca_el_crudo_con_ni_sin_op_pendiente() {
    let (_temp, manager) = store("google_crudo_intacto").await;
    let id = seed(&manager, "Ana", "ana@x.com").await;
    manager
        .with_store(ACCOUNT, move |s| {
            s.upsert_contact_enrichment(&ContactEnrichment {
                contact_id: id,
                resource_name: "people/c1".into(),
                etag: None,
                photo_etag: Some("u".into()),
            })?;
            s.set_contact_photo(id, b"hello", "image/png")
        })
        .await
        .unwrap();

    let read_raw = |m: Arc<StoreManager<FakeKeys>>| async move {
        m.with_store(ACCOUNT, move |s| {
            Ok(s.connection()
                .query_row("SELECT raw_vcard FROM contacts WHERE id = ?1", [id], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap())
        })
        .await
        .unwrap()
    };
    let read_card = |m: Arc<StoreManager<FakeKeys>>| async move {
        m.with_store(ACCOUNT, |s| {
            Ok(crate::store::contacts_read::list_cards(s.connection(), None, None, 100).unwrap())
        })
        .await
        .unwrap()
        .items
        .pop()
        .unwrap()
        .vcard
    };

    let raw_before = read_raw(manager.clone()).await;

    // Sin op pendiente: la tarjeta lleva la foto, el crudo sigue igual.
    let served = read_card(manager.clone()).await;
    assert!(served.contains("PHOTO;ENCODING=b;TYPE=PNG:"));
    assert_eq!(read_raw(manager.clone()).await, raw_before);

    // Con op pendiente: la tarjeta es exactamente el crudo, y éste no cambió.
    manager
        .with_store(ACCOUNT, move |s| {
            s.connection()
                .execute("UPDATE contacts SET pending_op = 'put' WHERE id = ?1", [id])
                .unwrap();
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(read_card(manager.clone()).await, raw_before);
    assert_eq!(read_raw(manager.clone()).await, raw_before);
}

/// Al volver a quedar sin op pendiente la foto vuelve sola a la lectura (no se
/// perdió al servir la tarjeta cruda).
#[tokio::test]
async fn la_foto_vuelve_a_la_lectura_cuando_se_va_la_op_pendiente() {
    let (_temp, manager) = store("google_foto_vuelve").await;
    let id = seed(&manager, "Ana", "ana@x.com").await;
    manager
        .with_store(ACCOUNT, move |s| {
            s.upsert_contact_enrichment(&ContactEnrichment {
                contact_id: id,
                resource_name: "people/c1".into(),
                etag: None,
                photo_etag: Some("u".into()),
            })?;
            s.set_contact_photo(id, b"hello", "image/png")?;
            s.connection()
                .execute("UPDATE contacts SET pending_op = 'put' WHERE id = ?1", [id])
                .unwrap();
            s.connection()
                .execute("UPDATE contacts SET pending_op = NULL WHERE id = ?1", [id])
                .unwrap();
            Ok(())
        })
        .await
        .unwrap();
    let vcard = manager
        .with_store(ACCOUNT, |s| {
            Ok(crate::store::contacts_read::list_cards(s.connection(), None, None, 100).unwrap())
        })
        .await
        .unwrap()
        .items
        .pop()
        .unwrap()
        .vcard;
    assert!(vcard.contains("PHOTO;ENCODING=b;TYPE=PNG:"));
}

/// Un backend Google de punta a punta: el CardDAV sincroniza, la pasada de People
/// usa el mismo token (sólo hacia People) y, si la foto no baja (acá el host no
/// es de Google, así que la descarga real la rechaza sin tocar la red), la vuelta
/// sigue siendo `Synced` con los contactos guardados.
#[tokio::test]
async fn el_backend_google_sincroniza_el_carddav_y_enriquece_con_el_mismo_token() {
    let (_temp, manager) = store("google_backend").await;
    let dav = FakeDav::start().await;
    dav.put(0, "ana.vcf", &card("u1", "Ana", "ana@x.com"));
    let people = FakeGraph::start().await;
    people.push(
        r#"{"connections":[{"resourceName":"people/c1",
            "emailAddresses":[{"value":"ana@x.com"}],
            "photos":[{"url":"https://evil.example/p.jpg"}]}]}"#,
    );
    let credential = DavCredential {
        home: dav.home_url(),
        username: "ana".into(),
        secret: zeroize::Zeroizing::new(TOKEN.into()),
        auth: AuthKind::Token,
    };
    let ctx = SyncContext {
        manager: &manager,
        account_id: ACCOUNT,
        notify: Arc::new(|| {}),
    };
    let outcome = GoogleBackend
        .sync(
            ctx,
            &credential,
            HttpPolicy::plain_loopback(),
            Some(&people.base_url()),
        )
        .await;
    let SyncResult::Synced(report) = outcome else {
        panic!("la vuelta tenía que terminar Synced");
    };
    assert_eq!(report.photos_fetched, 0, "el host no es de Google");
    let contacts: i64 = manager
        .with_store(ACCOUNT, |s| {
            Ok(s.connection()
                .query_row("SELECT COUNT(*) FROM contacts", [], |r| r.get(0))
                .unwrap())
        })
        .await
        .unwrap();
    assert_eq!(contacts, 1, "el CardDAV guardó el contacto");

    let requests = people.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].authorization, format!("Bearer {TOKEN}"));
}

/// Si People falla (500), los contactos del CardDAV quedan y la vuelta sigue
/// `Synced`; el motivo queda en la bitácora. Y sin token OAuth no se llama a
/// People.
#[tokio::test]
async fn si_people_falla_la_vuelta_sigue_synced_y_sin_token_no_se_la_llama() {
    let (_temp, manager) = store("google_mejor_esfuerzo").await;
    let dav = FakeDav::start().await;
    dav.put(0, "ana.vcf", &card("u1", "Ana", "ana@x.com"));
    let people = FakeGraph::start().await; // cola vacía: contesta 500
    let credential = |auth| DavCredential {
        home: dav.home_url(),
        username: "ana".into(),
        secret: zeroize::Zeroizing::new(TOKEN.into()),
        auth,
    };

    let run = |auth| {
        let manager = &manager;
        let credential = credential(auth);
        let url = people.base_url();
        async move {
            GoogleBackend
                .sync(
                    SyncContext {
                        manager,
                        account_id: ACCOUNT,
                        notify: Arc::new(|| {}),
                    },
                    &credential,
                    HttpPolicy::plain_loopback(),
                    Some(&url),
                )
                .await
        }
    };

    assert!(matches!(run(AuthKind::Token).await, SyncResult::Synced(_)));
    assert_eq!(people.requests().len(), 1);
    let logged: i64 = manager
        .with_store(ACCOUNT, |s| {
            Ok(s.connection()
                .query_row(
                    "SELECT COUNT(*) FROM sync_log WHERE message LIKE '%no se completó%'",
                    [],
                    |r| r.get(0),
                )
                .unwrap())
        })
        .await
        .unwrap();
    assert_eq!(logged, 1);

    // Sin token (contraseña): ni un pedido más a People.
    assert!(matches!(
        run(AuthKind::Password).await,
        SyncResult::Synced(_)
    ));
    assert_eq!(people.requests().len(), 1, "sin token no se llama a People");
}

// ── Grupos/etiquetas y destacado (PR3 de #111) ───────────────────────────────

/// La tarjeta de salida de la lectura (`list_cards`), la primera.
async fn read_vcard(manager: &Arc<StoreManager<FakeKeys>>) -> String {
    manager
        .with_store(ACCOUNT, |s| {
            Ok(crate::store::contacts_read::list_cards(s.connection(), None, None, 100).unwrap())
        })
        .await
        .unwrap()
        .items
        .pop()
        .expect("hay una tarjeta")
        .vcard
}

async fn read_raw(manager: &Arc<StoreManager<FakeKeys>>, id: i64) -> String {
    manager
        .with_store(ACCOUNT, move |s| {
            Ok(s.connection()
                .query_row("SELECT raw_vcard FROM contacts WHERE id = ?1", [id], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap())
        })
        .await
        .unwrap()
}

async fn generation(manager: &Arc<StoreManager<FakeKeys>>) -> u64 {
    manager
        .with_store(ACCOUNT, |s| {
            crate::store::read_generation(s.connection(), CONTACTS_AREA)
        })
        .await
        .unwrap()
}

/// Una pasada de enriquecimiento con el fetcher de fotos de mentira.
async fn enrich(
    manager: &Arc<StoreManager<FakeKeys>>,
    server: &FakeGraph,
) -> Result<(usize, usize), PeopleError> {
    enrich_photos(
        manager,
        ACCOUNT,
        TOKEN,
        &server.base_url(),
        PeopleLimits::DEFAULT,
        stub_fetcher(Arc::new(AtomicUsize::new(0))),
    )
    .await
}

/// Un grupo de la respuesta de `contactGroups.list`.
fn group_json(resource: &str, name: &str) -> String {
    format!(r#"{{"resourceName":"{resource}","formattedName":"{name}"}}"#)
}

/// Casa por email, con los nombres del catálogo: los grupos entran a la lectura
/// como `CATEGORIES` y la pertenencia a `contactGroups/starred` como
/// `X-VASAK-STARRED:1`; el grupo de destacado **no** es una categoría; el crudo
/// guardado no se toca; y se pidió `memberships` y el catálogo.
#[tokio::test]
async fn los_grupos_y_el_destacado_de_people_entran_en_la_lectura() {
    let (_temp, manager) = store("google_grupos").await;
    let id = seed(&manager, "Ana", "ana@x.com").await;
    let raw_before = read_raw(&manager, id).await;

    let server = FakeGraph::start().await;
    server.push(
        r#"{"connections":[{"resourceName":"people/c1",
            "emailAddresses":[{"value":"ANA@x.com"}],
            "memberships":[
              {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/starred"}},
              {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/g1"}},
              {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/g2"}},
              {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/g1"}},
              {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/borrado"}}]}]}"#,
    );
    server.push(format!(
        r#"{{"contactGroups":[{},{},{},{}]}}"#,
        group_json("contactGroups/starred", "Favoritos"),
        group_json("contactGroups/g1", "Familia"),
        group_json("contactGroups/g2", "Trabajo"),
        group_json("contactGroups/g9", "Nadie lo usa"),
    ));

    enrich(&manager, &server).await.unwrap();

    let vcard = read_vcard(&manager).await;
    assert!(
        vcard.contains("\r\nCATEGORIES:Familia,Trabajo\r\n"),
        "los grupos entran como CATEGORIES, sin duplicados ni el destacado: {vcard}"
    );
    assert!(vcard.contains("\r\nX-VASAK-STARRED:1\r\n"), "{vcard}");
    assert!(!vcard.contains("Favoritos"), "{vcard}");
    assert!(vcard.find("CATEGORIES").unwrap() < vcard.find("END:VCARD").unwrap());
    assert!(vcard.find("X-VASAK-STARRED").unwrap() < vcard.find("END:VCARD").unwrap());
    assert_eq!(
        read_raw(&manager, id).await,
        raw_before,
        "el crudo no se toca"
    );

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[0].path.contains("memberships"),
        "se piden las pertenencias: {}",
        requests[0].path
    );
    assert!(requests[1].path.contains("/contactGroups"));
    assert_eq!(requests[1].authorization, format!("Bearer {TOKEN}"));
}

/// Sólo el destacado, sin otro grupo: no hace falta el catálogo (un solo pedido),
/// el contacto queda destacado y sin `CATEGORIES`. Una persona sin pertenencias no
/// recibe nada.
#[tokio::test]
async fn el_destacado_solo_no_pide_el_catalogo_y_sin_membresias_no_se_inyecta_nada() {
    let (_temp, manager) = store("google_destacado").await;
    seed(&manager, "Ana", "ana@x.com").await;

    let server = FakeGraph::start().await;
    server.push(
        r#"{"connections":[{"resourceName":"people/c1",
            "emailAddresses":[{"value":"ana@x.com"}],
            "memberships":[
              {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/starred"}},
              {"domainMembership":{"inViewerDomain":true}}]}]}"#,
    );
    enrich(&manager, &server).await.unwrap();
    assert_eq!(server.requests().len(), 1, "sin otro grupo no hay catálogo");
    let vcard = read_vcard(&manager).await;
    assert!(vcard.contains("\r\nX-VASAK-STARRED:1\r\n"), "{vcard}");
    assert!(!vcard.contains("CATEGORIES"), "{vcard}");

    // La misma persona sin pertenencias: ya no es destacada y no hay categorías.
    server.push(
        r#"{"connections":[{"resourceName":"people/c1",
            "emailAddresses":[{"value":"ana@x.com"}]}]}"#,
    );
    enrich(&manager, &server).await.unwrap();
    let vcard = read_vcard(&manager).await;
    assert!(!vcard.contains("X-VASAK-STARRED"), "{vcard}");
    assert!(!vcard.contains("CATEGORIES"), "{vcard}");
}

/// **Anti-inyección de punta a punta**: el nombre de un grupo viene de la red. Con
/// coma, punto y coma, barra y un salto de línea que intenta cerrar la tarjeta y
/// abrir otra, la lectura no gana ninguna propiedad, no se parte la categoría y,
/// al releer, salen los mismos nombres.
#[tokio::test]
async fn un_nombre_de_grupo_hostil_de_la_red_no_inyecta_nada_en_la_lectura() {
    let (_temp, manager) = store("google_grupos_hostiles").await;
    seed(&manager, "Ana", "ana@x.com").await;
    let plain = read_vcard(&manager).await;

    let server = FakeGraph::start().await;
    server.push(
        r#"{"connections":[{"resourceName":"people/c1",
            "emailAddresses":[{"value":"ana@x.com"}],
            "memberships":[
              {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/a"}},
              {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/b"}},
              {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/c"}}]}]}"#,
    );
    server.push(
        r#"{"contactGroups":[
            {"resourceName":"contactGroups/a","formattedName":"Mal\r\nEND:VCARD\r\nBEGIN:VCARD\r\nFN:Evil"},
            {"resourceName":"contactGroups/b","formattedName":"uno, dos;tres\\cuatro\nTEL:+000"},
            {"resourceName":"contactGroups/c","formattedName":"termina en barra\\"}]}"#,
    );
    enrich(&manager, &server).await.unwrap();

    let vcard = read_vcard(&manager).await;
    let lines = crate::vcard::unfold_lines(&vcard);
    let names = |text: &str| -> Vec<String> {
        crate::vcard::unfold_lines(text)
            .iter()
            .filter_map(|l| crate::vcard::split_property(l))
            .map(|p| p.name)
            .collect()
    };
    // Una propiedad más (CATEGORIES) y nada fabricado.
    let mut expected = names(&plain);
    expected.insert(expected.len() - 1, "CATEGORIES".into());
    assert_eq!(names(&vcard), expected, "{vcard:?}");
    assert_eq!(lines.len(), crate::vcard::unfold_lines(&plain).len() + 1);
    for marker in ["BEGIN:VCARD", "END:VCARD"] {
        assert_eq!(lines.iter().filter(|l| l.trim() == marker).count(), 1);
    }

    // Y los nombres se releen tal cual (el `\r` se descarta; el `\n` queda).
    let value =
        crate::vcard::split_property(lines.iter().find(|l| l.starts_with("CATEGORIES")).unwrap())
            .unwrap()
            .value;
    let mut got = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for c in value.chars() {
        match (escaped, c) {
            (true, c) => {
                current.push('\\');
                current.push(c);
                escaped = false;
            }
            (false, '\\') => escaped = true,
            (false, ',') => got.push(std::mem::take(&mut current)),
            (false, c) => current.push(c),
        }
    }
    got.push(current);
    let got: Vec<String> = got.iter().map(|v| crate::vcard::unescape_text(v)).collect();
    assert_eq!(
        got,
        vec![
            "Mal\nEND:VCARD\nBEGIN:VCARD\nFN:Evil".to_string(),
            "uno, dos;tres\\cuatro\nTEL:+000".to_string(),
            "termina en barra\\".to_string(),
        ]
    );
}

/// El largo de un nombre de grupo y la cantidad de grupos por contacto están
/// acotados: son datos de red que van a parar a un vCard.
#[tokio::test]
async fn el_nombre_y_la_cantidad_de_grupos_por_contacto_estan_acotados() {
    let (_temp, manager) = store("google_grupos_acotados").await;
    seed(&manager, "Ana", "ana@x.com").await;

    let total = MAX_GROUPS_PER_CONTACT + 10;
    let memberships: Vec<String> = (0..total)
        .map(|n| {
            format!(r#"{{"contactGroupMembership":{{"contactGroupResourceName":"contactGroups/g{n}"}}}}"#)
        })
        .collect();
    let groups: Vec<String> = (0..total)
        .map(|n| group_json(&format!("contactGroups/g{n}"), &format!("G{n:03}")))
        .collect();
    let long = "ñ".repeat(MAX_GROUP_NAME_CHARS * 4);
    let server = FakeGraph::start().await;
    server.push(format!(
        r#"{{"connections":[{{"resourceName":"people/c1",
            "emailAddresses":[{{"value":"ana@x.com"}}],
            "memberships":[{}]}}]}}"#,
        memberships.join(",")
    ));
    server.push(format!(
        r#"{{"contactGroups":[{},{}]}}"#,
        groups.join(","),
        group_json("contactGroups/largo", &long)
    ));
    enrich(&manager, &server).await.unwrap();

    let vcard = read_vcard(&manager).await;
    let unfolded = crate::vcard::unfold_lines(&vcard);
    let line = unfolded
        .iter()
        .find(|l| l.starts_with("CATEGORIES:"))
        .unwrap();
    assert_eq!(
        line.trim_start_matches("CATEGORIES:").split(',').count(),
        MAX_GROUPS_PER_CONTACT,
        "tope de grupos por contacto"
    );

    // El nombre largo se recorta al tope (en la persona que sí lo tiene).
    let id: i64 = manager
        .with_store(ACCOUNT, |s| {
            Ok(s.connection()
                .query_row("SELECT id FROM contacts", [], |r| r.get(0))
                .unwrap())
        })
        .await
        .unwrap();
    let server = FakeGraph::start().await;
    server.push(
        r#"{"connections":[{"resourceName":"people/c1",
            "emailAddresses":[{"value":"ana@x.com"}],
            "memberships":[{"contactGroupMembership":{"contactGroupResourceName":"contactGroups/largo"}}]}]}"#,
    );
    server.push(format!(
        r#"{{"contactGroups":[{}]}}"#,
        group_json("contactGroups/largo", &long)
    ));
    enrich(&manager, &server).await.unwrap();
    let stored: String = manager
        .with_store(ACCOUNT, move |s| {
            Ok(s.connection()
                .query_row(
                    "SELECT groups FROM contact_enrichment WHERE contact_id = ?1",
                    [id],
                    |r| r.get(0),
                )
                .unwrap())
        })
        .await
        .unwrap();
    let stored: Vec<String> = serde_json::from_str(&stored).unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].chars().count(), MAX_GROUP_NAME_CHARS);
}

/// Mejor esfuerzo: si el catálogo de grupos falla (500), la pasada **no** falla,
/// y el destacado y la foto se aplican igual; sólo faltan los nombres de grupo.
#[tokio::test]
async fn si_el_catalogo_de_grupos_falla_se_aplican_el_destacado_y_la_foto() {
    let (_temp, manager) = store("google_catalogo_falla").await;
    let id = seed(&manager, "Ana", "ana@x.com").await;

    let server = FakeGraph::start().await;
    server.push(
        r#"{"connections":[{"resourceName":"people/c1",
            "emailAddresses":[{"value":"ana@x.com"}],
            "photos":[{"url":"https://lh3.googleusercontent.com/p1"}],
            "memberships":[
              {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/starred"}},
              {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/g1"}}]}]}"#,
    );
    server.push_status(500, "{}"); // el catálogo

    let (fetched, _) = enrich(&manager, &server)
        .await
        .expect("el catálogo es mejor esfuerzo");
    assert_eq!(fetched, 1, "la foto se bajó");
    assert_eq!(server.requests().len(), 2, "se intentó el catálogo");

    let photo = manager
        .with_store(ACCOUNT, move |s| s.contact_photo(id))
        .await
        .unwrap();
    assert!(photo.is_some(), "la foto se aplicó");
    let vcard = read_vcard(&manager).await;
    assert!(vcard.contains("X-VASAK-STARRED:1"), "{vcard}");
    assert!(vcard.contains("PHOTO;ENCODING=b;TYPE=JPEG:"), "{vcard}");
    assert!(!vcard.contains("CATEGORIES"), "sin catálogo no hay nombres");
}

/// El catálogo se mapea `resourceName → formattedName`, saltando los incompletos,
/// pide sólo el nombre y manda el token sólo a nuestra url.
#[tokio::test]
async fn el_catalogo_de_grupos_mapea_el_recurso_a_su_nombre() {
    let server = FakeGraph::start().await;
    server.push(format!(
        r#"{{"contactGroups":[{},{},
            {{"resourceName":"contactGroups/sin-nombre"}},{{"formattedName":"sin recurso"}}],
            "nextPageToken":"t2"}}"#,
        group_json("contactGroups/g1", "Familia"),
        group_json("contactGroups/g2", "Trabajo"),
    ));
    server.push(format!(
        r#"{{"contactGroups":[{}]}}"#,
        group_json("contactGroups/g3", "Amigos")
    ));
    let names = fetch_contact_groups(&client(), TOKEN, &server.base_url(), &PeopleLimits::DEFAULT)
        .await
        .unwrap();
    assert_eq!(names.len(), 3);
    assert_eq!(names["contactGroups/g1"], "Familia");
    assert_eq!(names["contactGroups/g3"], "Amigos");

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].path.contains("/contactGroups"));
    assert!(requests[0].path.contains("groupFields=name"));
    assert!(requests[1].path.contains("pageToken=t2"));
    assert!(requests
        .iter()
        .all(|r| r.authorization == format!("Bearer {TOKEN}")));
}

/// El paginador del catálogo acota igual que el de las personas: token repetido
/// (cortando apenas se ve), tope de páginas, tope de grupos.
#[tokio::test]
async fn el_catalogo_de_grupos_corta_por_token_repetido_paginas_y_grupos() {
    // Token repetido: termina en el segundo pedido aunque la cola siga.
    let server = FakeGraph::start().await;
    for _ in 0..50 {
        server.push(r#"{"contactGroups":[],"nextPageToken":"t1"}"#);
    }
    let result =
        fetch_contact_groups(&client(), TOKEN, &server.base_url(), &PeopleLimits::DEFAULT).await;
    assert!(matches!(result, Err(PeopleError::PaginationLoop)));
    assert_eq!(server.requests().len(), 2);

    // Tokens siempre nuevos: exactamente el tope de páginas.
    let server = FakeGraph::start().await;
    for n in 0..50 {
        server.push(format!(r#"{{"contactGroups":[],"nextPageToken":"n{n}"}}"#));
    }
    let limits = PeopleLimits {
        max_pages: 3,
        ..PeopleLimits::DEFAULT
    };
    let result = fetch_contact_groups(&client(), TOKEN, &server.base_url(), &limits).await;
    assert!(matches!(result, Err(PeopleError::TooManyPages)));
    assert_eq!(server.requests().len(), 3, "ni un pedido más que el tope");

    // Tope de grupos acumulados.
    let server = FakeGraph::start().await;
    server.push(format!(
        r#"{{"contactGroups":[{},{}]}}"#,
        group_json("contactGroups/g1", "Uno"),
        group_json("contactGroups/g2", "Dos")
    ));
    let limits = PeopleLimits {
        max_groups: 1,
        ..PeopleLimits::DEFAULT
    };
    let result = fetch_contact_groups(&client(), TOKEN, &server.base_url(), &limits).await;
    assert!(matches!(result, Err(PeopleError::TooManyItems)));
}

/// El catálogo **nunca** sigue una url de la respuesta: un `nextPageToken` con
/// forma de url se pega como parámetro a la nuestra, y el segundo pedido va al
/// mismo endpoint con el mismo token de acceso.
#[tokio::test]
async fn el_catalogo_de_grupos_no_sigue_ninguna_url_de_la_respuesta() {
    let server = FakeGraph::start().await;
    server.push(r#"{"contactGroups":[],"nextPageToken":"http://evil.example/steal"}"#);
    server.push(format!(
        r#"{{"contactGroups":[{}]}}"#,
        group_json("contactGroups/g1", "Familia")
    ));
    let names = fetch_contact_groups(&client(), TOKEN, &server.base_url(), &PeopleLimits::DEFAULT)
        .await
        .unwrap();
    assert_eq!(names.len(), 1);
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[1].path.starts_with("/v1.0/contactGroups?"),
        "{}",
        requests[1].path
    );
    assert!(requests[1].path.contains("pageToken=http"));
    assert_eq!(requests[1].authorization, format!("Bearer {TOKEN}"));
}

/// Un error HTTP, un cuerpo que pasa el tope de tamaño y uno que no es JSON del
/// catálogo se devuelven como error (la pasada los traga como mejor esfuerzo).
#[tokio::test]
async fn el_catalogo_de_grupos_rechaza_error_http_cuerpo_enorme_y_basura() {
    let server = FakeGraph::start().await; // cola vacía: 500
    assert!(matches!(
        fetch_contact_groups(&client(), TOKEN, &server.base_url(), &PeopleLimits::DEFAULT).await,
        Err(PeopleError::Http(_))
    ));

    let server = FakeGraph::start().await;
    server.push(format!(
        r#"{{"contactGroups":[{}]}}"#,
        group_json("contactGroups/g1", &"x".repeat(1000))
    ));
    let limits = PeopleLimits {
        max_response_bytes: 100,
        ..PeopleLimits::DEFAULT
    };
    assert!(matches!(
        fetch_contact_groups(&client(), TOKEN, &server.base_url(), &limits).await,
        Err(PeopleError::TooLarge)
    ));

    let server = FakeGraph::start().await;
    server.push("no es json");
    assert!(matches!(
        fetch_contact_groups(&client(), TOKEN, &server.base_url(), &PeopleLimits::DEFAULT).await,
        Err(PeopleError::Parse)
    ));

    assert!(matches!(
        fetch_contact_groups(&client(), TOKEN, "no es una url", &PeopleLimits::DEFAULT).await,
        Err(PeopleError::MalformedUrl)
    ));
}

/// El plazo por pedido del catálogo: un servidor que recibe y no contesta corta
/// con `Timeout` (el reloj va pausado: no se esperan los 60 s de verdad).
#[tokio::test(start_paused = true)]
async fn el_catalogo_de_grupos_corta_por_plazo_si_el_servidor_no_contesta() {
    let server = FakeGraph::start().await;
    server.push_status(0, "");
    let result =
        fetch_contact_groups(&client(), TOKEN, &server.base_url(), &PeopleLimits::DEFAULT).await;
    assert!(matches!(result, Err(PeopleError::Timeout)), "{result:?}");
}

/// `set_contact_groups` escribe sólo si algo cambió: la misma lista y el mismo
/// destacado no suben la generación; un grupo de más, uno de menos o el destacado
/// sí; sin fila de enlace no toca nada. Los nombres con coma sobreviven (JSON).
#[tokio::test]
async fn guardar_los_mismos_grupos_no_sube_la_generacion_y_un_cambio_si() {
    let (_temp, manager) = store("google_grupos_generacion").await;
    let id = seed(&manager, "Ana", "ana@x.com").await;
    let set = |groups: Vec<String>, starred: bool| {
        let manager = manager.clone();
        async move {
            manager
                .with_store(ACCOUNT, move |s| s.set_contact_groups(id, &groups, starred))
                .await
                .unwrap();
        }
    };
    let stored = || {
        let manager = manager.clone();
        async move {
            manager
                .with_store(ACCOUNT, move |s| {
                    Ok(s.connection()
                        .query_row(
                            "SELECT groups, starred FROM contact_enrichment WHERE contact_id = ?1",
                            [id],
                            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
                        )
                        .unwrap())
                })
                .await
                .unwrap()
        }
    };

    // Sin fila de enlace: nada que guardar, la generación no se mueve.
    let before = generation(&manager).await;
    set(vec!["Familia".into()], true).await;
    assert_eq!(generation(&manager).await, before);

    manager
        .with_store(ACCOUNT, move |s| {
            s.upsert_contact_enrichment(&ContactEnrichment {
                contact_id: id,
                resource_name: "people/c1".into(),
                etag: None,
                photo_etag: None,
            })
        })
        .await
        .unwrap();
    // Una fila nueva trae los defaults: guardar vacío y no destacado es no-op.
    assert_eq!(stored().await, ("[]".to_string(), 0));
    let before = generation(&manager).await;
    set(vec![], false).await;
    assert_eq!(generation(&manager).await, before, "vacío sobre vacío");

    // Un cambio sube; repetirlo no.
    let names = vec!["Familia, cercana".to_string(), "Trabajo".to_string()];
    set(names.clone(), true).await;
    let after = generation(&manager).await;
    assert!(after > before, "un cambio sube la generación");
    assert_eq!(
        stored().await,
        (r#"["Familia, cercana","Trabajo"]"#.to_string(), 1)
    );
    set(names.clone(), true).await;
    assert_eq!(generation(&manager).await, after, "lo mismo no sube");

    // Cambiar sólo el destacado, o sólo los grupos, sí sube.
    set(names.clone(), false).await;
    let unstarred = generation(&manager).await;
    assert!(unstarred > after);
    set(vec!["Trabajo".into()], false).await;
    assert!(generation(&manager).await > unstarred);
}

/// Una segunda pasada con lo mismo no sube la generación (no dispara relecturas
/// en las apps); y si People saca un grupo y el destacado, se reflejan.
#[tokio::test]
async fn la_segunda_pasada_con_los_mismos_grupos_no_sube_la_generacion() {
    let (_temp, manager) = store("google_grupos_incremental").await;
    seed(&manager, "Ana", "ana@x.com").await;

    let page = r#"{"connections":[{"resourceName":"people/c1",
        "emailAddresses":[{"value":"ana@x.com"}],
        "photos":[{"url":"https://lh3.googleusercontent.com/p1"}],
        "memberships":[
          {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/starred"}},
          {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/g1"}}]}]}"#;
    let catalog = format!(
        r#"{{"contactGroups":[{}]}}"#,
        group_json("contactGroups/g1", "Familia")
    );
    let server = FakeGraph::start().await;
    server.push(page);
    server.push(catalog.clone());
    enrich(&manager, &server).await.unwrap();
    let first = generation(&manager).await;

    server.push(page);
    server.push(catalog);
    enrich(&manager, &server).await.unwrap();
    assert_eq!(generation(&manager).await, first, "nada cambió: no sube");

    // People saca el grupo y el destacado.
    server.push(
        r#"{"connections":[{"resourceName":"people/c1",
            "emailAddresses":[{"value":"ana@x.com"}],
            "photos":[{"url":"https://lh3.googleusercontent.com/p1"}]}]}"#,
    );
    enrich(&manager, &server).await.unwrap();
    assert!(generation(&manager).await > first);
    let vcard = read_vcard(&manager).await;
    assert!(!vcard.contains("CATEGORIES"), "{vcard}");
    assert!(!vcard.contains("X-VASAK-STARRED"), "{vcard}");
}

/// Una op pendiente no se pisa: el contacto con una edición local sin confirmar
/// queda fuera del casamiento (no recibe grupos ni destacado), y si el
/// enriquecimiento ya estaba guardado, la lectura sirve el crudo sin inyectar
/// `CATEGORIES` ni `X-VASAK-STARRED`; al irse la op, vuelven solos.
#[tokio::test]
async fn con_op_pendiente_no_se_enriquecen_los_grupos_y_la_lectura_sirve_el_crudo() {
    let (_temp, manager) = store("google_grupos_pendiente").await;
    let id = seed(&manager, "Ana", "ana@x.com").await;
    let set_pending = |value: &'static str| {
        let manager = manager.clone();
        async move {
            manager
                .with_store(ACCOUNT, move |s| {
                    s.connection()
                        .execute(
                            &format!("UPDATE contacts SET pending_op = {value} WHERE id = ?1"),
                            [id],
                        )
                        .unwrap();
                    Ok(())
                })
                .await
                .unwrap();
        }
    };
    let page = r#"{"connections":[{"resourceName":"people/c1",
        "emailAddresses":[{"value":"ana@x.com"}],
        "memberships":[
          {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/starred"}},
          {"contactGroupMembership":{"contactGroupResourceName":"contactGroups/g1"}}]}]}"#;
    let catalog = format!(
        r#"{{"contactGroups":[{}]}}"#,
        group_json("contactGroups/g1", "Familia")
    );

    // 1. Con la op pendiente de antemano: la pasada no escribe nada.
    set_pending("'put'").await;
    let server = FakeGraph::start().await;
    server.push(page);
    server.push(catalog.clone());
    enrich(&manager, &server).await.unwrap();
    let rows: i64 = manager
        .with_store(ACCOUNT, |s| {
            Ok(s.connection()
                .query_row("SELECT COUNT(*) FROM contact_enrichment", [], |r| r.get(0))
                .unwrap())
        })
        .await
        .unwrap();
    assert_eq!(rows, 0, "un contacto pendiente no se enriquece");

    // 2. Sin op pendiente se enriquece; con una op nueva, la lectura es el crudo.
    set_pending("NULL").await;
    server.push(page);
    server.push(catalog);
    enrich(&manager, &server).await.unwrap();
    let raw = read_raw(&manager, id).await;
    let vcard = read_vcard(&manager).await;
    assert!(vcard.contains("CATEGORIES:Familia"), "{vcard}");
    assert!(vcard.contains("X-VASAK-STARRED:1"), "{vcard}");

    set_pending("'put'").await;
    assert_eq!(
        read_vcard(&manager).await,
        raw,
        "con op pendiente, el crudo"
    );

    set_pending("NULL").await;
    assert_eq!(read_vcard(&manager).await, vcard, "al irse la op, vuelven");
}
