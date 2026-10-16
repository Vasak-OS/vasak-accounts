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

use super::{enrich_photos, fetch_connections, is_google_photo_host, PeopleError, PeopleLimits};
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
