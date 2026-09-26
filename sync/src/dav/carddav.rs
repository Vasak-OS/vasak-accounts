//! Leer los contactos de un servidor CardDAV.
//!
//! Viene de `vasak-contacts` (`src-tauri/src/carddav.rs`), con sus pruebas y
//! los nombres pasados al inglés. Lo que cambió al mudarse: el `REPORT`
//! `addressbook-query` que traía todas las tarjetas de una vez se reemplazó por
//! `sync-collection` (en `webdav.rs`) más `addressbook-multiget` de a tandas,
//! que es lo que deja traer sólo lo que cambió; y cada dirección del servidor
//! pasa por [`resolve_href`], que rechaza las de otro origen.
//!
//! Tres pedidos, todos de lectura:
//!
//! - `PROPFIND` sobre la carpeta de la persona: qué libretas tiene, cómo se
//!   llaman, su `getctag` y si saben `sync-collection`.
//! - `PROPFIND` sobre una libreta: el ETag de cada tarjeta, para el servidor
//!   que no sabe `sync-collection`.
//! - `REPORT addressbook-multiget`: las tarjetas pedidas, por dirección.
//!
//! No crea, no edita y no borra nada en el servidor.

use super::webdav::{
    self, href_for_request, parse_multistatus, resolve_href, same_collection, xml_escape,
    DavClient, DavError, Method, NS_DAV,
};

pub const NS_CARDDAV: &str = "urn:ietf:params:xml:ns:carddav";
/// El de `getctag`, una extensión de Apple que casi todos los servidores
/// hablan: cambia cada vez que cambia algo de la libreta.
pub const NS_CALENDARSERVER: &str = "http://calendarserver.org/ns/";

/// Hasta cuánto del nombre de una libreta se guarda.
const MAX_BOOK_NAME: usize = 256;

/// Una libreta de la persona.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressBook {
    pub href: url::Url,
    pub display_name: String,
    /// El `getctag`, si el servidor lo da.
    pub ctag: Option<String>,
    /// Si sabe `sync-collection`, según su `supported-report-set`. `None` si no
    /// lo dijo: se prueba, y si contesta que no, se va por ETag.
    pub sync_collection: Option<bool>,
}

/// La dirección y el ETag de cada tarjeta de una libreta.
pub type Etags = Vec<(url::Url, Option<String>)>;

/// Una tarjeta tal como vino del servidor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardResource {
    pub href: url::Url,
    pub etag: Option<String>,
    pub data: String,
}

// ---------------------------------------------------------------------------
// Lo que se puede probar sin red
// ---------------------------------------------------------------------------

fn short(text: &str, cap: usize) -> String {
    let text = text.trim();
    if text.len() <= cap {
        return text.to_string();
    }
    let mut cut = cap;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text[..cut].to_string()
}

/// Un token o un `getctag` que se puede guardar.
fn storable(text: Option<&str>) -> Option<String> {
    text.filter(|t| t.len() <= webdav::MAX_TOKEN_BYTES)
        .map(str::to_string)
}

/// Lee las libretas de una respuesta `PROPFIND`. Devuelve también cuántas
/// direcciones de otro origen se descartaron.
///
/// **Un XML que no se entiende no es una libreta vacía.** Devolver una lista
/// vacía hacía que una respuesta cortada a la mitad —una conexión que se
/// interrumpió, un servidor que contestó una página de error— se viera igual
/// que «esta cuenta no tiene libretas». La persona miraría la pantalla vacía
/// creyendo que perdió sus contactos. Y acá sería peor: el almacén borraría lo
/// que tenía.
pub fn address_books_from(
    xml: &str,
    base: &url::Url,
    max_nodes: u32,
) -> Result<(Vec<AddressBook>, usize), DavError> {
    let document = webdav::parse_xml(xml, max_nodes)?;
    let multistatus = parse_multistatus(&document)?;
    let mut foreign = 0;

    let books = multistatus
        .responses
        .iter()
        .filter(|response| response.status.is_none_or(|s| (200..300).contains(&s)))
        .filter_map(|response| {
            // Sólo las colecciones que de verdad son libretas: la carpeta trae
            // también cosas que no lo son, y listarlas daría entradas que al
            // abrirlas no tienen nada.
            let is_book = response
                .prop(NS_DAV, "resourcetype")
                .is_some_and(|p| p.contains(NS_CARDDAV, "addressbook"));
            if !is_book {
                return None;
            }

            let Ok(href) = resolve_href(base, &response.href) else {
                foreign += 1;
                return None;
            };

            let display_name = response
                .text(NS_DAV, "displayname")
                .map(|n| short(n, MAX_BOOK_NAME))
                .unwrap_or_default();

            Some(AddressBook {
                href,
                // Una libreta sin nombre igual se muestra: es donde puede estar
                // el contacto que la persona busca.
                display_name: if display_name.is_empty() {
                    "Contactos".into()
                } else {
                    display_name
                },
                ctag: storable(response.text(NS_CALENDARSERVER, "getctag")),
                sync_collection: response
                    .prop(NS_DAV, "supported-report-set")
                    .map(|p| p.contains(NS_DAV, "sync-collection")),
            })
        })
        .collect();

    Ok((books, foreign))
}

/// Saca las tarjetas, su dirección y su ETag de una respuesta
/// `addressbook-multiget`. Devuelve también cuántas direcciones de otro origen
/// se descartaron.
///
/// La dirección va con la tarjeta porque es lo que la identifica en el
/// servidor: el `UID` de adentro lo escribe quien la creó y puede faltar, estar
/// repetido, o ser el mismo en dos libretas distintas.
pub fn cards_from(
    xml: &str,
    base: &url::Url,
    max_nodes: u32,
) -> Result<(Vec<CardResource>, usize), DavError> {
    let document = webdav::parse_xml(xml, max_nodes)?;
    let multistatus = parse_multistatus(&document)?;
    let mut foreign = 0;

    let cards = multistatus
        .responses
        .iter()
        .filter_map(|response| {
            let data = response.prop(NS_CARDDAV, "address-data")?.text.clone();
            if data.trim().is_empty() {
                return None;
            }
            let Ok(href) = resolve_href(base, &response.href) else {
                foreign += 1;
                return None;
            };
            Some(CardResource {
                href,
                etag: storable(response.text(NS_DAV, "getetag")),
                data,
            })
        })
        .collect();

    Ok((cards, foreign))
}

/// Saca el ETag de cada tarjeta de un `PROPFIND` sobre una libreta, para los
/// servidores que no saben `sync-collection`. Sin la libreta misma ni las
/// subcarpetas.
pub fn etags_from(xml: &str, book: &url::Url, max_nodes: u32) -> Result<(Etags, usize), DavError> {
    let document = webdav::parse_xml(xml, max_nodes)?;
    let multistatus = parse_multistatus(&document)?;
    let mut foreign = 0;

    let etags = multistatus
        .responses
        .iter()
        .filter(|response| response.status.is_none_or(|s| (200..300).contains(&s)))
        .filter(|response| {
            !response
                .prop(NS_DAV, "resourcetype")
                .is_some_and(|p| p.contains(NS_DAV, "collection"))
        })
        .filter_map(|response| {
            let Ok(href) = resolve_href(book, &response.href) else {
                foreign += 1;
                return None;
            };
            if same_collection(&href, book) {
                return None;
            }
            Some((href, storable(response.text(NS_DAV, "getetag"))))
        })
        .collect();

    Ok((etags, foreign))
}

/// El cuerpo del `PROPFIND` que pide las libretas.
pub fn address_books_query() -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="{NS_CARDDAV}" xmlns:cs="{NS_CALENDARSERVER}">
  <d:prop><d:resourcetype/><d:displayname/><cs:getctag/><d:supported-report-set/></d:prop>
</d:propfind>"#
    )
}

/// El cuerpo del `PROPFIND` que pide el ETag de cada tarjeta de una libreta.
pub fn etags_query() -> String {
    r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop><d:resourcetype/><d:getetag/></d:prop>
</d:propfind>"#
        .to_string()
}

/// El cuerpo del `REPORT` que pide unas tarjetas por su dirección.
pub fn multiget_body(hrefs: &[url::Url]) -> String {
    let hrefs: String = hrefs
        .iter()
        .map(|h| format!("  <d:href>{}</d:href>\n", xml_escape(&href_for_request(h))))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<c:addressbook-multiget xmlns:d="DAV:" xmlns:c="{NS_CARDDAV}">
  <d:prop><d:getetag/><c:address-data/></d:prop>
{hrefs}</c:addressbook-multiget>"#
    )
}

// ---------------------------------------------------------------------------
// La parte que habla por la red
// ---------------------------------------------------------------------------

fn expect_multistatus(reply: webdav::Reply) -> Result<String, DavError> {
    match reply.status {
        207 => Ok(reply.body),
        other => Err(DavError::Status(other)),
    }
}

/// Las libretas que hay en la carpeta de la persona.
pub async fn list_address_books(client: &DavClient) -> Result<Vec<AddressBook>, DavError> {
    let home = client.home().clone();
    let reply = client
        // 1: la carpeta y lo que hay dentro. Con 0 sólo vendría la carpeta, que
        // es justo lo que no interesa.
        .request(Method::Propfind, &home, "1", address_books_query())
        .await?;
    let xml = expect_multistatus(reply)?;
    let (books, foreign) = address_books_from(&xml, &home, client.limits().max_xml_nodes)?;
    if foreign > 0 {
        tracing::warn!("se descartaron {foreign} libretas con dirección de otro servidor");
    }
    let cap = client.limits().max_address_books;
    if books.len() > cap {
        return Err(DavError::TooManyAddressBooks(cap));
    }
    Ok(books)
}

/// El ETag de cada tarjeta de una libreta.
pub async fn list_etags(client: &DavClient, book: &url::Url) -> Result<Etags, DavError> {
    let reply = client
        .request(Method::Propfind, book, "1", etags_query())
        .await?;
    let xml = expect_multistatus(reply)?;
    let (etags, foreign) = etags_from(&xml, book, client.limits().max_xml_nodes)?;
    if foreign > 0 {
        tracing::warn!("se descartaron {foreign} tarjetas con dirección de otro servidor");
    }
    Ok(etags)
}

/// Unas tarjetas de una libreta, por su dirección.
pub async fn multiget(
    client: &DavClient,
    book: &url::Url,
    hrefs: &[url::Url],
) -> Result<Vec<CardResource>, DavError> {
    // 1: las tarjetas de esta libreta. El estándar lo pide, y hay servidores
    // que sin esto devuelven vacío.
    let reply = client
        .request(Method::Report, book, "1", multiget_body(hrefs))
        .await?;
    let xml = expect_multistatus(reply)?;
    let (cards, foreign) = cards_from(&xml, book, client.limits().max_xml_nodes)?;
    if foreign > 0 {
        tracing::warn!("se descartaron {foreign} tarjetas con dirección de otro servidor");
    }
    Ok(cards)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODES: u32 = 100_000;

    fn url(text: &str) -> url::Url {
        url::Url::parse(text).unwrap()
    }

    const BOOKS: &str = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav" xmlns:cs="http://calendarserver.org/ns/">
  <d:response>
    <d:href>/dav/addressbooks/users/ana/</d:href>
    <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>
      <d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/dav/addressbooks/users/ana/personal/</d:href>
    <d:propstat><d:prop>
      <d:resourcetype><d:collection/><c:addressbook/></d:resourcetype>
      <d:displayname>Personal</d:displayname>
      <cs:getctag>ctag-1</cs:getctag>
      <d:supported-report-set>
        <d:supported-report><d:report><d:sync-collection/></d:report></d:supported-report>
      </d:supported-report-set>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
</d:multistatus>"#;

    /// La carpeta trae también cosas que no son libretas. Listarlas daría
    /// entradas que al abrirlas no tienen nada.
    #[test]
    fn solo_se_listan_las_colecciones_que_son_libretas() {
        let (books, foreign) = address_books_from(
            BOOKS,
            &url("https://nube.ejemplo.com/dav/addressbooks/users/ana/"),
            NODES,
        )
        .unwrap();

        assert_eq!(foreign, 0);
        assert_eq!(books.len(), 1);
        assert_eq!(books[0].display_name, "Personal");
        assert_eq!(
            books[0].href.as_str(),
            "https://nube.ejemplo.com/dav/addressbooks/users/ana/personal/"
        );
        assert_eq!(books[0].ctag.as_deref(), Some("ctag-1"));
        assert_eq!(books[0].sync_collection, Some(true));
    }

    /// Los servidores contestan con una ruta absoluta casi siempre y con una
    /// URL entera a veces. Pegarlas a mano rompería la segunda.
    #[test]
    fn un_href_con_url_entera_no_se_pega_dos_veces() {
        let xml = BOOKS.replace(
            "<d:href>/dav/addressbooks/users/ana/personal/</d:href>",
            "<d:href>https://nube.ejemplo.com/x/</d:href>",
        );
        let (books, _) = address_books_from(
            &xml,
            &url("https://nube.ejemplo.com/dav/addressbooks/users/ana/"),
            NODES,
        )
        .unwrap();
        assert_eq!(books[0].href.as_str(), "https://nube.ejemplo.com/x/");
    }

    /// **Una libreta de otro servidor no se lista.** En `vasak-contacts` se
    /// aceptaba; acá cada pedido lleva la credencial de la cuenta, y pedirla
    /// se la mandaría a quien diga el servidor.
    #[test]
    fn una_libreta_de_otro_origen_se_descarta() {
        let xml = BOOKS.replace(
            "<d:href>/dav/addressbooks/users/ana/personal/</d:href>",
            "<d:href>https://otra.ejemplo.com/x/</d:href>",
        );
        let (books, foreign) = address_books_from(
            &xml,
            &url("https://nube.ejemplo.com/dav/addressbooks/users/ana/"),
            NODES,
        )
        .unwrap();
        assert!(books.is_empty());
        assert_eq!(foreign, 1);
    }

    /// Una libreta sin nombre igual se muestra: es donde puede estar el
    /// contacto que la persona busca.
    #[test]
    fn una_libreta_sin_nombre_se_muestra_igual() {
        let xml = BOOKS.replace("<d:displayname>Personal</d:displayname>", "");
        let (books, _) = address_books_from(&xml, &url("https://x/"), NODES).unwrap();
        assert_eq!(books.len(), 1);
        assert_eq!(books[0].display_name, "Contactos");
    }

    /// Un servidor que no dice qué informes sabe se prueba; uno que lo dice y
    /// no nombra `sync-collection`, no.
    #[test]
    fn se_lee_si_la_libreta_sabe_sync_collection() {
        let without_set = BOOKS.replace(
            r#"<d:supported-report-set>
        <d:supported-report><d:report><d:sync-collection/></d:report></d:supported-report>
      </d:supported-report-set>"#,
            "",
        );
        let (books, _) = address_books_from(&without_set, &url("https://x/"), NODES).unwrap();
        assert_eq!(books[0].sync_collection, None);

        let other_reports = BOOKS.replace("<d:sync-collection/>", "<c:addressbook-multiget/>");
        let (books, _) = address_books_from(&other_reports, &url("https://x/"), NODES).unwrap();
        assert_eq!(books[0].sync_collection, Some(false));
    }

    const CARDS: &str = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">
  <d:response>
    <d:href>/dav/addressbooks/users/ana/personal/ana.vcf</d:href>
    <d:propstat><d:prop><d:getetag>"e1"</d:getetag><c:address-data>BEGIN:VCARD
VERSION:3.0
FN:Ana Pérez
N:Pérez;Ana;;;
EMAIL:ana@ejemplo.com
END:VCARD
</c:address-data></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
</d:multistatus>"#;

    /// La dirección va con la tarjeta porque es lo que la identifica en el
    /// servidor: el `UID` de adentro lo escribe quien la creó y puede faltar,
    /// estar repetido, o ser el mismo en dos libretas distintas.
    #[test]
    fn la_tarjeta_sale_con_su_direccion() {
        let (cards, _) = cards_from(
            CARDS,
            &url("https://nube.ejemplo.com/dav/addressbooks/users/ana/personal/"),
            NODES,
        )
        .unwrap();

        assert_eq!(cards.len(), 1);
        assert!(
            cards[0].href.as_str().ends_with("/ana.vcf"),
            "{}",
            cards[0].href
        );
        assert!(cards[0].data.contains("Ana Pérez"));
        assert_eq!(cards[0].etag.as_deref(), Some("\"e1\""));
    }

    /// Una tarjeta de otro servidor no se guarda: la próxima vuelta la pediría.
    #[test]
    fn una_tarjeta_de_otro_origen_se_descarta() {
        let xml = CARDS.replace(
            "/dav/addressbooks/users/ana/personal/ana.vcf",
            "https://otra.ejemplo.com/ana.vcf",
        );
        let (cards, foreign) =
            cards_from(&xml, &url("https://nube.ejemplo.com/dav/"), NODES).unwrap();
        assert!(cards.is_empty());
        assert_eq!(foreign, 1);
    }

    /// **Un XML roto no es una libreta vacía.** Devolver una lista vacía hacía
    /// que una respuesta cortada a la mitad se viera igual que «esta cuenta no
    /// tiene a nadie», y la persona miraría la pantalla creyendo que perdió sus
    /// contactos.
    #[test]
    fn un_xml_roto_se_dice_en_vez_de_parecer_vacio() {
        for garbage in ["no es xml", "<abierto>", ""] {
            assert!(
                address_books_from(garbage, &url("https://x/"), NODES).is_err(),
                "{garbage:?}"
            );
            assert!(
                cards_from(garbage, &url("https://x/"), NODES).is_err(),
                "{garbage:?}"
            );
            assert!(
                etags_from(garbage, &url("https://x/"), NODES).is_err(),
                "{garbage:?}"
            );
        }
    }

    /// Y un XML válido sin nada adentro **sí** es una libreta vacía: la
    /// diferencia es justamente la que se quería poder decir.
    #[test]
    fn un_xml_valido_y_vacio_si_es_una_libreta_vacia() {
        let empty = r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"/>"#;
        assert!(address_books_from(empty, &url("https://x/"), NODES)
            .unwrap()
            .0
            .is_empty());
        assert!(cards_from(empty, &url("https://x/"), NODES)
            .unwrap()
            .0
            .is_empty());
        assert!(etags_from(empty, &url("https://x/"), NODES)
            .unwrap()
            .0
            .is_empty());
    }

    /// El `PROPFIND` de una libreta trae la libreta misma: no es una tarjeta.
    #[test]
    fn los_etags_no_incluyen_la_libreta_ni_sus_subcarpetas() {
        let xml = r#"<d:multistatus xmlns:d="DAV:">
  <d:response><d:href>/libro</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
  <d:response><d:href>/libro/sub/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
  <d:response><d:href>/libro/a.vcf</d:href><d:propstat><d:prop><d:resourcetype/><d:getetag>"1"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
</d:multistatus>"#;
        let (etags, _) = etags_from(xml, &url("https://x/libro/"), NODES).unwrap();
        assert_eq!(
            etags,
            vec![(url("https://x/libro/a.vcf"), Some("\"1\"".to_string()))]
        );
    }

    #[test]
    fn las_consultas_son_xml_valido() {
        assert!(roxmltree::Document::parse(&address_books_query()).is_ok());
        assert!(roxmltree::Document::parse(&etags_query()).is_ok());
        let body = multiget_body(&[url("https://x/libro/a&b.vcf"), url("https://x/libro/c.vcf")]);
        let document = roxmltree::Document::parse(&body).unwrap();
        let hrefs: Vec<&str> = document
            .descendants()
            .filter(|n| n.has_tag_name((NS_DAV, "href")))
            .filter_map(|n| n.text())
            .collect();
        assert_eq!(hrefs, vec!["/libro/a&b.vcf", "/libro/c.vcf"]);
    }
}
