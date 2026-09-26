//! Leer los calendarios de un servidor CalDAV.
//!
//! Viene de `vasak-calendar` (`src-tauri/src/caldav.rs`, la mitad que habla
//! por la red), con los nombres pasados al inglés: `Calendario` →
//! [`CalendarCollection`], `calendarios_de` → [`calendars_from`],
//! `ical_de_respuesta` → [`objects_from`], `calendarios` → [`list_calendars`].
//! Lo que cambió al mudarse, lo mismo que con `carddav.rs`: el cliente, la
//! credencial y los topes son los de `webdav.rs`; el `calendar-query` por rango
//! que traía los eventos de un mes se reemplazó por `sync-collection` más
//! `calendar-multiget` de a tandas, que traen **todo** y sólo lo que cambió; y
//! cada dirección del servidor pasa por [`resolve_href`], que rechaza las de
//! otro origen (`vasak-calendar` las aceptaba, y les mandaba la contraseña).
//!
//! Tres pedidos, todos de lectura:
//!
//! - `PROPFIND` sobre la carpeta de la persona: qué calendarios tiene, cómo se
//!   llaman, de qué color, qué componentes guardan
//!   (`supported-calendar-component-set`), su `getctag` y si saben
//!   `sync-collection`.
//! - `PROPFIND` sobre un calendario: el ETag de cada objeto, para el servidor
//!   que no sabe `sync-collection` ([`webdav::list_etags`]).
//! - `REPORT calendar-multiget`: los objetos pedidos, por dirección.
//!
//! No crea, no edita y no borra nada en el servidor.

use super::webdav::{
    self, expect_multistatus, href_for_request, off_runtime, parse_multistatus, resolve_href,
    storable, xml_escape, DavClient, DavError, Limits, Method, NS_CALENDARSERVER, NS_DAV,
};

pub const NS_CALDAV: &str = "urn:ietf:params:xml:ns:caldav";
/// El de `calendar-color`, otra extensión de Apple.
pub const NS_APPLE: &str = "http://apple.com/ns/ical/";

/// Hasta cuánto del nombre de un calendario se guarda.
const MAX_CALENDAR_NAME: usize = 256;

/// Los componentes que guarda el almacén. Un calendario que sólo tiene notas
/// (`VJOURNAL`) no se lista.
pub const STORED_COMPONENTS: [&str; 2] = ["VEVENT", "VTODO"];

/// Un calendario de la persona.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarCollection {
    pub href: url::Url,
    pub display_name: String,
    /// El color que la persona le puso en su servidor, si le puso uno que sea
    /// un color: `#RRGGBB` o `#RRGGBBAA`. Cualquier otro texto no se guarda.
    pub color: Option<String>,
    /// De los que guarda el almacén, cuáles dice que guarda: `VEVENT`,
    /// `VTODO`. Un servidor que no lo dice guarda todos (RFC 4791, 5.2.3).
    pub components: Vec<String>,
    pub ctag: Option<String>,
    /// Si sabe `sync-collection`, según su `supported-report-set`. `None` si no
    /// lo dijo: se prueba, y si contesta que no, se va por ETag.
    pub sync_collection: Option<bool>,
}

/// Un objeto —un evento o una tarea— tal como vino del servidor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarResource {
    pub href: url::Url,
    pub etag: Option<String>,
    pub data: String,
}

// ---------------------------------------------------------------------------
// Lo que se puede probar sin red
// ---------------------------------------------------------------------------

fn short(text: &str, cap: usize) -> String {
    crate::ical::visible(text, cap)
}

/// Un color como lo escriben Apple, Nextcloud y Google: `#RRGGBB` o
/// `#RRGGBBAA`, en hexadecimal. Lo que no es eso no llega al widget.
pub fn color_from(text: &str) -> Option<String> {
    let text = text.trim();
    let hex = text.strip_prefix('#')?;
    ((hex.len() == 6 || hex.len() == 8) && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| text.to_ascii_uppercase())
}

/// Lee los calendarios de una respuesta `PROPFIND`. Devuelve también cuántas
/// direcciones de otro origen se descartaron.
///
/// **Un XML que no se entiende no es una cuenta sin calendarios**: el almacén
/// borraría lo que tenía. Es un error.
pub fn calendars_from(
    xml: &str,
    base: &url::Url,
    limits: &Limits,
) -> Result<(Vec<CalendarCollection>, usize), DavError> {
    let document = webdav::parse_xml(xml, limits)?;
    let multistatus = parse_multistatus(&document)?;
    let mut foreign = 0;

    let calendars = multistatus
        .responses
        .iter()
        .filter(|response| response.status.is_none_or(|s| (200..300).contains(&s)))
        .filter_map(|response| {
            // Sólo las colecciones que de verdad son calendarios: la carpeta
            // también trae cosas que no lo son, y listarlas daría entradas que
            // al abrirlas no tienen nada.
            let is_calendar = response
                .prop(NS_DAV, "resourcetype")
                .is_some_and(|p| p.contains(NS_CALDAV, "calendar"));
            if !is_calendar {
                return None;
            }
            let components: Vec<String> =
                match response.prop(NS_CALDAV, "supported-calendar-component-set") {
                    Some(set) => STORED_COMPONENTS
                        .iter()
                        .filter(|c| {
                            set.name_attributes
                                .iter()
                                .any(|n| n.eq_ignore_ascii_case(c))
                        })
                        .map(|c| c.to_string())
                        .collect(),
                    None => STORED_COMPONENTS.iter().map(|c| c.to_string()).collect(),
                };
            if components.is_empty() {
                return None;
            }

            let Ok(href) = resolve_href(base, &response.href) else {
                foreign += 1;
                return None;
            };

            let display_name = response
                .text(NS_DAV, "displayname")
                .map(|n| short(n, MAX_CALENDAR_NAME))
                .unwrap_or_default();

            Some(CalendarCollection {
                href,
                // Un calendario sin nombre igual se muestra: es donde puede
                // estar el evento que la persona busca.
                display_name: if display_name.is_empty() {
                    "Calendario".into()
                } else {
                    display_name
                },
                color: response
                    .text(NS_APPLE, "calendar-color")
                    .and_then(color_from),
                components,
                ctag: storable(response.text(NS_CALENDARSERVER, "getctag")),
                sync_collection: response
                    .prop(NS_DAV, "supported-report-set")
                    .map(|p| p.contains(NS_DAV, "sync-collection")),
            })
        })
        .collect();

    Ok((calendars, foreign))
}

/// Saca los objetos, su dirección y su ETag de una respuesta
/// `calendar-multiget`. Devuelve también cuántas direcciones de otro origen se
/// descartaron.
pub fn objects_from(
    xml: &str,
    base: &url::Url,
    limits: &Limits,
) -> Result<(Vec<CalendarResource>, usize), DavError> {
    let document = webdav::parse_xml(xml, limits)?;
    let multistatus = parse_multistatus(&document)?;
    let mut foreign = 0;

    let objects = multistatus
        .responses
        .iter()
        .filter_map(|response| {
            let data = response.prop(NS_CALDAV, "calendar-data")?.text.clone();
            if data.trim().is_empty() {
                return None;
            }
            let Ok(href) = resolve_href(base, &response.href) else {
                foreign += 1;
                return None;
            };
            Some(CalendarResource {
                href,
                etag: storable(response.text(NS_DAV, "getetag")),
                data,
            })
        })
        .collect();

    Ok((objects, foreign))
}

/// El cuerpo del `PROPFIND` que pide los calendarios.
pub fn calendars_query() -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="{NS_CALDAV}" xmlns:cs="{NS_CALENDARSERVER}" xmlns:a="{NS_APPLE}">
  <d:prop><d:resourcetype/><d:displayname/><a:calendar-color/><cs:getctag/><d:supported-report-set/><c:supported-calendar-component-set/></d:prop>
</d:propfind>"#
    )
}

/// El cuerpo del `REPORT` que pide unos objetos por su dirección.
pub fn multiget_body(hrefs: &[url::Url]) -> String {
    let hrefs: String = hrefs
        .iter()
        .map(|h| format!("  <d:href>{}</d:href>\n", xml_escape(&href_for_request(h))))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<c:calendar-multiget xmlns:d="DAV:" xmlns:c="{NS_CALDAV}">
  <d:prop><d:getetag/><c:calendar-data/></d:prop>
{hrefs}</c:calendar-multiget>"#
    )
}

/// Se queda con los objetos que se pidieron, una vez cada uno, y cuenta los
/// que no (ver [`webdav::keep_requested_by`]).
pub fn keep_requested(
    objects: Vec<CalendarResource>,
    hrefs: &[url::Url],
) -> (Vec<CalendarResource>, usize) {
    webdav::keep_requested_by(objects, hrefs, |o| &o.href)
}

// ---------------------------------------------------------------------------
// La parte que habla por la red
// ---------------------------------------------------------------------------

/// Los calendarios que hay en la carpeta de la persona, y cuántos se
/// descartaron por venir con una dirección de otro origen.
pub async fn list_calendars(
    client: &DavClient,
) -> Result<(Vec<CalendarCollection>, usize), DavError> {
    let home = client.home().clone();
    let reply = client
        // 1: la carpeta y lo que hay dentro.
        .request(Method::Propfind, &home, "1", calendars_query())
        .await?;
    let xml = expect_multistatus(reply)?;
    let limits = *client.limits();
    let (calendars, foreign) = off_runtime(move || calendars_from(&xml, &home, &limits)).await?;
    if foreign > 0 {
        tracing::warn!("se descartaron {foreign} calendarios con dirección de otro servidor");
    }
    let cap = client.limits().max_calendars;
    if calendars.len() > cap {
        return Err(DavError::TooManyCalendars(cap));
    }
    Ok((calendars, foreign))
}

/// Unos objetos de un calendario, por su dirección. Sólo los pedidos, una vez
/// cada uno; devuelve también cuántos vinieron de más.
pub async fn multiget(
    client: &DavClient,
    calendar: &url::Url,
    hrefs: &[url::Url],
) -> Result<(Vec<CalendarResource>, usize), DavError> {
    // 1: los objetos de este calendario. El estándar lo pide, y hay servidores
    // que sin esto devuelven vacío.
    let reply = client
        .request(Method::Report, calendar, "1", multiget_body(hrefs))
        .await?;
    let xml = expect_multistatus(reply)?;
    let limits = *client.limits();
    let calendar = calendar.clone();
    let requested = hrefs.to_vec();
    let (objects, foreign, unrequested) = off_runtime(move || {
        let (objects, foreign) = objects_from(&xml, &calendar, &limits)?;
        let (objects, unrequested) = keep_requested(objects, &requested);
        Ok((objects, foreign, unrequested))
    })
    .await?;
    if foreign > 0 {
        tracing::warn!("se descartaron {foreign} objetos con dirección de otro servidor");
    }
    if unrequested > 0 {
        tracing::warn!("se descartaron {unrequested} objetos que no se pidieron");
    }
    Ok((objects, unrequested))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODES: &Limits = &Limits {
        max_xml_nodes: 100_000,
        ..Limits::DEFAULT
    };

    fn url(text: &str) -> url::Url {
        url::Url::parse(text).unwrap()
    }

    /// El listado de `vasak-calendar`, con el `<d:status>` de cada `propstat`
    /// que allá faltaba: RFC 4918 lo exige, y `parse_multistatus` sólo lee
    /// las propiedades que vinieron con un `2xx`.
    const CALENDARS: &str = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"
               xmlns:a="http://apple.com/ns/ical/" xmlns:cs="http://calendarserver.org/ns/">
  <d:response>
    <d:href>/dav/calendars/ana/</d:href>
    <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop>
      <d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/dav/calendars/ana/personal/</d:href>
    <d:propstat><d:prop>
      <d:resourcetype><d:collection/><c:calendar/></d:resourcetype>
      <d:displayname>Personal</d:displayname>
      <a:calendar-color>#FF5733</a:calendar-color>
      <cs:getctag>ctag-1</cs:getctag>
      <c:supported-calendar-component-set><c:comp name="VEVENT"/><c:comp name="VJOURNAL"/></c:supported-calendar-component-set>
      <d:supported-report-set>
        <d:supported-report><d:report><d:sync-collection/></d:report></d:supported-report>
      </d:supported-report-set>
    </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
</d:multistatus>"#;

    /// La carpeta también trae cosas que no son calendarios. Listarlas daría
    /// entradas que al abrirlas no tienen nada.
    #[test]
    fn solo_se_listan_las_colecciones_que_son_calendarios() {
        let (calendars, foreign) = calendars_from(
            CALENDARS,
            &url("https://nube.ejemplo.com/dav/calendars/ana/"),
            NODES,
        )
        .unwrap();

        assert_eq!(foreign, 0);
        assert_eq!(calendars.len(), 1);
        assert_eq!(calendars[0].display_name, "Personal");
        assert_eq!(calendars[0].color.as_deref(), Some("#FF5733"));
        assert_eq!(
            calendars[0].href.as_str(),
            "https://nube.ejemplo.com/dav/calendars/ana/personal/"
        );
        assert_eq!(calendars[0].ctag.as_deref(), Some("ctag-1"));
        assert_eq!(calendars[0].sync_collection, Some(true));
        // `VJOURNAL` no lo guarda el almacén.
        assert_eq!(calendars[0].components, vec!["VEVENT"]);
    }

    /// Los servidores contestan con una ruta absoluta casi siempre y con una URL
    /// entera a veces. Pegarlas a mano rompería la segunda.
    #[test]
    fn un_href_con_url_entera_no_se_pega_dos_veces() {
        let xml = CALENDARS.replace(
            "<d:href>/dav/calendars/ana/personal/</d:href>",
            "<d:href>https://nube.ejemplo.com/x/</d:href>",
        );
        let (calendars, _) = calendars_from(
            &xml,
            &url("https://nube.ejemplo.com/dav/calendars/ana/"),
            NODES,
        )
        .unwrap();
        assert_eq!(calendars[0].href.as_str(), "https://nube.ejemplo.com/x/");
    }

    /// **Un calendario de otro servidor no se lista.** En `vasak-calendar` se
    /// aceptaba —su prueba de la URL entera usaba `otra.ejemplo.com`— y cada
    /// pedido siguiente le mandaba la contraseña de la cuenta.
    #[test]
    fn un_calendario_de_otro_origen_se_descarta() {
        let xml = CALENDARS.replace(
            "<d:href>/dav/calendars/ana/personal/</d:href>",
            "<d:href>https://otra.ejemplo.com/x/</d:href>",
        );
        let (calendars, foreign) = calendars_from(
            &xml,
            &url("https://nube.ejemplo.com/dav/calendars/ana/"),
            NODES,
        )
        .unwrap();
        assert!(calendars.is_empty());
        assert_eq!(foreign, 1);
    }

    /// **Un XML roto no es una cuenta sin calendarios**: en `vasak-calendar`
    /// daba una lista vacía, y acá eso borraría lo guardado.
    #[test]
    fn un_xml_roto_no_da_calendarios() {
        for garbage in ["no es xml", "<abierto>", ""] {
            assert!(calendars_from(garbage, &url("https://x/"), NODES).is_err());
            assert!(objects_from(garbage, &url("https://x/"), NODES).is_err());
        }
    }

    /// Un servidor que no dice qué componentes guarda los guarda todos; uno que
    /// sólo guarda tareas se lista con tareas; uno de notas no se lista.
    #[test]
    fn los_componentes_de_un_calendario_se_leen() {
        let without = CALENDARS.replace(
            r#"<c:supported-calendar-component-set><c:comp name="VEVENT"/><c:comp name="VJOURNAL"/></c:supported-calendar-component-set>"#,
            "",
        );
        let (calendars, _) = calendars_from(&without, &url("https://x/"), NODES).unwrap();
        assert_eq!(calendars[0].components, vec!["VEVENT", "VTODO"]);

        let tasks = CALENDARS.replace(
            r#"<c:comp name="VEVENT"/><c:comp name="VJOURNAL"/>"#,
            r#"<c:comp name="vtodo"/>"#,
        );
        let (calendars, _) = calendars_from(&tasks, &url("https://x/"), NODES).unwrap();
        assert_eq!(calendars[0].components, vec!["VTODO"]);

        let notes = CALENDARS.replace(r#"<c:comp name="VEVENT"/>"#, "");
        let (calendars, _) = calendars_from(&notes, &url("https://x/"), NODES).unwrap();
        assert!(calendars.is_empty());
    }

    /// El color llega al widget: sólo si es un color.
    #[test]
    fn el_color_tiene_que_ser_un_color() {
        assert_eq!(color_from("#ff5733"), Some("#FF5733".into()));
        assert_eq!(color_from(" #FF5733CC "), Some("#FF5733CC".into()));
        for garbage in ["rojo", "#FF57", "#GGGGGG", "FF5733", "#FF5733;x", ""] {
            assert_eq!(color_from(garbage), None, "{garbage:?}");
        }
        let xml = CALENDARS.replace("#FF5733", "url(javascript:alert(1))");
        let (calendars, _) = calendars_from(&xml, &url("https://x/"), NODES).unwrap();
        assert_eq!(calendars[0].color, None);
    }

    /// Un calendario sin nombre igual se muestra, y el nombre no lleva
    /// caracteres de control.
    #[test]
    fn un_calendario_sin_nombre_se_muestra_igual() {
        let xml = CALENDARS.replace("<d:displayname>Personal</d:displayname>", "");
        let (calendars, _) = calendars_from(&xml, &url("https://x/"), NODES).unwrap();
        assert_eq!(calendars[0].display_name, "Calendario");

        let xml = CALENDARS.replace("Personal", "Personal&#10;&#9;");
        let (calendars, _) = calendars_from(&xml, &url("https://x/"), NODES).unwrap();
        assert_eq!(calendars[0].display_name, "Personal");
    }

    const OBJECTS: &str = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:response>
    <d:href>/dav/calendars/ana/personal/r.ics</d:href>
    <d:propstat><d:prop><d:getetag>"e1"</d:getetag><c:calendar-data>BEGIN:VCALENDAR
BEGIN:VEVENT
UID:r
SUMMARY:Reunión
DTSTART:20260915T140000Z
END:VEVENT
END:VCALENDAR
</c:calendar-data></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
</d:multistatus>"#;

    /// El objeto sale con su dirección y su ETag: la dirección es lo que lo
    /// identifica en el servidor, no el `UID` de adentro.
    #[test]
    fn el_objeto_sale_con_su_direccion() {
        let (objects, _) = objects_from(
            OBJECTS,
            &url("https://nube.ejemplo.com/dav/calendars/ana/personal/"),
            NODES,
        )
        .unwrap();
        assert_eq!(objects.len(), 1);
        assert!(objects[0].href.as_str().ends_with("/r.ics"));
        assert!(objects[0].data.contains("Reunión"));
        assert_eq!(objects[0].etag.as_deref(), Some("\"e1\""));
    }

    /// Un objeto de otro servidor no se guarda.
    #[test]
    fn un_objeto_de_otro_origen_se_descarta() {
        let xml = OBJECTS.replace(
            "/dav/calendars/ana/personal/r.ics",
            "https://otra.ejemplo.com/r.ics",
        );
        let (objects, foreign) =
            objects_from(&xml, &url("https://nube.ejemplo.com/dav/"), NODES).unwrap();
        assert!(objects.is_empty());
        assert_eq!(foreign, 1);
    }

    #[test]
    fn las_consultas_son_xml_valido() {
        assert!(roxmltree::Document::parse(&calendars_query()).is_ok());
        let body = multiget_body(&[url("https://x/cal/a&b.ics"), url("https://x/cal/c.ics")]);
        let document = roxmltree::Document::parse(&body).unwrap();
        let hrefs: Vec<&str> = document
            .descendants()
            .filter(|n| n.has_tag_name((NS_DAV, "href")))
            .filter_map(|n| n.text())
            .collect();
        assert_eq!(hrefs, vec!["/cal/a&b.ics", "/cal/c.ics"]);
        assert!(document
            .descendants()
            .any(|n| n.has_tag_name((NS_CALDAV, "calendar-multiget"))));
    }
}
