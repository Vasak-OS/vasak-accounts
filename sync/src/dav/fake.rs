//! Un servidor CardDAV de mentira en `127.0.0.1`, para las pruebas.
//!
//! Habla HTTP/1.1 de verdad —el cliente es `reqwest`, sin atajos— y contesta
//! lo mínimo de CardDAV que usa el sincronizador: `PROPFIND` de la carpeta y
//! de cada libreta, `sync-collection` con tokens `t<versión>` y
//! `addressbook-multiget`. Anota cada pedido que le llega, para que una prueba
//! pueda decir «no se pidió nada».
//!
//! Cada cambio sube la versión del servidor entero, como un contador de
//! Nextcloud: el token `t7` quiere decir «como estaba en la versión 7», y las
//! diferencias desde ahí son lo que tenga versión más alta.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::webdav::xml_escape;

/// Un pedido tal como llegó.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub depth: String,
    pub authorization: String,
    pub body: String,
}

impl RecordedRequest {
    pub fn is_multiget(&self) -> bool {
        self.method == "REPORT" && self.body.contains("addressbook-multiget")
    }

    pub fn is_sync_collection(&self) -> bool {
        self.method == "REPORT" && self.body.contains("sync-collection")
    }
}

#[derive(Debug, Clone)]
pub struct FakeCard {
    pub etag: String,
    pub data: String,
    pub version: u64,
}

#[derive(Debug, Clone)]
pub struct FakeBook {
    /// La ruta, con barra al final: `/dav/ana/personal/`.
    pub path: String,
    pub name: String,
    pub supports_sync: bool,
    /// El `getctag` que se anuncia, si alguno.
    pub ctag: Option<String>,
    pub cards: BTreeMap<String, FakeCard>,
    /// Lo borrado, con la versión en que se borró.
    pub removed: BTreeMap<String, u64>,
}

type Hook = Box<dyn FnMut(&RecordedRequest) + Send>;

/// Lo que sabe y lo que hace el servidor. Todo público: cada prueba lo toca a
/// mano.
pub struct FakeState {
    pub home: String,
    pub books: Vec<FakeBook>,
    pub version: u64,
    pub requests: Vec<RecordedRequest>,
    /// Un token de antes de esta versión se contesta como vencido.
    pub min_valid_token: u64,
    /// El número de `multiget` (contando desde 1) a partir del cual se
    /// contesta 500.
    pub fail_multiget_from: Option<usize>,
    pub multigets: usize,
    /// Algo que se corre con cada pedido, antes de contestarlo: bloquear el
    /// llavero a mitad de camino, por ejemplo.
    pub on_request: Option<Hook>,
    /// Relleno que se suma a cada respuesta, para pasar el tope.
    pub padding: usize,
    /// Contestar con `Transfer-Encoding: chunked`, sin `Content-Length`.
    pub chunked: bool,
    /// No decir qué informes sabe cada libreta: el cliente tiene que probar.
    pub hide_reports: bool,
    /// `<d:response>` de más que se suman al listado de libretas.
    pub extra_books_xml: String,
    /// `<d:response>` de más que se suman a cada `sync-collection`.
    pub extra_sync_xml: String,
    /// `<d:response>` de más que se suman a cada `addressbook-multiget`.
    pub extra_multiget_xml: String,
    /// Cortar cada `sync-collection` a estas tarjetas, con un `507` sobre la
    /// libreta: la respuesta truncada de RFC 6578.
    pub truncate_sync: Option<usize>,
}

#[derive(Clone)]
pub struct FakeDav {
    pub state: Arc<Mutex<FakeState>>,
    pub port: u16,
}

impl FakeDav {
    /// Levanta el servidor con una libreta vacía, `personal`, que sabe
    /// `sync-collection`.
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(FakeState {
            home: "/dav/ana/".into(),
            books: vec![FakeBook {
                path: "/dav/ana/personal/".into(),
                name: "Personal".into(),
                supports_sync: true,
                ctag: None,
                cards: BTreeMap::new(),
                removed: BTreeMap::new(),
            }],
            version: 1,
            requests: Vec::new(),
            min_valid_token: 0,
            fail_multiget_from: None,
            multigets: 0,
            on_request: None,
            padding: 0,
            chunked: false,
            hide_reports: false,
            extra_books_xml: String::new(),
            extra_sync_xml: String::new(),
            extra_multiget_xml: String::new(),
            truncate_sync: None,
        }));

        let shared = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let state = Arc::clone(&shared);
                tokio::spawn(serve(socket, state));
            }
        });

        Self { state, port }
    }

    pub fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().unwrap()
    }

    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn home_url(&self) -> url::Url {
        let home = self.state().home.clone();
        url::Url::parse(&format!("{}{home}", self.origin())).unwrap()
    }

    pub fn book_url(&self, index: usize) -> url::Url {
        let path = self.state().books[index].path.clone();
        url::Url::parse(&format!("{}{path}", self.origin())).unwrap()
    }

    /// Agrega o cambia una tarjeta de una libreta.
    pub fn put(&self, book: usize, name: &str, data: &str) {
        let mut state = self.state();
        state.version += 1;
        let version = state.version;
        let book = &mut state.books[book];
        book.removed.remove(name);
        book.cards.insert(
            name.to_string(),
            FakeCard {
                etag: format!("\"v{version}\""),
                data: data.to_string(),
                version,
            },
        );
    }

    pub fn remove(&self, book: usize, name: &str) {
        let mut state = self.state();
        state.version += 1;
        let version = state.version;
        let book = &mut state.books[book];
        if book.cards.remove(name).is_some() {
            book.removed.insert(name.to_string(), version);
        }
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.state().requests.clone()
    }

    /// Suma una libreta vacía que sabe `sync-collection`.
    pub fn add_book(&self, path: &str, name: &str) -> usize {
        let mut state = self.state();
        state.books.push(FakeBook {
            path: path.into(),
            name: name.into(),
            supports_sync: true,
            ctag: None,
            cards: BTreeMap::new(),
            removed: BTreeMap::new(),
        });
        state.books.len() - 1
    }
}

/// Una tarjeta mínima.
pub fn card(uid: &str, name: &str, email: &str) -> String {
    format!(
        "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:{uid}\r\nFN:{name}\r\nEMAIL;TYPE=HOME:{email}\r\n\
         TEL;TYPE=CELL:+54 11 {uid}\r\nEND:VCARD\r\n"
    )
}

async fn read_more(socket: &mut tokio::net::TcpStream, buffer: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 8192];
    match socket.read(&mut chunk).await {
        Ok(0) | Err(_) => false,
        Ok(n) => {
            buffer.extend_from_slice(&chunk[..n]);
            true
        }
    }
}

async fn serve(mut socket: tokio::net::TcpStream, state: Arc<Mutex<FakeState>>) {
    let mut buffer = Vec::new();
    loop {
        // La cabecera entera.
        let header_end = loop {
            if let Some(end) = find(&buffer, b"\r\n\r\n") {
                break end;
            }
            if !read_more(&mut socket, &mut buffer).await {
                return;
            }
        };
        let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or("").to_string();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();
        let mut headers = BTreeMap::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }
        let length: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let body_start = header_end + 4;
        while buffer.len() < body_start + length {
            if !read_more(&mut socket, &mut buffer).await {
                return;
            }
        }
        let body = String::from_utf8_lossy(&buffer[body_start..body_start + length]).into_owned();
        buffer.drain(..body_start + length);

        let request = RecordedRequest {
            method,
            path,
            depth: headers.get("depth").cloned().unwrap_or_default(),
            authorization: headers.get("authorization").cloned().unwrap_or_default(),
            body,
        };

        let (status, reply, chunked) = {
            let mut state = state.lock().unwrap();
            state.requests.push(request.clone());
            if let Some(hook) = state.on_request.as_mut() {
                hook(&request);
            }
            let (status, mut reply) = answer(&mut state, &request);
            if state.padding > 0 {
                reply = reply.replacen(
                    "<d:multistatus",
                    &format!("<!--{}--><d:multistatus", "x".repeat(state.padding)),
                    1,
                );
            }
            (status, reply, state.chunked)
        };

        let mut out =
            format!("HTTP/1.1 {status} X\r\nContent-Type: application/xml; charset=utf-8\r\n");
        let bytes = if chunked {
            out.push_str("Transfer-Encoding: chunked\r\n\r\n");
            let mut bytes = out.into_bytes();
            for piece in reply.as_bytes().chunks(4096) {
                bytes.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
                bytes.extend_from_slice(piece);
                bytes.extend_from_slice(b"\r\n");
            }
            bytes.extend_from_slice(b"0\r\n\r\n");
            bytes
        } else {
            out.push_str(&format!("Content-Length: {}\r\n\r\n", reply.len()));
            let mut bytes = out.into_bytes();
            bytes.extend_from_slice(reply.as_bytes());
            bytes
        };
        if socket.write_all(&bytes).await.is_err() {
            return;
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

const HEAD: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav" xmlns:cs="http://calendarserver.org/ns/">"#;
const TAIL: &str = "</d:multistatus>";

fn ok(prop: &str) -> String {
    format!("<d:propstat><d:prop>{prop}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>")
}

fn answer(state: &mut FakeState, request: &RecordedRequest) -> (u16, String) {
    let book = state.books.iter().position(|b| b.path == request.path);

    match (request.method.as_str(), book) {
        ("PROPFIND", None) if request.path == state.home => {
            let mut xml = String::from(HEAD);
            xml.push_str(&format!(
                "<d:response><d:href>{}</d:href>{}</d:response>",
                state.home,
                ok("<d:resourcetype><d:collection/></d:resourcetype>")
            ));
            for book in &state.books {
                let reports = match (state.hide_reports, book.supports_sync) {
                    (true, _) => String::new(),
                    (false, true) => "<d:supported-report-set><d:supported-report><d:report>\
                        <d:sync-collection/></d:report></d:supported-report></d:supported-report-set>"
                        .into(),
                    (false, false) => "<d:supported-report-set><d:supported-report><d:report>\
                        <c:addressbook-multiget/></d:report></d:supported-report></d:supported-report-set>"
                        .into(),
                };
                let ctag = book
                    .ctag
                    .as_ref()
                    .map(|c| format!("<cs:getctag>{}</cs:getctag>", xml_escape(c)))
                    .unwrap_or_default();
                xml.push_str(&format!(
                    "<d:response><d:href>{}</d:href>{}</d:response>",
                    book.path,
                    ok(&format!(
                        "<d:resourcetype><d:collection/><c:addressbook/></d:resourcetype>\
                         <d:displayname>{}</d:displayname>{ctag}{reports}",
                        xml_escape(&book.name)
                    ))
                ));
            }
            xml.push_str(&state.extra_books_xml);
            xml.push_str(TAIL);
            (207, xml)
        }
        ("PROPFIND", Some(index)) => {
            let book = &state.books[index];
            let mut xml = String::from(HEAD);
            xml.push_str(&format!(
                "<d:response><d:href>{}</d:href>{}</d:response>",
                book.path,
                ok("<d:resourcetype><d:collection/><c:addressbook/></d:resourcetype>")
            ));
            for (name, card) in &book.cards {
                xml.push_str(&format!(
                    "<d:response><d:href>{}{name}</d:href>{}</d:response>",
                    book.path,
                    ok(&format!(
                        "<d:resourcetype/><d:getetag>{}</d:getetag>",
                        xml_escape(&card.etag)
                    ))
                ));
            }
            xml.push_str(TAIL);
            (207, xml)
        }
        ("REPORT", Some(index)) if request.is_sync_collection() => {
            let book = &state.books[index];
            if !book.supports_sync {
                return (501, String::new());
            }
            let token = roxmltree::Document::parse(&request.body)
                .ok()
                .and_then(|d| {
                    d.descendants()
                        .find(|n| n.has_tag_name(("DAV:", "sync-token")))
                        .map(|n| n.text().unwrap_or("").to_string())
                })
                .unwrap_or_default();
            let since = if token.is_empty() {
                None
            } else {
                match token.strip_prefix('t').and_then(|n| n.parse::<u64>().ok()) {
                    Some(n) if n >= state.min_valid_token && n <= state.version => Some(n),
                    _ => {
                        return (
                            403,
                            r#"<?xml version="1.0"?><d:error xmlns:d="DAV:"><d:valid-sync-token/></d:error>"#
                                .into(),
                        )
                    }
                }
            };
            let mut xml = String::from(HEAD);
            let changed = book
                .cards
                .iter()
                .filter(|(_, card)| since.is_none_or(|n| card.version > n))
                .take(state.truncate_sync.unwrap_or(usize::MAX));
            for (name, card) in changed {
                xml.push_str(&format!(
                    "<d:response><d:href>{}{name}</d:href>{}</d:response>",
                    book.path,
                    ok(&format!(
                        "<d:getetag>{}</d:getetag>",
                        xml_escape(&card.etag)
                    ))
                ));
            }
            if let Some(n) = since {
                for (name, version) in &book.removed {
                    if *version > n {
                        xml.push_str(&format!(
                            "<d:response><d:href>{}{name}</d:href>\
                             <d:status>HTTP/1.1 404 Not Found</d:status></d:response>",
                            book.path
                        ));
                    }
                }
            }
            if state.truncate_sync.is_some() {
                xml.push_str(&format!(
                    "<d:response><d:href>{}</d:href>\
                     <d:status>HTTP/1.1 507 Insufficient Storage</d:status></d:response>",
                    book.path
                ));
            }
            xml.push_str(&state.extra_sync_xml);
            xml.push_str(&format!("<d:sync-token>t{}</d:sync-token>", state.version));
            xml.push_str(TAIL);
            (207, xml)
        }
        ("REPORT", Some(index)) if request.is_multiget() => {
            state.multigets += 1;
            if state
                .fail_multiget_from
                .is_some_and(|from| state.multigets >= from)
            {
                return (500, String::new());
            }
            let book = &state.books[index];
            let hrefs: Vec<String> = roxmltree::Document::parse(&request.body)
                .map(|d| {
                    d.descendants()
                        .filter(|n| n.has_tag_name(("DAV:", "href")))
                        .filter_map(|n| n.text().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let mut xml = String::from(HEAD);
            for href in hrefs {
                let name = href.strip_prefix(&book.path).unwrap_or("");
                match book.cards.get(name) {
                    Some(card) => xml.push_str(&format!(
                        "<d:response><d:href>{href}</d:href>{}</d:response>",
                        ok(&format!(
                            "<d:getetag>{}</d:getetag><c:address-data>{}</c:address-data>",
                            xml_escape(&card.etag),
                            xml_escape(&card.data)
                        ))
                    )),
                    None => xml.push_str(&format!(
                        "<d:response><d:href>{href}</d:href>\
                         <d:status>HTTP/1.1 404 Not Found</d:status></d:response>"
                    )),
                }
            }
            xml.push_str(&state.extra_multiget_xml);
            xml.push_str(TAIL);
            (207, xml)
        }
        _ => (404, String::new()),
    }
}
