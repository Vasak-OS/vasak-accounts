//! Lo genérico de WebDAV: la credencial, el cliente HTTP, el `multistatus`, las
//! direcciones que manda el servidor y `sync-collection` (RFC 6578).
//!
//! Aparte de `carddav.rs` porque el calendario va a hablar lo mismo: CalDAV y
//! CardDAV son WebDAV con otro espacio de nombres para los datos.
//!
//! ── Qué se le cree al servidor, y qué no ────────────────────────────────────
//!
//! El servidor es el de la persona, pero lo que contesta **se lee como si lo
//! hubiera escrito cualquiera**: una respuesta rota, una desmedida o una armada
//! para hacer trabajar al programa no pueden tumbar el sincronizador ni llevarse
//! la credencial a otra parte. Por eso:
//!
//! - **Sólo se lee.** El cliente conoce dos métodos, `PROPFIND` y `REPORT`, y
//!   ningún otro ([`Method`]): no hay forma de escribir en el servidor desde
//!   acá, ni por descuido.
//! - **Cada respuesta tiene tope** ([`Limits::max_body_bytes`]), cortado mientras
//!   llega y no después de leerla entera.
//! - **El XML sin DTD**: `roxmltree` la rechaza por omisión, que es lo que
//!   cierra las entidades externas y las expansiones en cadena. Y con tope de
//!   nodos.
//! - **Cada dirección que manda el servidor se resuelve contra la colección y
//!   se rechaza si es de otro origen** —esquema, máquina y puerto— antes de
//!   pedirla o guardarla ([`resolve_href`]). La credencial viaja sólo al origen
//!   de la cuenta: el cliente se niega a mandar un pedido a otro, y **no sigue
//!   redirecciones**.
//! - **Sólo `https`.** La única excepción es de las pruebas, contra
//!   `127.0.0.1`, y no existe en el programa compilado ([`HttpPolicy`]).
//! - **La credencial no se imprime**: ni en el diario ni en un `{:?}`. La
//!   cabecera va marcada como sensible y los errores de la red salen sin la
//!   dirección.

use std::time::Duration;

use base64::Engine;
use zeroize::Zeroizing;

pub const NS_DAV: &str = "DAV:";

/// Cuánto se espera una respuesta.
const TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// El largo máximo de una dirección que manda el servidor. Una de más es algo
/// armado para llenar la base, no una tarjeta.
pub const MAX_HREF_BYTES: usize = 2048;

/// El largo máximo de un `sync-token` o un `getctag` que se guarda. Los de
/// verdad son una URL corta o un número.
pub const MAX_TOKEN_BYTES: usize = 1024;

/// Los topes de lo que llega de la red.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Lo que se lee de una respuesta. Una agenda de mil contactos son unos
    /// pocos megabytes; dieciséis es de sobra y corta un servidor que devuelve
    /// basura antes de que la memoria crezca sin freno.
    pub max_body_bytes: usize,
    /// Nodos de un documento XML. Una respuesta de veinte mil tarjetas son unos
    /// ciento sesenta mil; un millón es un documento hecho de etiquetas vacías.
    pub max_xml_nodes: u32,
    /// Libretas por cuenta.
    pub max_address_books: usize,
    /// Tarjetas por libreta.
    pub max_cards_per_book: usize,
    /// El tamaño de una tarjeta. Una con foto ronda los cien kilobytes; una de
    /// más no se guarda, y queda contada.
    pub max_vcard_bytes: usize,
    /// Cuántas tarjetas se piden en cada `addressbook-multiget`. Si una tanda
    /// pasa el tope del cuerpo se parte en dos, hasta llegar a una sola.
    pub multiget_batch: usize,
    /// Cuántas veces seguidas se sigue un `sync-collection` truncado (`507`).
    pub max_sync_rounds: usize,
}

impl Limits {
    pub const DEFAULT: Limits = Limits {
        max_body_bytes: 16 * 1024 * 1024,
        max_xml_nodes: 1_000_000,
        max_address_books: 100,
        max_cards_per_book: 20_000,
        max_vcard_bytes: 512 * 1024,
        multiget_batch: 50,
        max_sync_rounds: 50,
    };
}

/// Lo que puede salir mal hablando con un servidor DAV.
///
/// El texto de cada uno **no lleva direcciones** ni nada del servidor: sale
/// tal cual en el estado del almacén, que lo lee cualquiera de la sesión. El
/// detalle va al diario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DavError {
    /// La dirección de la cuenta no es `https`, o trae usuario y contraseña.
    InsecureUrl,
    /// Una dirección de otro origen que el de la cuenta.
    ForeignOrigin,
    /// 401: la credencial no vale.
    Unauthorized,
    /// El servidor quiso redirigir. No se sigue: el pedido lleva la credencial.
    Redirect(u16),
    /// Cualquier otro estado que no se esperaba.
    Status(u16),
    /// La respuesta pasó el tope.
    BodyTooLarge(usize),
    /// No se pudo hablar con el servidor.
    Network(String),
    /// La respuesta no es un XML que se entienda.
    BadXml(String),
    TooManyAddressBooks(usize),
    TooManyCards(usize),
}

impl std::fmt::Display for DavError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DavError::InsecureUrl => f.write_str(
                "la dirección de la cuenta no está cifrada: por ahí la contraseña viajaría a la \
                 vista de cualquiera en la red",
            ),
            DavError::ForeignOrigin => {
                f.write_str("el servidor mandó una dirección de otro servidor, y no se sigue")
            }
            DavError::Unauthorized => f.write_str(
                "el servidor rechazó el usuario o la contraseña; volvé a conectar la cuenta \
                 desde Configuración",
            ),
            DavError::Redirect(status) => write!(
                f,
                "el servidor respondió {status} para mandar a otra dirección, y no se sigue: el \
                 pedido lleva la credencial"
            ),
            DavError::Status(status) => write!(f, "el servidor respondió {status}"),
            DavError::BodyTooLarge(cap) => write!(
                f,
                "el servidor mandó más de {cap} bytes, que es lo que se lee de una vez"
            ),
            DavError::Network(detail) => write!(f, "no se pudo hablar con el servidor: {detail}"),
            DavError::BadXml(detail) => {
                write!(f, "el servidor contestó algo que no se entiende: {detail}")
            }
            DavError::TooManyAddressBooks(cap) => {
                write!(f, "la cuenta tiene más de {cap} libretas")
            }
            DavError::TooManyCards(cap) => write!(f, "una libreta tiene más de {cap} tarjetas"),
        }
    }
}

impl std::error::Error for DavError {}

// ---------------------------------------------------------------------------
// La credencial
// ---------------------------------------------------------------------------

/// Cómo autenticarse contra el servidor.
///
/// Se decide por **lo que guardó el servicio de cuentas** y no por el proveedor:
/// una cuenta de Google conectada por OAuth2 y una conectada como servidor
/// personalizado con contraseña se ven igual desde acá. La marca es el
/// `client_id`, que sólo tienen las que pasaron por un flujo OAuth2 —lo escribe
/// el servicio junto con las URLs para renovar el token—. Es el mismo criterio
/// que usa el correo, y por el mismo motivo.
///
/// Confundirlas manda una contraseña donde va un token: el servidor contesta un
/// rechazo que parece de credenciales y manda a revisar la contraseña de una
/// cuenta que está perfecta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    /// Usuario y contraseña, en una cabecera `Basic`.
    Password,
    /// Un token de acceso, en una cabecera `Bearer`. Google no acepta otra cosa.
    Token,
}

/// Lo necesario para hablar con el servidor de una cuenta.
///
/// **Sin `Debug` derivado**: `secret` es la contraseña o el token de la cuenta,
/// y un `Debug` derivado lo escribiría entero en cualquier registro, en
/// cualquier `dbg!` de paso y en el mensaje de cualquier pánico que lo lleve
/// adentro. Y en `Zeroizing`: al soltarla, la copia de este lado se borra.
#[derive(Clone, PartialEq, Eq)]
pub struct DavCredential {
    /// La dirección donde viven las colecciones de la persona.
    pub home: url::Url,
    pub username: String,
    pub secret: Zeroizing<String>,
    /// Qué **es** ese secreto, que decide cómo se manda.
    pub auth: AuthKind,
}

impl std::fmt::Debug for DavCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DavCredential")
            .field("home", &self.home.as_str())
            .field("username", &self.username)
            .field("secret", &"<tachado>")
            .field("auth", &self.auth)
            .finish()
    }
}

/// Arma la credencial a partir de lo que guardó el servicio al conectar.
///
/// Viene de `credencial_desde` de `vasak-contacts`. `config` es lo que
/// contesta `GetAccountData` para la capacidad, ya sacado del envoltorio.
pub fn credential_from(
    config: &serde_json::Value,
    secret: Zeroizing<String>,
) -> Result<DavCredential, String> {
    let field = |name: &str| config.get(name).and_then(|v| v.as_str());

    let home = field("url").ok_or(
        "la cuenta no guardó la dirección de su libreta; volvé a conectarla desde Configuración",
    )?;
    let username = field("username")
        .ok_or("la cuenta no guardó el usuario")?
        .to_string();

    let home = url::Url::parse(home.trim())
        .map_err(|_| "la dirección guardada de la libreta no es una dirección".to_string())?;
    if home.scheme() != "https" {
        return Err(DavError::InsecureUrl.to_string());
    }
    if !home.username().is_empty() || home.password().is_some() {
        return Err("la dirección guardada de la libreta trae usuario y contraseña adentro".into());
    }

    // El `client_id` es la marca de que la cuenta pasó por un flujo OAuth2, así
    // que el secreto es un token y no una contraseña. Ver `AuthKind`.
    let auth = if field("client_id").is_some() {
        AuthKind::Token
    } else {
        AuthKind::Password
    };

    Ok(DavCredential {
        home,
        username,
        secret,
        auth,
    })
}

/// La cabecera `Authorization` que le corresponde a esta cuenta.
///
/// `Basic` para una contraseña y `Bearer` para un token. No es una preferencia:
/// Google contesta 401 a cualquier `Basic`, y un servidor que espera contraseña
/// no entiende un `Bearer`. Cuál va lo decide lo que guardó el servicio de
/// cuentas, no el proveedor — ver [`AuthKind`].
pub fn authorization_header(credential: &DavCredential) -> Zeroizing<String> {
    match credential.auth {
        AuthKind::Password => {
            let pair = Zeroizing::new(format!(
                "{}:{}",
                credential.username,
                credential.secret.as_str()
            ));
            Zeroizing::new(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())
            ))
        }
        AuthKind::Token => Zeroizing::new(format!("Bearer {}", credential.secret.as_str())),
    }
}

// ---------------------------------------------------------------------------
// Las direcciones
// ---------------------------------------------------------------------------

/// Resuelve una dirección que mandó el servidor contra la colección en la que
/// vino, y la rechaza si es de otro origen.
///
/// Los servidores contestan con una ruta absoluta casi siempre, con una URL
/// entera a veces y con una relativa de vez en cuando: `Url::join` resuelve las
/// tres, y pegarlas a mano rompería la segunda.
///
/// **Otro origen —esquema, máquina o puerto— es `ForeignOrigin`**: pedirla
/// mandaría la credencial de la cuenta a quien diga el servidor, y guardarla
/// haría que la próxima vuelta la pida. También se rechaza una con usuario y
/// contraseña adentro, o una desmedida. El fragmento se descarta: no llega al
/// servidor, así que dos direcciones que sólo difieren en él son la misma.
pub fn resolve_href(base: &url::Url, href: &str) -> Result<url::Url, DavError> {
    let href = href.trim();
    if href.is_empty() || href.len() > MAX_HREF_BYTES {
        return Err(DavError::ForeignOrigin);
    }
    let mut resolved = base.join(href).map_err(|_| DavError::ForeignOrigin)?;
    if resolved.origin() != base.origin()
        || !resolved.username().is_empty()
        || resolved.password().is_some()
    {
        return Err(DavError::ForeignOrigin);
    }
    resolved.set_fragment(None);
    Ok(resolved)
}

/// Si dos direcciones son la misma colección, con la barra final o sin ella.
pub fn same_collection(a: &url::Url, b: &url::Url) -> bool {
    a.origin() == b.origin()
        && a.path().trim_end_matches('/') == b.path().trim_end_matches('/')
        && a.query() == b.query()
}

/// Escapa un texto para meterlo en un elemento XML.
pub fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// Lo que va en un `<d:href>` de un pedido: la ruta, con su consulta si tiene.
///
/// No la URL entera: los servidores comparan rutas, y alguno contesta vacío a
/// una URL absoluta.
pub fn href_for_request(url: &url::Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

// ---------------------------------------------------------------------------
// El cliente
// ---------------------------------------------------------------------------

/// Los únicos métodos HTTP que conoce el cliente: **los dos de lectura**.
///
/// Un tipo y no un texto para que escribir en el servidor —`PUT`, `DELETE`,
/// `PROPPATCH`— no se pueda hacer sin agregar una variante acá, y la prueba
/// `el_cliente_no_tiene_ningun_metodo_de_escritura` lo fija. Escribir llega
/// con la cola de operaciones (PR 7 de `vasak-accounts#23`), que es la que
/// decide qué gana en un conflicto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Propfind,
    Report,
}

impl Method {
    #[cfg(test)]
    pub const ALL: [Method; 2] = [Method::Propfind, Method::Report];

    pub fn as_str(self) -> &'static str {
        match self {
            Method::Propfind => "PROPFIND",
            Method::Report => "REPORT",
        }
    }

    fn to_reqwest(self) -> reqwest::Method {
        reqwest::Method::from_bytes(self.as_str().as_bytes()).expect("es un método válido")
    }
}

/// Qué se deja hablar sin cifrar. En el programa, **nada**: esto existe para
/// que las pruebas puedan levantar un servidor de mentira en `127.0.0.1` sin
/// certificados, y la perilla no está compilada fuera de ellas.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HttpPolicy {
    #[cfg(test)]
    plain_loopback: bool,
}

impl HttpPolicy {
    /// `http://127.0.0.1`, sólo en las pruebas.
    #[cfg(test)]
    pub fn plain_loopback() -> Self {
        Self {
            plain_loopback: true,
        }
    }

    fn allows(&self, url: &url::Url) -> bool {
        if url.scheme() == "https" {
            return true;
        }
        #[cfg(test)]
        if self.plain_loopback
            && url.scheme() == "http"
            && url.host() == Some(url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST))
        {
            return true;
        }
        false
    }

    #[cfg(test)]
    fn https_only(&self) -> bool {
        !self.plain_loopback
    }

    #[cfg(not(test))]
    fn https_only(&self) -> bool {
        true
    }
}

/// Una respuesta ya leída entera, con tope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub body: String,
}

/// Un cliente para **una** cuenta: su credencial y su origen.
pub struct DavClient {
    http: reqwest::Client,
    authorization: reqwest::header::HeaderValue,
    home: url::Url,
    limits: Limits,
}

impl DavClient {
    pub fn new(
        credential: &DavCredential,
        limits: Limits,
        policy: HttpPolicy,
    ) -> Result<Self, DavError> {
        if !policy.allows(&credential.home)
            || !credential.home.username().is_empty()
            || credential.home.password().is_some()
        {
            return Err(DavError::InsecureUrl);
        }

        let header = authorization_header(credential);
        let mut authorization = reqwest::header::HeaderValue::from_str(header.as_str())
            .map_err(|_| DavError::Network("la credencial no se puede mandar en HTTP".into()))?;
        // Para que ni `{:?}` ni el diario de `reqwest` la muestren.
        authorization.set_sensitive(true);

        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            // Sin redirecciones: el pedido lleva la contraseña, y una
            // redirección la mandaría adonde el servidor diga.
            .redirect(reqwest::redirect::Policy::none())
            .https_only(policy.https_only())
            .user_agent("VasakOS")
            .build()
            .map_err(|e| DavError::Network(e.without_url().to_string()))?;

        Ok(Self {
            http,
            authorization,
            home: credential.home.clone(),
            limits,
        })
    }

    pub fn home(&self) -> &url::Url {
        &self.home
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Manda un pedido y lee la respuesta con tope.
    ///
    /// **Sólo al origen de la cuenta**: una dirección de otro no sale, aunque
    /// alguien se haya olvidado de pasarla por [`resolve_href`]. Un `401` y una
    /// redirección son error; cualquier otro estado vuelve con su cuerpo, para
    /// que quien llamó decida (un `403` de `sync-collection` puede ser un
    /// token vencido).
    pub async fn request(
        &self,
        method: Method,
        url: &url::Url,
        depth: &str,
        body: String,
    ) -> Result<Reply, DavError> {
        if url.origin() != self.home.origin() {
            return Err(DavError::ForeignOrigin);
        }

        let response = self
            .http
            .request(method.to_reqwest(), url.clone())
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone())
            .header("Depth", depth)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/xml; charset=utf-8",
            )
            .body(body)
            .send()
            .await
            .map_err(|e| DavError::Network(e.without_url().to_string()))?;

        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(DavError::Unauthorized);
        }
        if status.is_redirection() {
            return Err(DavError::Redirect(status.as_u16()));
        }

        let body = body_with_cap(response, self.limits.max_body_bytes).await?;
        Ok(Reply {
            status: status.as_u16(),
            body,
        })
    }

    /// Lee un documento XML con los topes de este cliente.
    pub fn parse<'a>(&self, xml: &'a str) -> Result<roxmltree::Document<'a>, DavError> {
        parse_xml(xml, self.limits.max_xml_nodes)
    }
}

/// Lee el cuerpo de una respuesta, cortando apenas pasa el tope.
///
/// Por trozos y cortando en el momento: leer todo y medir después es
/// enterarse del problema cuando ya pasó — un servidor que manda gigabytes
/// hace crecer la memoria hasta donde quiera. Viene de `cuerpo_con_tope` de
/// `vasak-contacts`.
pub async fn body_with_cap(
    mut response: reqwest::Response,
    cap: usize,
) -> Result<String, DavError> {
    if response
        .content_length()
        .is_some_and(|length| length > cap as u64)
    {
        return Err(DavError::BodyTooLarge(cap));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| DavError::Network(e.without_url().to_string()))?
    {
        if body.len() + chunk.len() > cap {
            return Err(DavError::BodyTooLarge(cap));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Lee un documento, **sin DTD** y con tope de nodos.
///
/// Un XML que no se entiende es un error y no una lista vacía: una respuesta
/// cortada a la mitad —una conexión que se interrumpió, un servidor que
/// contestó una página de error— no puede verse igual que «esta cuenta no
/// tiene nada».
pub fn parse_xml(xml: &str, max_nodes: u32) -> Result<roxmltree::Document<'_>, DavError> {
    let options = roxmltree::ParsingOptions {
        allow_dtd: false,
        nodes_limit: max_nodes,
        ..roxmltree::ParsingOptions::default()
    };
    roxmltree::Document::parse_with_options(xml, options)
        .map_err(|e| DavError::BadXml(e.to_string()))
}

// ---------------------------------------------------------------------------
// El multistatus
// ---------------------------------------------------------------------------

/// Una propiedad de una respuesta, con lo que interesa de ella.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prop {
    pub namespace: String,
    pub name: String,
    /// El texto de adentro, entero.
    pub text: String,
    /// Los elementos de adentro, a cualquier profundidad: `collection` y
    /// `addressbook` en un `resourcetype`, `sync-collection` en un
    /// `supported-report-set`.
    pub descendants: Vec<(String, String)>,
}

impl Prop {
    pub fn contains(&self, namespace: &str, name: &str) -> bool {
        self.descendants
            .iter()
            .any(|(ns, n)| ns == namespace && n == name)
    }
}

/// Una `<d:response>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DavResponse {
    /// Tal como vino: se resuelve con [`resolve_href`].
    pub href: String,
    /// El estado de la respuesta entera, si vino (`404` para lo que se borró
    /// en un `sync-collection`, `507` para uno truncado).
    pub status: Option<u16>,
    /// Las propiedades que vinieron con un estado `2xx`.
    pub props: Vec<Prop>,
}

impl DavResponse {
    pub fn prop(&self, namespace: &str, name: &str) -> Option<&Prop> {
        self.props
            .iter()
            .find(|p| p.namespace == namespace && p.name == name)
    }

    /// El texto de una propiedad, recortado y no vacío.
    pub fn text(&self, namespace: &str, name: &str) -> Option<&str> {
        self.prop(namespace, name)
            .map(|p| p.text.trim())
            .filter(|t| !t.is_empty())
    }
}

/// Un `<d:multistatus>` leído.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Multistatus {
    pub responses: Vec<DavResponse>,
    /// El `<d:sync-token>` de un `sync-collection`, si vino.
    pub sync_token: Option<String>,
}

/// El número de una línea de estado: `HTTP/1.1 404 Not Found` → 404.
fn status_code(line: &str) -> Option<u16> {
    line.split_whitespace().nth(1)?.parse().ok()
}

fn all_text(node: roxmltree::Node<'_, '_>) -> String {
    node.descendants()
        .filter(|n| n.is_text())
        .filter_map(|n| n.text())
        .collect()
}

/// Lee un `multistatus` entero.
///
/// Sólo las propiedades que vinieron con un estado `2xx`: un `404` en un
/// `propstat` quiere decir «esa propiedad no la tengo», y leerla como vacía
/// confundiría «no hay ETag» con «el ETag es vacío».
pub fn parse_multistatus(document: &roxmltree::Document<'_>) -> Result<Multistatus, DavError> {
    let root = document.root_element();
    if !root.has_tag_name((NS_DAV, "multistatus")) {
        return Err(DavError::BadXml("no es un multistatus".into()));
    }

    let mut multistatus = Multistatus {
        sync_token: root
            .children()
            .find(|n| n.has_tag_name((NS_DAV, "sync-token")))
            .map(|n| all_text(n).trim().to_string())
            .filter(|t| !t.is_empty()),
        ..Default::default()
    };

    for response in root
        .children()
        .filter(|n| n.has_tag_name((NS_DAV, "response")))
    {
        let Some(href) = response
            .children()
            .find(|n| n.has_tag_name((NS_DAV, "href")))
            .map(|n| all_text(n).trim().to_string())
        else {
            continue;
        };
        let status = response
            .children()
            .find(|n| n.has_tag_name((NS_DAV, "status")))
            .and_then(|n| status_code(&all_text(n)));

        let mut props = Vec::new();
        for propstat in response
            .children()
            .filter(|n| n.has_tag_name((NS_DAV, "propstat")))
        {
            let ok = propstat
                .children()
                .find(|n| n.has_tag_name((NS_DAV, "status")))
                .and_then(|n| status_code(&all_text(n)))
                .is_some_and(|code| (200..300).contains(&code));
            if !ok {
                continue;
            }
            for prop in propstat
                .children()
                .filter(|n| n.has_tag_name((NS_DAV, "prop")))
                .flat_map(|n| n.children().filter(|c| c.is_element()))
            {
                props.push(Prop {
                    namespace: prop.tag_name().namespace().unwrap_or("").to_string(),
                    name: prop.tag_name().name().to_string(),
                    text: all_text(prop),
                    descendants: prop
                        .descendants()
                        .skip(1)
                        .filter(|n| n.is_element())
                        .map(|n| {
                            (
                                n.tag_name().namespace().unwrap_or("").to_string(),
                                n.tag_name().name().to_string(),
                            )
                        })
                        .collect(),
                });
            }
        }

        multistatus.responses.push(DavResponse {
            href,
            status,
            props,
        });
    }

    Ok(multistatus)
}

// ---------------------------------------------------------------------------
// sync-collection (RFC 6578)
// ---------------------------------------------------------------------------

/// El cuerpo del `REPORT` de `sync-collection`: sin token es la carga inicial,
/// con token son las diferencias desde entonces. Sólo pide el ETag: las
/// tarjetas se traen después, de a tandas, con `addressbook-multiget`.
pub fn sync_collection_body(token: Option<&str>) -> String {
    let token = token.map(xml_escape).unwrap_or_default();
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<d:sync-collection xmlns:d="DAV:">
  <d:sync-token>{token}</d:sync-token>
  <d:sync-level>1</d:sync-level>
  <d:prop><d:getetag/></d:prop>
</d:sync-collection>"#
    )
}

/// Lo que cambió en una colección desde un token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncDelta {
    /// Lo nuevo o cambiado, con su ETag si vino.
    pub changed: Vec<(url::Url, Option<String>)>,
    /// Lo que se borró: vino con `404` dentro de su `<d:response>`.
    pub removed: Vec<url::Url>,
    /// El token para la próxima vez.
    pub token: Option<String>,
    /// Si el servidor cortó la respuesta (`507` sobre la colección) y hay que
    /// volver a pedir desde `token`.
    pub truncated: bool,
    /// Direcciones de otro origen que se descartaron.
    pub foreign: usize,
}

/// Cómo contestó el servidor un `sync-collection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncCollection {
    Delta(SyncDelta),
    /// El token que se mandó ya no vale (`DAV:valid-sync-token`): hay que
    /// tirarlo y empezar de cero.
    InvalidToken,
    /// El servidor no sabe hacer `sync-collection`: se va por ETag.
    NotSupported,
}

/// Si un cuerpo de error es la condición `DAV:valid-sync-token` (RFC 6578,
/// 3.2) o `DAV:supported-report` (RFC 3253, 3.6).
fn has_precondition(client: &DavClient, body: &str, name: &str) -> bool {
    client.parse(body).is_ok_and(|document| {
        document
            .descendants()
            .any(|n| n.has_tag_name((NS_DAV, name)))
    })
}

/// Pide las diferencias de una colección desde `token` (o todo, sin token).
///
/// - `207` → las diferencias. Lo que viene con `404` en su `<d:response>` se
///   borró; lo que trae `getetag`, cambió; un `507` sobre la colección misma
///   es una respuesta truncada.
/// - `403` o `409` con `DAV:valid-sync-token` → [`SyncCollection::InvalidToken`].
/// - `400`, `405`, `415`, `501`, o `403` con `DAV:supported-report` →
///   [`SyncCollection::NotSupported`].
pub async fn sync_collection(
    client: &DavClient,
    collection: &url::Url,
    token: Option<&str>,
) -> Result<SyncCollection, DavError> {
    let reply = client
        .request(
            Method::Report,
            collection,
            // La RFC lo define sólo con `Depth: 0`; con otro valor es un 400.
            "0",
            sync_collection_body(token),
        )
        .await?;

    match reply.status {
        207 => {}
        403 | 409 if has_precondition(client, &reply.body, "valid-sync-token") => {
            return Ok(SyncCollection::InvalidToken)
        }
        403 if has_precondition(client, &reply.body, "supported-report") => {
            return Ok(SyncCollection::NotSupported)
        }
        400 | 405 | 415 | 501 => return Ok(SyncCollection::NotSupported),
        other => return Err(DavError::Status(other)),
    }

    let document = client.parse(&reply.body)?;
    let multistatus = parse_multistatus(&document)?;
    let mut delta = SyncDelta {
        token: multistatus.sync_token.clone(),
        ..Default::default()
    };

    for response in &multistatus.responses {
        let Ok(url) = resolve_href(collection, &response.href) else {
            delta.foreign += 1;
            continue;
        };
        match response.status {
            // La colección misma: sólo interesa si dice que cortó la respuesta.
            _ if same_collection(&url, collection) => {
                if response.status == Some(507) {
                    delta.truncated = true;
                }
            }
            Some(404) => delta.removed.push(url),
            // Cualquier otro estado de error sobre una tarjeta no dice ni que
            // cambió ni que se fue: se deja para la próxima.
            Some(code) if !(200..300).contains(&code) => {}
            _ => {
                let etag = response.text(NS_DAV, "getetag").map(str::to_string);
                delta.changed.push((url, etag));
            }
        }
    }

    Ok(SyncCollection::Delta(delta))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(auth: AuthKind) -> DavCredential {
        DavCredential {
            home: url::Url::parse("https://servidor.ejemplo.com/dav/").unwrap(),
            username: "ana@ejemplo.com".into(),
            secret: Zeroizing::new("el-secreto".into()),
            auth,
        }
    }

    /// Una contraseña va en `Basic`, con el usuario delante.
    #[test]
    fn la_contrasena_viaja_en_basic() {
        let header = authorization_header(&credential(AuthKind::Password));

        assert!(header.starts_with("Basic "), "{}", header.as_str());
        let encoded =
            base64::engine::general_purpose::STANDARD.encode("ana@ejemplo.com:el-secreto");
        assert_eq!(header.as_str(), format!("Basic {encoded}"));
    }

    /// Un token va en `Bearer` y **sin el usuario**: Google contesta 401 a
    /// cualquier `Basic`, y el rechazo parece de credenciales.
    #[test]
    fn el_token_viaja_en_bearer() {
        let header = authorization_header(&credential(AuthKind::Token));

        assert_eq!(header.as_str(), "Bearer el-secreto");
    }

    /// El secreto nunca se codifica en base64 cuando es un token: eso es lo que
    /// hacía que Google lo rechazara, y el modo de fallo es silencioso porque
    /// una cabecera mal armada se ve igual que una bien armada.
    #[test]
    fn las_dos_formas_no_se_parecen() {
        let with_password = authorization_header(&credential(AuthKind::Password));
        let with_token = authorization_header(&credential(AuthKind::Token));

        assert_ne!(with_password, with_token);
    }

    // ── La credencial, desde lo que guardó el servicio ────────────────────

    fn from(config: serde_json::Value) -> Result<DavCredential, String> {
        credential_from(&config, Zeroizing::new("la-contrasena".into()))
    }

    /// El secreto no puede aparecer en un registro ni en un pánico.
    #[test]
    fn el_secreto_no_se_imprime() {
        let credential = DavCredential {
            home: url::Url::parse("https://nube.ejemplo.com/dav/addressbooks/users/ana/").unwrap(),
            username: "ana".into(),
            secret: Zeroizing::new("la-contrasena-de-verdad".into()),
            auth: AuthKind::Password,
        };

        let printed = format!("{credential:?}");
        assert!(!printed.contains("la-contrasena-de-verdad"), "{printed}");
        // Y lo que sirve para diagnosticar se sigue viendo.
        assert!(printed.contains("nube.ejemplo.com"), "{printed}");
        assert!(printed.contains("ana"), "{printed}");

        // Ni el cliente armado con ella.
        let client = DavClient::new(&credential, Limits::DEFAULT, HttpPolicy::default()).unwrap();
        let header = format!("{:?}", client.authorization);
        assert!(!header.contains("Basic"), "{header}");
    }

    #[test]
    fn la_credencial_sale_de_lo_que_guardo_el_servicio() {
        let credential = from(serde_json::json!({
            "url": "https://nube.ejemplo.com/remote.php/dav/addressbooks/users/ana/",
            "username": "ana",
            "auth": "basic",
        }))
        .unwrap();
        assert_eq!(credential.username, "ana");
        assert!(credential.home.as_str().ends_with("/users/ana/"));
    }

    /// Una cuenta con contraseña se autentica con contraseña.
    ///
    /// Es la de Nextcloud y la del servidor escrito a mano: lo que guardó el
    /// servicio no tiene `client_id` porque nunca pasó por un flujo OAuth2.
    #[test]
    fn sin_client_id_el_secreto_es_una_contrasena() {
        let credential = from(serde_json::json!({
            "url": "https://nube.ejemplo.com/remote.php/dav/addressbooks/users/ana/",
            "username": "ana",
        }))
        .unwrap();
        assert_eq!(credential.auth, AuthKind::Password);
    }

    /// Y una de Google, con token.
    ///
    /// La marca es el `client_id`, que sólo lo escribe el servicio cuando la
    /// cuenta pasó por OAuth2. Mandarle `Basic` a Google da 401, y el rechazo
    /// parece de credenciales: manda a revisar la contraseña de una cuenta que
    /// está perfecta.
    #[test]
    fn con_client_id_el_secreto_es_un_token() {
        let credential = from(serde_json::json!({
            "url": "https://www.googleapis.com/carddav/v1/principals/ana@gmail.com/",
            "username": "ana@gmail.com",
            "client_id": "algo.apps.googleusercontent.com",
            "token_url": "https://oauth2.googleapis.com/token",
        }))
        .unwrap();
        assert_eq!(credential.auth, AuthKind::Token);
        assert_eq!(credential.username, "ana@gmail.com");
    }

    /// Sin cifrar no se habla: por ahí la contraseña de la cuenta viajaría en
    /// claro. El servicio ya exige HTTPS al conectar, así que llegar acá con
    /// `http://` es una cuenta armada a mano contra esa recomendación.
    #[test]
    fn una_direccion_sin_cifrar_se_rechaza() {
        let error =
            from(serde_json::json!({ "url": "http://nube.ejemplo.com/dav/", "username": "ana" }))
                .unwrap_err();
        assert!(error.contains("cifrada"), "{error}");
        // Tampoco con usuario y contraseña pegados a la dirección.
        assert!(from(serde_json::json!({
            "url": "https://ana:otra@nube.ejemplo.com/dav/",
            "username": "ana"
        }))
        .is_err());
    }

    /// El mensaje tiene que decir qué hacer. Una cuenta a la que le falta la
    /// dirección se conectó antes de que se guardara, y lo que corresponde es
    /// reconectarla.
    #[test]
    fn una_cuenta_sin_direccion_dice_que_se_reconecte() {
        let error = from(serde_json::json!({ "username": "ana" })).unwrap_err();
        assert!(error.contains("volvé a conectarla"), "{error}");
    }

    // ── El cliente ─────────────────────────────────────────────────────────

    /// **El cliente sólo lee.** Escribir en el servidor —`PUT`, `DELETE`,
    /// `PROPPATCH`, `MOVE`— tiene que ser una decisión que se ve en el código,
    /// no un texto que alguien pasa. El `match` de abajo no tiene comodín: una
    /// variante nueva no compila sin pasar por acá.
    #[test]
    fn el_cliente_no_tiene_ningun_metodo_de_escritura() {
        for method in Method::ALL {
            let read_only = match method {
                Method::Propfind | Method::Report => true,
            };
            assert!(read_only);
            assert!(
                !matches!(
                    method.as_str(),
                    "PUT"
                        | "POST"
                        | "DELETE"
                        | "PATCH"
                        | "PROPPATCH"
                        | "MKCOL"
                        | "MKCALENDAR"
                        | "MOVE"
                        | "COPY"
                        | "LOCK"
                        | "UNLOCK"
                ),
                "{}",
                method.as_str()
            );
        }
        assert_eq!(Method::ALL.len(), 2);
    }

    /// Sólo `https`. `http` no se acepta ni siquiera contra la propia máquina
    /// fuera de las pruebas, y dentro de ellas sólo contra `127.0.0.1`.
    #[test]
    fn el_cliente_solo_habla_cifrado() {
        let mut plain = credential(AuthKind::Password);
        plain.home = url::Url::parse("http://servidor.ejemplo.com/dav/").unwrap();
        assert_eq!(
            DavClient::new(&plain, Limits::DEFAULT, HttpPolicy::default()).err(),
            Some(DavError::InsecureUrl)
        );
        assert_eq!(
            DavClient::new(&plain, Limits::DEFAULT, HttpPolicy::plain_loopback()).err(),
            Some(DavError::InsecureUrl),
            "la perilla de las pruebas no abre `http` hacia afuera"
        );

        plain.home = url::Url::parse("http://127.0.0.1:8080/dav/").unwrap();
        assert!(DavClient::new(&plain, Limits::DEFAULT, HttpPolicy::default()).is_err());
        assert!(DavClient::new(&plain, Limits::DEFAULT, HttpPolicy::plain_loopback()).is_ok());
    }

    // ── Las direcciones ────────────────────────────────────────────────────

    #[test]
    fn las_direcciones_se_resuelven_contra_la_coleccion() {
        let base = url::Url::parse("https://nube.ejemplo.com/dav/libro/").unwrap();
        assert_eq!(
            resolve_href(&base, "/dav/libro/ana.vcf").unwrap().as_str(),
            "https://nube.ejemplo.com/dav/libro/ana.vcf"
        );
        assert_eq!(
            resolve_href(&base, "juan.vcf").unwrap().as_str(),
            "https://nube.ejemplo.com/dav/libro/juan.vcf"
        );
        assert_eq!(
            resolve_href(&base, "https://nube.ejemplo.com:443/dav/libro/x.vcf#y")
                .unwrap()
                .as_str(),
            "https://nube.ejemplo.com/dav/libro/x.vcf"
        );
    }

    /// **Otro origen no se pide ni se guarda**: esquema, máquina o puerto
    /// distintos mandarían la credencial adonde diga el servidor.
    #[test]
    fn una_direccion_de_otro_origen_se_rechaza() {
        let base = url::Url::parse("https://nube.ejemplo.com/dav/libro/").unwrap();
        for foreign in [
            "https://otra.ejemplo.com/dav/libro/ana.vcf",
            "http://nube.ejemplo.com/dav/libro/ana.vcf",
            "https://nube.ejemplo.com:8443/dav/libro/ana.vcf",
            "//otra.ejemplo.com/x",
            "https://ana:clave@nube.ejemplo.com/dav/libro/ana.vcf",
            "",
        ] {
            assert_eq!(
                resolve_href(&base, foreign),
                Err(DavError::ForeignOrigin),
                "{foreign}"
            );
        }
        let long = format!("/{}", "a".repeat(MAX_HREF_BYTES));
        assert_eq!(resolve_href(&base, &long), Err(DavError::ForeignOrigin));
    }

    #[test]
    fn lo_que_va_en_un_href_se_escapa() {
        assert_eq!(xml_escape("a<b>&\"c'"), "a&lt;b&gt;&amp;&quot;c&apos;");
        let url = url::Url::parse("https://x/dav/a%20b.vcf?v=1").unwrap();
        assert_eq!(href_for_request(&url), "/dav/a%20b.vcf?v=1");
    }

    // ── El XML ─────────────────────────────────────────────────────────────

    /// Sin DTD: es lo que cierra las entidades externas y las expansiones en
    /// cadena («mil millones de risas»).
    #[test]
    fn un_xml_con_dtd_se_rechaza() {
        let with_dtd = r#"<?xml version="1.0"?>
<!DOCTYPE d [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]>
<d:multistatus xmlns:d="DAV:">&b;</d:multistatus>"#;
        assert!(matches!(
            parse_xml(with_dtd, 1_000_000),
            Err(DavError::BadXml(_))
        ));
        let external = r#"<?xml version="1.0"?>
<!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<d:multistatus xmlns:d="DAV:">&x;</d:multistatus>"#;
        assert!(parse_xml(external, 1_000_000).is_err());
    }

    #[test]
    fn un_xml_con_demasiados_nodos_se_rechaza() {
        let many = format!(
            r#"<d:multistatus xmlns:d="DAV:">{}</d:multistatus>"#,
            "<d:x/>".repeat(200)
        );
        assert!(parse_xml(&many, 1_000).is_ok());
        assert!(parse_xml(&many, 100).is_err());
    }

    const SYNC: &str = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/dav/libro/ana.vcf</d:href>
    <d:propstat><d:prop><d:getetag>"e1"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  </d:response>
  <d:response>
    <d:href>/dav/libro/juan.vcf</d:href>
    <d:status>HTTP/1.1 404 Not Found</d:status>
  </d:response>
  <d:response>
    <d:href>/dav/libro/sin-etag.vcf</d:href>
    <d:propstat><d:prop><d:getetag/></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>
  </d:response>
  <d:sync-token>https://x/sync/42</d:sync-token>
</d:multistatus>"#;

    /// El estado de la respuesta entera y el de cada `propstat` no son lo
    /// mismo: un `404` en el `propstat` es «esa propiedad no la tengo», no
    /// «se borró».
    #[test]
    fn el_multistatus_separa_el_estado_de_la_respuesta_del_de_sus_propiedades() {
        let document = parse_xml(SYNC, 1_000).unwrap();
        let multistatus = parse_multistatus(&document).unwrap();

        assert_eq!(multistatus.sync_token.as_deref(), Some("https://x/sync/42"));
        assert_eq!(multistatus.responses.len(), 3);
        assert_eq!(
            multistatus.responses[0].text(NS_DAV, "getetag"),
            Some("\"e1\"")
        );
        assert_eq!(multistatus.responses[1].status, Some(404));
        assert!(multistatus.responses[2].status.is_none());
        assert!(multistatus.responses[2].props.is_empty());
    }

    #[test]
    fn lo_que_no_es_un_multistatus_no_se_lee_como_vacio() {
        for garbage in ["<html/>", r#"<d:error xmlns:d="DAV:"/>"#] {
            let document = parse_xml(garbage, 1_000).unwrap();
            assert!(parse_multistatus(&document).is_err(), "{garbage}");
        }
        let empty = parse_xml(r#"<d:multistatus xmlns:d="DAV:"/>"#, 1_000).unwrap();
        assert_eq!(parse_multistatus(&empty).unwrap(), Multistatus::default());
    }

    #[test]
    fn el_pedido_de_diferencias_es_xml_valido_y_escapa_el_token() {
        for token in [None, Some("http://x/?a=1&b=<2>")] {
            let body = sync_collection_body(token);
            let document = roxmltree::Document::parse(&body).unwrap();
            let sent = document
                .descendants()
                .find(|n| n.has_tag_name((NS_DAV, "sync-token")))
                .unwrap()
                .text()
                .unwrap_or("");
            assert_eq!(sent, token.unwrap_or(""));
        }
    }
}
