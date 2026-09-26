//! Lo genérico de WebDAV: la credencial, el cliente HTTP, el `multistatus`, las
//! direcciones que manda el servidor y `sync-collection` (RFC 6578).
//!
//! Aparte de `carddav.rs` y `caldav.rs` porque los dos hablan lo mismo: CalDAV
//! y CardDAV son WebDAV con otro espacio de nombres para los datos. Lo que es de
//! los dos —el ETag de cada recurso de una colección, quedarse con lo que se
//! pidió de un `multiget`— vive acá.
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
//!   nodos, de profundidad, de espacios de nombres y de atributos por
//!   elemento, mirados antes de armarlo ([`check_shape`]): `roxmltree` baja
//!   de forma recursiva —un anidado de más aborta el proceso—, tarda como el
//!   cubo con miles de espacios de nombres y como el cuadrado con miles de
//!   atributos en un elemento. Se lee fuera del bucle de eventos
//!   ([`off_runtime`]).
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
/// El de `getctag`, una extensión de Apple que casi todos los servidores
/// hablan, de contactos y de calendario: cambia cada vez que cambia algo de la
/// colección.
pub const NS_CALENDARSERVER: &str = "http://calendarserver.org/ns/";

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
    /// Niveles de anidado de un documento XML. Un `multistatus` de verdad
    /// tiene menos de diez. `roxmltree` baja por los elementos de forma
    /// recursiva y sin tope propio: unos miles de niveles desbordan la pila,
    /// y eso **aborta el proceso** entero, sin pánico que atrapar.
    pub max_xml_depth: usize,
    /// Espacios de nombres **distintos** —cada par prefijo y dirección— que
    /// declara un documento. Un servidor de verdad usa entre tres y seis. Con
    /// miles, `roxmltree` tarda un tiempo que crece como el cubo: copia los
    /// que están a la vista en cada elemento que declara uno.
    ///
    /// Distintos y no cada declaración: hay servidores que repiten
    /// `xmlns="DAV:"` en cada elemento, y eso no le cuesta nada a `roxmltree`
    /// (los que están a la vista siguen siendo pocos). Lo que cuesta es cuántos
    /// hay a la vista a la vez, y eso no pasa de los distintos.
    pub max_xml_namespaces: usize,
    /// Atributos de un mismo elemento, con sus declaraciones `xmlns`. Un
    /// elemento DAV de verdad lleva de cero a tres, más sus `xmlns`: menos de
    /// diez. `roxmltree` busca el repetido comparando cada atributo con todos
    /// los anteriores del elemento, así que tarda como el cuadrado: sesenta
    /// mil atributos vacíos —menos de seiscientos kilobytes— son siete
    /// segundos en release, y con el tope del cuerpo, horas en un hilo que no
    /// se puede cancelar.
    pub max_xml_attributes: usize,
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
    /// Bytes de tarjetas crudas por cuenta. Los otros topes multiplicados dan
    /// un terabyte —cien libretas de veinte mil tarjetas de medio mega—; una
    /// agenda de verdad, con fotos, son decenas de megas. Pasarlo corta la
    /// vuelta sin guardar el token.
    pub max_account_vcard_bytes: u64,
    /// Calendarios por cuenta.
    pub max_calendars: usize,
    /// Objetos —eventos y tareas— por calendario. Una agenda de diez años con
    /// dos mil eventos por año son veinte mil.
    pub max_objects_per_calendar: usize,
    /// El tamaño de un objeto de calendario. Uno con adjuntos en línea puede
    /// pesar; uno de más no se guarda, y queda contado.
    pub max_ical_bytes: usize,
    /// Bytes de iCalendar crudo por cuenta, como el de las tarjetas.
    pub max_account_ical_bytes: u64,
    /// Ocurrencias guardadas por cuenta: lo que deja la expansión de todas las
    /// series en la ventana, con cada vez de cada evento que no se repite.
    pub max_account_occurrences: u64,
    /// Recordatorios guardados por cuenta: hasta diez por ocurrencia, así que
    /// sin un tope propio el de ocurrencias dejaba pasar diez millones.
    pub max_account_alarms: u64,
    /// Cuánto puede durar la vuelta de una cuenta. Las cuentas van de a una:
    /// sin esto, un servidor lento —cuatrocientos `multiget` de treinta
    /// segundos por libreta— dejaba esperando horas a las otras y a cada
    /// `RequestSync`. Pasarlo corta la vuelta sin guardar el token.
    pub max_round: Duration,
}

impl Limits {
    pub const DEFAULT: Limits = Limits {
        max_body_bytes: 16 * 1024 * 1024,
        max_xml_nodes: 1_000_000,
        max_xml_depth: 64,
        max_xml_namespaces: 32,
        max_xml_attributes: 64,
        max_address_books: 100,
        max_cards_per_book: 20_000,
        max_vcard_bytes: 512 * 1024,
        multiget_batch: 50,
        max_sync_rounds: 50,
        max_account_vcard_bytes: 1024 * 1024 * 1024,
        max_calendars: 100,
        max_objects_per_calendar: 50_000,
        max_ical_bytes: 512 * 1024,
        max_account_ical_bytes: 1024 * 1024 * 1024,
        max_account_occurrences: 1_000_000,
        max_account_alarms: 1_000_000,
        max_round: Duration::from_secs(10 * 60),
    };
}

/// Hasta cuánto del detalle de un error se guarda para el diario.
pub const MAX_ERROR_DETAIL_BYTES: usize = 200;

/// Lo que puede salir mal hablando con un servidor DAV.
///
/// El texto de cada uno (`Display`) **es fijo**: sin direcciones y sin nada que
/// haya escrito el servidor, ni siquiera de paso. Sale tal cual en el estado
/// del almacén, que lo lee cualquiera de la sesión y que Configuración muestra
/// como el motivo del error. El error de `roxmltree` lleva nombres de
/// etiquetas y prefijos del documento —ocho megas cada uno, si el servidor
/// quiere, o «tu cuenta fue suspendida, entrá a…»—, y el de la red puede
/// llevar los nombres del certificado del otro lado.
///
/// El detalle va aparte, recortado a [`MAX_ERROR_DETAIL_BYTES`] y **sólo al
/// diario** ([`DavError::log_text`]). Los que lo llevan se arman con
/// [`DavError::bad_xml`] y [`DavError::network`], que recortan.
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
    /// No se pudo hablar con el servidor. El detalle, recortado, es para el
    /// diario.
    Network(String),
    /// La respuesta no es un XML que se entienda. El detalle, recortado, es
    /// para el diario.
    BadXml(String),
    TooManyAddressBooks(usize),
    TooManyCards(usize),
    TooManyCalendars(usize),
    TooManyObjects(usize),
    /// Lo pedido en un `multiget` que no volvió, cuántos: la colección no se
    /// da por al día y se vuelve a pedir en la vuelta siguiente.
    MissingResources(usize),
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
            DavError::Network(_) => f.write_str("no se pudo hablar con el servidor"),
            DavError::BadXml(_) => f.write_str("el servidor contestó algo que no se entiende"),
            DavError::TooManyAddressBooks(cap) => {
                write!(f, "la cuenta tiene más de {cap} libretas")
            }
            DavError::TooManyCards(cap) => write!(f, "una libreta tiene más de {cap} tarjetas"),
            DavError::TooManyCalendars(cap) => {
                write!(f, "la cuenta tiene más de {cap} calendarios")
            }
            DavError::TooManyObjects(cap) => {
                write!(f, "un calendario tiene más de {cap} eventos y tareas")
            }
            DavError::MissingResources(count) => write!(
                f,
                "el servidor no devolvió {count} de los elementos que se le pidieron; se vuelven \
                 a pedir en la próxima vuelta"
            ),
        }
    }
}

impl std::error::Error for DavError {}

/// Lo primero de un texto, hasta `cap` bytes y sin partir un carácter.
fn clipped(text: &str, cap: usize) -> String {
    if text.len() <= cap {
        return text.to_string();
    }
    let mut cut = cap;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &text[..cut])
}

impl DavError {
    /// Un XML que no se entiende, con el detalle recortado para el diario.
    pub fn bad_xml(detail: impl std::fmt::Display) -> Self {
        DavError::BadXml(clipped(&detail.to_string(), MAX_ERROR_DETAIL_BYTES))
    }

    /// No se pudo hablar con el servidor, con el detalle recortado para el
    /// diario.
    pub fn network(detail: impl std::fmt::Display) -> Self {
        DavError::Network(clipped(&detail.to_string(), MAX_ERROR_DETAIL_BYTES))
    }

    /// Lo que va al diario: el texto fijo y, si hay, el detalle recortado. **No
    /// va al estado**: el detalle puede venir del servidor.
    pub fn log_text(&self) -> String {
        match self {
            DavError::Network(detail) | DavError::BadXml(detail) => {
                format!("{self}: {}", clipped(detail, MAX_ERROR_DETAIL_BYTES))
            }
            _ => self.to_string(),
        }
    }
}

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
/// contraseña adentro, o una desmedida, antes o después de resolverla. El fragmento se descarta: no llega al
/// servidor, así que dos direcciones que sólo difieren en él son la misma.
pub fn resolve_href(base: &url::Url, href: &str) -> Result<url::Url, DavError> {
    let href = href.trim();
    if href.is_empty() || href.len() > MAX_HREF_BYTES {
        return Err(DavError::ForeignOrigin);
    }
    let mut resolved = base.join(href).map_err(|_| DavError::ForeignOrigin)?;
    // Otra vez después de resolver: `join` codifica, y dos mil espacios son
    // seis mil bytes de `%20`.
    if resolved.as_str().len() > MAX_HREF_BYTES
        || resolved.origin() != base.origin()
        || !resolved.username().is_empty()
        || resolved.password().is_some()
    {
        return Err(DavError::ForeignOrigin);
    }
    resolved.set_fragment(None);
    Ok(resolved)
}

/// Por qué dirección se reconoce un recurso: la clave con la que se comparan
/// las del servidor entre sí y contra las guardadas, y la que se guarda.
///
/// `Url` no iguala los escapes: deja `%2d`, `%2D` y `-` como vinieron, y son el
/// mismo recurso. Un servidor que lista una tarjeta de una forma y la contesta
/// en el `multiget` de otra hacía que se descartara como no pedida, o que se
/// guardara con una dirección que el listado siguiente no reconocía. La clave
/// hace las dos normalizaciones que RFC 3986 (§6.2.2.1 y §6.2.2.2) da por
/// equivalentes para cualquier esquema: el hexadecimal de un escape en
/// mayúsculas, y un carácter no reservado (§2.3: letras, dígitos y `-._~`)
/// sin escapar.
///
/// **Un reservado escapado no se toca**: `%40` no pasa a `@` ni `%2F` a `/`.
/// Que signifiquen lo mismo escapados o no lo decide cada servidor, no el
/// estándar —`a%2Fb` y `a/b` son dos recursos en casi todos—, e igualarlos
/// podría juntar dos tarjetas distintas en una fila.
///
/// Lo que se pide al servidor sigue siendo la dirección tal como la dio él
/// (`href_for_request` sobre el `Url`): la clave es sólo la identidad.
pub fn href_key(url: &url::Url) -> String {
    // El esquema, la máquina y el puerto no llevan escapes: se recorre entera.
    normalize_escapes(url.as_str())
}

/// Las dos normalizaciones de [`href_key`] sobre un pedazo de una dirección ya
/// resuelta. La serialización de `Url` es ASCII —lo que no lo es ya vino
/// escapado—, así que se recorre por bytes.
fn normalize_escapes(text: &str) -> String {
    let bytes = text.as_bytes();
    let hex = |b: u8| (b as char).to_digit(16);
    let mut key = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escape = (bytes[i] == b'%')
            .then(|| Some((hex(*bytes.get(i + 1)?)?, hex(*bytes.get(i + 2)?)?)))
            .flatten();
        match escape {
            Some((high, low)) => {
                let byte = (high * 16 + low) as u8;
                if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                    key.push(byte as char);
                } else {
                    key.push('%');
                    key.push(bytes[i + 1].to_ascii_uppercase() as char);
                    key.push(bytes[i + 2].to_ascii_uppercase() as char);
                }
                i += 3;
            }
            // Un `%` que no es un escape queda como está.
            None => {
                key.push(bytes[i] as char);
                i += 1;
            }
        }
    }
    key
}

/// Si dos direcciones son la misma colección, con la barra final o sin ella, y
/// con los escapes igualados como en [`href_key`]: la libreta que el servidor
/// nombra `/libro%2d1/` en su respuesta es la `/libro-1/` que se le pidió, y
/// no reconocerla hacía, por ejemplo, que el `507` de un `sync-collection`
/// truncado no se viera.
pub fn same_collection(a: &url::Url, b: &url::Url) -> bool {
    let path = |u: &url::Url| normalize_escapes(u.path().trim_end_matches('/'));
    a.origin() == b.origin()
        && path(a) == path(b)
        && a.query().map(normalize_escapes) == b.query().map(normalize_escapes)
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
            .map_err(|_| DavError::network("la credencial no se puede mandar en HTTP"))?;
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
            .map_err(|e| DavError::network(e.without_url()))?;

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
            .map_err(|e| DavError::network(e.without_url()))?;

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
        .map_err(|e| DavError::network(e.without_url()))?
    {
        if body.len() + chunk.len() > cap {
            return Err(DavError::BodyTooLarge(cap));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Lee un documento, **sin DTD**, con tope de nodos, de profundidad, de
/// espacios de nombres y de atributos por elemento.
///
/// Un XML que no se entiende es un error y no una lista vacía: una respuesta
/// cortada a la mitad —una conexión que se interrumpió, un servidor que
/// contestó una página de error— no puede verse igual que «esta cuenta no
/// tiene nada».
///
/// Antes de `roxmltree` pasa [`check_shape`], una lectura lineal que mira la
/// profundidad, los espacios de nombres y los atributos de cada elemento: son
/// los topes que `roxmltree` no tiene y que un documento chico puede usar para
/// tumbar o trabar el programa.
/// Es trabajo de CPU: quien lo llama desde el bucle de eventos lo hace con
/// [`off_runtime`].
pub fn parse_xml<'a>(xml: &'a str, limits: &Limits) -> Result<roxmltree::Document<'a>, DavError> {
    check_shape(xml, limits).map_err(DavError::bad_xml)?;
    let options = roxmltree::ParsingOptions {
        allow_dtd: false,
        nodes_limit: limits.max_xml_nodes,
        ..roxmltree::ParsingOptions::default()
    };
    roxmltree::Document::parse_with_options(xml, options).map_err(DavError::bad_xml)
}

/// Corre un trabajo de CPU —leer un XML, desarmar tarjetas— fuera de los
/// hilos del bucle de eventos.
///
/// Un documento de dieciséis megas tarda lo suyo aun con los topes, y mientras
/// ocupa un hilo del bucle, la sincronización no atiende nada más. Si el
/// trabajo cae con un pánico, vuelve como un XML que no se entiende y no se
/// lleva la tarea puesta.
pub async fn off_runtime<T, F>(work: F) -> Result<T, DavError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, DavError> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| DavError::bad_xml("la lectura de la respuesta se cayó"))?
}

/// Cuánto trabajo de espacios de nombres se le deja hacer a `roxmltree` en un
/// documento.
///
/// Cada elemento que declara alguno le cuesta, más o menos, el cuadrado de los
/// que hay a la vista. Con el tope de distintos eso es mil por elemento, y un
/// millón de elementos así son dos segundos de CPU en release y quince en
/// depuración, por respuesta. Un servidor que repite `xmlns` en cada elemento
/// tiene tres o cuatro a la vista: dieciséis por elemento, y con este tope le
/// alcanza para un millón de elementos, que es el tope de nodos.
const NAMESPACE_WORK_BUDGET: usize = 16_000_000;

/// Lo que dice [`check_shape`] de un elemento con más atributos que
/// [`Limits::max_xml_attributes`].
const TOO_MANY_ATTRIBUTES: &str = "un elemento con demasiados atributos";

/// Busca `needle` desde `from`, y devuelve dónde **termina**.
fn end_of(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|at| from + at + needle.len())
}

/// Mira la forma de un documento sin armarlo: cuántos niveles de anidado
/// tiene, cuántos espacios de nombres distintos declara y cuántos atributos
/// lleva cada elemento.
///
/// Una sola pasada por los bytes, sin recursión y sin guardar nada que crezca
/// con el documento: la memoria es la de los espacios de nombres que ya se
/// vieron, que tienen tope. Salta comentarios, `CDATA` e instrucciones de
/// proceso, y dentro de una etiqueta respeta las comillas de los atributos —un
/// `>` o un `xmlns` dentro de un valor no cuentan— y reconoce la que se cierra
/// sola (`/>`), que no abre un nivel. Una DTD se rechaza acá mismo, que es lo
/// que igual haría `roxmltree`.
///
/// Los atributos se cuentan por su `=` fuera de comillas —todo atributo
/// tiene uno, y un nombre de elemento no puede llevarlo—, así que cuentan
/// también los que vienen pegados sin espacio (`a="1"b="2"`), y las
/// declaraciones `xmlns` cuentan como uno más.
///
/// No valida el XML: eso lo hace `roxmltree` después. Lo que no entiende lo
/// rechaza, y un documento bien formado nunca cae acá por algo que no sea uno
/// de los topes.
pub fn check_shape(xml: &str, limits: &Limits) -> Result<(), &'static str> {
    let bytes = xml.as_bytes();
    let mut depth = 0usize;
    let mut namespaces: Vec<Declaration<'_>> = Vec::new();
    let mut namespace_work = 0usize;
    let mut at = 0;

    while let Some(offset) = bytes[at..].iter().position(|&b| b == b'<') {
        let start = at + offset;
        let rest = &bytes[start..];
        if rest.starts_with(b"<!--") {
            at = end_of(bytes, start + 4, b"-->").ok_or("un comentario sin cerrar")?;
            continue;
        }
        if rest.starts_with(b"<![CDATA[") {
            at = end_of(bytes, start + 9, b"]]>").ok_or("un CDATA sin cerrar")?;
            continue;
        }
        if rest.starts_with(b"<?") {
            at = end_of(bytes, start + 2, b"?>").ok_or("una instrucción sin cerrar")?;
            continue;
        }
        if rest.starts_with(b"<!") {
            return Err("trae una DTD");
        }
        if rest.starts_with(b"</") {
            depth = depth.saturating_sub(1);
            at = end_of(bytes, start + 2, b">").ok_or("una etiqueta sin cerrar")?;
            continue;
        }

        // Una etiqueta que abre: hasta su `>`, fuera de comillas.
        let mut i = start + 1;
        let mut quote: Option<u8> = None;
        let mut after_space = false;
        let mut last = 0u8;
        let mut declares = false;
        let mut attributes = 0usize;
        loop {
            let &c = bytes.get(i).ok_or("una etiqueta sin cerrar")?;
            if let Some(q) = quote {
                if c == q {
                    quote = None;
                }
                i += 1;
                continue;
            }
            match c {
                b'>' => break,
                b'"' | b'\'' => quote = Some(c),
                c if c.is_ascii_whitespace() => {
                    after_space = true;
                    i += 1;
                    continue;
                }
                b'=' => {
                    attributes += 1;
                    if attributes > limits.max_xml_attributes {
                        return Err(TOO_MANY_ATTRIBUTES);
                    }
                }
                _ if after_space => {
                    if let Some((declared, end)) = namespace_at(bytes, i)? {
                        attributes += 1;
                        if attributes > limits.max_xml_attributes {
                            return Err(TOO_MANY_ATTRIBUTES);
                        }
                        declares = true;
                        if !namespaces.contains(&declared) {
                            namespaces.push(declared);
                            if namespaces.len() > limits.max_xml_namespaces {
                                return Err("declara demasiados espacios de nombres");
                            }
                        }
                        last = b'"';
                        after_space = false;
                        i = end;
                        continue;
                    }
                }
                _ => {}
            }
            after_space = false;
            last = c;
            i += 1;
        }

        if declares {
            namespace_work = namespace_work.saturating_add(namespaces.len().pow(2));
            if namespace_work > NAMESPACE_WORK_BUDGET {
                return Err("declara espacios de nombres en demasiados elementos");
            }
        }
        if last != b'/' {
            depth += 1;
            if depth > limits.max_xml_depth {
                return Err("está anidado de más");
            }
        }
        at = i + 1;
    }

    Ok(())
}

/// Una declaración de espacio de nombres: el prefijo (vacío para el de
/// omisión) y la dirección, tal como vinieron.
type Declaration<'a> = (&'a [u8], &'a [u8]);

/// Si en `at` empieza la declaración de un espacio de nombres —`xmlns="…"` o
/// `xmlns:p="…"`—, el par (prefijo, dirección) tal como vino y dónde termina
/// el valor. `xmlnsx="…"` es un atributo cualquiera.
fn namespace_at(bytes: &[u8], at: usize) -> Result<Option<(Declaration<'_>, usize)>, &'static str> {
    let Some(rest) = bytes.get(at..).filter(|r| r.starts_with(b"xmlns")) else {
        return Ok(None);
    };
    let mut i = 5;
    let prefix = match rest.get(i) {
        Some(b':') => {
            let begin = i + 1;
            i = begin;
            while rest
                .get(i)
                .is_some_and(|&c| c != b'=' && !c.is_ascii_whitespace() && c != b'>')
            {
                i += 1;
            }
            &rest[begin..i]
        }
        Some(&c) if c == b'=' || c.is_ascii_whitespace() => &rest[i..i],
        _ => return Ok(None),
    };
    while rest.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    if rest.get(i) != Some(&b'=') {
        return Err("un atributo sin valor");
    }
    i += 1;
    while rest.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    let quote = match rest.get(i) {
        Some(&q) if q == b'"' || q == b'\'' => q,
        _ => return Err("un atributo sin comillas"),
    };
    let begin = i + 1;
    let length = rest[begin..]
        .iter()
        .position(|&c| c == quote)
        .ok_or("un atributo sin cerrar")?;
    let value = &rest[begin..begin + length];
    Ok(Some(((prefix, value), at + begin + length + 1)))
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
    /// El atributo `name` de los elementos de adentro que lo tienen, en orden:
    /// `VEVENT` y `VTODO` en un `supported-calendar-component-set`, que dice
    /// sus componentes como `<c:comp name="VEVENT"/>`.
    pub name_attributes: Vec<String>,
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
        return Err(DavError::bad_xml("no es un multistatus"));
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
                    name_attributes: prop
                        .descendants()
                        .skip(1)
                        .filter(|n| n.is_element())
                        .filter_map(|n| n.attribute("name"))
                        .map(str::to_string)
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
// Lo que comparten CardDAV y CalDAV
// ---------------------------------------------------------------------------

/// La dirección y el ETag de cada recurso de una colección.
pub type Etags = Vec<(url::Url, Option<String>)>;

/// Un token o un ETag que se puede guardar.
pub fn storable(text: Option<&str>) -> Option<String> {
    text.filter(|t| t.len() <= MAX_TOKEN_BYTES)
        .map(str::to_string)
}

/// Saca el ETag de cada recurso de un `PROPFIND` sobre una colección, para los
/// servidores que no saben `sync-collection`. Sin la colección misma ni las
/// subcarpetas. Devuelve también cuántas direcciones de otro origen se
/// descartaron.
pub fn etags_from(
    xml: &str,
    collection: &url::Url,
    limits: &Limits,
) -> Result<(Etags, usize), DavError> {
    let document = parse_xml(xml, limits)?;
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
            let Ok(href) = resolve_href(collection, &response.href) else {
                foreign += 1;
                return None;
            };
            if same_collection(&href, collection) {
                return None;
            }
            Some((href, storable(response.text(NS_DAV, "getetag"))))
        })
        .collect();

    Ok((etags, foreign))
}

/// El cuerpo del `PROPFIND` que pide el ETag de cada recurso de una colección.
pub fn etags_query() -> String {
    r#"<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop><d:resourcetype/><d:getetag/></d:prop>
</d:propfind>"#
        .to_string()
}

/// El ETag de cada recurso de una colección, y cuántos se descartaron por
/// venir con una dirección de otro origen: con alguno, el listado no dice
/// qué falta.
pub async fn list_etags(
    client: &DavClient,
    collection: &url::Url,
) -> Result<(Etags, usize), DavError> {
    let reply = client
        .request(Method::Propfind, collection, "1", etags_query())
        .await?;
    let xml = expect_multistatus(reply)?;
    let limits = *client.limits();
    let collection = collection.clone();
    let (etags, foreign) = off_runtime(move || etags_from(&xml, &collection, &limits)).await?;
    if foreign > 0 {
        tracing::warn!("se descartaron {foreign} recursos con dirección de otro servidor");
    }
    Ok((etags, foreign))
}

/// El cuerpo de un `207`, o el estado como error.
pub fn expect_multistatus(reply: Reply) -> Result<String, DavError> {
    match reply.status {
        207 => Ok(reply.body),
        other => Err(DavError::Status(other)),
    }
}

/// Los recursos que trajo un `multiget`, tal como se leyeron: antes de
/// quedarse con lo pedido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResources<T> {
    pub items: Vec<T>,
    /// Direcciones de otro origen que se descartaron.
    pub foreign: usize,
    /// Los que pasaban el tope de tamaño, por su dirección. **Se descartan al
    /// leerlos**, sin retenerlos: una tanda de cincuenta objetos de casi
    /// dieciséis megas —uno por respuesta, partida hasta aislarlos— eran unos
    /// 1,5 GB en memoria antes de mirar el tope (N8 del #55).
    pub oversized: Vec<url::Url>,
}

/// Saca los recursos de un `multiget` —su dirección, su ETag y el texto de la
/// propiedad `namespace:name`— con su tope de tamaño, `max_bytes`: el que lo
/// pasa no se copia ni se devuelve, sólo su dirección en
/// [`ReadResources::oversized`]. Uno sin datos, o con un estado de error, no
/// vino.
pub fn resources_from<T>(
    xml: &str,
    base: &url::Url,
    limits: &Limits,
    (namespace, name): (&str, &str),
    max_bytes: usize,
    make: impl Fn(url::Url, Option<String>, String) -> T,
) -> Result<ReadResources<T>, DavError> {
    let document = parse_xml(xml, limits)?;
    let multistatus = parse_multistatus(&document)?;
    drop(document);
    let mut read = ReadResources {
        items: Vec::new(),
        foreign: 0,
        oversized: Vec::new(),
    };
    for mut response in multistatus.responses {
        let Some(position) = response
            .props
            .iter()
            .position(|p| p.namespace == namespace && p.name == name)
        else {
            continue;
        };
        if response.props[position].text.trim().is_empty() {
            continue;
        }
        let Ok(href) = resolve_href(base, &response.href) else {
            read.foreign += 1;
            continue;
        };
        if response.props[position].text.len() > max_bytes {
            read.oversized.push(href);
            continue;
        }
        let etag = storable(response.text(NS_DAV, "getetag"));
        // Se mueve y no se copia: el texto de un recurso puede ser el tope
        // entero.
        let data = std::mem::take(&mut response.props[position].text);
        read.items.push(make(href, etag, data));
    }
    Ok(read)
}

/// Lo que queda de un `multiget` después de quedarse con lo pedido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Multiget<T> {
    /// Lo pedido, una vez cada uno.
    pub items: Vec<T>,
    /// Lo que vino sin pedirlo, o repetido.
    pub unrequested: usize,
    /// Lo pedido que vino y pasaba el tope de tamaño: no se guarda, y queda
    /// contado.
    pub too_large: usize,
    /// Lo pedido que **no volvió**, por su clave ([`href_key`]): el servidor
    /// lo omitió, lo contestó con un estado de error o sin datos, o con la
    /// dirección escrita de otra forma (un reservado escapado distinto, que a
    /// propósito no se iguala).
    pub missing: Vec<String>,
}

/// Se queda con los recursos que se pidieron en un `multiget`, **una vez cada
/// uno**, cuenta los que no y dice cuáles de los pedidos no volvieron.
///
/// Un servidor puede contestar un `multiget` de un recurso con dieciséis megas
/// de recursos que nadie pidió: guardarlos saltaría el tope por colección, que
/// se mira sobre lo que se pide, y llenaría la base con lo que el servidor
/// nunca listó. Uno repetido es lo mismo: el primero que llega es el que vale.
///
/// Pedido y contestado se comparan por [`href_key`]: `a%2db` pedido y `a%2Db`
/// contestado son el mismo recurso. Uno de más tamaño que el tope volvió —no se
/// guarda, pero no falta—.
pub fn keep_requested_by<T>(
    read: ReadResources<T>,
    hrefs: &[url::Url],
    href_of: impl Fn(&T) -> &url::Url,
) -> Multiget<T> {
    let mut pending: std::collections::HashSet<String> = hrefs.iter().map(href_key).collect();
    let mut unrequested = 0;
    let mut too_large = 0;
    for href in &read.oversized {
        if pending.remove(&href_key(href)) {
            too_large += 1;
        } else {
            unrequested += 1;
        }
    }
    let items = read
        .items
        .into_iter()
        .filter(|item| {
            let requested = pending.remove(&href_key(href_of(item)));
            if !requested {
                unrequested += 1;
            }
            requested
        })
        .collect();
    let mut missing: Vec<String> = hrefs
        .iter()
        .map(href_key)
        .filter(|key| pending.remove(key))
        .collect();
    missing.sort();
    Multiget {
        items,
        unrequested,
        too_large,
        missing,
    }
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
fn has_precondition(body: &str, name: &str, limits: &Limits) -> bool {
    parse_xml(body, limits).is_ok_and(|document| {
        document
            .descendants()
            .any(|n| n.has_tag_name((NS_DAV, name)))
    })
}

/// Cómo se lee un cuerpo de error de `sync-collection`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    InvalidToken,
    NotSupported,
    Other,
}

fn refusal_from(status: u16, body: &str, limits: &Limits) -> Refusal {
    match status {
        403 | 409 if has_precondition(body, "valid-sync-token", limits) => Refusal::InvalidToken,
        403 if has_precondition(body, "supported-report", limits) => Refusal::NotSupported,
        400 | 405 | 415 | 501 => Refusal::NotSupported,
        _ => Refusal::Other,
    }
}

/// Las diferencias de un `207` de `sync-collection`, ya resueltas contra la
/// colección.
pub fn delta_from(
    xml: &str,
    collection: &url::Url,
    limits: &Limits,
) -> Result<SyncDelta, DavError> {
    let document = parse_xml(xml, limits)?;
    let multistatus = parse_multistatus(&document)?;
    // El token y cada ETag, con el tope de lo que se guarda: `changed` junta
    // lo de hasta [`Limits::max_sync_rounds`] respuestas de `507`, y un ETag
    // de dieciséis kilobytes por recurso eran cientos de megas retenidos antes
    // de pedir nada. Uno de más es `None`, y el recurso se trae igual.
    let mut delta = SyncDelta {
        token: storable(multistatus.sync_token.as_deref()),
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
                let etag = storable(response.text(NS_DAV, "getetag"));
                delta.changed.push((url, etag));
            }
        }
    }

    Ok(delta)
}

/// Pide las diferencias de una colección desde `token` (o todo, sin token).
///
/// - `207` → las diferencias. Lo que viene con `404` en su `<d:response>` se
///   borró; lo que trae `getetag`, cambió; un `507` sobre la colección misma
///   es una respuesta truncada.
/// - `403` o `409` con `DAV:valid-sync-token` → [`SyncCollection::InvalidToken`].
/// - `400`, `405`, `415`, `501`, o `403` con `DAV:supported-report` →
///   [`SyncCollection::NotSupported`].
///
/// Los dos cuerpos, el de las diferencias y el de un rechazo, se leen fuera
/// del bucle de eventos ([`off_runtime`]).
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

    let limits = *client.limits();
    let status = reply.status;
    if status != 207 {
        let body = reply.body;
        let refusal = off_runtime(move || Ok(refusal_from(status, &body, &limits))).await?;
        return match refusal {
            Refusal::InvalidToken => Ok(SyncCollection::InvalidToken),
            Refusal::NotSupported => Ok(SyncCollection::NotSupported),
            Refusal::Other => Err(DavError::Status(status)),
        };
    }

    let collection = collection.clone();
    let body = reply.body;
    let delta = off_runtime(move || delta_from(&body, &collection, &limits)).await?;
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

    // ── Los errores ────────────────────────────────────────────────────────

    /// Una variante de cada, con texto del servidor en las que llevan texto.
    /// El `match` no tiene comodín: una variante nueva no compila sin pasar
    /// por acá.
    fn every_error(server_text: &str) -> Vec<DavError> {
        let all = vec![
            DavError::InsecureUrl,
            DavError::ForeignOrigin,
            DavError::Unauthorized,
            DavError::Redirect(302),
            DavError::Status(507),
            DavError::BodyTooLarge(16 * 1024 * 1024),
            DavError::network(server_text),
            DavError::bad_xml(server_text),
            DavError::TooManyAddressBooks(100),
            DavError::TooManyCards(20_000),
            DavError::TooManyCalendars(100),
            DavError::TooManyObjects(50_000),
            DavError::MissingResources(50),
        ];
        for error in &all {
            match error {
                DavError::InsecureUrl
                | DavError::ForeignOrigin
                | DavError::Unauthorized
                | DavError::Redirect(_)
                | DavError::Status(_)
                | DavError::BodyTooLarge(_)
                | DavError::Network(_)
                | DavError::BadXml(_)
                | DavError::TooManyAddressBooks(_)
                | DavError::TooManyCards(_)
                | DavError::TooManyCalendars(_)
                | DavError::TooManyObjects(_)
                | DavError::MissingResources(_) => {}
            }
        }
        all
    }

    /// **Ningún error lleva texto del servidor al estado.** El texto de cada
    /// variante es corto y fijo, aunque adentro tenga un megabyte de lo que
    /// mandó el servidor; el detalle va al diario, recortado a doscientos
    /// bytes por un borde de carácter.
    #[test]
    fn ningun_error_lleva_texto_del_servidor_al_estado() {
        let marker = "Entrá-a-otro-sitio";
        let server_text = format!("expected '{}' tag", marker.repeat(60_000));
        for error in every_error(&server_text) {
            let shown = error.to_string();
            assert!(shown.len() <= 300, "{error:?}: {} bytes", shown.len());
            assert!(!shown.contains("Entr"), "{shown}");

            let logged = error.log_text();
            assert!(logged.starts_with(&shown), "{logged}");
            assert!(logged.len() <= shown.len() + 2 + MAX_ERROR_DETAIL_BYTES + 3);
            // Y el `{:?}`, que es lo que sale en un pánico, tampoco lo lleva
            // entero.
            assert!(format!("{error:?}").len() <= 300);
        }
        // Lo que se recorta cae en un borde de carácter aunque el tope caiga en
        // la mitad de una «á».
        let accents = "á".repeat(MAX_ERROR_DETAIL_BYTES);
        let DavError::BadXml(detail) = DavError::bad_xml(&accents) else {
            unreachable!()
        };
        assert!(detail.ends_with('…'));
        assert!(detail.len() <= MAX_ERROR_DETAIL_BYTES + 3);
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

    /// El largo se mira también **después** de resolver: `join` codifica, y
    /// una dirección de dos mil espacios pasa el tope como seis mil bytes de
    /// `%20`.
    #[test]
    fn una_direccion_que_crece_al_resolverla_se_rechaza() {
        let base = url::Url::parse("https://nube.ejemplo.com/dav/libro/").unwrap();
        let spaces = format!("/dav/libro/{}x.vcf", " ".repeat(2000));
        assert!(spaces.len() <= MAX_HREF_BYTES);
        assert_eq!(resolve_href(&base, &spaces), Err(DavError::ForeignOrigin));
        // Una normal sigue entrando.
        assert!(resolve_href(&base, "/dav/libro/a%20b.vcf").is_ok());
    }

    /// **La clave de una dirección iguala los escapes que el estándar da por
    /// iguales, y ninguno más.** Hexadecimal en mayúsculas y los no reservados
    /// sin escapar; `%40` y `%2F` quedan escapados, porque para el servidor
    /// pueden ser otro recurso.
    #[test]
    fn la_clave_de_una_direccion_iguala_solo_los_escapes_equivalentes() {
        let base = url::Url::parse("https://nube.ejemplo.com/dav/libro/").unwrap();
        let key = |href: &str| href_key(&resolve_href(&base, href).unwrap());

        let same = [
            ("a%2db.vcf", "a-b.vcf"),
            ("a%2Db.vcf", "a-b.vcf"),
            ("a%7Eb.vcf", "a~b.vcf"),
            ("%41na%5f1%2E%76cf", "Ana_1.vcf"),
            ("%c3%a9.vcf", "é.vcf"),
            ("a%2fb.vcf", "a%2Fb.vcf"),
            ("a.vcf?v=%7e1", "a.vcf?v=~1"),
        ];
        for (one, other) in same {
            assert_eq!(key(one), key(other), "{one} y {other}");
        }
        assert_eq!(
            key("a%2db.vcf"),
            "https://nube.ejemplo.com/dav/libro/a-b.vcf"
        );
        assert_eq!(
            key("%c3%a9.vcf"),
            "https://nube.ejemplo.com/dav/libro/%C3%A9.vcf"
        );

        let different = [
            ("a%40b.vcf", "a@b.vcf"),
            ("a%2Fb.vcf", "a/b.vcf"),
            ("a%3Bb.vcf", "a;b.vcf"),
            ("a%2Bb.vcf", "a+b.vcf"),
        ];
        for (one, other) in different {
            assert_ne!(key(one), key(other), "{one} y {other}");
        }
        assert_eq!(
            key("a%40b.vcf"),
            "https://nube.ejemplo.com/dav/libro/a%40b.vcf"
        );

        // Un `%` que no es un escape queda, y dos pasadas son una.
        assert_eq!(
            key("a%zz%4.vcf"),
            "https://nube.ejemplo.com/dav/libro/a%zz%4.vcf"
        );
        for href in ["a%2db.vcf", "%c3%a9.vcf", "a%40b%7e.vcf"] {
            let once = key(href);
            assert_eq!(href_key(&url::Url::parse(&once).unwrap()), once);
        }
    }

    /// La libreta se reconoce en su propia respuesta aunque el servidor la
    /// escriba con otros escapes; una reservada escapada sigue siendo otra.
    #[test]
    fn la_misma_coleccion_con_otros_escapes() {
        let book = url::Url::parse("https://x/dav/libro-1/").unwrap();
        let other = |path: &str| url::Url::parse(&format!("https://x{path}")).unwrap();
        assert!(same_collection(&other("/dav/libro%2d1"), &book));
        assert!(same_collection(&other("/dav/libro%2D1/"), &book));
        assert!(!same_collection(&other("/dav/libro%2F1/"), &book));
    }

    #[test]
    fn lo_que_va_en_un_href_se_escapa() {
        assert_eq!(xml_escape("a<b>&\"c'"), "a&lt;b&gt;&amp;&quot;c&apos;");
        let url = url::Url::parse("https://x/dav/a%20b.vcf?v=1").unwrap();
        assert_eq!(href_for_request(&url), "/dav/a%20b.vcf?v=1");
    }

    // ── El XML ─────────────────────────────────────────────────────────────

    fn nodes(max_xml_nodes: u32) -> Limits {
        Limits {
            max_xml_nodes,
            ..Limits::DEFAULT
        }
    }

    /// Sin DTD: es lo que cierra las entidades externas y las expansiones en
    /// cadena («mil millones de risas»).
    #[test]
    fn un_xml_con_dtd_se_rechaza() {
        let with_dtd = r#"<?xml version="1.0"?>
<!DOCTYPE d [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]>
<d:multistatus xmlns:d="DAV:">&b;</d:multistatus>"#;
        assert!(matches!(
            parse_xml(with_dtd, &Limits::DEFAULT),
            Err(DavError::BadXml(_))
        ));
        let external = r#"<?xml version="1.0"?>
<!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<d:multistatus xmlns:d="DAV:">&x;</d:multistatus>"#;
        assert!(parse_xml(external, &Limits::DEFAULT).is_err());
    }

    #[test]
    fn un_xml_con_demasiados_nodos_se_rechaza() {
        let many = format!(
            r#"<d:multistatus xmlns:d="DAV:">{}</d:multistatus>"#,
            "<d:x/>".repeat(200)
        );
        assert!(parse_xml(&many, &nodes(1_000)).is_ok());
        assert!(parse_xml(&many, &nodes(100)).is_err());
    }

    /// Corre `work` en otro hilo y falla si no termina en `budget`. Sin esto,
    /// una prueba de tiempo sin el arreglo no falla: se cuelga.
    fn finishes_within<T: Send + 'static>(
        budget: std::time::Duration,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (done, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(work());
        });
        wait.recv_timeout(budget)
            .unwrap_or_else(|_| panic!("no terminó en {budget:?}"))
    }

    fn nested(levels: usize) -> String {
        format!(
            r#"<d:multistatus xmlns:d="DAV:">{}{}</d:multistatus>"#,
            "<d:x>".repeat(levels),
            "</d:x>".repeat(levels)
        )
    }

    /// **Un XML anidado de más no tumba el proceso.** `roxmltree` baja por los
    /// elementos de forma recursiva: cien mil niveles —trescientos kilobytes,
    /// muy por debajo del tope del cuerpo— desbordan la pila, y un desborde de
    /// pila aborta el programa entero, correo incluido. Tiene que volver como
    /// un error, y el proceso seguir.
    #[test]
    fn un_xml_demasiado_anidado_se_rechaza_sin_caer() {
        let deep = nested(100_000);
        assert!(deep.len() < 2 * 1024 * 1024);
        assert!(matches!(
            parse_xml(&deep, &Limits::DEFAULT),
            Err(DavError::BadXml(_))
        ));
        // Y el tope es justo: el multistatus más sus niveles.
        let limit = Limits::DEFAULT.max_xml_depth;
        assert!(parse_xml(&nested(limit - 1), &Limits::DEFAULT).is_ok());
        assert!(parse_xml(&nested(limit), &Limits::DEFAULT).is_err());
    }

    /// Lo que no abre un nivel no cuenta: la etiqueta que se cierra sola, un
    /// comentario, un `CDATA`, una instrucción de proceso, y un `>` o un
    /// `xmlns` dentro del valor de un atributo, con comillas dobles o simples.
    #[test]
    fn la_forma_del_xml_respeta_comentarios_cdata_y_comillas() {
        let limits = Limits {
            max_xml_depth: 3,
            max_xml_namespaces: 2,
            ..Limits::DEFAULT
        };
        let fine = r#"<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" a='x > y xmlns:p="1"'>
  <!-- <d:a><d:b><d:c><d:e> xmlns:q="2" -->
  <d:response b="/>" c = 'xmlns:r="3"'>
    <d:href><![CDATA[<d:a><d:b><d:c>]]></d:href>
    <d:x/><d:y /><d:z w="/"/>
    <?proceso <d:a><d:b> ?>
  </d:response>
  <d:response xmlnsx="no-es-un-espacio" xmlns:c="urn:c"><d:x/></d:response>
</d:multistatus>"#;
        assert_eq!(check_shape(fine, &limits), Ok(()));
        assert!(parse_xml(fine, &limits).is_ok());

        let deep = r#"<d:multistatus xmlns:d="DAV:"><d:a><d:b><d:c/></d:b></d:a></d:multistatus>"#;
        assert_eq!(check_shape(deep, &limits), Ok(()));
        let deeper =
            r#"<d:multistatus xmlns:d="DAV:"><d:a><d:b><d:c></d:c></d:b></d:a></d:multistatus>"#;
        assert!(check_shape(deeper, &limits).is_err());

        let many = r#"<d:multistatus xmlns:d="DAV:" xmlns:c="urn:c" xmlns = "urn:x"/>"#;
        assert!(check_shape(many, &limits).is_err());
        assert!(check_shape("<!DOCTYPE d><d/>", &limits).is_err());
        for broken in ["<a", "<a b='x>", "<!-- sin cerrar", "<![CDATA[ x", "<? x"] {
            assert!(check_shape(broken, &limits).is_err(), "{broken}");
        }
    }

    /// **Miles de espacios de nombres no traban el programa.** Una raíz que
    /// declara cinco mil prefijos y cinco mil hijos que declaran uno cada uno
    /// son doscientos kilobytes, y `roxmltree` tarda más de dos minutos en
    /// leerlos: copia los que están a la vista en cada elemento que declara uno.
    /// Tiene que rechazarse enseguida.
    #[test]
    fn un_xml_con_miles_de_espacios_de_nombres_se_rechaza_enseguida() {
        let n = 5000;
        let root: String = (0..n).map(|i| format!(r#" xmlns:p{i}="u{i}""#)).collect();
        let children = r#"<a xmlns:z="q"/>"#.repeat(n);
        let xml = format!(r#"<d:multistatus xmlns:d="DAV:"{root}>{children}</d:multistatus>"#);

        let result = finishes_within(std::time::Duration::from_secs(5), move || {
            parse_xml(&xml, &Limits::DEFAULT).map(|_| ())
        });
        assert!(matches!(result, Err(DavError::BadXml(_))), "{result:?}");
    }

    /// Y dentro del tope de distintos, lo que cuesta es cuántos elementos
    /// declaran con muchos a la vista: treinta en la raíz y novecientos mil
    /// hijos que declaran uno son catorce megas —dentro del tope del cuerpo— y
    /// dos segundos de `roxmltree` en release, quince en depuración, por cada
    /// respuesta. También se rechaza enseguida.
    #[test]
    fn muchos_elementos_que_declaran_con_muchos_a_la_vista_se_rechazan() {
        let root: String = (0..30).map(|i| format!(r#" xmlns:p{i}="u{i}""#)).collect();
        let children = r#"<a xmlns:z="q"/>"#.repeat(900_000);
        let xml = format!(r#"<d:multistatus xmlns:d="DAV:"{root}>{children}</d:multistatus>"#);
        assert!(xml.len() < Limits::DEFAULT.max_body_bytes);

        let result = finishes_within(std::time::Duration::from_secs(5), move || {
            parse_xml(&xml, &Limits::DEFAULT).map(|_| ())
        });
        assert!(matches!(result, Err(DavError::BadXml(_))), "{result:?}");
    }

    /// Y la misma declaración repetida en cada elemento —hay servidores que
    /// ponen `xmlns="DAV:"` en todos— no cuenta de más: a la vista sigue
    /// habiendo una.
    #[test]
    fn una_declaracion_repetida_en_cada_elemento_no_cuenta_de_mas() {
        let responses = r#"<response xmlns="DAV:"><href xmlns="DAV:">/a.vcf</href><propstat xmlns="DAV:"><prop><getetag xmlns="DAV:">"1"</getetag><address-data xmlns="urn:ietf:params:xml:ns:carddav">BEGIN:VCARD</address-data></prop><status>HTTP/1.1 200 OK</status></propstat></response>"#
            .repeat(20_000);
        let xml = format!(r#"<multistatus xmlns="DAV:">{responses}</multistatus>"#);

        let count = finishes_within(std::time::Duration::from_secs(10), move || {
            let document = parse_xml(&xml, &Limits::DEFAULT).unwrap();
            parse_multistatus(&document).unwrap().responses.len()
        });
        assert_eq!(count, 20_000);
    }

    /// Un `multistatus` con `declarations` espacios de nombres propios —además
    /// de `d`— y `plain` atributos vacíos, pegados o con espacio.
    fn with_attributes(declarations: usize, plain: usize, separator: &str) -> String {
        let declared: String = (0..declarations)
            .map(|i| format!(r#" xmlns:p{i}="u{i}""#))
            .collect();
        let attributes: String = (0..plain)
            .map(|i| format!(r#"{separator}a{i}="""#))
            .collect();
        format!(r#"<d:multistatus xmlns:d="DAV:"{declared}{attributes}/>"#)
    }

    /// **Miles de atributos en un elemento no traban el programa.**
    /// `roxmltree` busca el atributo repetido comparando cada uno con todos
    /// los anteriores del elemento: sesenta mil atributos vacíos en el
    /// `multistatus` son menos de seiscientos kilobytes y siete segundos en
    /// release —mucho más en depuración—, y con el tope del cuerpo, horas de
    /// CPU en un hilo que no se cancela. Tiene que rechazarse enseguida.
    #[test]
    fn un_elemento_con_miles_de_atributos_se_rechaza_enseguida() {
        let xml = with_attributes(0, 60_000, " ");
        assert!(xml.len() < 600 * 1024);

        let result = finishes_within(std::time::Duration::from_secs(5), move || {
            parse_xml(&xml, &Limits::DEFAULT).map(|_| ())
        });
        assert!(matches!(result, Err(DavError::BadXml(_))), "{result:?}");
    }

    /// El tope es justo, por elemento, y cuenta las declaraciones `xmlns` y
    /// los atributos pegados sin espacio.
    #[test]
    fn el_tope_de_atributos_es_justo_y_cuenta_los_xmlns_y_los_pegados() {
        let limit = Limits::DEFAULT.max_xml_attributes;
        assert_eq!(limit, 64);

        // `xmlns:d` más 63 atributos: 64 pasan, 65 no.
        let fine = with_attributes(0, limit - 1, " ");
        assert_eq!(check_shape(&fine, &Limits::DEFAULT), Ok(()));
        assert!(parse_xml(&fine, &Limits::DEFAULT).is_ok());
        let over = with_attributes(0, limit, " ");
        assert_eq!(
            check_shape(&over, &Limits::DEFAULT),
            Err(TOO_MANY_ATTRIBUTES)
        );
        assert!(matches!(
            parse_xml(&over, &Limits::DEFAULT),
            Err(DavError::BadXml(_))
        ));

        // Las declaraciones cuentan: 1 + 30 `xmlns` + 33 atributos son 64.
        let declared = with_attributes(30, limit - 31, " ");
        assert_eq!(check_shape(&declared, &Limits::DEFAULT), Ok(()));
        assert!(parse_xml(&declared, &Limits::DEFAULT).is_ok());
        let declared_over = with_attributes(30, limit - 30, " ");
        assert_eq!(
            check_shape(&declared_over, &Limits::DEFAULT),
            Err(TOO_MANY_ATTRIBUTES)
        );

        // Y los pegados sin espacio también, `xmlns` incluido.
        let glued = with_attributes(0, limit - 1, "");
        assert_eq!(check_shape(&glued, &Limits::DEFAULT), Ok(()));
        let glued_over = with_attributes(0, limit, "");
        assert_eq!(
            check_shape(&glued_over, &Limits::DEFAULT),
            Err(TOO_MANY_ATTRIBUTES)
        );
        let glued_xmlns = format!(
            r#"<d:multistatus{}/>"#,
            (0..=limit)
                .map(|i| format!(r#"a{i}="1"xmlns:p{i}="u""#))
                .collect::<String>()
        );
        assert_eq!(
            check_shape(&glued_xmlns, &Limits::DEFAULT),
            Err(TOO_MANY_ATTRIBUTES)
        );

        // El tope es de cada elemento, no del documento.
        let one = (0..limit - 1)
            .map(|i| format!(r#" a{i}="""#))
            .collect::<String>();
        let siblings = format!(r#"<d:x{one}/>"#).repeat(100);
        let xml = format!(r#"<d:multistatus xmlns:d="DAV:">{siblings}</d:multistatus>"#);
        assert_eq!(check_shape(&xml, &Limits::DEFAULT), Ok(()));
        assert!(parse_xml(&xml, &Limits::DEFAULT).is_ok());
    }

    /// Lo que está entre comillas no es un atributo: un valor que trae
    /// `a="x" b="y"` adentro, con comillas simples o dobles, cuenta uno.
    #[test]
    fn un_valor_con_atributos_adentro_de_las_comillas_no_cuenta() {
        let limits = Limits {
            max_xml_attributes: 3,
            ..Limits::DEFAULT
        };
        let inside = r#"a="x" b="y" xmlns:p="u" c = "z""#.repeat(1000);
        let xml = format!(
            r#"<d:multistatus xmlns:d="DAV:" v='{inside}' w="{}"/>"#,
            inside.replace('"', "'")
        );
        assert_eq!(check_shape(&xml, &limits), Ok(()));
        assert!(parse_xml(&xml, &limits).is_ok());

        let one_more = xml.replace("/>", r#" k=""/>"#);
        assert_eq!(check_shape(&one_more, &limits), Err(TOO_MANY_ATTRIBUTES));
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
        let document = parse_xml(SYNC, &Limits::DEFAULT).unwrap();
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
            let document = parse_xml(garbage, &Limits::DEFAULT).unwrap();
            assert!(parse_multistatus(&document).is_err(), "{garbage}");
        }
        let empty = parse_xml(r#"<d:multistatus xmlns:d="DAV:"/>"#, &Limits::DEFAULT).unwrap();
        assert_eq!(parse_multistatus(&empty).unwrap(), Multistatus::default());
    }

    /// **N9**: el ETag de un `sync-collection` tiene el tope de lo que se
    /// guarda al leerlo, como el de un `PROPFIND` o un `multiget`. Sin él,
    /// cincuenta respuestas de `507` retenían unos 800 MB de ETags.
    #[test]
    fn un_etag_desmedido_en_las_diferencias_no_se_guarda() {
        let collection = url::Url::parse("https://nube.ejemplo.com/dav/personal/").unwrap();
        let big = "e".repeat(100 * 1024);
        let xml = format!(
            r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:">
  <d:response><d:href>/dav/personal/a.ics</d:href>
    <d:propstat><d:prop><d:getetag>{big}</d:getetag></d:prop>
      <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
  <d:response><d:href>/dav/personal/b.ics</d:href>
    <d:propstat><d:prop><d:getetag>"corto"</d:getetag></d:prop>
      <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
  <d:sync-token>{big}</d:sync-token>
</d:multistatus>"#
        );
        let delta = delta_from(&xml, &collection, &Limits::DEFAULT).unwrap();
        assert_eq!(delta.changed.len(), 2, "el recurso se trae igual");
        assert_eq!(delta.changed[0].1, None, "el ETag desmedido se guardó");
        assert_eq!(delta.changed[1].1.as_deref(), Some("\"corto\""));
        assert_eq!(delta.token, None, "el token desmedido se guardó");
    }

    /// El pedido de diferencias es XML válido y lleva el token escapado.
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
