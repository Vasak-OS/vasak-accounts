//! Lo común a los backends de Microsoft Graph (contactos y calendario): la
//! credencial, su fuente, los errores de red y la **paginación por
//! `@odata.nextLink` con validación de mismo-origen**.
//!
//! Antes vivía todo en `contacts_sync::graph`; cuando entró el calendario por
//! Graph se extrajo acá para que los dos backends compartan la misma defensa en
//! vez de copiarla (regla de `AGENTS.md` §6). La defensa clave es [`fetch_all_pages`]:
//! un `@odata.nextLink` es dato de red y **no se sigue a ciegas** —antes de
//! adjuntarle el token se exige que comparta esquema, host y puerto con la URL
//! base de la credencial—, además de las cotas de paginación (tope de páginas,
//! de elementos, deduplicado y plazo por pedido).

use std::collections::HashSet;
use std::time::Duration;

use serde::de::DeserializeOwned;
use url::Url;

use crate::broker::BrokerError;
use crate::dav_sync::CredentialError;

/// URL base de Microsoft Graph en producción. El servicio de cuentas siempre
/// rellena [`GraphCredential::base_url`] con esto; las pruebas lo cambian por un
/// endpoint falso en `127.0.0.1`.
pub const GRAPH_BASE_URL: &str = "https://graph.microsoft.com/v1.0";

/// Plazo para que un pedido a Graph conecte, como el resto del servicio.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Plazo por pedido —conexión más respuesta— al paginar. Corta un servidor que
/// acepta la conexión y no responde. Igual que `dav_sync` acota cada pedido con
/// [`tokio::time::timeout_at`].
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Tope de páginas de la paginación por `@odata.nextLink`. Con `$top=100` da de
/// sobra para una agenda o un calendario personal; un servidor que no corta es
/// un bucle o un intento de agotar memoria.
pub const MAX_PAGES: usize = 1_000;

/// Tope del cuerpo de un objeto traído de a uno con [`fetch_one`] (la copia del
/// servidor de un recurso en conflicto). Un evento o un contacto es chico; más que
/// esto es un servidor roto o adversario y se corta.
pub const MAX_OBJECT_BYTES: usize = 1024 * 1024;

/// Tope del cuerpo de **una página** de un listado ([`fetch_all_pages`]). Con
/// `$top=100` y descripciones de hasta `MAX_DESCRIPTION` por ítem una página legítima
/// entra de sobra; mucho más es un servidor que intenta agotar la memoria.
pub const MAX_PAGE_BYTES: usize = 16 * 1024 * 1024;

/// Lo que puede salir mal al leer un cuerpo con [`read_capped`]: la red se cortó, o el
/// cuerpo pasó el tope. Quien llama lo mapea a su propio error.
pub enum CappedReadError {
    Network(String),
    TooLarge,
}

/// Lee el cuerpo de una respuesta **por chunks, abortando en cuanto el acumulado pasa
/// `max`**, sin bufferizar el cuerpo entero antes de chequear: `Content-Length` es lo
/// que el servidor **promete**, no lo que manda, así que un servidor hostil que
/// promete un kilobyte y manda un gigabyte no puede agotar la memoria del servicio.
/// Permite un cuerpo vacío (un `204 No Content` válido). Mismo criterio que el lector
/// capado del flujo de imágenes ([`crate::images`]), pero con el tope por parámetro y
/// sin rechazar el cuerpo vacío.
pub async fn read_capped(
    response: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, CappedReadError> {
    use futures_util::StreamExt;

    let mut received: Vec<u8> = Vec::new();
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        // `without_url()`: el error de red no tiene por qué llevar la URL (con el
        // `user_id`) a ningún registro.
        let chunk = chunk.map_err(|e| CappedReadError::Network(e.without_url().to_string()))?;
        if received.len() + chunk.len() > max {
            return Err(CappedReadError::TooLarge);
        }
        received.extend_from_slice(&chunk);
    }
    Ok(received)
}

/// Un cliente HTTP con el plazo de conexión del servicio. Nunca
/// `reqwest::Client::new()` pelado: ése no tiene plazo de conexión.
pub fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        // Graph no redirige: seguir un `Location` de la respuesta es seguir una URL
        // que puso la red (el token se descarta, pero lo que conteste ese origen se
        // guardaría como dato de Graph).
        .build()
}

/// Credencial para Microsoft Graph API.
///
/// Contiene el token de acceso OAuth2 y el ID de usuario para armar la ruta de
/// la colección (`/users/{id}/...`).
///
/// No deriva `Debug`: su `Debug` manual redacta el token para que no termine en
/// un log ni en un volcado. El token se guarda en [`zeroize::Zeroizing`], que lo
/// pone en cero al soltarlo.
#[derive(Clone)]
pub struct GraphCredential {
    /// Token de acceso OAuth2.
    pub access_token: zeroize::Zeroizing<String>,
    /// ID del usuario (para multi-tenant); por omisión «me».
    pub user_id: String,
    /// Raíz de la API de Graph (`https://graph.microsoft.com/v1.0` en
    /// producción). Es un campo para que las pruebas puedan apuntar el
    /// sincronizador a un endpoint falso en `127.0.0.1`; el servicio de cuentas
    /// siempre la rellena con [`GRAPH_BASE_URL`]. El host (y el esquema) de esta
    /// URL es el único al que el sincronizador adjunta el token: ver
    /// [`fetch_all_pages`].
    pub base_url: String,
}

impl std::fmt::Debug for GraphCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphCredential")
            .field("access_token", &"<redactado>")
            .field("user_id", &self.user_id)
            .field("base_url", &self.base_url)
            .finish()
    }
}

/// Fuente de credenciales para Graph API.
///
/// Obtiene el token de acceso y el ID de usuario del servicio de cuentas, para
/// la capacidad que se le pase (`contacts` o `calendar`).
pub struct GraphCredentialSource;

impl GraphCredentialSource {
    /// Obtiene la credencial de Graph API para una cuenta y una capacidad.
    pub async fn credential(
        &self,
        account_id: &str,
        capability: &'static str,
    ) -> Result<GraphCredential, CredentialError> {
        let classify = |e: BrokerError| match e {
            BrokerError::Denied(_) => CredentialError::Denied,
            other => CredentialError::Failed(other.to_string()),
        };
        let broker = crate::broker::Broker::connect().await.map_err(classify)?;
        let token = zeroize::Zeroizing::new(
            broker
                .access_token(account_id, capability)
                .await
                .map_err(classify)?,
        );
        let data = broker
            .account_data(account_id, capability)
            .await
            .map_err(classify)?;
        let config = data.get("config").unwrap_or(&data);
        // Extraer el user_id de la configuración (viene del proveedor).
        let user_id = config
            .get("user_id")
            .and_then(|v| v.as_str())
            .unwrap_or("me")
            .to_string();

        Ok(GraphCredential {
            access_token: token,
            user_id,
            base_url: GRAPH_BASE_URL.to_string(),
        })
    }
}

/// Lo que puede fallar al traer una colección paginada de Graph.
///
/// Tipado a propósito: la validación del `@odata.nextLink` corta la
/// sincronización con una variante propia, y las pruebas pueden distinguir
/// «host no confiable» de un simple error de red. Ninguna variante vuelca el
/// cuerpo crudo de la respuesta de Graph al estado que se muestra.
#[derive(Debug)]
pub enum GraphFetchError {
    /// No se pudo contactar al servidor.
    Network(String),
    /// La respuesta no se pudo parsear como la colección esperada.
    Parse,
    /// Graph respondió con un código de error. Sólo el código, nunca el cuerpo.
    Http(reqwest::StatusCode),
    /// La URL base o un `nextLink` no es una URL válida.
    MalformedUrl,
    /// El `nextLink` apunta a un host o esquema distinto del de la URL base: se
    /// aborta para no mandarle el token a otro servidor.
    UntrustedNextLink,
    /// El servidor repitió un `nextLink` ya visto: paginación en bucle.
    PaginationLoop,
    /// Se superó el tope de páginas.
    TooManyPages,
    /// Se superó el tope de elementos acumulados.
    TooManyItems,
    /// El cuerpo de la respuesta superó el tope de bytes ([`read_capped`]): se cortó
    /// la lectura sin bufferizarlo entero.
    TooLarge,
    /// Se agotó el plazo de un pedido.
    Timeout,
}

impl std::fmt::Display for GraphFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // El `e` de reqwest trae la URL y el motivo (DNS, TLS, conexión),
            // nunca el token ni el cuerpo de la respuesta.
            GraphFetchError::Network(e) => write!(f, "error de red con Graph: {e}"),
            GraphFetchError::Parse => write!(f, "no se pudo parsear la respuesta de Graph"),
            GraphFetchError::Http(status) => write!(f, "Graph respondió con error {status}"),
            GraphFetchError::MalformedUrl => write!(f, "URL inválida al paginar"),
            GraphFetchError::UntrustedNextLink => write!(
                f,
                "Graph devolvió un enlace de paginación a un host no confiable; se abortó la \
                 sincronización"
            ),
            GraphFetchError::PaginationLoop => write!(
                f,
                "Graph repitió un enlace de paginación; se abortó la sincronización"
            ),
            GraphFetchError::TooManyPages => {
                write!(f, "demasiadas páginas; se abortó la sincronización")
            }
            GraphFetchError::TooManyItems => {
                write!(f, "demasiados elementos; se abortó la sincronización")
            }
            GraphFetchError::TooLarge => {
                write!(f, "la respuesta de Graph superó el tope de tamaño")
            }
            GraphFetchError::Timeout => write!(f, "se agotó el tiempo de espera de Graph"),
        }
    }
}

/// Una página de una colección de OData: `value` y el `@odata.nextLink` de la
/// paginación; el resto de los anotadores de OData se ignora.
///
/// Genérica en el recurso (`GraphContact`, `GraphEvent`): cada backend la
/// instancia con el suyo. Todo opcional y con `default`: es dato de red.
#[derive(Debug, serde::Deserialize)]
pub struct GraphPage<T> {
    #[serde(default = "Vec::new")]
    pub value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
}

/// Arma la URL inicial de una colección sobre la base de la credencial.
///
/// Cada segmento entra percent-codificado (`path_segments_mut`): un `?`, un `#`
/// o una `/` en, por ejemplo, el `user_id`, no pueden alterar la query, el
/// fragmento ni la ruta. La query (`$top`, `$select`) va tal cual la pasa quien
/// llama.
pub fn build_url(base_url: &str, segments: &[&str], query: &str) -> Result<Url, GraphFetchError> {
    let base = Url::parse(base_url).map_err(|_| GraphFetchError::MalformedUrl)?;
    let mut url = base.clone();
    {
        let mut seg = url
            .path_segments_mut()
            .map_err(|_| GraphFetchError::MalformedUrl)?;
        seg.pop_if_empty();
        for s in segments {
            seg.push(s);
        }
    }
    url.set_query(Some(query));
    Ok(url)
}

/// Trae todos los elementos de una colección paginando por `@odata.nextLink`.
///
/// **El `nextLink` es dato de red y no se sigue a ciegas.** Antes de adjuntarle
/// el token de Graph, cada `nextLink` se parsea y se exige que comparta *origen*
/// con la URL base de la credencial —mismo esquema, mismo host y mismo puerto—.
/// En producción la base es [`GRAPH_BASE_URL`], así que el token sólo viaja a
/// `graph.microsoft.com` por HTTPS; las pruebas apuntan `base_url` a un endpoint
/// falso y la validación compara contra *ese* host, no contra un literal. Un
/// `nextLink` a otro host —un servidor comprometido o un MITM— aborta la
/// sincronización sin haberle mandado el token.
///
/// Además acota la paginación: tope de páginas, tope de elementos
/// (`max_items`), deduplicado de `nextLink` para cortar un bucle, y un plazo por
/// pedido.
///
/// `extra_headers` se adjunta a cada pedido además de `Authorization` y
/// `Accept`: el calendario lo usa para pedir las fechas en UTC
/// (`Prefer: outlook.timezone="UTC"`), de modo que Graph no devuelva nombres de
/// zona de Windows que habría que traducir.
pub async fn fetch_all_pages<T: DeserializeOwned>(
    client: &reqwest::Client,
    credential: &GraphCredential,
    first_url: Url,
    max_items: usize,
    extra_headers: &[(&str, &str)],
) -> Result<Vec<T>, GraphFetchError> {
    // El origen de confianza sale de la URL base de la credencial, no de un
    // literal: así la validación sirve igual para producción, para una nube
    // alternativa de Graph y para el endpoint falso de las pruebas.
    let base = Url::parse(&credential.base_url).map_err(|_| GraphFetchError::MalformedUrl)?;
    let same_origin = |candidate: &Url| -> bool {
        candidate.scheme() == base.scheme()
            && candidate.host_str() == base.host_str()
            && candidate.port_or_known_default() == base.port_or_known_default()
    };

    let mut url = first_url;
    let mut all: Vec<T> = Vec::new();
    // Los `nextLink` ya pedidos, para cortar un servidor que repite el mismo
    // enlace en bucle. Incluye la URL inicial.
    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(url.as_str().to_string());

    for _page in 0..MAX_PAGES {
        // Plazo por pedido: conexión más respuesta. El token sólo se adjunta
        // acá, y `url` ya fue validada como del mismo origen que la base.
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        let mut request = client
            .get(url.as_str())
            .bearer_auth(credential.access_token.as_str())
            .header("Accept", "application/json");
        for (name, value) in extra_headers {
            request = request.header(*name, *value);
        }

        let fetch_page = async {
            let response = request
                .send()
                .await
                .map_err(|e| GraphFetchError::Network(e.to_string()))?;
            if !response.status().is_success() {
                // Sólo el código: el cuerpo crudo del error de Graph no se
                // vuelca al estado que ve quien usa el sistema.
                return Err(GraphFetchError::Http(response.status()));
            }
            // Lectura capada por chunks: una página que pasa el tope se corta sin
            // bufferizarla entera (`Content-Length` es promesa, no garantía).
            let bytes = read_capped(response, MAX_PAGE_BYTES)
                .await
                .map_err(|e| match e {
                    CappedReadError::Network(detail) => GraphFetchError::Network(detail),
                    CappedReadError::TooLarge => GraphFetchError::TooLarge,
                })?;
            serde_json::from_slice::<GraphPage<T>>(&bytes).map_err(|_| GraphFetchError::Parse)
        };

        let data = match tokio::time::timeout_at(deadline, fetch_page).await {
            Ok(result) => result?,
            Err(_) => return Err(GraphFetchError::Timeout),
        };

        // No materializamos más allá del tope: si esta página excedería
        // `max_items`, cortamos antes de extender el `Vec`.
        if all.len() + data.value.len() > max_items {
            return Err(GraphFetchError::TooManyItems);
        }
        all.extend(data.value);

        let Some(next) = data.next_link else {
            return Ok(all);
        };
        let next_url = Url::parse(&next).map_err(|_| GraphFetchError::MalformedUrl)?;
        if !same_origin(&next_url) {
            return Err(GraphFetchError::UntrustedNextLink);
        }
        if !seen.insert(next_url.as_str().to_string()) {
            return Err(GraphFetchError::PaginationLoop);
        }
        url = next_url;
    }

    Err(GraphFetchError::TooManyPages)
}

/// Trae **un solo** objeto de Graph por `GET`, deserializándolo. Como
/// [`fetch_all_pages`] pero sin paginar: la URL ya la construyó quien llama **sobre
/// `base_url`** (así el token sólo viaja a ese origen; acá no hay `nextLink` que
/// validar), se le adjunta el token, `Accept` y `extra_headers` (el calendario pide
/// las fechas en UTC). Acota la respuesta en tamaño ([`MAX_OBJECT_BYTES`]) y en plazo
/// ([`REQUEST_TIMEOUT`]).
///
/// `Ok(None)` cuando el servidor contesta `404`: el objeto ya no está (la copia del
/// servidor de un conflicto sobre un recurso borrado). Cualquier otro estado de error
/// es [`GraphFetchError::Http`] —sólo el código, nunca el cuerpo—.
pub async fn fetch_one<T: DeserializeOwned>(
    client: &reqwest::Client,
    credential: &GraphCredential,
    url: Url,
    extra_headers: &[(&str, &str)],
) -> Result<Option<T>, GraphFetchError> {
    let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
    let mut request = client
        .get(url.as_str())
        .bearer_auth(credential.access_token.as_str())
        .header("Accept", "application/json");
    for (name, value) in extra_headers {
        request = request.header(*name, *value);
    }

    let fetch = async {
        // `without_url()`: el `Display` de `reqwest::Error` trae la URL (con el
        // `user_id`), que no tiene por qué aparecer en ningún registro.
        let response = request
            .send()
            .await
            .map_err(|e| GraphFetchError::Network(e.without_url().to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(GraphFetchError::Http(response.status()));
        }
        // Lectura capada por chunks: se aborta en cuanto pasa el tope, sin
        // bufferizar el cuerpo entero.
        let bytes = read_capped(response, MAX_OBJECT_BYTES)
            .await
            .map_err(|e| match e {
                CappedReadError::Network(detail) => GraphFetchError::Network(detail),
                CappedReadError::TooLarge => GraphFetchError::TooLarge,
            })?;
        serde_json::from_slice::<T>(&bytes)
            .map(Some)
            .map_err(|_| GraphFetchError::Parse)
    };

    match tokio::time::timeout_at(deadline, fetch).await {
        Ok(result) => result,
        Err(_) => Err(GraphFetchError::Timeout),
    }
}

/// Maquinaria de endpoint falso de Microsoft Graph para las pruebas de los
/// backends que lo consumen (contactos y calendario).
///
/// Habla HTTP/1.1 de verdad contra `reqwest` —sin atajos—, sirve una cola de
/// respuestas JSON y anota cada pedido —su ruta, su cabecera `Authorization` y
/// su `Prefer`— para que una prueba pueda decir «a este host no se le mandó el
/// token» o «se pidieron las fechas en UTC». Vive junto al módulo compartido que
/// prueba, al estilo de [`crate::dav::fake`], para que contactos y calendario
/// reusen la misma defensa en vez de copiarla.
#[cfg(test)]
pub mod fake {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::GraphCredential;

    /// El token que la credencial lleva al endpoint falso. Lo único que prueba
    /// «no se le mandó el token a otro host» es que ese host no lo haya
    /// recibido.
    pub const TOKEN: &str = "token-secreto-de-prueba";

    /// Un pedido HTTP tal como llegó al endpoint falso de Graph.
    #[derive(Clone)]
    pub struct GraphRequest {
        /// El método (`GET`, `POST`, `PATCH`, `DELETE`): lo mira la escritura
        /// (`#97`) para distinguir crear de editar de borrar.
        pub method: String,
        pub path: String,
        pub authorization: String,
        /// La cabecera `Prefer`, vacía si no vino: el calendario la usa para
        /// pedir las fechas en UTC (`outlook.timezone="UTC"`).
        pub prefer: String,
        /// La cabecera `If-Match`, vacía si no vino: la escritura (`#97`) manda
        /// acá el `@odata.etag` de precondición.
        pub if_match: String,
        /// El cuerpo del pedido, vacío si no trajo: la escritura manda el JSON del
        /// objeto.
        pub body: String,
    }

    /// Lo que el endpoint falso sabe contestar.
    struct FakeGraphState {
        /// Respuestas `(estado, cuerpo JSON)` a servir en orden de llegada.
        responses: VecDeque<(u16, String)>,
        /// Cada pedido que llegó, con sus cabeceras: para poder decir «este host
        /// no recibió el token» o «se pidió en UTC».
        requests: Vec<GraphRequest>,
        /// Si la cola se vacía: con `Some(origin)` se generan páginas únicas sin
        /// fin (para el tope de páginas); con `None` se contesta 500.
        auto_next: Option<String>,
        /// Contador de páginas autogeneradas, para que cada `nextLink` sea único
        /// y no dispare el deduplicado.
        auto_count: usize,
    }

    /// Un servidor HTTP/JSON de mentira en `127.0.0.1`, al estilo de
    /// `crate::dav::fake`.
    #[derive(Clone)]
    pub struct FakeGraph {
        state: Arc<Mutex<FakeGraphState>>,
        port: u16,
    }

    impl FakeGraph {
        pub async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let state = Arc::new(Mutex::new(FakeGraphState {
                responses: VecDeque::new(),
                requests: Vec::new(),
                auto_next: None,
                auto_count: 0,
            }));
            let shared = Arc::clone(&state);
            tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    let state = Arc::clone(&shared);
                    tokio::spawn(serve_graph(socket, state));
                }
            });
            Self { state, port }
        }

        pub fn origin(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }

        /// La raíz que la credencial le pasa al sincronizador; en producción es
        /// [`super::GRAPH_BASE_URL`]. El host y el puerto de esta URL son el
        /// único origen al que el sincronizador adjunta el token.
        pub fn base_url(&self) -> String {
            format!("{}/v1.0", self.origin())
        }

        /// Encola una respuesta JSON con estado 200.
        pub fn push(&self, body: impl Into<String>) {
            self.state
                .lock()
                .unwrap()
                .responses
                .push_back((200, body.into()));
        }

        /// Encola una respuesta con un estado arbitrario. Estados especiales: `0` no
        /// contesta nunca (plazo), `1` corta la conexión sin contestar (error de
        /// transporte), `2` manda un `201` con el cuerpo cortado.
        pub fn push_status(&self, status: u16, body: impl Into<String>) {
            self.state
                .lock()
                .unwrap()
                .responses
                .push_back((status, body.into()));
        }

        /// A partir de que se vacíe la cola, generar páginas únicas sin fin: para
        /// llegar al tope de páginas sin que se dispare el deduplicado.
        pub fn auto_paginate(&self) {
            let origin = self.origin();
            self.state.lock().unwrap().auto_next = Some(origin);
        }

        pub fn requests(&self) -> Vec<GraphRequest> {
            self.state.lock().unwrap().requests.clone()
        }
    }

    async fn serve_graph(mut socket: tokio::net::TcpStream, state: Arc<Mutex<FakeGraphState>>) {
        let mut buffer = Vec::new();
        loop {
            // La cabecera entera.
            let header_end = loop {
                if let Some(end) = find(&buffer, b"\r\n\r\n") {
                    break end;
                }
                let mut chunk = [0u8; 8192];
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                }
            };
            let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
            let mut lines = head.split("\r\n");
            let request_line = lines.next().unwrap_or("").to_string();
            let method = request_line
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string();
            let mut authorization = String::new();
            let mut prefer = String::new();
            let mut if_match = String::new();
            let mut length = 0usize;
            for line in lines {
                if let Some((name, value)) = line.split_once(':') {
                    let name = name.trim().to_ascii_lowercase();
                    let value = value.trim();
                    if name == "authorization" {
                        authorization = value.to_string();
                    } else if name == "prefer" {
                        prefer = value.to_string();
                    } else if name == "if-match" {
                        if_match = value.to_string();
                    } else if name == "content-length" {
                        length = value.parse().unwrap_or(0);
                    }
                }
            }
            let body_start = header_end + 4;
            while buffer.len() < body_start + length {
                let mut chunk = [0u8; 8192];
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                }
            }
            // Acotar el final al tamaño leído: un `Content-Length` que exceda el
            // cuerpo recibido no debe hacer panic por slice fuera de rango.
            let end = (body_start + length).min(buffer.len());
            let request_body = String::from_utf8_lossy(&buffer[body_start..end]).into_owned();
            buffer.drain(..end);

            let (status, body) = {
                let mut state = state.lock().unwrap();
                state.requests.push(GraphRequest {
                    method: method.clone(),
                    path: path.clone(),
                    authorization: authorization.clone(),
                    prefer: prefer.clone(),
                    if_match: if_match.clone(),
                    body: request_body,
                });
                match state.responses.pop_front() {
                    Some(answer) => answer,
                    None => {
                        match state.auto_next.clone() {
                            Some(origin) => {
                                state.auto_count += 1;
                                let n = state.auto_count;
                                (
                                200,
                                format!("{{\"value\":[],\"@odata.nextLink\":\"{origin}/auto/{n}\"}}"),
                            )
                            }
                            None => (500, String::new()),
                        }
                    }
                }
            };

            // Estado 0 = «no contestar nunca»: para probar el plazo de un pedido.
            if status == 0 {
                std::future::pending::<()>().await;
            }
            // Estado 1 = «cerrar sin contestar»: el pedido llegó y la conexión se corta,
            // o sea un error de transporte en `.send()` tras haber enviado.
            if status == 1 {
                return;
            }
            // Estado 2 = un `201` que promete más cuerpo del que manda y corta: la
            // lectura del cuerpo se corta **después** de un 2xx (el POST se procesó).
            if status == 2 {
                let _ = socket
                    .write_all(b"HTTP/1.1 201 X\r\nContent-Length: 100\r\n\r\n{")
                    .await;
                return;
            }
            // En una redirección (3xx) el «cuerpo» encolado es el `Location`.
            let (location, body) = if (300..400).contains(&status) {
                (format!("Location: {body}\r\n"), String::new())
            } else {
                (String::new(), body)
            };
            let out = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n{location}Content-Length: {}\r\n\r\n",
                body.len()
            );
            let mut bytes = out.into_bytes();
            bytes.extend_from_slice(body.as_bytes());
            if socket.write_all(&bytes).await.is_err() {
                return;
            }
        }
    }

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    /// Un cliente HTTP con el plazo de conexión del servicio, como en
    /// producción.
    pub fn client() -> reqwest::Client {
        super::http_client().unwrap()
    }

    /// Una credencial que apunta al endpoint falso, con el token de prueba y
    /// `user_id` «me».
    pub fn credential_for(server: &FakeGraph) -> GraphCredential {
        GraphCredential {
            access_token: zeroize::Zeroizing::new(TOKEN.to_string()),
            user_id: "me".to_string(),
            base_url: server.base_url(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{client, credential_for, FakeGraph};
    use super::*;

    /// Una página de `n` ítems enteros, con `nextLink` opcional.
    fn page(n: usize, next: Option<&str>) -> String {
        let items = (0..n).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        match next {
            Some(link) => format!("{{\"value\":[{items}],\"@odata.nextLink\":\"{link}\"}}"),
            None => format!("{{\"value\":[{items}]}}"),
        }
    }

    async fn fetch(server: &FakeGraph, max_items: usize) -> Result<Vec<u32>, GraphFetchError> {
        let url = Url::parse(&format!("{}/v1.0/me/items", server.origin())).unwrap();
        fetch_all_pages(&client(), &credential_for(server), url, max_items, &[]).await
    }

    /// Una página que por sí sola pasa el tope corta con `TooManyItems`. Ojo: el
    /// endurecimiento (comprobar antes de `extend`) no cambia lo que ve quien
    /// llama, sólo evita materializar de más; esta prueba y las dos de abajo
    /// guardan el **contrato** del tope (corte y borde `>`), no la asignación.
    #[tokio::test]
    async fn una_pagina_que_excede_el_tope_de_items_corta_con_too_many_items() {
        let server = FakeGraph::start().await;
        server.push(page(6, None));

        let result = fetch(&server, 5).await;
        assert!(
            matches!(result, Err(GraphFetchError::TooManyItems)),
            "6 ítems con tope 5 deben cortar con TooManyItems, dio {result:?}"
        );
    }

    /// El tope cuenta lo acumulado: dos páginas que juntas pasan el tope cortan
    /// en la segunda, y no se pide una tercera.
    #[tokio::test]
    async fn el_tope_de_items_cuenta_lo_acumulado_entre_paginas() {
        let server = FakeGraph::start().await;
        let next = format!("{}/v1.0/me/items?$skip=3", server.origin());
        server.push(page(3, Some(&next)));
        server.push(page(3, Some(&format!("{}/otra", server.origin()))));

        let result = fetch(&server, 5).await;
        assert!(
            matches!(result, Err(GraphFetchError::TooManyItems)),
            "3 + 3 con tope 5 deben cortar, dio {result:?}"
        );
        assert_eq!(server.requests().len(), 2, "no se pide una tercera página");
    }

    /// El borde: exactamente `max_items` ítems se aceptan (el corte es `>`, no
    /// `>=`).
    #[tokio::test]
    async fn exactamente_el_tope_de_items_se_acepta() {
        let server = FakeGraph::start().await;
        let next = format!("{}/v1.0/me/items?$skip=3", server.origin());
        server.push(page(3, Some(&next)));
        server.push(page(2, None));

        let items = fetch(&server, 5).await.expect("5 ítems con tope 5 pasan");
        assert_eq!(items, vec![0, 1, 2, 0, 1]);
    }
}
