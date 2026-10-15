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

/// Un cliente HTTP con el plazo de conexión del servicio. Nunca
/// `reqwest::Client::new()` pelado: ése no tiene plazo de conexión.
pub fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
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
            response
                .json::<GraphPage<T>>()
                .await
                .map_err(|_| GraphFetchError::Parse)
        };

        let data = match tokio::time::timeout_at(deadline, fetch_page).await {
            Ok(result) => result?,
            Err(_) => return Err(GraphFetchError::Timeout),
        };

        all.extend(data.value);
        if all.len() > max_items {
            return Err(GraphFetchError::TooManyItems);
        }

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
