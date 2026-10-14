//! Backend Microsoft Graph API para sincronización de contactos.
//!
//! Lee la **carpeta de contactos** del usuario (`/me/contacts`, o
//! `/users/{id}/contacts` para multi-tenant) con paginación por
//! `@odata.nextLink`. Esa es la agenda que la persona guardó a mano, a
//! diferencia de la People API (`/me/people`), que devuelve «personas
//! relevantes» por ranking —incluye a quien se le escribió sin guardar— y queda
//! reservada para enriquecimiento a futuro, no para sincronizar la agenda.
//!
//! Es **de sólo lectura**: no escribe nada contra Graph. La escritura por Graph
//! (`Contacts.ReadWrite`) es fase 2 (Vasak-OS/vasak-accounts#97).

use std::collections::HashSet;
use std::time::Duration;

use url::Url;

use crate::broker::BrokerError;
use crate::contacts_sync::backend::{SyncContext, SyncResult};
use crate::contacts_sync::SyncReport;
use crate::dav_sync::CredentialError;
use crate::store::contacts::{ContactOp, ContactRow};
use crate::store::key::KeySource;
use crate::store::lifecycle::{AreaState, CONTACTS_AREA};
use crate::vcard;

/// Cada cuánto se sincronizan los contactos de una cuenta encendida.
const CONTACTS_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Plazo para que un pedido a Graph conecte, como el resto del servicio.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Plazo por pedido —conexión más respuesta— al paginar la carpeta. Corta un
/// servidor que acepta la conexión y no responde. Igual que `dav_sync` acota
/// cada pedido con [`tokio::time::timeout_at`].
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Tope de páginas de la paginación por `@odata.nextLink`. Con `$top=100` da de
/// sobra para una agenda personal; un servidor que no corta es un bucle o un
/// intento de agotar memoria.
const MAX_PAGES: usize = 1_000;

/// Tope de contactos acumulados. Cota de memoria independiente del tope de
/// páginas, por si un servidor devuelve páginas enormes.
const MAX_CONTACTS: usize = 100_000;

/// Lo que se ve en el estado cuando el servicio de cuentas dice que no.
const DENIED_DETAIL: &str = "el servicio de cuentas no le da al sincronizador permiso para los \
     contactos de esta cuenta";

/// Lo que se ve cuando la base no está abierta.
const CLOSED_DETAIL: &str =
    "la base no está abierta: se sincroniza cuando se desbloquee el llavero";

/// URL base de Microsoft Graph.
const GRAPH_BASE_URL: &str = "https://graph.microsoft.com/v1.0";

/// Credencial para Microsoft Graph API.
///
/// Contiene el token de acceso OAuth2 y el ID de usuario para la carpeta de
/// contactos.
///
/// No deriva `Debug`: su `Debug` manual redacta el token para que no termine en
/// un log ni en un volcado. El token se guarda en [`zeroize::Zeroizing`], que lo
/// pone en cero al soltarlo.
#[derive(Clone)]
pub struct GraphCredential {
    /// Token de acceso OAuth2.
    pub access_token: zeroize::Zeroizing<String>,
    /// URL base del usuario (para multi-tenant).
    pub user_id: String,
    /// Raíz de la API de Graph (`https://graph.microsoft.com/v1.0` en
    /// producción). Es un campo para que las pruebas puedan apuntar el
    /// sincronizador a un endpoint falso en `127.0.0.1`; el servicio de cuentas
    /// siempre la rellena con [`GRAPH_BASE_URL`]. El host (y el esquema) de esta
    /// URL es el único al que el sincronizador adjunta el token: ver
    /// [`GraphApiBackend::fetch_all_contacts`].
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
/// Obtiene el token de acceso y el ID de usuario del servicio de cuentas.
pub struct GraphCredentialSource;

impl GraphCredentialSource {
    /// Obtiene la credencial de Graph API para una cuenta.
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
        // Extraer el user_id de la configuración (viene del proveedor)
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

/// Lo que puede fallar al traer la carpeta de contactos de Graph.
///
/// Tipado a propósito: la validación del `@odata.nextLink` (ver
/// [`GraphApiBackend::fetch_all_contacts`]) corta la sincronización con una
/// variante propia, y las pruebas pueden distinguir «host no confiable» de un
/// simple error de red. Ninguna variante vuelca el cuerpo crudo de la respuesta
/// de Graph al estado que se muestra.
#[derive(Debug)]
enum GraphFetchError {
    /// No se pudo contactar al servidor.
    Network(String),
    /// La respuesta no se pudo parsear como la carpeta de contactos.
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
    /// Se superó el tope de contactos acumulados.
    TooManyContacts,
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
            GraphFetchError::MalformedUrl => write!(f, "URL inválida al paginar los contactos"),
            GraphFetchError::UntrustedNextLink => write!(
                f,
                "Graph devolvió un enlace de paginación a un host no confiable; se abortó la \
                 sincronización"
            ),
            GraphFetchError::PaginationLoop => {
                write!(
                    f,
                    "Graph repitió un enlace de paginación; se abortó la sincronización"
                )
            }
            GraphFetchError::TooManyPages => {
                write!(
                    f,
                    "demasiadas páginas de contactos; se abortó la sincronización"
                )
            }
            GraphFetchError::TooManyContacts => {
                write!(f, "demasiados contactos; se abortó la sincronización")
            }
            GraphFetchError::Timeout => write!(f, "se agotó el tiempo de espera de Graph"),
        }
    }
}

/// Respuesta de la carpeta de contactos (`/me/contacts`) de Microsoft Graph.
///
/// Sólo se mira `value` y el `@odata.nextLink` de la paginación; el resto de los
/// anotadores de OData se ignora.
#[derive(Debug, Default, serde::Deserialize)]
struct GraphContactsResponse {
    #[serde(default)]
    value: Vec<GraphContact>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

/// Un contacto de la carpeta de contactos de Microsoft Graph.
///
/// Todo opcional y con `default`: es dato de red, así que un campo que no venga
/// queda vacío y nunca hace fallar el parseo.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GraphContact {
    id: String,
    display_name: Option<String>,
    given_name: Option<String>,
    surname: Option<String>,
    middle_name: Option<String>,
    email_addresses: Vec<GraphEmailAddress>,
    business_phones: Vec<String>,
    home_phones: Vec<String>,
    mobile_phone: Option<String>,
    home_address: Option<GraphPhysicalAddress>,
    business_address: Option<GraphPhysicalAddress>,
    other_address: Option<GraphPhysicalAddress>,
    company_name: Option<String>,
    job_title: Option<String>,
    birthday: Option<String>,
    personal_notes: Option<String>,
}

/// Dirección de correo de un contacto de Graph.
#[derive(Debug, Default, serde::Deserialize)]
struct GraphEmailAddress {
    /// La dirección misma; si no viene, no se emite el `EMAIL`.
    address: Option<String>,
}

/// Dirección postal de un contacto de Graph (`homeAddress`, `businessAddress`,
/// `otherAddress`).
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GraphPhysicalAddress {
    street: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country_or_region: Option<String>,
}

impl GraphPhysicalAddress {
    /// `true` si todos los componentes están vacíos: una dirección así no se
    /// emite.
    fn is_empty(&self) -> bool {
        [
            &self.street,
            &self.city,
            &self.state,
            &self.postal_code,
            &self.country_or_region,
        ]
        .iter()
        .all(|c| c.as_deref().unwrap_or("").is_empty())
    }
}

/// Backend Microsoft Graph API.
///
/// Sincroniza los contactos contra la carpeta de contactos de Microsoft Graph
/// (`/users/{id}/contacts`). Convierte cada contacto a vCard y hace upsert en la
/// libreta «Graph Contacts» del almacén local. De sólo lectura.
pub struct GraphApiBackend;

impl GraphApiBackend {
    /// Sincroniza los contactos usando la carpeta de contactos de Microsoft
    /// Graph.
    ///
    /// Trae los contactos con paginación, los convierte a vCard y los guarda en
    /// el almacén local. Crea la libreta por defecto si no existe.
    pub async fn sync<K: KeySource>(
        &self,
        ctx: SyncContext<'_, K>,
        credential: &GraphCredential,
    ) -> SyncResult {
        let manager = ctx.manager;
        let account_id = ctx.account_id;
        let notify = ctx.notify;

        let set_status = |state: AreaState, detail: &str| {
            let manager = manager.clone();
            let account_id = account_id.to_string();
            let detail = detail.to_string();
            let notify = notify.clone();
            async move {
                if manager
                    .set_area_status(CONTACTS_AREA, &account_id, state, &detail)
                    .await
                {
                    (notify)();
                }
            }
        };

        if !manager.prepare_for_sync(CONTACTS_AREA, account_id).await {
            set_status(AreaState::Pending, CLOSED_DETAIL).await;
            return SyncResult::StoreClosed;
        }
        set_status(AreaState::Syncing, "").await;

        let client = match reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                set_status(AreaState::Failed, "no se pudo preparar el cliente HTTP").await;
                return SyncResult::Failed(e.to_string());
            }
        };
        let mut report = SyncReport::default();

        // Traer la carpeta de contactos completa (sin delta sync por ahora).
        let contacts = match Self::fetch_all_contacts(&client, credential).await {
            Ok(c) => c,
            Err(e) => {
                set_status(AreaState::Failed, &e.to_string()).await;
                return SyncResult::Failed(e.to_string());
            }
        };

        // Convertir a filas de contactos
        let mut rows = Vec::new();
        for contact in contacts {
            if let Some(row) = Self::contact_to_row(contact) {
                rows.push(row);
            }
        }

        // Crear una libreta por defecto para Graph API
        let default_book = "graph://default";
        let stored_books = manager
            .with_store(account_id, move |s| {
                s.upsert_address_books(&[(default_book.to_string(), "Graph Contacts".to_string())])
            })
            .await;

        let stored_book = match stored_books {
            Ok(mut books) => books.pop(),
            Err(e) => {
                set_status(AreaState::Failed, "no se pudo crear la libreta Graph").await;
                return SyncResult::Failed(e.to_string());
            }
        };

        let stored_book = match stored_book {
            Some(b) => b,
            None => {
                set_status(AreaState::Failed, "no se creó la libreta Graph").await;
                return SyncResult::Failed("no se creó la libreta Graph".into());
            }
        };

        let fetched_count = rows.len();
        // Guardar en el almacén
        let applied = manager
            .with_store(account_id, move |s| {
                let ops: Vec<ContactOp> = rows
                    .into_iter()
                    .map(|r| ContactOp::Upsert(Box::new(r)))
                    .collect();
                s.apply_contacts(&stored_book, &ops, None, u64::MAX)
            })
            .await;

        match applied {
            Ok(_) => {
                report.fetched = fetched_count;
                set_status(AreaState::Synced, "").await;
                SyncResult::Synced(report)
            }
            Err(e) => {
                set_status(AreaState::Failed, "no se pudieron guardar los contactos").await;
                SyncResult::Failed(e.to_string())
            }
        }
    }

    /// Trae todos los contactos de la carpeta con paginación por
    /// `@odata.nextLink`.
    ///
    /// **El `nextLink` es dato de red y no se sigue a ciegas.** Antes de
    /// adjuntarle el token de Graph, cada `nextLink` se parsea y se exige que
    /// comparta *origen* con la URL base de la credencial —mismo esquema, mismo
    /// host y mismo puerto—. En producción la base es [`GRAPH_BASE_URL`]
    /// (`https://graph.microsoft.com/v1.0`), así que el token sólo viaja a ese
    /// host por HTTPS; las pruebas apuntan `base_url` a un endpoint falso y la
    /// validación compara contra *ese* host, no contra un literal. Un `nextLink`
    /// a otro host —un servidor comprometido o un MITM— aborta la sincronización
    /// sin haberle mandado el token.
    ///
    /// Además acota la paginación: tope de páginas, de contactos, dedup de
    /// `nextLink` para cortar un bucle, y un plazo por pedido.
    async fn fetch_all_contacts(
        client: &reqwest::Client,
        credential: &GraphCredential,
    ) -> Result<Vec<GraphContact>, GraphFetchError> {
        // El origen de confianza sale de la URL base de la credencial, no de un
        // literal: así la validación sirve igual para producción, para una nube
        // alternativa de Graph y para el endpoint falso de las pruebas.
        let base = Url::parse(&credential.base_url).map_err(|_| GraphFetchError::MalformedUrl)?;
        let same_origin = |candidate: &Url| -> bool {
            candidate.scheme() == base.scheme()
                && candidate.host_str() == base.host_str()
                && candidate.port_or_known_default() == base.port_or_known_default()
        };

        // La primera URL se arma sobre la base. `user_id` entra como *segmento*
        // de ruta: `path_segments_mut` lo percent-codifica, así que un `?`, un
        // `#` o una `/` en el id no pueden alterar la query, el fragmento ni la
        // ruta.
        let mut url = base.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| GraphFetchError::MalformedUrl)?;
            segments.pop_if_empty();
            segments.push("users");
            segments.push(&credential.user_id);
            segments.push("contacts");
        }
        url.set_query(Some(
            "$top=100&$select=id,displayName,givenName,surname,middleName,emailAddresses,\
             businessPhones,homePhones,mobilePhone,homeAddress,businessAddress,otherAddress,\
             companyName,jobTitle,birthday,personalNotes",
        ));

        let mut all_contacts = Vec::new();
        // Los `nextLink` ya pedidos, para cortar un servidor que repite el mismo
        // enlace en bucle. Incluye la URL inicial.
        let mut seen: HashSet<String> = HashSet::new();
        seen.insert(url.as_str().to_string());

        for _page in 0..MAX_PAGES {
            // Plazo por pedido: conexión más respuesta. El token sólo se adjunta
            // acá, y `url` ya fue validada como del mismo origen que la base.
            let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
            let request = client
                .get(url.as_str())
                .bearer_auth(credential.access_token.as_str())
                .header("Accept", "application/json");

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
                    .json::<GraphContactsResponse>()
                    .await
                    .map_err(|_| GraphFetchError::Parse)
            };

            let data = match tokio::time::timeout_at(deadline, fetch_page).await {
                Ok(result) => result?,
                Err(_) => return Err(GraphFetchError::Timeout),
            };

            all_contacts.extend(data.value);
            if all_contacts.len() > MAX_CONTACTS {
                return Err(GraphFetchError::TooManyContacts);
            }

            let Some(next) = data.next_link else {
                return Ok(all_contacts);
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

    /// Convierte un `GraphContact` a `ContactRow`.
    ///
    /// Un contacto sin `id` se descarta: el `id` es el `href` y el `UID`, y sin
    /// él no hay forma estable de hacer upsert.
    fn contact_to_row(contact: GraphContact) -> Option<ContactRow> {
        if contact.id.is_empty() {
            return None;
        }
        // El `id` es dato de red: se escapa igual que cualquier otro campo antes
        // de usarlo como `href`. Así un `id` con `\r\n` no puede fabricar nada
        // allí donde el `href` se vuelque a un formato por líneas.
        let href = vcard::escape_vcard_public(&contact.id);
        let vcard = Self::contact_to_vcard(&contact);
        let parsed = vcard::contact_from(&vcard, &href).unwrap_or_default();
        Some(ContactRow {
            href,
            etag: None,
            raw_vcard: vcard,
            contact: parsed,
        })
    }

    /// Convierte un `GraphContact` a vCard 3.0.
    ///
    /// Cada campo ausente se omite; nunca hace fallar la conversión.
    fn contact_to_vcard(contact: &GraphContact) -> String {
        let mut vcard = String::new();
        vcard.push_str("BEGIN:VCARD\r\n");
        vcard.push_str("VERSION:3.0\r\n");
        // El `id` también se escapa: era el único campo que iba crudo, y un `id`
        // con `\r\n` fabricaría propiedades o registros nuevos (inyección vCard).
        vcard.push_str(&format!(
            "UID:{}\r\n",
            vcard::escape_vcard_public(&contact.id)
        ));

        let display_name = contact.display_name.as_deref().unwrap_or("");
        if !display_name.is_empty() {
            vcard.push_str(&format!(
                "FN:{}\r\n",
                vcard::escape_vcard_public(display_name)
            ));
        }

        // N: apellido;nombre;segundo nombre;prefijo;sufijo
        let surname = contact.surname.as_deref().unwrap_or("");
        let given = contact.given_name.as_deref().unwrap_or("");
        let middle = contact.middle_name.as_deref().unwrap_or("");
        if !surname.is_empty() || !given.is_empty() || !middle.is_empty() {
            vcard.push_str(&format!(
                "N:{};{};{};;\r\n",
                vcard::escape_vcard_public(surname),
                vcard::escape_vcard_public(given),
                vcard::escape_vcard_public(middle)
            ));
        }

        // Emails
        for email in &contact.email_addresses {
            if let Some(address) = email.address.as_deref() {
                if !address.is_empty() {
                    vcard.push_str(&format!(
                        "EMAIL:{}\r\n",
                        vcard::escape_vcard_public(address)
                    ));
                }
            }
        }

        // Teléfonos: cada lista con su tipo de vCard.
        for phone in &contact.business_phones {
            if !phone.is_empty() {
                vcard.push_str(&format!(
                    "TEL;TYPE=WORK:{}\r\n",
                    vcard::escape_vcard_public(phone)
                ));
            }
        }
        for phone in &contact.home_phones {
            if !phone.is_empty() {
                vcard.push_str(&format!(
                    "TEL;TYPE=HOME:{}\r\n",
                    vcard::escape_vcard_public(phone)
                ));
            }
        }
        if let Some(mobile) = contact.mobile_phone.as_deref() {
            if !mobile.is_empty() {
                vcard.push_str(&format!(
                    "TEL;TYPE=CELL:{}\r\n",
                    vcard::escape_vcard_public(mobile)
                ));
            }
        }

        // Direcciones postales
        Self::push_address(&mut vcard, "HOME", contact.home_address.as_ref());
        Self::push_address(&mut vcard, "WORK", contact.business_address.as_ref());
        Self::push_address(&mut vcard, "OTHER", contact.other_address.as_ref());

        // Organización y puesto
        if let Some(company) = contact.company_name.as_deref() {
            if !company.is_empty() {
                vcard.push_str(&format!("ORG:{}\r\n", vcard::escape_vcard_public(company)));
            }
        }
        if let Some(title) = contact.job_title.as_deref() {
            if !title.is_empty() {
                vcard.push_str(&format!("TITLE:{}\r\n", vcard::escape_vcard_public(title)));
            }
        }

        // Cumpleaños: Graph lo da como fecha-hora ISO; alcanza con la fecha.
        if let Some(birthday) = contact.birthday.as_deref() {
            let date = birthday.split('T').next().unwrap_or(birthday);
            if !date.is_empty() {
                vcard.push_str(&format!("BDAY:{}\r\n", vcard::escape_vcard_public(date)));
            }
        }

        // Notas
        if let Some(notes) = contact.personal_notes.as_deref() {
            if !notes.is_empty() {
                vcard.push_str(&format!("NOTE:{}\r\n", vcard::escape_vcard_public(notes)));
            }
        }

        vcard.push_str("END:VCARD\r\n");
        vcard
    }

    /// Agrega un `ADR` con su tipo si la dirección tiene algún componente.
    ///
    /// Componentes de `ADR`: apartado;extendido;calle;ciudad;provincia;código
    /// postal;país. Graph no trae apartado ni extendido, así que van vacíos.
    fn push_address(vcard: &mut String, kind: &str, address: Option<&GraphPhysicalAddress>) {
        let Some(address) = address else {
            return;
        };
        if address.is_empty() {
            return;
        }
        let street = vcard::escape_vcard_public(address.street.as_deref().unwrap_or(""));
        let city = vcard::escape_vcard_public(address.city.as_deref().unwrap_or(""));
        let state = vcard::escape_vcard_public(address.state.as_deref().unwrap_or(""));
        let postal = vcard::escape_vcard_public(address.postal_code.as_deref().unwrap_or(""));
        let country =
            vcard::escape_vcard_public(address.country_or_region.as_deref().unwrap_or(""));
        vcard.push_str(&format!(
            "ADR;TYPE={kind}:;;{street};{city};{state};{postal};{country}\r\n"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pruebas mínimas del parseo de la carpeta de contactos de Graph. Las
    /// definitivas —endpoint falso y bordes de campos— las escribe qa.

    #[test]
    fn un_contacto_completo_se_convierte_a_vcard() {
        let json = r#"{
            "id": "AAA-123",
            "displayName": "Ada Lovelace",
            "givenName": "Ada",
            "surname": "Lovelace",
            "middleName": "Byron",
            "emailAddresses": [{ "name": "Ada", "address": "ada@example.com" }],
            "businessPhones": ["+54 11 5555-0000"],
            "homePhones": ["+54 11 4444-0000"],
            "mobilePhone": "+54 9 11 3333-0000",
            "homeAddress": {
                "street": "Calle Falsa 123",
                "city": "Buenos Aires",
                "state": "CABA",
                "postalCode": "1000",
                "countryOrRegion": "Argentina"
            },
            "companyName": "Analytical Engines",
            "jobTitle": "Matemática",
            "birthday": "1815-12-10T00:00:00Z",
            "personalNotes": "La primera programadora"
        }"#;
        let contact: GraphContact = serde_json::from_str(json).expect("JSON de contacto válido");
        let vcard = GraphApiBackend::contact_to_vcard(&contact);

        assert!(vcard.contains("UID:AAA-123\r\n"));
        assert!(vcard.contains("FN:Ada Lovelace\r\n"));
        assert!(vcard.contains("N:Lovelace;Ada;Byron;;\r\n"));
        assert!(vcard.contains("EMAIL:ada@example.com\r\n"));
        assert!(vcard.contains("TEL;TYPE=WORK:+54 11 5555-0000\r\n"));
        assert!(vcard.contains("TEL;TYPE=HOME:+54 11 4444-0000\r\n"));
        assert!(vcard.contains("TEL;TYPE=CELL:+54 9 11 3333-0000\r\n"));
        assert!(
            vcard.contains("ADR;TYPE=HOME:;;Calle Falsa 123;Buenos Aires;CABA;1000;Argentina\r\n")
        );
        assert!(vcard.contains("ORG:Analytical Engines\r\n"));
        assert!(vcard.contains("TITLE:Matemática\r\n"));
        assert!(vcard.contains("BDAY:1815-12-10\r\n"));
        assert!(vcard.contains("NOTE:La primera programadora\r\n"));
    }

    #[test]
    fn un_contacto_sin_campos_no_rompe_y_omite_lo_ausente() {
        let contact: GraphContact =
            serde_json::from_str(r#"{ "id": "solo-id" }"#).expect("JSON con sólo id");
        let vcard = GraphApiBackend::contact_to_vcard(&contact);

        assert!(vcard.starts_with("BEGIN:VCARD\r\n"));
        assert!(vcard.ends_with("END:VCARD\r\n"));
        assert!(vcard.contains("UID:solo-id\r\n"));
        // Nada de lo que no vino se emite. Se comparan líneas enteras para no
        // confundir, por ejemplo, el `N:` de la propiedad con el de `VERSION:`.
        assert!(!vcard.contains("\r\nFN:"));
        assert!(!vcard.contains("\r\nN:"));
        assert!(!vcard.contains("\r\nEMAIL:"));
        assert!(!vcard.contains("\r\nTEL"));
        assert!(!vcard.contains("\r\nADR"));
    }

    #[test]
    fn un_contacto_sin_id_se_descarta() {
        let contact: GraphContact =
            serde_json::from_str(r#"{ "displayName": "Sin Id" }"#).expect("JSON sin id");
        assert!(GraphApiBackend::contact_to_row(contact).is_none());
    }

    #[test]
    fn la_respuesta_se_deserializa_con_next_link() {
        let json = r#"{
            "value": [{ "id": "a" }, { "id": "b" }],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/me/contacts?$skip=100"
        }"#;
        let response: GraphContactsResponse = serde_json::from_str(json).expect("respuesta válida");
        assert_eq!(response.value.len(), 2);
        assert_eq!(
            response.next_link.as_deref(),
            Some("https://graph.microsoft.com/v1.0/me/contacts?$skip=100")
        );
    }

    // --- Pruebas definitivas: endpoint falso, paginación y hallazgos de
    // seguridad. Escritas por qa. ---

    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::store::key::fake::FakeKeys;
    use crate::store::lifecycle::{
        AccountListing, Consent, ListedAccount, Locations, StoreManager,
    };
    use crate::store::paths::tests::TempDir;

    const ACCOUNT: &str = "cuenta";
    /// El token que la credencial lleva al endpoint falso. Lo único que prueba
    /// «no se le mandó el token a otro host» es que ese host no lo haya recibido.
    const TOKEN: &str = "token-secreto-de-prueba";

    /// Un pedido HTTP tal como llegó al endpoint falso de Graph.
    #[derive(Clone)]
    struct GraphRequest {
        path: String,
        authorization: String,
    }

    /// Lo que el endpoint falso sabe contestar.
    struct FakeGraphState {
        /// Respuestas `(estado, cuerpo JSON)` a servir en orden de llegada.
        responses: VecDeque<(u16, String)>,
        /// Cada pedido que llegó, con su cabecera `Authorization`: para poder
        /// decir «este host no recibió el token».
        requests: Vec<GraphRequest>,
        /// Si la cola se vacía: con `Some(origin)` se generan páginas únicas sin
        /// fin (para el tope de páginas); con `None` se contesta 500.
        auto_next: Option<String>,
        /// Contador de páginas autogeneradas, para que cada `nextLink` sea único
        /// y no dispare el deduplicado.
        auto_count: usize,
    }

    /// Un servidor HTTP/JSON de mentira en `127.0.0.1`, al estilo de `dav::fake`:
    /// habla HTTP/1.1 de verdad contra `reqwest`, sirve una cola de respuestas
    /// JSON y anota cada pedido —incluida la cabecera `Authorization`— para que
    /// una prueba pueda decir «a este host no se le mandó el token».
    #[derive(Clone)]
    struct FakeGraph {
        state: Arc<Mutex<FakeGraphState>>,
        port: u16,
    }

    impl FakeGraph {
        async fn start() -> Self {
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

        fn origin(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }

        /// La raíz que la credencial le pasa al sincronizador; en producción es
        /// [`GRAPH_BASE_URL`]. El host y el puerto de esta URL son el único
        /// origen al que el sincronizador adjunta el token.
        fn base_url(&self) -> String {
            format!("{}/v1.0", self.origin())
        }

        /// Encola una respuesta JSON con estado 200.
        fn push(&self, body: impl Into<String>) {
            self.state
                .lock()
                .unwrap()
                .responses
                .push_back((200, body.into()));
        }

        /// Encola una respuesta con un estado arbitrario.
        fn push_status(&self, status: u16, body: impl Into<String>) {
            self.state
                .lock()
                .unwrap()
                .responses
                .push_back((status, body.into()));
        }

        /// A partir de que se vacíe la cola, generar páginas únicas sin fin: para
        /// llegar al tope de páginas sin que se dispare el deduplicado.
        fn auto_paginate(&self) {
            let origin = self.origin();
            self.state.lock().unwrap().auto_next = Some(origin);
        }

        fn requests(&self) -> Vec<GraphRequest> {
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
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string();
            let mut authorization = String::new();
            let mut length = 0usize;
            for line in lines {
                if let Some((name, value)) = line.split_once(':') {
                    let name = name.trim().to_ascii_lowercase();
                    let value = value.trim();
                    if name == "authorization" {
                        authorization = value.to_string();
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
            buffer.drain(..body_start + length);

            let (status, body) = {
                let mut state = state.lock().unwrap();
                state.requests.push(GraphRequest {
                    path: path.clone(),
                    authorization: authorization.clone(),
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

            let out = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
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

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .unwrap()
    }

    fn credential_for(server: &FakeGraph) -> GraphCredential {
        GraphCredential {
            access_token: zeroize::Zeroizing::new(TOKEN.to_string()),
            user_id: "me".to_string(),
            base_url: server.base_url(),
        }
    }

    /// Un contacto completo, con las tres direcciones, para comprobar la
    /// conversión de todos los campos de punta a punta.
    fn contacto_completo_json() -> &'static str {
        r#"{
            "id": "AAA-123",
            "displayName": "Ada Lovelace",
            "givenName": "Ada",
            "surname": "Lovelace",
            "middleName": "Byron",
            "emailAddresses": [{ "address": "ada@example.com" }],
            "businessPhones": ["+54 11 5555-0000"],
            "homePhones": ["+54 11 4444-0000"],
            "mobilePhone": "+54 9 11 3333-0000",
            "homeAddress": {
                "street": "Calle Falsa 123", "city": "Buenos Aires",
                "state": "CABA", "postalCode": "1000", "countryOrRegion": "Argentina"
            },
            "businessAddress": {
                "street": "Av Trabajo 1", "city": "Cordoba",
                "state": "CBA", "postalCode": "5000", "countryOrRegion": "Argentina"
            },
            "otherAddress": {
                "street": "Quinta 9", "city": "Rosario",
                "state": "SF", "postalCode": "2000", "countryOrRegion": "Argentina"
            },
            "companyName": "Analytical Engines",
            "jobTitle": "Matematica",
            "birthday": "1815-12-10T00:00:00Z",
            "personalNotes": "La primera programadora"
        }"#
    }

    /// El almacén local y el gestor, con la cuenta lista y el área de contactos
    /// activada, para correr `GraphApiBackend::sync` de punta a punta.
    struct Fixture {
        _temp: TempDir,
        manager: Arc<StoreManager<FakeKeys>>,
        server: FakeGraph,
    }

    impl Fixture {
        async fn new(label: &str) -> Self {
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
            let server = FakeGraph::start().await;
            Self {
                _temp: temp,
                manager,
                server,
            }
        }

        async fn sync(&self) -> SyncResult {
            let ctx = SyncContext {
                manager: &self.manager,
                account_id: ACCOUNT,
                notify: Arc::new(|| {}),
            };
            GraphApiBackend
                .sync(ctx, &credential_for(&self.server))
                .await
        }

        async fn synced(&self) -> SyncReport {
            match self.sync().await {
                SyncResult::Synced(report) => report,
                other => panic!("la vuelta no terminó bien: {other:?}"),
            }
        }

        /// Las vCard crudas guardadas, ordenadas por `href`.
        async fn stored_vcards(&self) -> Vec<String> {
            self.manager
                .with_store(ACCOUNT, |store| {
                    let c = store.connection();
                    Ok(c.prepare("SELECT raw_vcard FROM contacts ORDER BY href")
                        .unwrap()
                        .query_map([], |row| row.get::<_, String>(0))
                        .unwrap()
                        .collect::<Result<Vec<_>, _>>()
                        .unwrap())
                })
                .await
                .expect("la base tenía que estar abierta")
        }

        /// Los nombres de las libretas guardadas.
        async fn book_names(&self) -> Vec<String> {
            self.manager
                .with_store(ACCOUNT, |store| {
                    let c = store.connection();
                    Ok(
                        c.prepare("SELECT display_name FROM address_books ORDER BY display_name")
                            .unwrap()
                            .query_map([], |row| row.get::<_, String>(0))
                            .unwrap()
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap(),
                    )
                })
                .await
                .expect("la base tenía que estar abierta")
        }
    }

    /// (1) Paginación: dos páginas con `nextLink` al **mismo host** se siguen,
    /// todos los contactos se upsertan en «Graph Contacts» y el contacto completo
    /// se convierte a vCard con todos sus campos.
    #[tokio::test]
    async fn la_paginacion_del_mismo_host_trae_y_convierte_todos_los_contactos() {
        let f = Fixture::new("graph_paginacion").await;
        let origin = f.server.origin();
        f.server.push(format!(
            "{{\"value\":[{completo},{{\"id\":\"BBB\",\"displayName\":\"Bob\"}}],\
             \"@odata.nextLink\":\"{origin}/v1.0/me/contacts?$skip=100\"}}",
            completo = contacto_completo_json()
        ));
        f.server
            .push(r#"{"value":[{"id":"CCC","displayName":"Carol"}]}"#);

        let report = f.synced().await;
        assert_eq!(report.fetched, 3, "tres contactos entre las dos páginas");

        // Se pidieron las dos páginas, y cada pedido llevó el token (la base_url
        // es el único origen al que se adjunta).
        let requests = f.server.requests();
        assert_eq!(requests.len(), 2, "se siguió el nextLink del mismo host");
        for r in &requests {
            assert_eq!(r.authorization, format!("Bearer {TOKEN}"));
        }
        // La primera URL se arma sobre la base, con `user_id` como segmento de
        // ruta: `/v1.0/users/me/contacts`.
        assert!(
            requests[0].path.starts_with("/v1.0/users/me/contacts"),
            "la URL inicial sale de la base_url: {}",
            requests[0].path
        );

        assert_eq!(f.book_names().await, vec!["Graph Contacts".to_string()]);

        let vcards = f.stored_vcards().await;
        assert_eq!(vcards.len(), 3);
        let completo = vcards
            .iter()
            .find(|v| v.contains("UID:AAA-123\r\n"))
            .expect("el contacto completo se guardó");
        assert!(completo.contains("FN:Ada Lovelace\r\n"));
        assert!(completo.contains("N:Lovelace;Ada;Byron;;\r\n"));
        assert!(completo.contains("EMAIL:ada@example.com\r\n"));
        assert!(completo.contains("TEL;TYPE=WORK:+54 11 5555-0000\r\n"));
        assert!(completo.contains("TEL;TYPE=HOME:+54 11 4444-0000\r\n"));
        assert!(completo.contains("TEL;TYPE=CELL:+54 9 11 3333-0000\r\n"));
        assert!(completo
            .contains("ADR;TYPE=HOME:;;Calle Falsa 123;Buenos Aires;CABA;1000;Argentina\r\n"));
        assert!(completo.contains("ADR;TYPE=WORK:;;Av Trabajo 1;Cordoba;CBA;5000;Argentina\r\n"));
        assert!(completo.contains("ADR;TYPE=OTHER:;;Quinta 9;Rosario;SF;2000;Argentina\r\n"));
        assert!(completo.contains("ORG:Analytical Engines\r\n"));
        assert!(completo.contains("TITLE:Matematica\r\n"));
        assert!(completo.contains("BDAY:1815-12-10\r\n"));
        assert!(completo.contains("NOTE:La primera programadora\r\n"));
    }

    /// (2 · H1) Un `nextLink` a **otro host** aborta la sincronización con
    /// `UntrustedNextLink` y **no** le manda el token a ese host: no hay una
    /// segunda petición al atacante. Un `nextLink` al mismo host sí se sigue.
    ///
    /// Es la prueba clave del arreglo ALTA. Rojo-sin-arreglo: si se quita la
    /// validación `same_origin` en `fetch_all_contacts`, el sincronizador sigue
    /// el enlace, el atacante recibe el token y esta prueba falla.
    #[tokio::test]
    async fn un_next_link_a_otro_host_aborta_sin_mandar_el_token() {
        let victima = FakeGraph::start().await;
        let atacante = FakeGraph::start().await;
        // La víctima contesta una página con un nextLink al host del atacante.
        victima.push(format!(
            "{{\"value\":[{{\"id\":\"AAA\",\"displayName\":\"Ada\"}}],\
             \"@odata.nextLink\":\"{}/v1.0/me/contacts?$skip=100\"}}",
            atacante.origin()
        ));

        let result =
            GraphApiBackend::fetch_all_contacts(&client(), &credential_for(&victima)).await;
        assert!(
            matches!(result, Err(GraphFetchError::UntrustedNextLink)),
            "un nextLink a otro host tiene que abortar con UntrustedNextLink, dio {result:?}"
        );

        // La víctima recibió exactamente un pedido, con el token.
        let de_la_victima = victima.requests();
        assert_eq!(de_la_victima.len(), 1);
        assert_eq!(de_la_victima[0].authorization, format!("Bearer {TOKEN}"));
        // Y el atacante no recibió NADA: ni el pedido ni, por lo tanto, el token.
        assert!(
            atacante.requests().is_empty(),
            "el token no debe viajar al host del nextLink no confiable"
        );
    }

    /// (2 · H1) El contrapunto: un `nextLink` al **mismo host** sí se sigue.
    #[tokio::test]
    async fn un_next_link_al_mismo_host_se_sigue() {
        let server = FakeGraph::start().await;
        let origin = server.origin();
        server.push(format!(
            "{{\"value\":[{{\"id\":\"AAA\"}}],\
             \"@odata.nextLink\":\"{origin}/v1.0/me/contacts?$skip=100\"}}"
        ));
        server.push(r#"{"value":[{"id":"BBB"}]}"#);

        let result = GraphApiBackend::fetch_all_contacts(&client(), &credential_for(&server)).await;
        let contacts = result.expect("el nextLink del mismo host se sigue");
        assert_eq!(contacts.len(), 2);
        assert_eq!(server.requests().len(), 2);
    }

    /// (3 · H2) Un `id` con `\r\n` no puede fabricar propiedades ni partir el
    /// registro: el `\r\n` del `UID` queda escapado, no se vuelve un salto de
    /// línea real.
    ///
    /// Rojo-sin-arreglo: si el `UID:` vuelve a emitir el `id` crudo
    /// (`format!("UID:{}\r\n", contact.id)`), el `\r\n` del id abre una línea
    /// `TEL;TYPE=WORK` y un segundo `UID` reales, y esta prueba falla.
    #[test]
    fn un_id_con_salto_de_linea_no_inyecta_propiedades_en_la_vcard() {
        // El `id` trae CR y LF de verdad (el JSON los produce de los escapes).
        let contact: GraphContact =
            serde_json::from_str(r#"{ "id": "AAA\r\nTEL;TYPE=WORK:+1-900-EVIL\r\nUID:AAA" }"#)
                .expect("JSON con id malicioso");
        let vcard = GraphApiBackend::contact_to_vcard(&contact);

        // Ninguna línea real fabricada: ni un TEL, ni un segundo UID.
        let lineas: Vec<&str> = vcard.split("\r\n").collect();
        assert_eq!(
            lineas.iter().filter(|l| l.starts_with("UID:")).count(),
            1,
            "el id partido no debe fabricar un segundo UID: {vcard:?}"
        );
        assert_eq!(
            lineas.iter().filter(|l| l.starts_with("TEL")).count(),
            0,
            "el id partido no debe fabricar un TEL: {vcard:?}"
        );
        assert!(
            !vcard.contains("\r\nTEL;TYPE=WORK:+1-900-EVIL"),
            "el TEL inyectado no debe quedar como línea propia: {vcard:?}"
        );
        // El salto queda escapado como `\n` dentro del valor del UID.
        assert!(vcard.contains("UID:AAA\\nTEL"));
    }

    /// (4 · H3) Un campo estructurado que termina en `\` no corre ni funde los
    /// componentes de `N:` ni de `ADR:`: la barra se escapa como `\\`, así que el
    /// `;` siguiente sigue siendo separador.
    ///
    /// Rojo-sin-arreglo: si `surname`/`street` se emiten sin pasar por
    /// `escape_vcard_public` (la barra sin duplicar), el `\;` resultante escapa
    /// el separador, el apellido se come el nombre y el componente se corre.
    #[test]
    fn una_barra_final_no_funde_los_componentes_estructurados() {
        let contact: GraphContact = serde_json::from_str(
            r#"{
                "id": "BS",
                "surname": "Evil\\",
                "givenName": "Good",
                "homeAddress": { "street": "Calle\\", "city": "City" }
            }"#,
        )
        .expect("JSON con barra final");
        let vcard = GraphApiBackend::contact_to_vcard(&contact);

        // La barra final va duplicada, y el `;` siguiente parte el campo.
        assert!(
            vcard.contains("N:Evil\\\\;Good;;;\r\n"),
            "N: con la barra final sin fundir el nombre: {vcard:?}"
        );
        assert!(
            vcard.contains("ADR;TYPE=HOME:;;Calle\\\\;City;;;\r\n"),
            "ADR: con la barra final sin correr los componentes: {vcard:?}"
        );

        // Y el parser propio revierte el `N` a sus componentes, cada uno con su
        // barra final intacta: el apellido no se comió el nombre.
        let n_value = vcard
            .lines()
            .find_map(|l| l.strip_prefix("N:"))
            .expect("hay una línea N:");
        let fields = crate::vcard::split_fields(n_value);
        assert_eq!(fields[0], "Evil\\", "el apellido conserva su barra final");
        assert_eq!(fields[1], "Good", "el nombre quedó separado del apellido");
    }

    /// (5 · H4) Un `nextLink` que se repite corta la paginación con
    /// `PaginationLoop` sin colgarse.
    #[tokio::test]
    async fn un_next_link_repetido_corta_el_bucle() {
        let server = FakeGraph::start().await;
        let origin = server.origin();
        let bucle = format!("{origin}/v1.0/me/contacts?$skip=100");
        server.push(format!("{{\"value\":[],\"@odata.nextLink\":\"{bucle}\"}}"));
        server.push(format!("{{\"value\":[],\"@odata.nextLink\":\"{bucle}\"}}"));

        let result = GraphApiBackend::fetch_all_contacts(&client(), &credential_for(&server)).await;
        assert!(
            matches!(result, Err(GraphFetchError::PaginationLoop)),
            "un nextLink repetido corta con PaginationLoop, dio {result:?}"
        );
    }

    /// (5 · H4) Superar el tope de páginas da `TooManyPages` sin agotar memoria:
    /// el servidor genera páginas únicas sin fin.
    #[tokio::test]
    async fn superar_el_tope_de_paginas_aborta() {
        let server = FakeGraph::start().await;
        server.auto_paginate();

        let result = GraphApiBackend::fetch_all_contacts(&client(), &credential_for(&server)).await;
        assert!(
            matches!(result, Err(GraphFetchError::TooManyPages)),
            "pasado el tope de páginas se aborta con TooManyPages, dio {result:?}"
        );
        assert_eq!(
            server.requests().len(),
            MAX_PAGES,
            "se pidieron exactamente MAX_PAGES páginas antes de cortar"
        );
    }

    /// (6) Bordes: un HTTP de error devuelve un error tipado **sin** el cuerpo
    /// crudo de Graph.
    #[tokio::test]
    async fn un_http_de_error_no_vuelca_el_cuerpo_crudo() {
        let server = FakeGraph::start().await;
        server.push_status(500, "cuerpo-secreto-crudo-de-graph");

        let result = GraphApiBackend::fetch_all_contacts(&client(), &credential_for(&server)).await;
        let err = result.expect_err("un 500 tiene que ser Err");
        assert!(
            matches!(err, GraphFetchError::Http(s) if s == reqwest::StatusCode::INTERNAL_SERVER_ERROR)
        );
        assert!(
            !err.to_string().contains("cuerpo-secreto-crudo-de-graph"),
            "el cuerpo crudo del error no se muestra: {err}"
        );
    }

    /// (6) Bordes: un JSON inválido da `Parse`, no un pánico.
    #[tokio::test]
    async fn un_json_invalido_da_error_de_parseo() {
        let server = FakeGraph::start().await;
        server.push("esto no es json {{{");

        let result = GraphApiBackend::fetch_all_contacts(&client(), &credential_for(&server)).await;
        assert!(matches!(result, Err(GraphFetchError::Parse)));
    }

    /// (6) Bordes, de punta a punta: un contacto sin `id` se descarta; uno con
    /// sólo `id` y `displayName` se guarda.
    #[tokio::test]
    async fn un_contacto_sin_id_se_descarta_en_la_sincronizacion() {
        let f = Fixture::new("graph_sin_id").await;
        f.server.push(
            r#"{"value":[{"id":"","displayName":"Fantasma"},{"id":"keep","displayName":"Solo Nombre"}]}"#,
        );

        let report = f.synced().await;
        assert_eq!(report.fetched, 1, "el contacto sin id no se guarda");

        let vcards = f.stored_vcards().await;
        assert_eq!(vcards.len(), 1);
        assert!(vcards[0].contains("UID:keep\r\n"));
        assert!(vcards[0].contains("FN:Solo Nombre\r\n"));
    }
}
