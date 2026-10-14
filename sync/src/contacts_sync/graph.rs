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

use std::time::Duration;

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
#[derive(Debug, Clone)]
pub struct GraphCredential {
    /// Token de acceso OAuth2.
    pub access_token: String,
    /// URL base del usuario (para multi-tenant).
    pub user_id: String,
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
            access_token: (*token).clone(),
            user_id,
        })
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

        let client = reqwest::Client::new();
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
    async fn fetch_all_contacts(
        client: &reqwest::Client,
        credential: &GraphCredential,
    ) -> Result<Vec<GraphContact>, String> {
        let mut all_contacts = Vec::new();
        let mut url = format!(
            "{}/users/{}/contacts?$top=100&$select=id,displayName,givenName,surname,middleName,emailAddresses,businessPhones,homePhones,mobilePhone,homeAddress,businessAddress,otherAddress,companyName,jobTitle,birthday,personalNotes",
            GRAPH_BASE_URL, credential.user_id
        );

        loop {
            let request = client
                .get(&url)
                .bearer_auth(&credential.access_token)
                .header("Accept", "application/json");

            let response = request
                .send()
                .await
                .map_err(|e| format!("error de red: {e}"))?;

            if !response.status().is_success() {
                let status = response.status();
                let text = response.text().await.unwrap_or_default();
                return Err(format!("Graph API error {status}: {text}"));
            }

            let data: GraphContactsResponse = response
                .json()
                .await
                .map_err(|e| format!("error parseando respuesta: {e}"))?;

            all_contacts.extend(data.value);

            match data.next_link {
                Some(next) => url = next,
                None => break,
            }
        }

        Ok(all_contacts)
    }

    /// Convierte un `GraphContact` a `ContactRow`.
    ///
    /// Un contacto sin `id` se descarta: el `id` es el `href` y el `UID`, y sin
    /// él no hay forma estable de hacer upsert.
    fn contact_to_row(contact: GraphContact) -> Option<ContactRow> {
        if contact.id.is_empty() {
            return None;
        }
        let href = contact.id.clone();
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
        vcard.push_str(&format!("UID:{}\r\n", contact.id));

        let display_name = contact.display_name.as_deref().unwrap_or("");
        if !display_name.is_empty() {
            vcard.push_str(&format!("FN:{}\r\n", Self::escape_vcard(display_name)));
        }

        // N: apellido;nombre;segundo nombre;prefijo;sufijo
        let surname = contact.surname.as_deref().unwrap_or("");
        let given = contact.given_name.as_deref().unwrap_or("");
        let middle = contact.middle_name.as_deref().unwrap_or("");
        if !surname.is_empty() || !given.is_empty() || !middle.is_empty() {
            vcard.push_str(&format!(
                "N:{};{};{};;\r\n",
                Self::escape_vcard(surname),
                Self::escape_vcard(given),
                Self::escape_vcard(middle)
            ));
        }

        // Emails
        for email in &contact.email_addresses {
            if let Some(address) = email.address.as_deref() {
                if !address.is_empty() {
                    vcard.push_str(&format!("EMAIL:{}\r\n", Self::escape_vcard(address)));
                }
            }
        }

        // Teléfonos: cada lista con su tipo de vCard.
        for phone in &contact.business_phones {
            if !phone.is_empty() {
                vcard.push_str(&format!("TEL;TYPE=WORK:{}\r\n", Self::escape_vcard(phone)));
            }
        }
        for phone in &contact.home_phones {
            if !phone.is_empty() {
                vcard.push_str(&format!("TEL;TYPE=HOME:{}\r\n", Self::escape_vcard(phone)));
            }
        }
        if let Some(mobile) = contact.mobile_phone.as_deref() {
            if !mobile.is_empty() {
                vcard.push_str(&format!("TEL;TYPE=CELL:{}\r\n", Self::escape_vcard(mobile)));
            }
        }

        // Direcciones postales
        Self::push_address(&mut vcard, "HOME", contact.home_address.as_ref());
        Self::push_address(&mut vcard, "WORK", contact.business_address.as_ref());
        Self::push_address(&mut vcard, "OTHER", contact.other_address.as_ref());

        // Organización y puesto
        if let Some(company) = contact.company_name.as_deref() {
            if !company.is_empty() {
                vcard.push_str(&format!("ORG:{}\r\n", Self::escape_vcard(company)));
            }
        }
        if let Some(title) = contact.job_title.as_deref() {
            if !title.is_empty() {
                vcard.push_str(&format!("TITLE:{}\r\n", Self::escape_vcard(title)));
            }
        }

        // Cumpleaños: Graph lo da como fecha-hora ISO; alcanza con la fecha.
        if let Some(birthday) = contact.birthday.as_deref() {
            let date = birthday.split('T').next().unwrap_or(birthday);
            if !date.is_empty() {
                vcard.push_str(&format!("BDAY:{}\r\n", Self::escape_vcard(date)));
            }
        }

        // Notas
        if let Some(notes) = contact.personal_notes.as_deref() {
            if !notes.is_empty() {
                vcard.push_str(&format!("NOTE:{}\r\n", Self::escape_vcard(notes)));
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
        let street = Self::escape_vcard(address.street.as_deref().unwrap_or(""));
        let city = Self::escape_vcard(address.city.as_deref().unwrap_or(""));
        let state = Self::escape_vcard(address.state.as_deref().unwrap_or(""));
        let postal = Self::escape_vcard(address.postal_code.as_deref().unwrap_or(""));
        let country = Self::escape_vcard(address.country_or_region.as_deref().unwrap_or(""));
        vcard.push_str(&format!(
            "ADR;TYPE={kind}:;;{street};{city};{state};{postal};{country}\r\n"
        ));
    }

    fn escape_vcard(s: &str) -> String {
        s.replace(',', "\\,")
            .replace(';', "\\;")
            .replace('\n', "\\n")
            .replace('\r', "")
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
}
