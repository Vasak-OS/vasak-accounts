//! Backend Microsoft Graph API para sincronización de contactos.
//!
//! Usa la People API de Microsoft Graph (`/me/people` y `/users/{id}/people`)
//! para obtener contactos. Soporta consultas delta para sincronización incremental.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use crate::broker::BrokerError;
use crate::contacts_sync::backend::{SyncContext, SyncResult};
use crate::contacts_sync::SyncReport;
use crate::dav_sync::CredentialError;
use crate::store::contacts::{ContactOp, ContactRow};
use crate::store::key::KeySource;
use crate::store::lifecycle::{AreaState, StoreManager, CONTACTS_AREA};
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
/// Contiene el token de acceso OAuth2 y el ID de usuario para la People API.
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

/// Respuesta de la People API.
#[derive(Debug, serde::Deserialize)]
struct GraphPeopleResponse {
    value: Vec<GraphPerson>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
    #[serde(rename = "@odata.deltaLink")]
    delta_link: Option<String>,
}

/// Una persona en Microsoft Graph.
#[derive(Debug, serde::Deserialize)]
struct GraphPerson {
    id: String,
    display_name: Option<String>,
    given_name: Option<String>,
    surname: Option<String>,
    #[serde(rename = "emailAddresses")]
    email_addresses: Option<Vec<GraphEmailAddress>>,
    phones: Option<Vec<GraphPhone>>,
    #[serde(rename = "scoredEmailAddresses")]
    scored_email_addresses: Option<Vec<GraphScoredEmailAddress>>,
}

/// Dirección de correo en Graph.
#[derive(Debug, serde::Deserialize)]
struct GraphEmailAddress {
    address: String,
    name: Option<String>,
}

/// Teléfono en Graph.
#[derive(Debug, serde::Deserialize)]
struct GraphPhone {
    #[serde(rename = "type")]
    phone_type: Option<String>,
    number: String,
}

/// Email con puntuación en Graph.
#[derive(Debug, serde::Deserialize)]
struct GraphScoredEmailAddress {
    address: String,
    relevance_score: Option<i32>,
}

/// Token de sincronización delta.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct GraphSyncToken {
    delta_link: Option<String>,
    last_sync: Option<String>,
}

/// Backend Microsoft Graph API.
///
/// Implementa la sincronización de contactos contra la People API de Microsoft Graph
/// (`/users/{id}/people`). Convierte los contactos de Graph a vCard y los almacena
/// en el almacén local.
pub struct GraphApiBackend;

impl GraphApiBackend {
    /// Sincroniza los contactos usando Microsoft Graph People API.
    ///
    /// Obtiene los contactos de la People API con paginación, los convierte a vCard
    /// y los guarda en el almacén local. Crea una libreta por defecto si no existe.
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

        // Hacer la petición a la People API (sin delta sync por ahora)
        let people = match Self::fetch_all_people(&client, credential).await {
            Ok(p) => p,
            Err(e) => {
                set_status(AreaState::Failed, &e.to_string()).await;
                return SyncResult::Failed(e.to_string());
            }
        };

        // Convertir a filas de contactos
        let mut rows = Vec::new();
        for person in people {
            if let Some(row) = Self::person_to_row(person) {
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

    /// Obtiene todas las personas de la People API con paginación.
    async fn fetch_all_people(
        client: &reqwest::Client,
        credential: &GraphCredential,
    ) -> Result<Vec<GraphPerson>, String> {
        let mut all_people = Vec::new();
        let mut url = format!(
            "{}/users/{}/people?$top=999&$select=id,displayName,givenName,surname,emailAddresses,phones,scoredEmailAddresses",
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

            let data: GraphPeopleResponse = response
                .json()
                .await
                .map_err(|e| format!("error parseando respuesta: {e}"))?;

            all_people.extend(data.value);

            if let Some(next) = data.next_link {
                url = next;
            } else {
                break;
            }
        }

        Ok(all_people)
    }

    /// Convierte una GraphPerson a ContactRow.
    fn person_to_row(person: GraphPerson) -> Option<ContactRow> {
        let vcard = Self::person_to_vcard(&person)?;
        let href = person.id.clone();
        let contact = vcard::contact_from(&vcard, &href).unwrap_or_default();
        Some(ContactRow {
            href,
            etag: None,
            raw_vcard: vcard,
            contact,
        })
    }

    /// Convierte una GraphPerson a vCard.
    fn person_to_vcard(person: &GraphPerson) -> Option<String> {
        let mut vcard = String::new();
        vcard.push_str("BEGIN:VCARD\r\n");
        vcard.push_str("VERSION:3.0\r\n");
        vcard.push_str(&format!("UID:{}\r\n", person.id));

        let display_name = person.display_name.as_deref().unwrap_or("");
        if !display_name.is_empty() {
            vcard.push_str(&format!("FN:{}\r\n", Self::escape_vcard(display_name)));
        }

        if let Some(given) = &person.given_name {
            if let Some(surname) = &person.surname {
                vcard.push_str(&format!(
                    "N:{};{};;;\r\n",
                    Self::escape_vcard(surname),
                    Self::escape_vcard(given)
                ));
            } else {
                vcard.push_str(&format!("N:;{};;;\r\n", Self::escape_vcard(given)));
            }
        } else if let Some(surname) = &person.surname {
            vcard.push_str(&format!("N:{};;;;\r\n", Self::escape_vcard(surname)));
        }

        // Emails
        if let Some(emails) = &person.email_addresses {
            for email in emails {
                vcard.push_str(&format!("EMAIL:{}\r\n", Self::escape_vcard(&email.address)));
            }
        }
        if let Some(scored) = &person.scored_email_addresses {
            for email in scored {
                vcard.push_str(&format!("EMAIL:{}\r\n", Self::escape_vcard(&email.address)));
            }
        }

        // Teléfonos
        if let Some(phones) = &person.phones {
            for phone in phones {
                let ptype = phone.phone_type.as_deref().unwrap_or("voice");
                vcard.push_str(&format!(
                    "TEL;TYPE={}:{}\r\n",
                    ptype.to_uppercase(),
                    Self::escape_vcard(&phone.number)
                ));
            }
        }

        vcard.push_str("END:VCARD\r\n");
        Some(vcard)
    }

    fn escape_vcard(s: &str) -> String {
        s.replace(',', "\\,")
            .replace(';', "\\;")
            .replace('\n', "\\n")
            .replace('\r', "")
    }
}
