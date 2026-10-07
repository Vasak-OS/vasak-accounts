//! Backend LDAP/AD para sincronización de contactos (solo lectura).
//!
//! Conecta a un servidor LDAP/AD y busca entradas con objectClass=person
//! u organizationalPerson. No soporta escritura: es solo para consulta.

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
use crate::store::{LogLevel, Store, StoreError};
use crate::vcard;

/// Cada cuánto se sincronizan los contactos de una cuenta encendida.
const CONTACTS_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Lo que se ve en el estado cuando el servicio de cuentas dice que no.
const DENIED_DETAIL: &str = "el servicio de cuentas no le da al sincronizador permiso para los \
     contactos de esta cuenta";

/// Lo que se ve cuando la base no está abierta.
const CLOSED_DETAIL: &str =
    "la base no está abierta: se sincroniza cuando se desbloquee el llavero";

/// Credencial para LDAP.
#[derive(Debug, Clone)]
pub struct LdapCredential {
    /// URL del servidor LDAP (ldap:// o ldaps://).
    pub url: String,
    /// DN de enlace.
    pub bind_dn: String,
    /// Contraseña.
    pub password: String,
    /// Base DN para búsquedas.
    pub search_base: String,
    /// Filtro de búsqueda (default: (objectClass=person)).
    pub search_filter: String,
    /// Atributos a recuperar.
    pub attributes: Vec<String>,
}

/// Fuente de credenciales para LDAP.
pub struct LdapCredentialSource;

impl LdapCredentialSource {
    pub async fn credential(
        &self,
        account_id: &str,
        capability: &'static str,
    ) -> Result<LdapCredential, CredentialError> {
        let classify = |e: BrokerError| match e {
            BrokerError::Denied(_) => CredentialError::Denied,
            other => CredentialError::Failed(other.to_string()),
        };
        let broker = crate::broker::Broker::connect().await.map_err(classify)?;
        let data = broker
            .account_data(account_id, capability)
            .await
            .map_err(classify)?;
        let config = data.get("config").unwrap_or(&data);

        let url = config
            .get("ldap_url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CredentialError::Failed("falta ldap_url".into()))?
            .to_string();
        let bind_dn = config
            .get("ldap_bind_dn")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CredentialError::Failed("falta ldap_bind_dn".into()))?
            .to_string();
        let password = config
            .get("ldap_password")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CredentialError::Failed("falta ldap_password".into()))?
            .to_string();
        let search_base = config
            .get("ldap_search_base")
            .and_then(|v| v.as_str())
            .unwrap_or("dc=example,dc=com")
            .to_string();
        let search_filter = config
            .get("ldap_search_filter")
            .and_then(|v| v.as_str())
            .unwrap_or("(objectClass=person)")
            .to_string();
        let attributes: Vec<String> = config
            .get("ldap_attributes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_else(|| {
                vec![
                    "cn".into(),
                    "sn".into(),
                    "givenName".into(),
                    "mail".into(),
                    "telephoneNumber".into(),
                    "mobile".into(),
                    "title".into(),
                    "department".into(),
                    "company".into(),
                    "streetAddress".into(),
                    "l".into(),
                    "st".into(),
                    "postalCode".into(),
                    "co".into(),
                ]
            });

        Ok(LdapCredential {
            url,
            bind_dn,
            password,
            search_base,
            search_filter,
            attributes,
        })
    }
}

/// Backend LDAP/AD.
pub struct LdapBackend;

impl LdapBackend {
    /// Sincroniza los contactos usando LDAP.
    pub async fn sync<K: KeySource>(
        &self,
        ctx: SyncContext<'_, K>,
        credential: &LdapCredential,
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

        // Conectar al servidor LDAP
        let ldap = match Self::connect_ldap(credential).await {
            Ok(l) => l,
            Err(e) => {
                set_status(AreaState::Failed, &e.to_string()).await;
                return SyncResult::Failed(e.to_string());
            }
        };

        // Buscar entradas
        let mut ldap = ldap;
        let entries = match Self::search_ldap(&mut ldap, credential).await {
            Ok(e) => e,
            Err(e) => {
                set_status(AreaState::Failed, &e.to_string()).await;
                return SyncResult::Failed(e.to_string());
            }
        };

        // Convertir a filas de contactos
        let mut rows = Vec::new();
        for entry in entries {
            if let Some(row) = Self::entry_to_row(entry) {
                rows.push(row);
            }
        }

        // Crear una libreta por defecto para LDAP
        let default_book = "ldap://default";
        let stored_books = manager
            .with_store(account_id, move |s| {
                s.upsert_address_books(&[(default_book.to_string(), "LDAP Contacts".to_string())])
            })
            .await;

        let stored_book = match stored_books {
            Ok(mut books) => books.pop(),
            Err(e) => {
                set_status(AreaState::Failed, "no se pudo crear la libreta LDAP").await;
                return SyncResult::Failed(e.to_string());
            }
        };

        let stored_book = match stored_book {
            Some(b) => b,
            None => {
                set_status(AreaState::Failed, "no se creó la libreta LDAP").await;
                return SyncResult::Failed("no se creó la libreta LDAP".into());
            }
        };

        // Guardar contactos en la libreta
        let fetched_count = rows.len();
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
                let mut report = SyncReport::default();
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

    /// Conecta al servidor LDAP.
    async fn connect_ldap(credential: &LdapCredential) -> Result<ldap3::Ldap, String> {
        let (conn, mut ldap) = ldap3::LdapConnAsync::new(&credential.url)
            .await
            .map_err(|e| format!("no se pudo conectar a LDAP: {e}"))?;

        ldap3::drive!(conn);

        ldap.simple_bind(&credential.bind_dn, &credential.password)
            .await
            .map_err(|e| format!("error en bind LDAP: {e}"))?;

        Ok(ldap)
    }

    /// Busca entradas en LDAP.
    async fn search_ldap(
        ldap: &mut ldap3::Ldap,
        credential: &LdapCredential,
    ) -> Result<Vec<ldap3::SearchEntry>, String> {
        let rs = ldap
            .search(
                &credential.search_base,
                ldap3::Scope::Subtree,
                &credential.search_filter,
                &credential.attributes,
            )
            .await
            .map_err(|e| format!("error en búsqueda LDAP: {e}"))?;

        Ok(rs
            .0
            .into_iter()
            .map(ldap3::SearchEntry::construct)
            .collect())
    }

    /// Convierte una entrada LDAP a ContactRow.
    fn entry_to_row(entry: ldap3::SearchEntry) -> Option<ContactRow> {
        let attrs = entry.attrs;
        let dn = entry.dn;

        let mut vcard = String::new();
        vcard.push_str("BEGIN:VCARD\r\n");
        vcard.push_str("VERSION:3.0\r\n");
        vcard.push_str(&format!("UID:{}\r\n", Self::escape_vcard(&dn)));

        // CN o displayName
        let cn = attrs
            .get("cn")
            .and_then(|v| v.first())
            .or_else(|| attrs.get("displayName").and_then(|v| v.first()))
            .cloned();
        if let Some(cn) = cn {
            vcard.push_str(&format!("FN:{}\r\n", Self::escape_vcard(&cn)));
        }

        // Nombre estructurado
        let given = attrs
            .get("givenName")
            .and_then(|v| v.first())
            .map(|s| s.as_str());
        let sn = attrs.get("sn").and_then(|v| v.first()).map(|s| s.as_str());
        if given.is_some() || sn.is_some() {
            vcard.push_str(&format!(
                "N:{};{};;;\r\n",
                sn.map(Self::escape_vcard).unwrap_or_default(),
                given.map(Self::escape_vcard).unwrap_or_default()
            ));
        }

        // Emails
        if let Some(mails) = attrs.get("mail") {
            for mail in mails {
                vcard.push_str(&format!("EMAIL:{}\r\n", Self::escape_vcard(mail)));
            }
        }

        // Teléfonos
        if let Some(phones) = attrs.get("telephoneNumber") {
            for phone in phones {
                vcard.push_str(&format!("TEL;TYPE=WORK:{}\r\n", Self::escape_vcard(phone)));
            }
        }
        if let Some(mobiles) = attrs.get("mobile") {
            for mobile in mobiles {
                vcard.push_str(&format!("TEL;TYPE=CELL:{}\r\n", Self::escape_vcard(mobile)));
            }
        }

        // Título
        if let Some(title) = attrs.get("title").and_then(|v| v.first()) {
            vcard.push_str(&format!("TITLE:{}\r\n", Self::escape_vcard(title)));
        }

        // Departamento
        if let Some(dept) = attrs.get("department").and_then(|v| v.first()) {
            vcard.push_str(&format!(
                "ORG;TYPE=DEPARTMENT:{}\r\n",
                Self::escape_vcard(dept)
            ));
        }

        // Empresa
        if let Some(company) = attrs.get("company").and_then(|v| v.first()) {
            vcard.push_str(&format!("ORG:{}\r\n", Self::escape_vcard(company)));
        }

        // Dirección
        if let Some(street) = attrs.get("streetAddress").and_then(|v| v.first()) {
            vcard.push_str(&format!(
                "ADR;TYPE=WORK:;;{}\r\n",
                Self::escape_vcard(street)
            ));
        }
        if let Some(locality) = attrs.get("l").and_then(|v| v.first()) {
            vcard.push_str(&format!(
                "ADR;TYPE=WORK:;;;{}\r\n",
                Self::escape_vcard(locality)
            ));
        }
        if let Some(state) = attrs.get("st").and_then(|v| v.first()) {
            vcard.push_str(&format!(
                "ADR;TYPE=WORK:;;;;{}\r\n",
                Self::escape_vcard(state)
            ));
        }
        if let Some(postal) = attrs.get("postalCode").and_then(|v| v.first()) {
            vcard.push_str(&format!(
                "ADR;TYPE=WORK:;;;;;{}\r\n",
                Self::escape_vcard(postal)
            ));
        }
        if let Some(country) = attrs.get("co").and_then(|v| v.first()) {
            vcard.push_str(&format!(
                "ADR;TYPE=WORK:;;;;;;{}\r\n",
                Self::escape_vcard(country)
            ));
        }

        vcard.push_str("END:VCARD\r\n");

        let href = format!("ldap://{}", dn);
        let contact = vcard::contact_from(&vcard, &href).unwrap_or_default();
        Some(ContactRow {
            href,
            etag: None,
            raw_vcard: vcard,
            contact,
        })
    }

    fn escape_vcard(s: &str) -> String {
        s.replace(',', "\\,")
            .replace(';', "\\;")
            .replace('\n', "\\n")
            .replace('\r', "")
    }
}

pub fn escape_vcard_public(s: &str) -> String {
    s.replace(',', "\\,")
        .replace(';', "\\;")
        .replace('\n', "\\n")
        .replace('\r', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_vcard_escapa_caracteres_especiales() {
        assert_eq!(escape_vcard_public("a,b"), "a\\,b");
        assert_eq!(escape_vcard_public("a;b"), "a\\;b");
        assert_eq!(escape_vcard_public("a\nb"), "a\\nb");
        assert_eq!(escape_vcard_public("a\rb"), "ab");
    }
}
