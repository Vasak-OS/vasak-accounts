//! Backend LDAP/AD para sincronización de contactos (solo lectura).
//!
//! Conecta a un servidor LDAP/AD y busca entradas con objectClass=person
//! u organizationalPerson. No soporta escritura: es solo para consulta.

use zeroize::Zeroizing;

use crate::broker::BrokerError;
use crate::contacts_sync::backend::{SyncContext, SyncResult};
use crate::contacts_sync::SyncReport;
use crate::dav_sync::CredentialError;
use crate::store::contacts::{ContactOp, ContactRow};
use crate::store::key::KeySource;
use crate::store::lifecycle::{AreaState, CONTACTS_AREA};
use crate::vcard;

/// Lo que se ve cuando la base no está abierta.
const CLOSED_DETAIL: &str =
    "la base no está abierta: se sincroniza cuando se desbloquee el llavero";

/// Los atributos que se piden si la cuenta no nombra ninguno.
fn default_attributes() -> Vec<String> {
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
}

/// Credencial para LDAP.
///
/// **Sin `Debug` derivado**: `password` es la contraseña del bind, y un `Debug`
/// derivado la escribiría entera en cualquier registro o mensaje de pánico que
/// la lleve adentro. Y en `Zeroizing`: al soltarla, la copia de este lado se
/// borra. Mismo criterio que `DavCredential` (ver `dav/webdav.rs`).
#[derive(Clone)]
pub struct LdapCredential {
    /// URL del servidor LDAP (`ldaps://`, `ldap://` o `ldapi://`).
    pub url: String,
    /// DN de enlace.
    pub bind_dn: String,
    /// Contraseña. Sale del llavero, no del config. Ver [`LdapCredentialSource`].
    pub password: Zeroizing<String>,
    /// Base DN para búsquedas.
    pub search_base: String,
    /// Filtro de búsqueda (default: `(objectClass=person)`).
    pub search_filter: String,
    /// Atributos a recuperar.
    pub attributes: Vec<String>,
    /// Permitir `ldap://` en claro, sin StartTLS. Por omisión `false`: el bind
    /// viaja cifrado o no viaja. Ver [`LdapBackend::connect_ldap`].
    pub allow_insecure: bool,
}

impl std::fmt::Debug for LdapCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapCredential")
            .field("url", &self.url)
            .field("bind_dn", &self.bind_dn)
            .field("password", &"<tachado>")
            .field("search_base", &self.search_base)
            .field("search_filter", &self.search_filter)
            .field("attributes", &self.attributes)
            .field("allow_insecure", &self.allow_insecure)
            .finish()
    }
}

/// Fuente de credenciales para LDAP.
///
/// La **configuración** (URL, bind DN, base, filtro, atributos) sale de
/// `GetAccountData`; la **contraseña** sale del llavero por `GetAccessToken`,
/// nunca del config —el mismo patrón que `BrokerCredentials` para DAV (ver
/// `dav_sync.rs`)—. Así la contraseña queda cifrada en `vasak-keyring` y no en
/// `accounts.json`, donde la vería cualquiera que llame a `GetAccountData`.
pub struct LdapCredentialSource;

impl LdapCredentialSource {
    /// Obtiene la credencial LDAP para una cuenta.
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

        // El secreto primero, porque es lo que dispara el permiso: si el
        // servicio dice que no, no tiene sentido pedir el resto. Una contraseña
        // no vence, así que el servicio la entrega tal cual (ver el motor de
        // tokens del daemon). Guardada bajo la clave `access`, como en DAV.
        let password = Zeroizing::new(
            broker
                .access_token(account_id, capability)
                .await
                .map_err(classify)?,
        );
        if password.is_empty() {
            // Un bind con contraseña vacía es un «unauthenticated bind»: varios
            // servidores lo tratan como anónimo y contestan que sí. No es un
            // enlace autenticado, así que no se intenta.
            return Err(CredentialError::Failed(
                "la contraseña guardada está vacía: la cuenta no está autenticada".into(),
            ));
        }

        let data = broker
            .account_data(account_id, capability)
            .await
            .map_err(classify)?;
        // La configuración viene envuelta: el servicio devuelve la cuenta entera
        // con la capacidad adentro.
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
        let search_base = config
            .get("ldap_search_base")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CredentialError::Failed("falta ldap_search_base".into()))?
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
            .unwrap_or_else(default_attributes);
        let allow_insecure = config
            .get("ldap_allow_insecure")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(LdapCredential {
            url,
            bind_dn,
            password,
            search_base,
            search_filter,
            attributes,
            allow_insecure,
        })
    }
}

/// Backend LDAP/AD (solo lectura).
///
/// Implementa la sincronización de contactos contra un servidor LDAP/Active Directory
/// mediante búsquedas LDAP simples. Convierte las entradas LDAP a vCard y las almacena
/// en el almacén local. No soporta escritura.
pub struct LdapBackend;

impl LdapBackend {
    /// Sincroniza los contactos usando LDAP.
    ///
    /// Conecta al servidor LDAP, busca entradas con objectClass=person, las convierte
    /// a vCard y las guarda en el almacén local. Crea una libreta por defecto si no existe.
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
                let report = SyncReport {
                    fetched: fetched_count,
                    ..Default::default()
                };
                set_status(AreaState::Synced, "").await;
                SyncResult::Synced(report)
            }
            Err(e) => {
                set_status(AreaState::Failed, "no se pudieron guardar los contactos").await;
                SyncResult::Failed(e.to_string())
            }
        }
    }

    /// Conecta al servidor LDAP y hace el bind, **cifrando el canal**.
    ///
    /// El bind simple manda la contraseña al servidor, así que el canal tiene que
    /// ir cifrado o la contraseña viaja en claro:
    ///
    /// - `ldaps://`: TLS implícito, con validación de certificado contra el
    ///   almacén de confianza del sistema (lo trae `ldap3` con `rustls`).
    /// - `ldap://`: por omisión se sube a TLS con **StartTLS** antes del bind,
    ///   con la misma validación. Sólo si la cuenta pone `ldap_allow_insecure`
    ///   se manda el bind en claro, y se avisa.
    /// - `ldapi://`: socket Unix local, sin red: no hace falta cifrar.
    ///
    /// La validación de certificado **nunca** se apaga: no se toca
    /// `set_no_tls_verify`, así que un certificado que no valida corta la
    /// conexión antes de mandar nada.
    async fn connect_ldap(credential: &LdapCredential) -> Result<ldap3::Ldap, String> {
        let parsed = url::Url::parse(&credential.url)
            .map_err(|e| format!("ldap_url no es una dirección: {e}"))?;

        let mut settings = ldap3::LdapConnSettings::new();
        match parsed.scheme() {
            // TLS implícito: `ldap3` lo aplica solo y valida el certificado.
            "ldaps" => {}
            // Socket Unix local: no sale a la red, no hay nada que cifrar.
            "ldapi" => {}
            "ldap" => {
                if credential.allow_insecure {
                    tracing::warn!(
                        "'{}': conexión LDAP en claro por ldap_allow_insecure; el bind \
                         viaja sin cifrar",
                        credential.bind_dn
                    );
                } else {
                    // Sube a TLS antes del bind. Si el servidor no sabe StartTLS,
                    // el handshake falla y no se manda la contraseña en claro.
                    settings = settings.set_starttls(true);
                }
            }
            other => return Err(format!("esquema LDAP no soportado: {other}")),
        }

        let (conn, mut ldap) = ldap3::LdapConnAsync::with_settings(settings, &credential.url)
            .await
            .map_err(|e| format!("no se pudo conectar a LDAP: {e}"))?;

        ldap3::drive!(conn);

        // `.success()` convierte un código de resultado distinto de cero —una
        // contraseña incorrecta, por ejemplo— en error. Sin él, `simple_bind`
        // devuelve `Ok` con un bind fallido adentro y la búsqueda seguiría como
        // anónima.
        ldap.simple_bind(&credential.bind_dn, &credential.password)
            .await
            .map_err(|e| format!("error en bind LDAP: {e}"))?
            .success()
            .map_err(|e| format!("el servidor LDAP rechazó el bind: {e}"))?;

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

        // Igual que en el bind: un código de resultado distinto de cero —base
        // inexistente, filtro inválido— llega como `Ok` y hay que convertirlo.
        let (entries, _result) = rs
            .success()
            .map_err(|e| format!("el servidor LDAP rechazó la búsqueda: {e}"))?;

        Ok(entries
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
        vcard.push_str(&format!("UID:{}\r\n", vcard::escape_vcard_public(&dn)));

        // CN o displayName
        let cn = attrs
            .get("cn")
            .and_then(|v| v.first())
            .or_else(|| attrs.get("displayName").and_then(|v| v.first()))
            .cloned();
        if let Some(cn) = cn {
            vcard.push_str(&format!("FN:{}\r\n", vcard::escape_vcard_public(&cn)));
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
                sn.map(vcard::escape_vcard_public).unwrap_or_default(),
                given.map(vcard::escape_vcard_public).unwrap_or_default()
            ));
        }

        // Emails
        if let Some(mails) = attrs.get("mail") {
            for mail in mails {
                vcard.push_str(&format!("EMAIL:{}\r\n", vcard::escape_vcard_public(mail)));
            }
        }

        // Teléfonos
        if let Some(phones) = attrs.get("telephoneNumber") {
            for phone in phones {
                vcard.push_str(&format!(
                    "TEL;TYPE=WORK:{}\r\n",
                    vcard::escape_vcard_public(phone)
                ));
            }
        }
        if let Some(mobiles) = attrs.get("mobile") {
            for mobile in mobiles {
                vcard.push_str(&format!(
                    "TEL;TYPE=CELL:{}\r\n",
                    vcard::escape_vcard_public(mobile)
                ));
            }
        }

        // Título
        if let Some(title) = attrs.get("title").and_then(|v| v.first()) {
            vcard.push_str(&format!("TITLE:{}\r\n", vcard::escape_vcard_public(title)));
        }

        // Departamento
        if let Some(dept) = attrs.get("department").and_then(|v| v.first()) {
            vcard.push_str(&format!(
                "ORG;TYPE=DEPARTMENT:{}\r\n",
                vcard::escape_vcard_public(dept)
            ));
        }

        // Empresa
        if let Some(company) = attrs.get("company").and_then(|v| v.first()) {
            vcard.push_str(&format!("ORG:{}\r\n", vcard::escape_vcard_public(company)));
        }

        // Dirección
        if let Some(street) = attrs.get("streetAddress").and_then(|v| v.first()) {
            vcard.push_str(&format!(
                "ADR;TYPE=WORK:;;{}\r\n",
                vcard::escape_vcard_public(street)
            ));
        }
        if let Some(locality) = attrs.get("l").and_then(|v| v.first()) {
            vcard.push_str(&format!(
                "ADR;TYPE=WORK:;;;{}\r\n",
                vcard::escape_vcard_public(locality)
            ));
        }
        if let Some(state) = attrs.get("st").and_then(|v| v.first()) {
            vcard.push_str(&format!(
                "ADR;TYPE=WORK:;;;;{}\r\n",
                vcard::escape_vcard_public(state)
            ));
        }
        if let Some(postal) = attrs.get("postalCode").and_then(|v| v.first()) {
            vcard.push_str(&format!(
                "ADR;TYPE=WORK:;;;;;{}\r\n",
                vcard::escape_vcard_public(postal)
            ));
        }
        if let Some(country) = attrs.get("co").and_then(|v| v.first()) {
            vcard.push_str(&format!(
                "ADR;TYPE=WORK:;;;;;;{}\r\n",
                vcard::escape_vcard_public(country)
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
}
