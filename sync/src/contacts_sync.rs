//! Mantener al día los contactos de cada cuenta en el almacén local.
//!
//! ── Cuándo ──────────────────────────────────────────────────────────────────
//!
//! El área de contactos de una cuenta **se enciende la primera vez que alguien
//! la pide** —`RequestSync(account_id)` de `AccountsStore`— y desde ahí sigue
//! sola, también después de reiniciar (queda en `stores.json`). Sólo cuentas con
//! la capacidad `contacts` y que no piden reautenticarse.
//!
//! Cada cuenta encendida se sincroniza **cada [`CONTACTS_INTERVAL`]** (una
//! hora), y además cada vez que llega un `RequestSync`. La revisión corre cada
//! [`CONTACTS_TICK`], pero sólo cuenta como intento lo que llegó a pedir algo:
//! con el llavero bloqueado no se pide nada, y apenas se desbloquea la cuenta
//! entra en la próxima revisión. Un `AccessDenied` sí cuenta: se ve
//! `unavailable` y **no se vuelve a preguntar hasta la hora siguiente** o un
//! `RequestSync` (y dos `RequestSync` seguidos de la misma cuenta, con menos de
//! [`crate::dav_sync::REQUEST_COOLDOWN`] entre ellos, son uno).
//!
//! ── Cómo ────────────────────────────────────────────────────────────────────
//!
//! 1. **La base tiene que estar abierta.** Se pasa la tabla del ciclo de vida
//!    releyendo el llavero; si quedó cerrada, no se pide nada a nadie.
//! 2. La credencial, al servicio de cuentas, con la capacidad `contacts`
//!    (`GetAccessToken` y `GetAccountData`), como cualquier aplicación.
//! 3. El backend correspondiente (CardDAV, Graph API, LDAP) trae los contactos
//!    y los convierte a vCard.
//! 4. Todo se escribe **de a [`WRITE_BATCH_ROWS`] contactos por transacción**.
//!
//! Cada escritura vuelve a mirar el llavero: si se bloqueó a mitad de camino,
//! no se escribe nada más y la vuelta se corta.

pub mod backend;
pub mod carddav;
pub mod graph;
pub mod ldap;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use crate::broker::{Account, Broker, Provider};
use crate::contacts_sync::backend::{ContactBackendKind, SyncContext, SyncResult};
use crate::contacts_sync::carddav::CardDavBackend;
use crate::contacts_sync::graph::{GraphApiBackend, GraphCredentialSource};
use crate::contacts_sync::ldap::{LdapBackend, LdapCredentialSource};
use crate::dav::webdav::HttpPolicy;
use crate::dav_sync::{self, AreaSync, CredentialError, CredentialSource};
use crate::store::key::KeySource;
use crate::store::lifecycle::{AreaState, StoreManager, CONTACTS_AREA};

/// Cada cuánto se sincronizan los contactos de una cuenta encendida (supuesto
/// 1 de `vasak-accounts#23`).
pub const CONTACTS_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Cada cuánto se mira qué cuentas toca sincronizar.
pub const CONTACTS_TICK: Duration = crate::POLL_INTERVAL;

/// Lo que se ve en el estado cuando el servicio de cuentas dice que no.
const DENIED_DETAIL: &str = "el servicio de cuentas no le da al sincronizador permiso para los \
     contactos de esta cuenta: hace falta vasak-permissions 0.15.0 o posterior, y que la persona \
     lo permita en Configuración → Privacidad y seguridad";

/// Lo que se ve cuando la base no está abierta.
const CLOSED_DETAIL: &str =
    "la base no está abierta: se sincroniza cuando se desbloquee el llavero";

/// Lo que hizo una vuelta, para el diario y las pruebas.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub books: usize,
    /// Libretas que no se tocaron porque su `getctag` no cambió.
    pub unchanged_books: usize,
    pub fetched: usize,
    pub removed: usize,
    /// Transacciones escritas.
    pub batches: usize,
    /// Tokens vencidos que llevaron a una sincronización completa.
    pub full_resyncs: usize,
    /// Libretas que fueron por ETag porque el servidor no sabe
    /// `sync-collection`.
    pub etag_books: usize,
    /// Tarjetas que no se guardaron por pasar el tope de tamaño.
    pub too_large: usize,
    /// Direcciones de otro origen que se descartaron.
    pub foreign: usize,
    /// Tarjetas que vinieron en un `multiget` sin haberlas pedido, o
    /// repetidas: no se guardan.
    pub unrequested: usize,
    /// Tarjetas pedidas que no volvieron en [`MISSING_ROUNDS`] vueltas
    /// seguidas, y con las que la libreta se dio por al día igual.
    pub missing: usize,
}

/// La sincronización de contactos de todas las cuentas.
pub struct ContactsSync<K: KeySource> {
    manager: Arc<StoreManager<K>>,
    notify: Arc<dyn Fn() + Send + Sync>,
}

impl<K: KeySource> ContactsSync<K> {
    pub fn new(manager: Arc<StoreManager<K>>, notify: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self { manager, notify }
    }

    /// Crea un ContactsSync para pruebas, forzando el tipo de backend.
    #[cfg(test)]
    pub fn new_for_test(
        manager: Arc<StoreManager<K>>,
        notify: Arc<dyn Fn() + Send + Sync>,
        _backend_kind: ContactBackendKind,
    ) -> Self {
        Self { manager, notify }
    }

    async fn set_status(&self, account_id: &str, state: AreaState, detail: &str) {
        if self
            .manager
            .set_area_status(CONTACTS_AREA, account_id, state, detail)
            .await
        {
            (self.notify)();
        }
    }

    /// Obtiene el tipo de backend para una cuenta.
    async fn backend_kind_for_account(&self, account_id: &str) -> ContactBackendKind {
        let broker = match Broker::connect().await {
            Ok(b) => b,
            Err(_) => return ContactBackendKind::CardDav,
        };

        let providers = match broker.list_providers().await {
            Ok(p) => p,
            Err(_) => return ContactBackendKind::CardDav,
        };

        let accounts = match broker.accounts().await {
            Ok(a) => a,
            Err(_) => return ContactBackendKind::CardDav,
        };

        let account = accounts.iter().find(|a| a.id == account_id);
        let provider_type = account.map(|a| a.provider_type.as_str()).unwrap_or("");

        // Buscar el proveedor en el catálogo
        for provider in providers {
            if provider.id == provider_type {
                return match provider.kind.as_str() {
                    "graph" => ContactBackendKind::GraphApi,
                    "ldap" => ContactBackendKind::Ldap,
                    "carddav" => ContactBackendKind::CardDav,
                    _ => ContactBackendKind::CardDav,
                };
            }
        }

        ContactBackendKind::CardDav
    }

    /// Una vuelta de una cuenta, de punta a punta, con su estado.
    pub async fn sync_account(&self, account_id: &str) -> SyncResult {
        // Antes de nada, y releyendo el llavero: con la base cerrada no se le
        // pide nada ni al servicio de cuentas ni al servidor.
        if !self
            .manager
            .prepare_for_sync(CONTACTS_AREA, account_id)
            .await
        {
            self.set_status(account_id, AreaState::Pending, CLOSED_DETAIL)
                .await;
            return SyncResult::StoreClosed;
        }
        self.set_status(account_id, AreaState::Syncing, "").await;

        // Determinar el backend
        let backend_kind = self.backend_kind_for_account(account_id).await;

        // Ejecutar la sincronización según el backend
        match backend_kind {
            ContactBackendKind::CardDav => {
                let credential_source = crate::dav_sync::BrokerCredentials;
                let credential = match credential_source
                    .credential(account_id, CONTACTS_AREA)
                    .await
                {
                    Ok(credential) => credential,
                    Err(CredentialError::Denied) => {
                        tracing::info!("'{account_id}': sin permiso para los contactos");
                        self.set_status(account_id, AreaState::Unavailable, DENIED_DETAIL)
                            .await;
                        return SyncResult::Denied;
                    }
                    Err(CredentialError::Failed(detail)) => {
                        tracing::warn!(
                            "'{account_id}': no se obtuvo la credencial de los contactos: {detail}"
                        );
                        let shown =
                            "no se obtuvo la credencial de la cuenta del servicio de cuentas";
                        self.set_status(account_id, AreaState::Failed, shown).await;
                        return SyncResult::Failed(shown.into());
                    }
                };

                let ctx = SyncContext {
                    manager: &self.manager,
                    account_id,
                    notify: self.notify.clone(),
                };

                CardDavBackend
                    .sync(ctx, &credential, HttpPolicy::default())
                    .await
            }
            ContactBackendKind::GraphApi => {
                let credential_source = GraphCredentialSource;
                let credential = match credential_source
                    .credential(account_id, CONTACTS_AREA)
                    .await
                {
                    Ok(credential) => credential,
                    Err(CredentialError::Denied) => {
                        tracing::info!("'{account_id}': sin permiso para los contactos");
                        self.set_status(account_id, AreaState::Unavailable, DENIED_DETAIL)
                            .await;
                        return SyncResult::Denied;
                    }
                    Err(CredentialError::Failed(detail)) => {
                        tracing::warn!(
                            "'{account_id}': no se obtuvo la credencial de los contactos: {detail}"
                        );
                        let shown =
                            "no se obtuvo la credencial de la cuenta del servicio de cuentas";
                        self.set_status(account_id, AreaState::Failed, shown).await;
                        return SyncResult::Failed(shown.into());
                    }
                };

                let ctx = SyncContext {
                    manager: &self.manager,
                    account_id,
                    notify: self.notify.clone(),
                };

                GraphApiBackend.sync(ctx, &credential).await
            }
            ContactBackendKind::Ldap => {
                let credential_source = LdapCredentialSource;
                let credential = match credential_source
                    .credential(account_id, CONTACTS_AREA)
                    .await
                {
                    Ok(credential) => credential,
                    Err(CredentialError::Denied) => {
                        tracing::info!("'{account_id}': sin permiso para los contactos");
                        self.set_status(account_id, AreaState::Unavailable, DENIED_DETAIL)
                            .await;
                        return SyncResult::Denied;
                    }
                    Err(CredentialError::Failed(detail)) => {
                        tracing::warn!(
                            "'{account_id}': no se obtuvo la credencial de los contactos: {detail}"
                        );
                        let shown =
                            "no se obtuvo la credencial de la cuenta del servicio de cuentas";
                        self.set_status(account_id, AreaState::Failed, shown).await;
                        return SyncResult::Failed(shown.into());
                    }
                };

                let ctx = SyncContext {
                    manager: &self.manager,
                    account_id,
                    notify: self.notify.clone(),
                };

                LdapBackend.sync(ctx, &credential).await
            }
        }
    }
}

impl<K: KeySource> AreaSync for ContactsSync<K> {
    fn interval(&self) -> Duration {
        CONTACTS_INTERVAL
    }

    async fn targets(&self) -> Vec<String> {
        self.manager.area_targets(CONTACTS_AREA).await
    }

    async fn attempt(&self, account_id: &str) -> bool {
        self.sync_account(account_id).await != SyncResult::StoreClosed
    }
}

/// Decide cuándo le toca a cada cuenta.
pub type ContactsScheduler<K> = dav_sync::DavScheduler<ContactsSync<K>>;

#[cfg(test)]
mod tests;
