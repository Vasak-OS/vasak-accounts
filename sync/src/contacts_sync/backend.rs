//! Backend de sincronización de contactos: una capa que desacopla el
//! sincronizador del protocolo concreto (CardDAV, Graph API, LDAP).
//!
//! Cada backend sabe cómo autenticarse y cómo traer los contactos. El
//! sincronizador elige el backend basándose en el `ProviderKind` de la cuenta.

use std::sync::Arc;

use crate::contacts_sync::SyncReport;
use crate::store::key::KeySource;
use crate::store::lifecycle::StoreManager;

/// Resultado de una sincronización de contactos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncResult {
    /// La base no estaba abierta.
    StoreClosed,
    /// El servicio de cuentas no da permiso.
    Denied,
    /// Sincronizado con el reporte.
    Synced(SyncReport),
    /// Falló con el mensaje para el estado.
    Failed(String),
}

/// Lo que un backend necesita para sincronizar una cuenta.
pub struct SyncContext<'a, K: KeySource> {
    /// El gestor de bases de datos.
    pub manager: &'a Arc<StoreManager<K>>,
    /// El ID de la cuenta.
    pub account_id: &'a str,
    /// Función para notificar cambios de estado.
    pub notify: Arc<dyn Fn() + Send + Sync>,
}

/// El tipo de backend de contactos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactBackendKind {
    CardDav,
    GraphApi,
    Ldap,
}
