//! Backend de sincronización de calendario: una capa que desacopla el
//! sincronizador del protocolo concreto, espejo de la de contactos
//! ([`crate::contacts_sync::backend`]).
//!
//! El sincronizador elige el backend basándose en el `ProviderKind` de la
//! cuenta (`CalendarSync::calendar_backend_kind_for_account`). Por ahora el
//! único protocolo es CalDAV; Microsoft Graph (u otro no-CalDAV) se agrega en
//! un hito posterior sumando una variante y su rama de despacho, sin tocar el
//! camino existente.

/// El tipo de backend de calendario.
///
/// Por ahora sólo CalDAV. Las APIs propietarias (Graph) entran después (ver la
/// decisión 2 de `vasak-accounts#24`): cuando se agregue una variante, el
/// despacho de `CalendarSync::sync_account` suma su rama.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarBackendKind {
    CalDav,
}
