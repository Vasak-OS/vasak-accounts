//! Backend de sincronización de calendario: una capa que desacopla el
//! sincronizador del protocolo concreto, espejo de la de contactos
//! ([`crate::contacts_sync::backend`]).
//!
//! El sincronizador elige el backend basándose en el `ProviderKind` de la
//! cuenta (`CalendarSync::calendar_backend_kind_for_account`). Hay dos
//! protocolos: CalDAV y Microsoft Graph; un `kind` sin backend propio cae en
//! CalDAV.

use crate::broker::{Account, Provider};

/// El tipo de backend de calendario.
///
/// CalDAV para los proveedores estándar y Microsoft Graph para Microsoft (ver
/// la decisión 2 de `vasak-accounts#24`: las APIs propietarias entran). Cada
/// variante tiene su rama en el despacho de `CalendarSync::sync_account`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarBackendKind {
    CalDav,
    GraphApi,
}

/// Elige el backend para una cuenta a partir del catálogo de proveedores y la
/// lista de cuentas del broker. Es la **parte pura** de la selección, sin el
/// bus: la decisión entera (encontrar la cuenta, su `provider_type`, el
/// proveedor y su `kind`) se prueba con todos los casos. Una cuenta que no
/// está, o un proveedor que no está, caen en CalDAV.
pub fn calendar_backend_for_account(
    providers: &[Provider],
    accounts: &[Account],
    account_id: &str,
) -> CalendarBackendKind {
    let provider_type = accounts
        .iter()
        .find(|a| a.id == account_id)
        .map(|a| a.provider_type.as_str())
        .unwrap_or("");
    calendar_backend_for_provider(providers, provider_type)
}

/// Elige el backend a partir del catálogo de proveedores y el `provider_type`
/// de la cuenta. Un `provider_type` que no está en el catálogo cae en CalDAV,
/// igual que un `kind` sin backend propio.
pub fn calendar_backend_for_provider(
    providers: &[Provider],
    provider_type: &str,
) -> CalendarBackendKind {
    for provider in providers {
        if provider.id == provider_type {
            return calendar_backend_for_kind(&provider.kind);
        }
    }
    CalendarBackendKind::CalDav
}

/// El mapa de `provider.kind` a backend: `"graph"` —Microsoft— va por Graph, y
/// cualquier otro (`"caldav"`, lo desconocido) por CalDAV.
pub fn calendar_backend_for_kind(kind: &str) -> CalendarBackendKind {
    match kind {
        "graph" => CalendarBackendKind::GraphApi,
        "caldav" => CalendarBackendKind::CalDav,
        _ => CalendarBackendKind::CalDav,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(id: &str, kind: &str) -> Provider {
        Provider {
            id: id.into(),
            display_name: id.into(),
            capabilities: vec!["calendar".into()],
            unavailable_capabilities: Vec::new(),
            configured: true,
            kind: kind.into(),
        }
    }

    fn account(id: &str, provider_type: &str) -> Account {
        Account {
            id: id.into(),
            display_name: id.into(),
            provider_type: provider_type.into(),
            capabilities: vec!["calendar".into()],
            needs_reauth: false,
        }
    }

    #[test]
    fn un_kind_caldav_elige_el_backend_caldav() {
        let got = calendar_backend_for_kind("caldav");
        assert_eq!(got, CalendarBackendKind::CalDav);
    }

    #[test]
    fn un_kind_desconocido_cae_en_caldav() {
        // Lo que no tiene backend propio cae en CalDAV (nunca roto: decisión 2).
        for kind in ["ews", "", "lo-que-sea"] {
            let got = calendar_backend_for_kind(kind);
            assert_eq!(got, CalendarBackendKind::CalDav, "kind={kind}");
        }
    }

    #[test]
    fn un_kind_graph_elige_el_backend_graph() {
        let got = calendar_backend_for_kind("graph");
        assert_eq!(got, CalendarBackendKind::GraphApi);
    }

    #[test]
    fn el_proveedor_de_la_cuenta_decide_el_backend() {
        let catalog = [provider("fastmail", "caldav"), provider("otro", "graph")];
        let got = calendar_backend_for_provider(&catalog, "fastmail");
        assert_eq!(got, CalendarBackendKind::CalDav);
    }

    #[test]
    fn un_proveedor_graph_elige_el_backend_graph() {
        let catalog = [provider("microsoft", "graph")];
        let got = calendar_backend_for_provider(&catalog, "microsoft");
        assert_eq!(got, CalendarBackendKind::GraphApi);
    }

    #[test]
    fn un_provider_type_que_no_esta_en_el_catalogo_cae_en_caldav() {
        let catalog = [provider("fastmail", "caldav")];
        let got = calendar_backend_for_provider(&catalog, "desconocido");
        assert_eq!(got, CalendarBackendKind::CalDav);
    }

    #[test]
    fn un_catalogo_vacio_cae_en_caldav() {
        let got = calendar_backend_for_provider(&[], "fastmail");
        assert_eq!(got, CalendarBackendKind::CalDav);
    }

    #[test]
    fn la_cuenta_lleva_a_su_proveedor_y_a_su_backend() {
        let providers = [
            provider("fastmail", "caldav"),
            provider("microsoft", "graph"),
        ];
        let accounts = [account("ana", "fastmail"), account("beto", "microsoft")];
        // Cada cuenta resuelve por su proveedor: fastmail → CalDAV, microsoft →
        // Graph.
        let ana = calendar_backend_for_account(&providers, &accounts, "ana");
        assert_eq!(ana, CalendarBackendKind::CalDav);
        let beto = calendar_backend_for_account(&providers, &accounts, "beto");
        assert_eq!(beto, CalendarBackendKind::GraphApi);
    }

    #[test]
    fn una_cuenta_que_no_esta_cae_en_caldav() {
        let providers = [provider("fastmail", "caldav")];
        let accounts = [account("ana", "fastmail")];
        let got = calendar_backend_for_account(&providers, &accounts, "nadie");
        assert_eq!(got, CalendarBackendKind::CalDav);
    }

    #[test]
    fn sin_cuentas_cae_en_caldav() {
        let providers = [provider("fastmail", "caldav")];
        let got = calendar_backend_for_account(&providers, &[], "ana");
        assert_eq!(got, CalendarBackendKind::CalDav);
    }
}
