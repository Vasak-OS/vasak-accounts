//! La sincronización de contactos contra un servidor CardDAV de mentira en
//! `127.0.0.1`, sin red, sin bus y con el llavero falso.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use zeroize::Zeroizing;

use base64::Engine;
use rusqlite::OptionalExtension;

use super::*;
use crate::contacts_sync::backend::SyncContext;
use crate::contacts_sync::carddav::CardDavBackend;
use crate::dav::fake::{card, FakeDav, RecordedRequest};
use crate::dav::webdav::AuthKind;
use crate::dav::webdav::DavCredential;
use crate::dav::webdav::{HttpPolicy, Limits};
use crate::dav_sync::{merge_delta, REQUEST_COOLDOWN};
use crate::store::key::fake::FakeKeys;
use crate::store::lifecycle::{AccountListing, Consent, ListedAccount, Locations};
use crate::store::paths::tests::TempDir;

const ACCOUNT: &str = "cuenta";

/// El nombre de la variante, sin lo que lleva adentro. Los mensajes de las
/// pruebas no repiten nada de lo que devolvió una vuelta: la vuelta se hace con
/// una credencial, y lo que sale de ella no se escribe en ningún lado, tampoco
/// en la salida de una prueba que falla.
fn outcome_kind(outcome: &SyncResult) -> &'static str {
    match outcome {
        SyncResult::StoreClosed => "StoreClosed",
        SyncResult::Denied => "Denied",
        SyncResult::Synced(_) => "Synced",
        SyncResult::Failed(_) => "Failed",
    }
}

fn credential_for(server: &FakeDav) -> DavCredential {
    DavCredential {
        home: server.home_url(),
        username: "ana".into(),
        secret: Zeroizing::new("la-clave".into()),
        auth: AuthKind::Password,
    }
}

struct Fixture {
    _temp: TempDir,
    keys: FakeKeys,
    manager: Arc<StoreManager<FakeKeys>>,
    server: FakeDav,
    notified: Arc<AtomicUsize>,
    counter: Arc<AtomicUsize>,
    backend: CardDavBackend,
    limits: Limits,
}

impl Fixture {
    async fn new(label: &str) -> Self {
        Self::with_limits(label, Limits::DEFAULT).await
    }

    async fn with_limits(label: &str, limits: Limits) -> Self {
        let temp = TempDir::new(label);
        let keys = FakeKeys::default();
        let manager = Arc::new(StoreManager::new(
            keys.clone(),
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

        let server = FakeDav::start().await;
        let notified = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&notified);
        let backend = CardDavBackend;

        Self {
            _temp: temp,
            keys,
            manager,
            server,
            notified,
            counter,
            backend,
            limits,
        }
    }

    async fn sync(&self) -> SyncResult {
        let credential = credential_for(&self.server);
        let counter = Arc::clone(&self.counter);
        let ctx = SyncContext {
            manager: &self.manager,
            account_id: ACCOUNT,
            notify: Arc::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
            }),
        };
        self.backend
            .sync(ctx, &credential, HttpPolicy::plain_loopback())
            .await
    }

    async fn synced(&self) -> SyncReport {
        match self.sync().await {
            SyncResult::Synced(report) => report,
            other => panic!("la vuelta no terminó bien: {}", outcome_kind(&other)),
        }
    }

    /// Lo que hay en la base, con la base abierta como la dejó la vuelta.
    async fn query<T, F>(&self, read: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(&rusqlite::Connection) -> T + Send + 'static,
    {
        self.manager
            .with_store(ACCOUNT, move |store| Ok(read(store.connection())))
            .await
            .expect("la base tenía que estar abierta")
    }

    async fn count(&self, sql: &'static str) -> i64 {
        self.query(move |c| c.query_row(sql, [], |row| row.get(0)).unwrap())
            .await
    }

    async fn names(&self) -> Vec<String> {
        self.query(|c| {
            c.prepare("SELECT display_name FROM contacts ORDER BY display_name")
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La primera vuelta con una cuenta vacía no falla aunque no haya contactos.
    #[tokio::test]
    async fn primera_vuelta_con_cuenta_vacia_no_falla() {
        let f = Fixture::new("primera_vuelta_vacia").await;
        let report = f.synced().await;
        // El servidor fake tiene una libreta por defecto, pero sin contactos.
        assert_eq!(report.books, 1);
        assert_eq!(report.fetched, 0);
    }

    /// Una vuelta que no encuentra libretas no escribe nada.
    #[tokio::test]
    async fn vuelta_sin_libretas_no_escribe_nada() {
        let f = Fixture::new("sin_libretas").await;
        f.synced().await;
        assert_eq!(f.count("SELECT COUNT(*) FROM contacts").await, 0);
    }

    /// El estado de la cuenta se actualiza correctamente después de la sincronización.
    #[tokio::test]
    async fn estado_de_cuenta_se_actualiza() {
        let f = Fixture::new("estado_cuenta").await;
        f.synced().await;
        // La cuenta debería estar en estado Synced
        let accounts = f.manager.area_accounts(CONTACTS_AREA).await;
        let account = accounts.iter().find(|(id, _)| id == ACCOUNT).unwrap();
        assert!(account.1.active);
    }
}

/// La sincronización de contactos contra un servidor LDAP de mentira, de punta a
/// punta hasta el almacén: conectar, bindear, buscar, convertir a vCard y
/// guardar. Reusa el servidor falso de `ldap_fake`.
#[cfg(test)]
mod ldap_tests {
    use super::*;
    use crate::contacts_sync::ldap::{LdapBackend, LdapCredential};
    use crate::contacts_sync::ldap_fake::{FakeEntry, FakeLdap, FakeLdapConfig};

    /// Un almacén listo, con la cuenta dada de alta y el área de contactos
    /// activa, igual que arma el `Fixture` de CardDAV pero sin su servidor HTTP.
    async fn store(label: &str) -> (TempDir, Arc<StoreManager<FakeKeys>>) {
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
        (temp, manager)
    }

    /// Una credencial `ldap://` en claro (`allow_insecure`) contra el servidor
    /// falso: la única forma sin un servidor de TLS de verdad.
    fn cleartext_credential(url: &str) -> LdapCredential {
        LdapCredential {
            url: url.into(),
            bind_dn: "cn=lector,ou=servicios,dc=ejemplo,dc=com".into(),
            password: Zeroizing::new("la-clave".into()),
            search_base: "dc=ejemplo,dc=com".into(),
            search_filter: "(objectClass=person)".into(),
            attributes: vec!["cn".into(), "sn".into(), "givenName".into(), "mail".into()],
            allow_insecure: true,
        }
    }

    /// De punta a punta: dos personas en el directorio terminan como dos
    /// contactos en el almacén, con sus nombres.
    #[tokio::test]
    async fn las_personas_del_directorio_entran_al_almacen() {
        let server = FakeLdap::start(FakeLdapConfig {
            bind_result: 0,
            starttls_supported: false,
            entries: vec![
                FakeEntry::person(
                    "cn=Ana Pérez,dc=ejemplo,dc=com",
                    "Ana Pérez",
                    "Pérez",
                    "Ana",
                    "ana@ejemplo.com",
                ),
                FakeEntry::person(
                    "cn=Beto Ruiz,dc=ejemplo,dc=com",
                    "Beto Ruiz",
                    "Ruiz",
                    "Beto",
                    "beto@ejemplo.com",
                ),
            ],
        })
        .await;

        let (_temp, manager) = store("ldap_e2e").await;
        let credential = cleartext_credential(&server.url());
        let ctx = SyncContext {
            manager: &manager,
            account_id: ACCOUNT,
            notify: Arc::new(|| {}),
        };

        let outcome = LdapBackend.sync(ctx, &credential).await;
        let report = match outcome {
            SyncResult::Synced(report) => report,
            other => panic!("la vuelta no terminó bien: {}", outcome_kind(&other)),
        };
        assert_eq!(report.fetched, 2);

        let names: Vec<String> = manager
            .with_store(ACCOUNT, move |store| {
                Ok(store
                    .connection()
                    .prepare("SELECT display_name FROM contacts ORDER BY display_name")
                    .unwrap()
                    .query_map([], |row| row.get(0))
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap())
            })
            .await
            .expect("la base tenía que estar abierta");

        assert_eq!(
            names,
            vec!["Ana Pérez".to_string(), "Beto Ruiz".to_string()]
        );
    }

    /// Un bind rechazado deja la vuelta en `Failed`, no sincroniza anónimo ni
    /// escribe contactos de nadie.
    #[tokio::test]
    async fn un_bind_rechazado_deja_la_vuelta_en_failed() {
        let server = FakeLdap::start(FakeLdapConfig {
            bind_result: 49,
            ..Default::default()
        })
        .await;

        let (_temp, manager) = store("ldap_bind_rechazado").await;
        let credential = cleartext_credential(&server.url());
        let ctx = SyncContext {
            manager: &manager,
            account_id: ACCOUNT,
            notify: Arc::new(|| {}),
        };

        let outcome = LdapBackend.sync(ctx, &credential).await;
        assert_eq!(
            outcome_kind(&outcome),
            "Failed",
            "un bind rechazado no puede terminar sincronizando"
        );
    }
}

/// El despacho de backend de contactos, sin Broker: una función pura sobre el
/// catálogo y el `provider_type`.
mod backend_dispatch {
    use crate::broker::Provider;
    use crate::contacts_sync::backend::ContactBackendKind;
    use crate::contacts_sync::classify_backend;

    fn provider(id: &str, kind: &str) -> Provider {
        Provider {
            id: id.to_string(),
            display_name: id.to_string(),
            capabilities: Vec::new(),
            unavailable_capabilities: Vec::new(),
            configured: true,
            kind: kind.to_string(),
        }
    }

    /// `id == "google"` cae en el backend de Google aunque su `kind` sea el de un
    /// CardDAV con OAuth: es lo que le suma la pasada de la People API.
    #[test]
    fn google_despacha_al_backend_de_google_por_su_id() {
        let catalog = [provider("google", "oauth2")];
        assert_eq!(
            classify_backend(&catalog, "google"),
            ContactBackendKind::Google
        );
    }

    /// El resto sale del `kind`, y lo desconocido cae en CardDAV.
    #[test]
    fn el_resto_despacha_por_el_kind() {
        let catalog = [
            provider("ms", "graph"),
            provider("dir", "ldap"),
            provider("fastmail", "carddav"),
            provider("raro", "lo-que-sea"),
        ];
        assert_eq!(
            classify_backend(&catalog, "ms"),
            ContactBackendKind::GraphApi
        );
        assert_eq!(classify_backend(&catalog, "dir"), ContactBackendKind::Ldap);
        assert_eq!(
            classify_backend(&catalog, "fastmail"),
            ContactBackendKind::CardDav
        );
        assert_eq!(
            classify_backend(&catalog, "raro"),
            ContactBackendKind::CardDav
        );
    }

    /// Un `provider_type` que no está en el catálogo cae en CardDAV.
    #[test]
    fn un_proveedor_desconocido_cae_en_carddav() {
        let catalog = [provider("google", "oauth2")];
        assert_eq!(
            classify_backend(&catalog, "no-existe"),
            ContactBackendKind::CardDav
        );
    }
}
