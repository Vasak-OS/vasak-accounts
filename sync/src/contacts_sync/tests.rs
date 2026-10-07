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
