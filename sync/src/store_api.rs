//! `ar.net.vasak.os.AccountsStore` — el estado del almacén local, por D-Bus.
//!
//! Una interfaz aparte y no métodos nuevos en `AccountsSync`: lo que se pueda
//! leer del almacén va a pedir permiso por área, y `AccountsSync` no lo pide a
//! propósito. Mezclarlas obligaría a que cada método explique cuál de los dos
//! regímenes le toca.
//!
//! En este punto sólo hay **estado y control**: `GetStatus`, `SetStoreEnabled`,
//! `ClearStore`, `RequestSync` y la señal `StatusChanged`. Nada de eso lee lo
//! guardado —todavía no hay nada guardado—, así que no pide permiso; el permiso
//! llega con la primera lectura.
//!
//! Vive en el mismo nombre de bus que el resto del servicio
//! (`ar.net.vasak.os.AccountsSync`), en `/ar/net/vasak/os/AccountsStore`.
//! Respuestas en JSON, como `AccountsSync`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use zbus::interface;
use zbus::object_server::SignalContext;

use crate::broker::{self, BrokerError};
use crate::store::key::{self, KeySource, SecretServiceKeys};
use crate::store::lifecycle::{AccountListing, ListedAccount, Locations, StoreManager};
use crate::store::StoreError;

/// Dónde se publica la interfaz.
pub const PATH: &str = "/ar/net/vasak/os/AccountsStore";

/// Cuánto se espera para volver a escuchar al llavero si se cortó.
const RETRY: Duration = Duration::from_secs(15);

/// Cuánto se espera después de un aviso del llavero antes de pasar la tabla.
///
/// Junta en una sola vuelta los avisos que llegan de a varios —uno por
/// colección, o un desbloqueo seguido de otro cambio— y pone un techo a cuántas
/// veces por segundo el sync le vuelve a preguntar al llavero, aunque alguien
/// le mande señales sin parar.
const SETTLE: Duration = Duration::from_secs(1);

/// El objeto de D-Bus.
pub struct StoreApi<K: KeySource> {
    manager: Arc<StoreManager<K>>,
}

#[interface(name = "ar.net.vasak.os.AccountsStore")]
impl<K: KeySource> StoreApi<K> {
    /// El estado del almacén: el llavero, y por cada cuenta en qué está su base
    /// (`locked`, `open`, `rebuilt`, `disabled`, `unavailable`), por qué, y
    /// cuánto ocupa.
    ///
    /// `rebuilt` es una base abierta que se rehízo vacía en esta sesión porque
    /// su clave se había perdido: la ventana tiene que poder decir por qué
    /// desapareció lo que había.
    async fn get_status(&self) -> zbus::fdo::Result<String> {
        let status = self.manager.status().await;
        serde_json::to_string(&status)
            .map_err(|e| zbus::fdo::Error::Failed(format!("no se pudo serializar: {e}")))
    }

    /// Enciende o apaga la base de una cuenta. Apagarla la borra: la clave del
    /// llavero primero, después los archivos.
    ///
    /// Sólo para una cuenta del último `ListAccounts` bueno; con otra —o antes
    /// del primero— contesta `InvalidArgs`, como `RequestSync`.
    async fn set_store_enabled(
        &self,
        #[zbus(signal_context)] emitter: SignalContext<'_>,
        account_id: String,
        enabled: bool,
    ) -> zbus::fdo::Result<()> {
        let result = self.manager.set_enabled(&account_id, enabled).await;
        let _ = Self::status_changed(&emitter).await;
        result.map_err(to_fdo)
    }

    /// Vacía la base de una cuenta: la borra —clave y archivos— y, si está
    /// encendida, la vuelve a crear vacía con una clave nueva.
    ///
    /// **Lo que había se pierde** y se vuelve a traer del servidor. Quien llama
    /// tiene que preguntar antes; acá no hay cómo.
    ///
    /// Sólo para una cuenta del último `ListAccounts` bueno; con otra —o antes
    /// del primero— contesta `InvalidArgs`, como `RequestSync`.
    async fn clear_store(
        &self,
        #[zbus(signal_context)] emitter: SignalContext<'_>,
        account_id: String,
    ) -> zbus::fdo::Result<()> {
        let result = self.manager.clear(&account_id).await;
        let _ = Self::status_changed(&emitter).await;
        result.map_err(to_fdo)
    }

    /// Pide que la base de una cuenta se ponga al día. Lo llama una aplicación
    /// al abrirse.
    ///
    /// Hoy se asegura de que la base esté lista —pasa la tabla del ciclo de
    /// vida por esa cuenta—, que es lo que cualquier sincronización necesita
    /// antes de empezar. Traer datos llega con cada área.
    async fn request_sync(
        &self,
        #[zbus(signal_context)] emitter: SignalContext<'_>,
        account_id: String,
    ) -> zbus::fdo::Result<()> {
        let result = self.manager.request_sync(&account_id).await;
        let _ = Self::status_changed(&emitter).await;
        result.map_err(to_fdo)
    }

    /// Señal `StatusChanged` — cambió el estado de alguna base.
    ///
    /// Sin detalle, como las de `AccountsSync`: quien la recibe vuelve a leer
    /// `GetStatus` y ve el estado completo.
    #[zbus(signal)]
    async fn status_changed(emitter: &SignalContext<'_>) -> zbus::Result<()>;
}

fn to_fdo(error: StoreError) -> zbus::fdo::Error {
    match error {
        StoreError::InvalidAccountId(_) | StoreError::UnknownAccount(_) => {
            zbus::fdo::Error::InvalidArgs(error.to_string())
        }
        other => zbus::fdo::Error::Failed(other.to_string()),
    }
}

/// Convierte lo que contestó `ListAccounts` en lo que entiende el ciclo de
/// vida.
///
/// Un error es `Failed` —**no se borra nada**—, y una respuesta buena lleva
/// **todas** las cuentas, también las que piden reautenticarse: siguen siendo
/// de la persona, y su base se conserva.
pub fn listing_from(result: &Result<Vec<broker::Account>, BrokerError>) -> AccountListing {
    match result {
        Ok(accounts) => AccountListing::Listed(
            accounts
                .iter()
                .map(|a| ListedAccount {
                    id: a.id.clone(),
                    capabilities: a.capabilities.clone(),
                })
                .collect(),
        ),
        Err(_) => AccountListing::Failed,
    }
}

/// El almacén andando: la interfaz publicada y el llavero escuchado.
pub struct StoreService<K: KeySource> {
    manager: Arc<StoreManager<K>>,
    emitter: SignalContext<'static>,
}

impl StoreService<SecretServiceKeys> {
    /// Publica la interfaz en la conexión de sesión y empieza a escuchar al
    /// llavero.
    ///
    /// No falla por el almacén: sin directorio de datos o sin llavero la
    /// interfaz se publica igual y cada cuenta se ve «no disponible». Lo que no
    /// esté se tiene que ver como no disponible, nunca como roto.
    pub async fn start(connection: &zbus::Connection) -> zbus::Result<Self> {
        let keys = SecretServiceKeys::on_session_bus(connection.clone());
        let manager = Arc::new(StoreManager::new(keys, Locations::from_environment()));
        let service = Self::serve(connection, manager).await?;
        service.watch_keyring();
        Ok(service)
    }

    /// Escucha los cambios de `Locked` del llavero y vuelve a pasar la tabla.
    ///
    /// Es lo que abre las bases al iniciar sesión, cuando el llavero se
    /// desbloquea después de que este servicio arrancó. Lo contrario —que se
    /// bloquee— **no es inmediato**: `vasak-keyring` no avisa al bloquear, así
    /// que lo levanta la revisión de cada cinco minutos, y hasta entonces —hasta
    /// 300 segundos— la base sigue abierta con su clave en memoria.
    ///
    /// Sólo cuentan los avisos del dueño de `org.freedesktop.secrets`, y cada
    /// uno espera [`SETTLE`] antes de reaccionar.
    fn watch_keyring(&self) {
        use futures_util::{FutureExt, StreamExt};

        let manager = Arc::clone(&self.manager);
        let emitter = self.emitter.clone();
        tokio::spawn(async move {
            loop {
                match manager.keys().lock_changes().await {
                    Ok(mut changes) => {
                        while let Some(Ok(message)) = changes.next().await {
                            if !key::is_lock_change(&message)
                                || !manager.keys().is_from_keyring(&message).await
                            {
                                continue;
                            }
                            tokio::time::sleep(SETTLE).await;
                            // Lo que llegó mientras tanto queda cubierto por
                            // esta misma vuelta.
                            while let Some(Some(_)) = changes.next().now_or_never() {}
                            if manager.refresh().await {
                                let _ =
                                    StoreApi::<SecretServiceKeys>::status_changed(&emitter).await;
                            }
                        }
                    }
                    Err(e) => tracing::info!("no se puede escuchar al llavero: {e}"),
                }
                tokio::time::sleep(RETRY).await;
            }
        });
    }
}

impl<K: KeySource> StoreService<K> {
    async fn serve(
        connection: &zbus::Connection,
        manager: Arc<StoreManager<K>>,
    ) -> zbus::Result<Self> {
        connection
            .object_server()
            .at(
                PATH,
                StoreApi {
                    manager: Arc::clone(&manager),
                },
            )
            .await?;
        let emitter = SignalContext::new(connection, PATH)?.to_owned();
        Ok(Self { manager, emitter })
    }

    /// Lo que hay que hacer cada vez que se leen las cuentas.
    ///
    /// En una tarea aparte: el llavero puede tardar en contestar, y el bucle
    /// que atiende el correo no tiene por qué esperarlo. El momento se toma
    /// **acá**, al llegar la respuesta, y no cuando la tarea consigue la
    /// cerradura: es lo que mide la confirmación de una cuenta que se fue, y
    /// una espera por el llavero no puede acortar ni estirar la vuelta.
    pub fn accounts_listed(&self, listing: AccountListing) {
        let manager = Arc::clone(&self.manager);
        let emitter = self.emitter.clone();
        let arrived = Instant::now();
        tokio::spawn(async move {
            if manager.accounts_listed(listing, arrived).await {
                let _ = StoreApi::<K>::status_changed(&emitter).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;

    use super::*;
    use crate::store::key::fake::FakeKeys;
    use crate::store::paths::tests::TempDir;

    fn account(id: &str, needs_reauth: bool) -> broker::Account {
        broker::Account {
            id: id.into(),
            display_name: id.into(),
            provider_type: "custom".into(),
            capabilities: vec!["email".into(), "calendar".into()],
            needs_reauth,
        }
    }

    #[test]
    fn un_list_accounts_que_fallo_no_es_una_lista_vacia() {
        let failed: Result<Vec<broker::Account>, BrokerError> =
            Err(BrokerError::Unavailable("no está".into()));
        assert_eq!(listing_from(&failed), AccountListing::Failed);
        assert_eq!(
            listing_from(&Ok(Vec::new())),
            AccountListing::Listed(Vec::new())
        );
    }

    /// Una cuenta que pide reautenticarse entra en la lista igual: sigue
    /// siendo una cuenta, y su base no se borra.
    #[test]
    fn la_lista_lleva_tambien_las_cuentas_que_piden_reautenticarse() {
        let listing = listing_from(&Ok(vec![account("a", false), account("b", true)]));
        let AccountListing::Listed(accounts) = listing else {
            panic!("tenía que ser una lista");
        };
        let ids: Vec<&str> = accounts.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"]);
        assert_eq!(accounts[1].capabilities, vec!["email", "calendar"]);
    }

    /// La interfaz entera por una conexión punto a punto, con el llavero falso.
    #[tokio::test]
    async fn la_interfaz_contesta_en_json_y_avisa_los_cambios() {
        let temp = TempDir::new("api");
        let keys = FakeKeys::default();
        let manager = Arc::new(StoreManager::new(
            keys.clone(),
            Ok(Locations {
                stores: temp.0.join("stores"),
                settings: temp.0.join("stores.json"),
            }),
        ));
        manager
            .accounts_listed(
                listing_from(&Ok(vec![account("cuenta", false)])),
                Instant::now(),
            )
            .await;

        let (server_end, client_end) = tokio::net::UnixStream::pair().unwrap();
        let server = zbus::connection::Builder::unix_stream(server_end)
            .server(zbus::Guid::generate())
            .unwrap()
            .p2p()
            .build();
        let client = zbus::connection::Builder::unix_stream(client_end)
            .p2p()
            .build();
        let (server, client) = tokio::join!(server, client);
        let (server, client) = (server.unwrap(), client.unwrap());
        let _service = StoreService::serve(&server, Arc::clone(&manager))
            .await
            .unwrap();

        let call = |method: &'static str, body: &'static str| {
            let client = client.clone();
            async move {
                let reply = match body {
                    "" => {
                        client
                            .call_method(
                                None::<&str>,
                                PATH,
                                Some("ar.net.vasak.os.AccountsStore"),
                                method,
                                &(),
                            )
                            .await
                    }
                    id => {
                        client
                            .call_method(
                                None::<&str>,
                                PATH,
                                Some("ar.net.vasak.os.AccountsStore"),
                                method,
                                &(id,),
                            )
                            .await
                    }
                };
                reply
            }
        };

        // Sólo los cuatro métodos y la señal: ni uno más.
        let xml: String = client
            .call_method(
                None::<&str>,
                PATH,
                Some("org.freedesktop.DBus.Introspectable"),
                "Introspect",
                &(),
            )
            .await
            .unwrap()
            .body()
            .deserialize()
            .unwrap();
        let start = xml.find("ar.net.vasak.os.AccountsStore").unwrap();
        let iface = &xml[start..start + xml[start..].find("</interface>").unwrap()];
        let mut members: Vec<&str> = iface
            .split("name=\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .filter(|name| name.chars().next().is_some_and(char::is_uppercase))
            .collect();
        members.sort();
        assert_eq!(
            members,
            vec![
                "ClearStore",
                "GetStatus",
                "RequestSync",
                "SetStoreEnabled",
                "StatusChanged"
            ]
        );

        let status: String = call("GetStatus", "")
            .await
            .unwrap()
            .body()
            .deserialize()
            .unwrap();
        let status: serde_json::Value = serde_json::from_str(&status).unwrap();
        assert_eq!(status["keyring"], "unlocked");
        assert_eq!(status["accounts"][0]["account_id"], "cuenta");
        assert_eq!(status["accounts"][0]["state"], "open");

        // Un identificador con barra, o una cuenta que no está: argumento
        // inválido, y nada se toca.
        for bad in ["../cuenta", "desconocida"] {
            let error = call("ClearStore", bad).await.unwrap_err();
            assert!(
                matches!(&error, zbus::Error::MethodError(name, _, _) if name.as_str().ends_with("InvalidArgs")),
                "{error:?}"
            );
        }

        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface("ar.net.vasak.os.AccountsStore")
            .unwrap()
            .member("StatusChanged")
            .unwrap()
            .build();
        let mut signals = zbus::MessageStream::for_match_rule(rule, &client, None)
            .await
            .unwrap();

        call("RequestSync", "cuenta").await.unwrap();
        let reply = client
            .call_method(
                None::<&str>,
                PATH,
                Some("ar.net.vasak.os.AccountsStore"),
                "SetStoreEnabled",
                &("cuenta", false),
            )
            .await;
        reply.unwrap();
        tokio::time::timeout(Duration::from_secs(5), signals.next())
            .await
            .expect("no llegó StatusChanged")
            .unwrap()
            .unwrap();

        let status: String = call("GetStatus", "")
            .await
            .unwrap()
            .body()
            .deserialize()
            .unwrap();
        let status: serde_json::Value = serde_json::from_str(&status).unwrap();
        assert_eq!(status["accounts"][0]["state"], "disabled");
        assert_eq!(status["accounts"][0]["size_bytes"], 0);
        assert!(
            keys.state().keys.is_empty(),
            "apagar tenía que borrar la clave"
        );
    }
}
