//! La clave de cada base, y el llavero donde vive.
//!
//! ── Qué es la clave ─────────────────────────────────────────────────────────
//!
//! 32 bytes al azar del generador del sistema, guardados en el llavero de la
//! sesión como 64 caracteres hexadecimales. Se le pasan a SQLCipher **crudos**
//! (`x'…'`), sin derivar nada de una contraseña: ya son una clave, y derivar en
//! cada apertura sería pagar un PBKDF2 por nada.
//!
//! En memoria vive dentro de `Zeroizing`, que la pone en cero al soltarla, y
//! sólo lo que dura abrir la base: después la tiene SQLCipher, que borra la suya
//! al cerrar.
//!
//! ── La regla que no se rompe ────────────────────────────────────────────────
//!
//! **Nunca generar una clave nueva sin haber leído antes `Locked == false`.**
//! Antes del desbloqueo, el llavero no distingue «bloqueado» de «no existe»:
//! `SearchItems` devuelve vacío en los dos casos. Tomar ese vacío por «no hay
//! clave» y generar una nueva deja ilegible, para siempre, la base buena que ya
//! estaba en el disco.
//!
//! Y tampoco se llama nunca a `Unlock`: abriría un diálogo al arrancar la sesión,
//! que es justo cuando nadie lo pidió. Con el llavero bloqueado se espera el
//! `PropertiesChanged` de `Locked`.
//!
//! ── Por qué un cliente propio ───────────────────────────────────────────────
//!
//! Son seis métodos del estándar Secret Service sobre el mismo zbus 4 que el
//! servicio ya usa. `oo7` y `secret-service` traerían otro zbus —y otra pila de
//! criptografía— para lo mismo.
//!
//! La sesión es `plain`: el secreto viaja por el bus de sesión sin cifrar, como
//! en cualquier cliente que no negocie Diffie-Hellman. El bus de sesión es de la
//! persona y ningún otro usuario lo ve; negociar sumaría una biblioteca de
//! criptografía para proteger el secreto de procesos que igual pueden pedírselo
//! al llavero (ver la frontera del cifrado en `store/mod.rs`).

use std::collections::HashMap;
use std::future::Future;

use serde::{Deserialize, Serialize};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Type, Value};
use zeroize::{Zeroize, Zeroizing};

/// Cuántos bytes tiene una clave.
pub const KEY_BYTES: usize = 32;

/// El esquema de los ítems del llavero, para que se los distinga de los de
/// cualquier otro programa.
pub const SCHEMA: &str = "ar.net.vasak.os.AccountsStore";

const SCHEMA_ATTRIBUTE: &str = "xdg:schema";
const ACCOUNT_ATTRIBUTE: &str = "account_id";

const SERVICE_NAME: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
const COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";
const SESSION_IFACE: &str = "org.freedesktop.Secret.Session";
const PROPERTIES_IFACE: &str = "org.freedesktop.DBus.Properties";

/// La clave de una base, en hexadecimal y en memoria que se borra sola.
pub struct StoreKey(Zeroizing<String>);

impl StoreKey {
    /// Una clave nueva, del generador del sistema operativo.
    pub fn generate() -> Result<Self, KeyError> {
        let mut raw = Zeroizing::new([0u8; KEY_BYTES]);
        getrandom::fill(raw.as_mut_slice())
            .map_err(|e| KeyError::Failed(format!("no hay azar del sistema: {e}")))?;
        Ok(Self(hex_encode(raw.as_slice())))
    }

    /// La clave que devolvió el llavero.
    ///
    /// Tiene que ser exactamente 64 caracteres hexadecimales. Otra cosa no la
    /// escribió este servicio, y no se la usa: se avisa como `Malformed` para que
    /// el ciclo de vida la trate como una clave que no abre.
    pub fn from_secret(secret: Zeroizing<Vec<u8>>) -> Result<Self, KeyError> {
        let valid = secret.len() == KEY_BYTES * 2 && secret.iter().all(u8::is_ascii_hexdigit);
        if !valid {
            return Err(KeyError::Malformed);
        }
        let mut hex = Zeroizing::new(String::with_capacity(KEY_BYTES * 2));
        hex.extend(secret.iter().map(|b| b.to_ascii_lowercase() as char));
        Ok(Self(hex))
    }

    /// Los 64 caracteres, para guardarlos en el llavero.
    pub fn hex(&self) -> &str {
        &self.0
    }

    /// La orden que le da la clave a SQLCipher, también en memoria que se borra.
    ///
    /// Con la forma `x'…'`, que es la de clave cruda. La clave se validó al
    /// crearla —sólo hexadecimal—, así que no hay comillas que puedan cerrar la
    /// cadena antes de tiempo.
    pub(super) fn pragma(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", self.hex()))
    }
}

impl PartialEq for StoreKey {
    fn eq(&self, other: &Self) -> bool {
        self.hex() == other.hex()
    }
}

/// Nunca se imprime: un `{:?}` en un mensaje de error no puede dejar la clave
/// en el diario.
impl std::fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreKey(…)")
    }
}

fn hex_encode(bytes: &[u8]) -> Zeroizing<String> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes {
        hex.push(DIGITS[usize::from(byte >> 4)] as char);
        hex.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    hex
}

/// Lo que puede salir mal al hablar con el llavero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// No hay llavero, o no contesta, o no tiene colección por omisión.
    Unavailable(String),
    /// La colección está bloqueada, o se bloqueó a mitad de camino.
    Locked,
    /// El llavero pidió un diálogo para hacer esto. No se abre ninguno.
    PromptRequired,
    /// Lo guardado no es una clave de este servicio.
    Malformed,
    /// Otro error.
    Failed(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::Unavailable(d) => write!(f, "el llavero no está disponible: {d}"),
            KeyError::Locked => f.write_str("el llavero está bloqueado"),
            KeyError::PromptRequired => {
                f.write_str("el llavero pidió un diálogo, y este servicio no los abre")
            }
            KeyError::Malformed => f.write_str("lo guardado en el llavero no es una clave válida"),
            KeyError::Failed(d) => write!(f, "{d}"),
        }
    }
}

impl std::error::Error for KeyError {}

/// De dónde sale la clave de cada base.
///
/// Un rasgo y no el cliente de Secret Service a secas para que el ciclo de vida
/// se pueda probar entero —fila por fila de su tabla— sin un llavero de verdad.
pub trait KeySource: Send + Sync + 'static {
    /// Si la colección donde viven las claves está bloqueada.
    ///
    /// Es **la** pregunta: ninguna clave se genera sin haber leído `false` acá.
    fn is_locked(&self) -> impl Future<Output = Result<bool, KeyError>> + Send;

    /// La clave de una cuenta, si hay una.
    ///
    /// Con la colección bloqueada contesta `Err(Locked)`, nunca `Ok(None)`.
    /// Aun así, `Ok(None)` sólo quiere decir «no está» si antes se leyó que la
    /// colección no está bloqueada: un llavero que dice «desbloqueado» y no
    /// descifró nada también contesta vacío. Un error nunca es «no está».
    fn find(
        &self,
        account_id: &str,
    ) -> impl Future<Output = Result<Option<StoreKey>, KeyError>> + Send;

    /// Guarda la clave de una cuenta, reemplazando la que hubiera.
    fn store(
        &self,
        account_id: &str,
        key: &StoreKey,
    ) -> impl Future<Output = Result<(), KeyError>> + Send;

    /// Borra la clave de una cuenta. Que no hubiera ninguna no es un error;
    /// que la colección esté bloqueada, sí (`Err(Locked)`).
    ///
    /// Un `Ok(())` no prueba que la clave se haya ido: el ciclo de vida no
    /// vuelve a usar la clave de una cuenta vaciada aunque la encuentre.
    fn delete(&self, account_id: &str) -> impl Future<Output = Result<(), KeyError>> + Send;

    /// Las cuentas que tienen una clave guardada, para limpiar las huérfanas.
    fn key_accounts(&self) -> impl Future<Output = Result<Vec<String>, KeyError>> + Send;
}

/// Un secreto tal como viaja por Secret Service: `(oayays)`.
///
/// El valor se pone en cero al soltarlo. Lo que no se puede borrar es la copia
/// que queda en el búfer del mensaje de D-Bus; eso es de zbus, y vive lo que
/// dura el mensaje.
#[derive(Serialize, Deserialize, Type)]
pub(crate) struct Secret {
    pub session: OwnedObjectPath,
    pub parameters: Vec<u8>,
    pub value: Vec<u8>,
    pub content_type: String,
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// El cliente de Secret Service.
#[derive(Clone)]
pub struct SecretServiceKeys {
    connection: zbus::Connection,
    /// El nombre del llavero en el bus, o nada en una conexión punto a punto
    /// —las pruebas—, donde no hay nombres.
    destination: Option<&'static str>,
}

impl SecretServiceKeys {
    /// El llavero de la sesión, sobre una conexión al bus de sesión que ya
    /// existe.
    pub fn on_session_bus(connection: zbus::Connection) -> Self {
        Self {
            connection,
            destination: Some(SERVICE_NAME),
        }
    }

    /// Un llavero del otro lado de una conexión punto a punto.
    #[cfg(test)]
    fn peer(connection: zbus::Connection) -> Self {
        Self {
            connection,
            destination: None,
        }
    }

    async fn call<B, R>(
        &self,
        path: &str,
        iface: &str,
        method: &str,
        body: &B,
    ) -> Result<R, KeyError>
    where
        B: Serialize + zbus::zvariant::DynamicType,
        R: for<'d> Deserialize<'d> + Type,
    {
        let reply = self
            .connection
            .call_method(self.destination, path, Some(iface), method, body)
            .await
            .map_err(|e| classify(method, e))?;
        reply
            .body()
            .deserialize::<R>()
            .map_err(|e| KeyError::Failed(format!("respuesta inválida de {method}: {e}")))
    }

    async fn property<R>(&self, path: &str, iface: &str, name: &str) -> Result<R, KeyError>
    where
        R: TryFrom<OwnedValue>,
        R::Error: std::fmt::Display,
    {
        let value: OwnedValue = self
            .call(path, PROPERTIES_IFACE, "Get", &(iface, name))
            .await?;
        R::try_from(value)
            .map_err(|e| KeyError::Failed(format!("la propiedad {name} no se entiende: {e}")))
    }

    /// La colección por omisión. Sin ella no hay dónde guardar, y crear una
    /// abriría un diálogo.
    async fn default_collection(&self) -> Result<OwnedObjectPath, KeyError> {
        let path: OwnedObjectPath = self
            .call(SERVICE_PATH, SERVICE_IFACE, "ReadAlias", &("default",))
            .await?;
        if path.as_str() == "/" {
            return Err(KeyError::Unavailable(
                "el llavero no tiene una colección por omisión".into(),
            ));
        }
        Ok(path)
    }

    /// `Locked` de una colección.
    async fn collection_locked(&self, collection: &OwnedObjectPath) -> Result<bool, KeyError> {
        self.property(collection.as_str(), COLLECTION_IFACE, "Locked")
            .await
    }

    /// Los ítems de la colección que tienen estos atributos.
    ///
    /// **Un vacío con la colección bloqueada es `Err(Locked)`, no «no hay».**
    /// `vasak-keyring` sin la contraseña en memoria contesta `SearchItems` con
    /// una lista vacía, igual que si no hubiera nada, y quien llama —`find`,
    /// `delete`, `key_accounts`— tomaría ese vacío por «no está» o por «ya
    /// está borrado». Así que se lee `Locked` antes de buscar, y otra vez si la
    /// búsqueda volvió vacía, sobre **la misma** colección: un bloqueo que llega
    /// entre la primera lectura y la búsqueda también se ve.
    async fn search(
        &self,
        attributes: &HashMap<&str, &str>,
    ) -> Result<Vec<OwnedObjectPath>, KeyError> {
        let collection = self.default_collection().await?;
        if self.collection_locked(&collection).await? {
            return Err(KeyError::Locked);
        }
        let mut items: Vec<OwnedObjectPath> = self
            .call(
                collection.as_str(),
                COLLECTION_IFACE,
                "SearchItems",
                &(attributes,),
            )
            .await?;
        if items.is_empty() && self.collection_locked(&collection).await? {
            return Err(KeyError::Locked);
        }
        // Ordenados, para que dos claves duplicadas den siempre la misma.
        items.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        Ok(items)
    }

    async fn open_session(&self) -> Result<OwnedObjectPath, KeyError> {
        let (_output, session): (OwnedValue, OwnedObjectPath) = self
            .call(
                SERVICE_PATH,
                SERVICE_IFACE,
                "OpenSession",
                &("plain", Value::from("")),
            )
            .await?;
        Ok(session)
    }

    /// Cierra una sesión. Si falla no pasa nada: el llavero las cierra solo
    /// cuando se va la conexión.
    async fn close_session(&self, session: &OwnedObjectPath) {
        let _: Result<(), _> = self
            .call(session.as_str(), SESSION_IFACE, "Close", &())
            .await;
    }

    /// Escucha los cambios de `Locked` de las colecciones.
    ///
    /// Lo que llega es sólo un aviso de que **puede** haber cambiado: quien lo
    /// recibe vuelve a leer la propiedad. Así una señal falsa —cualquier proceso
    /// de la sesión puede emitir una— no cambia nada, y una perdida la levanta
    /// la revisión por reloj.
    pub async fn lock_changes(&self) -> Result<zbus::MessageStream, KeyError> {
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface(PROPERTIES_IFACE)
            .and_then(|r| r.member("PropertiesChanged"))
            .and_then(|r| r.arg(0, COLLECTION_IFACE))
            .map_err(|e| KeyError::Failed(format!("no se pudo armar el filtro: {e}")))?
            .build();
        zbus::MessageStream::for_match_rule(rule, &self.connection, None)
            .await
            .map_err(|e| KeyError::Unavailable(format!("no se puede escuchar al llavero: {e}")))
    }
}

/// Si un `PropertiesChanged` habla de `Locked` de una colección.
pub fn is_lock_change(message: &zbus::Message) -> bool {
    let Ok((iface, changed, invalidated)) =
        message
            .body()
            .deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>()
    else {
        return false;
    };
    iface == COLLECTION_IFACE
        && (changed.contains_key("Locked") || invalidated.iter().any(|p| p == "Locked"))
}

impl KeySource for SecretServiceKeys {
    async fn is_locked(&self) -> Result<bool, KeyError> {
        let collection = self.default_collection().await?;
        self.collection_locked(&collection).await
    }

    async fn find(&self, account_id: &str) -> Result<Option<StoreKey>, KeyError> {
        let attributes = account_attributes(account_id);
        let items = self.search(&attributes).await?;
        let Some(item) = items.first() else {
            return Ok(None);
        };

        let session = self.open_session().await?;
        // Un solo argumento que es una estructura: `((oayays))`, como lo manda
        // el estándar y como lo contesta `vasak-keyring`.
        let reply: Result<(Secret,), KeyError> = self
            .call(item.as_str(), ITEM_IFACE, "GetSecret", &(&session,))
            .await;
        self.close_session(&session).await;

        let (mut secret,) = reply?;
        StoreKey::from_secret(Zeroizing::new(std::mem::take(&mut secret.value))).map(Some)
    }

    async fn store(&self, account_id: &str, key: &StoreKey) -> Result<(), KeyError> {
        let collection = self.default_collection().await?;
        let attributes = account_attributes(account_id);
        let label = format!("Almacén local de VasakOS ({account_id})");
        let mut properties: HashMap<&str, Value<'_>> = HashMap::new();
        properties.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
        properties.insert(
            "org.freedesktop.Secret.Item.Attributes",
            Value::from(attributes),
        );

        let session = self.open_session().await?;
        let secret = Secret {
            session: session.clone(),
            parameters: Vec::new(),
            value: key.hex().as_bytes().to_vec(),
            content_type: "text/plain".into(),
        };
        // `replace = true`: si ya hubiera una con los mismos atributos, se
        // reemplaza en vez de sumar una segunda que después no se sabe cuál es.
        let reply: Result<(OwnedObjectPath, OwnedObjectPath), KeyError> = self
            .call(
                collection.as_str(),
                COLLECTION_IFACE,
                "CreateItem",
                &(properties, &secret, true),
            )
            .await;
        drop(secret);
        self.close_session(&session).await;

        let (_item, prompt) = reply?;
        if prompt.as_str() != "/" {
            return Err(KeyError::PromptRequired);
        }
        Ok(())
    }

    async fn delete(&self, account_id: &str) -> Result<(), KeyError> {
        let attributes = account_attributes(account_id);
        for item in self.search(&attributes).await? {
            let prompt: OwnedObjectPath =
                self.call(item.as_str(), ITEM_IFACE, "Delete", &()).await?;
            if prompt.as_str() != "/" {
                return Err(KeyError::PromptRequired);
            }
        }
        Ok(())
    }

    async fn key_accounts(&self) -> Result<Vec<String>, KeyError> {
        let attributes = HashMap::from([(SCHEMA_ATTRIBUTE, SCHEMA)]);
        let mut accounts = Vec::new();
        for item in self.search(&attributes).await? {
            let item_attributes: HashMap<String, String> = self
                .property(item.as_str(), ITEM_IFACE, "Attributes")
                .await?;
            if let Some(account_id) = item_attributes.get(ACCOUNT_ATTRIBUTE) {
                accounts.push(account_id.clone());
            }
        }
        accounts.sort();
        accounts.dedup();
        Ok(accounts)
    }
}

fn account_attributes(account_id: &str) -> HashMap<&str, &str> {
    HashMap::from([(SCHEMA_ATTRIBUTE, SCHEMA), (ACCOUNT_ATTRIBUTE, account_id)])
}

/// Separa «no hay llavero» de «está bloqueado» de «falló».
///
/// Importa por lo que se hace después: ninguno de los tres es «no hay clave»,
/// y ninguno lleva a borrar ni a generar nada.
fn classify(method: &str, error: zbus::Error) -> KeyError {
    if let zbus::Error::MethodError(name, detail, _) = &error {
        let name = name.as_str();
        let detail = detail.clone().unwrap_or_default();
        // `IsLocked` es el nombre del estándar. `vasak-keyring` contesta
        // `Failed` con el motivo en el texto —en inglés o en español según el
        // método—, así que también se mira eso. Equivocarse acá sólo cambia lo
        // que dice el estado: ninguno de los dos casos borra ni genera nada.
        let lowered = detail.to_lowercase();
        if name.ends_with(".IsLocked") || lowered.contains("locked") || lowered.contains("bloquead")
        {
            return KeyError::Locked;
        }
        if name.ends_with(".ServiceUnknown")
            || name.ends_with(".NameHasNoOwner")
            || name.ends_with(".NoReply")
            || name.ends_with(".UnknownObject")
            || name.ends_with(".UnknownMethod")
        {
            return KeyError::Unavailable(format!("{method}: {detail}"));
        }
        return KeyError::Failed(format!("{method}: {detail}"));
    }
    KeyError::Unavailable(format!("{method}: {error}"))
}

/// Un llavero en memoria, para probar el ciclo de vida sin bus.
#[cfg(test)]
pub(crate) mod fake {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Contesta como el cliente de verdad, [`SecretServiceKeys`]: con la
    /// colección bloqueada, `find`, `delete`, `key_accounts` y `store` dan
    /// `Err(Locked)`. Lo que el cliente de verdad no puede ver —un `Delete` que
    /// contesta bien y no borra, un llavero que dice «desbloqueado» y no ve
    /// nada— va por perillas aparte, con nombre.
    #[derive(Default)]
    pub(crate) struct FakeState {
        pub locked: bool,
        pub unavailable: bool,
        /// La clave de cada cuenta, en hexadecimal.
        pub keys: BTreeMap<String, String>,
        /// Las cuentas cuyo secreto es basura.
        pub malformed: BTreeSet<String>,
        /// Cada `store` que llegó, en orden.
        pub stored: Vec<String>,
        /// Cada `delete` que llegó, en orden.
        pub deleted: Vec<String>,
        /// Un `store` con la colección bloqueada: lo que no puede pasar nunca.
        pub stored_while_locked: usize,
        pub fail_delete: bool,
        /// Que `store` conteste bien y no guarde nada.
        pub lose_stores: bool,
        /// Que la colección se bloquee apenas se busca una clave.
        pub lock_after_find: bool,
        /// Que `find` falle.
        pub fail_find: bool,
        /// Que `delete` conteste bien y no borre nada: un llavero que miente,
        /// o el cliente de antes, que con el llavero bloqueado recibía un
        /// `SearchItems` vacío y contestaba `Ok(())`.
        pub lose_deletes: bool,
        /// Que la colección se bloquee justo después de contestar
        /// `is_locked() == false`.
        pub lock_after_is_locked: bool,
        /// Que `store` falle: `vasak-keyring` con la escritura bloqueada, o que
        /// rechaza el `CreateItem`.
        pub reject_stores: bool,
        /// Cuántas veces `find` contesta vacío con la colección desbloqueada y
        /// la clave ahí: `vasak-keyring` diciendo `Locked == false` antes de
        /// haber descifrado nada.
        pub blind_finds: usize,
    }

    #[derive(Clone, Default)]
    pub(crate) struct FakeKeys(pub Arc<Mutex<FakeState>>);

    impl FakeKeys {
        pub(crate) fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
            self.0.lock().unwrap()
        }
    }

    impl KeySource for FakeKeys {
        async fn is_locked(&self) -> Result<bool, KeyError> {
            let mut state = self.state();
            if state.unavailable {
                return Err(KeyError::Unavailable("sin llavero".into()));
            }
            let locked = state.locked;
            if !locked && state.lock_after_is_locked {
                state.lock_after_is_locked = false;
                state.locked = true;
            }
            Ok(locked)
        }

        async fn find(&self, account_id: &str) -> Result<Option<StoreKey>, KeyError> {
            let mut state = self.state();
            if state.unavailable {
                return Err(KeyError::Unavailable("sin llavero".into()));
            }
            if state.fail_find {
                return Err(KeyError::Failed("falló la búsqueda".into()));
            }
            // Como el cliente de verdad: la búsqueda vacía con la colección
            // bloqueada es un bloqueo, no «no está».
            if state.locked {
                return Err(KeyError::Locked);
            }
            if state.blind_finds > 0 {
                state.blind_finds -= 1;
                return Ok(None);
            }
            if state.lock_after_find {
                state.locked = true;
            }
            if state.malformed.contains(account_id) {
                return Err(KeyError::Malformed);
            }
            state
                .keys
                .get(account_id)
                .map(|hex| StoreKey::from_secret(Zeroizing::new(hex.as_bytes().to_vec())))
                .transpose()
        }

        async fn store(&self, account_id: &str, key: &StoreKey) -> Result<(), KeyError> {
            let mut state = self.state();
            if state.locked {
                state.stored_while_locked += 1;
                return Err(KeyError::Locked);
            }
            if state.reject_stores {
                return Err(KeyError::Failed("el llavero no dejó guardar".into()));
            }
            state.stored.push(account_id.to_string());
            state.malformed.remove(account_id);
            if !state.lose_stores {
                state
                    .keys
                    .insert(account_id.to_string(), key.hex().to_string());
            }
            Ok(())
        }

        async fn delete(&self, account_id: &str) -> Result<(), KeyError> {
            let mut state = self.state();
            if state.locked && !state.lose_deletes {
                return Err(KeyError::Locked);
            }
            if state.fail_delete {
                return Err(KeyError::Failed("no se pudo borrar".into()));
            }
            state.deleted.push(account_id.to_string());
            if state.lose_deletes {
                return Ok(());
            }
            state.keys.remove(account_id);
            state.malformed.remove(account_id);
            Ok(())
        }

        async fn key_accounts(&self) -> Result<Vec<String>, KeyError> {
            let state = self.state();
            if state.locked {
                return Err(KeyError::Locked);
            }
            Ok(state
                .keys
                .keys()
                .chain(state.malformed.iter())
                .cloned()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use futures_util::StreamExt;
    use zbus::object_server::ObjectServer;

    use super::*;

    #[test]
    fn una_clave_nueva_son_64_hexadecimales_al_azar() {
        let a = StoreKey::generate().unwrap();
        let b = StoreKey::generate().unwrap();
        assert_eq!(a.hex().len(), 64);
        assert!(a
            .hex()
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(a, b, "dos claves seguidas no pueden ser iguales");
    }

    #[test]
    fn la_clave_no_se_imprime() {
        let key = StoreKey::generate().unwrap();
        let printed = format!("{key:?}");
        assert!(!printed.contains(key.hex()));
    }

    #[test]
    fn lo_que_no_es_una_clave_se_rechaza() {
        for bad in [
            &b""[..],
            b"abc",
            &[b'a'; 63],
            &[b'a'; 65],
            &[b'g'; 64],
            "'; DROP TABLE x; --aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_bytes(),
        ] {
            assert_eq!(
                StoreKey::from_secret(Zeroizing::new(bad.to_vec())),
                Err(KeyError::Malformed)
            );
        }
        let upper = StoreKey::from_secret(Zeroizing::new(vec![b'A'; 64])).unwrap();
        assert_eq!(upper.hex(), "a".repeat(64));
    }

    #[test]
    fn la_orden_de_sqlcipher_usa_la_clave_cruda() {
        let key = StoreKey::from_secret(Zeroizing::new(vec![b'0'; 64])).unwrap();
        assert_eq!(
            key.pragma().as_str(),
            format!("PRAGMA key = \"x'{}'\";", "0".repeat(64))
        );
    }

    // ── Un llavero falso del otro lado de una conexión punto a punto ────────
    //
    // Sin `dbus-daemon`: dos puntas de un `UnixStream::pair()`, una hace de
    // servidor y la otra de cliente. Lo que se prueba es el cliente de verdad,
    // con los mismos mensajes que viajan por el bus de sesión.

    const COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/login";

    #[derive(Default)]
    struct FakeKeyring {
        locked: bool,
        /// Que la colección se bloquee en el momento de buscar: `SearchItems`
        /// ya contesta vacío, aunque `Locked` se haya leído `false` antes.
        lock_on_search: bool,
        next_item: u32,
        items: BTreeMap<String, (HashMap<String, String>, Vec<u8>)>,
        sessions: u32,
        closed_sessions: u32,
    }

    type Shared = Arc<Mutex<FakeKeyring>>;

    struct FakeService(Shared);

    #[zbus::interface(name = "org.freedesktop.Secret.Service")]
    impl FakeService {
        async fn open_session(
            &self,
            #[zbus(object_server)] server: &ObjectServer,
            algorithm: &str,
            _input: Value<'_>,
        ) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
            if algorithm != "plain" {
                return Err(zbus::fdo::Error::NotSupported(algorithm.into()));
            }
            let id = {
                let mut state = self.0.lock().unwrap();
                state.sessions += 1;
                state.sessions
            };
            let path = format!("/org/freedesktop/secrets/session/s{id}");
            server
                .at(path.clone(), FakeSession(self.0.clone()))
                .await
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
            let output = OwnedValue::try_from(Value::from(""))
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
            Ok((output, OwnedObjectPath::try_from(path).unwrap()))
        }

        async fn read_alias(&self, alias: &str) -> OwnedObjectPath {
            let path = if alias == "default" {
                COLLECTION_PATH
            } else {
                "/"
            };
            OwnedObjectPath::try_from(path).unwrap()
        }
    }

    struct FakeSession(Shared);

    #[zbus::interface(name = "org.freedesktop.Secret.Session")]
    impl FakeSession {
        async fn close(&self) {
            self.0.lock().unwrap().closed_sessions += 1;
        }
    }

    struct FakeCollection(Shared);

    #[zbus::interface(name = "org.freedesktop.Secret.Collection")]
    impl FakeCollection {
        async fn search_items(&self, attributes: HashMap<String, String>) -> Vec<OwnedObjectPath> {
            let mut state = self.0.lock().unwrap();
            if state.lock_on_search {
                state.lock_on_search = false;
                state.locked = true;
            }
            // Como `vasak-keyring` antes del desbloqueo: vacío.
            if state.locked {
                return Vec::new();
            }
            state
                .items
                .iter()
                .filter(|(_, (item_attributes, _))| {
                    attributes
                        .iter()
                        .all(|(k, v)| item_attributes.get(k) == Some(v))
                })
                .map(|(path, _)| OwnedObjectPath::try_from(path.as_str()).unwrap())
                .collect()
        }

        async fn create_item(
            &self,
            #[zbus(object_server)] server: &ObjectServer,
            properties: HashMap<String, OwnedValue>,
            mut secret: Secret,
            replace: bool,
        ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
            let attributes: HashMap<String, String> = properties
                .get("org.freedesktop.Secret.Item.Attributes")
                .and_then(|v| v.try_clone().ok())
                .and_then(|v| HashMap::try_from(v).ok())
                .ok_or_else(|| zbus::fdo::Error::InvalidArgs("sin atributos".into()))?;
            let path = {
                let mut state = self.0.lock().unwrap();
                if state.locked {
                    // El texto de `vasak-keyring` para esto, en español.
                    return Err(zbus::fdo::Error::Failed(
                        "el llavero está bloqueado: no hay contraseña maestra en memoria".into(),
                    ));
                }
                if replace {
                    state.items.retain(|_, (a, _)| a != &attributes);
                }
                state.next_item += 1;
                let path = format!("{COLLECTION_PATH}/items/{}", state.next_item);
                state.items.insert(
                    path.clone(),
                    (attributes, std::mem::take(&mut secret.value)),
                );
                path
            };
            server
                .at(path.clone(), FakeItem(self.0.clone(), path.clone()))
                .await
                .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
            Ok((
                OwnedObjectPath::try_from(path).unwrap(),
                OwnedObjectPath::try_from("/").unwrap(),
            ))
        }

        #[zbus(property)]
        async fn locked(&self) -> bool {
            self.0.lock().unwrap().locked
        }
    }

    struct FakeItem(Shared, String);

    #[zbus::interface(name = "org.freedesktop.Secret.Item")]
    impl FakeItem {
        async fn get_secret(&self, session: OwnedObjectPath) -> zbus::fdo::Result<(Secret,)> {
            let state = self.0.lock().unwrap();
            if state.locked {
                return Err(zbus::fdo::Error::Failed("collection is locked".into()));
            }
            let (_, value) = state
                .items
                .get(&self.1)
                .ok_or_else(|| zbus::fdo::Error::Failed("item not found".into()))?;
            Ok((Secret {
                session,
                parameters: Vec::new(),
                value: value.clone(),
                content_type: "text/plain".into(),
            },))
        }

        async fn delete(&self) -> OwnedObjectPath {
            self.0.lock().unwrap().items.remove(&self.1);
            OwnedObjectPath::try_from("/").unwrap()
        }

        #[zbus(property)]
        async fn attributes(&self) -> HashMap<String, String> {
            self.0
                .lock()
                .unwrap()
                .items
                .get(&self.1)
                .map(|(a, _)| a.clone())
                .unwrap_or_default()
        }
    }

    /// Levanta el llavero falso y devuelve el cliente de verdad conectado a él.
    async fn fake_keyring() -> (SecretServiceKeys, zbus::Connection, Shared) {
        let shared = Shared::default();
        let (server_end, client_end) = tokio::net::UnixStream::pair().unwrap();
        let guid = zbus::Guid::generate();

        let server = zbus::connection::Builder::unix_stream(server_end)
            .server(guid)
            .unwrap()
            .p2p()
            .serve_at(SERVICE_PATH, FakeService(shared.clone()))
            .unwrap()
            .serve_at(COLLECTION_PATH, FakeCollection(shared.clone()))
            .unwrap()
            .build();
        let client = zbus::connection::Builder::unix_stream(client_end)
            .p2p()
            .build();
        let (server, client) = tokio::join!(server, client);

        (
            SecretServiceKeys::peer(client.unwrap()),
            server.unwrap(),
            shared,
        )
    }

    #[tokio::test]
    async fn el_cliente_guarda_busca_y_borra_contra_un_llavero_falso() {
        let (keys, _server, shared) = fake_keyring().await;

        assert!(!keys.is_locked().await.unwrap());
        assert_eq!(keys.find("cuenta-a").await.unwrap(), None);

        let key = StoreKey::generate().unwrap();
        keys.store("cuenta-a", &key).await.unwrap();
        let other = StoreKey::generate().unwrap();
        keys.store("cuenta-b", &other).await.unwrap();

        assert_eq!(keys.find("cuenta-a").await.unwrap(), Some(key));
        assert_eq!(keys.find("cuenta-b").await.unwrap(), Some(other));

        // Con el esquema y la cuenta como atributos.
        {
            let state = shared.lock().unwrap();
            let (attributes, value) = state.items.values().next().unwrap();
            assert_eq!(
                attributes.get("xdg:schema").map(String::as_str),
                Some(SCHEMA)
            );
            assert!(attributes.contains_key("account_id"));
            assert_eq!(value.len(), 64);
        }

        assert_eq!(
            keys.key_accounts().await.unwrap(),
            vec!["cuenta-a".to_string(), "cuenta-b".to_string()]
        );

        keys.delete("cuenta-a").await.unwrap();
        assert_eq!(keys.find("cuenta-a").await.unwrap(), None);
        assert!(keys.find("cuenta-b").await.unwrap().is_some());
        // Borrar lo que no está no es un error.
        keys.delete("cuenta-a").await.unwrap();

        // Y las sesiones que se abren se cierran.
        let state = shared.lock().unwrap();
        assert!(state.sessions > 0);
        assert_eq!(state.sessions, state.closed_sessions);
    }

    #[tokio::test]
    async fn guardar_dos_veces_reemplaza_y_no_duplica() {
        let (keys, _server, shared) = fake_keyring().await;
        keys.store("cuenta", &StoreKey::generate().unwrap())
            .await
            .unwrap();
        let second = StoreKey::generate().unwrap();
        keys.store("cuenta", &second).await.unwrap();

        assert_eq!(shared.lock().unwrap().items.len(), 1);
        assert_eq!(keys.find("cuenta").await.unwrap(), Some(second));
    }

    /// `Locked` se lee de la colección, y un llavero bloqueado que contesta
    /// vacío no se confunde con «no hay clave» en la lectura del secreto.
    #[tokio::test]
    async fn el_cliente_lee_locked_y_no_toma_un_bloqueo_por_una_clave_que_falta() {
        let (keys, _server, shared) = fake_keyring().await;
        keys.store("cuenta", &StoreKey::generate().unwrap())
            .await
            .unwrap();

        shared.lock().unwrap().locked = true;
        assert!(keys.is_locked().await.unwrap());
        // Guardar con el llavero bloqueado falla, y como bloqueo.
        assert_eq!(
            keys.store("otra", &StoreKey::generate().unwrap()).await,
            Err(KeyError::Locked)
        );

        shared.lock().unwrap().locked = false;
        assert!(!keys.is_locked().await.unwrap());
        assert!(keys.find("cuenta").await.unwrap().is_some());
    }

    /// `vasak-keyring` sin la contraseña en memoria contesta `SearchItems`
    /// vacío. El cliente no puede tomar eso por «no hay clave» ni por «ya está
    /// borrada»: `delete` y `find` avisan el bloqueo, y la clave sigue ahí.
    #[tokio::test]
    async fn borrar_con_el_llavero_bloqueado_avisa_el_bloqueo_y_no_borra() {
        let (keys, _server, shared) = fake_keyring().await;
        let key = StoreKey::generate().unwrap();
        keys.store("cuenta", &key).await.unwrap();

        shared.lock().unwrap().locked = true;
        assert_eq!(keys.delete("cuenta").await, Err(KeyError::Locked));
        assert_eq!(keys.find("cuenta").await, Err(KeyError::Locked));
        assert_eq!(keys.key_accounts().await, Err(KeyError::Locked));

        shared.lock().unwrap().locked = false;
        assert_eq!(keys.find("cuenta").await.unwrap(), Some(key));
    }

    /// Un bloqueo que llega entre la lectura de `Locked` y la búsqueda
    /// tampoco se lee como vacío: se vuelve a mirar `Locked` después.
    #[tokio::test]
    async fn un_bloqueo_durante_la_busqueda_no_se_lee_como_vacio() {
        let (keys, _server, shared) = fake_keyring().await;
        let key = StoreKey::generate().unwrap();
        keys.store("cuenta", &key).await.unwrap();

        shared.lock().unwrap().lock_on_search = true;
        assert_eq!(keys.delete("cuenta").await, Err(KeyError::Locked));

        shared.lock().unwrap().locked = false;
        shared.lock().unwrap().lock_on_search = true;
        assert_eq!(keys.find("cuenta").await, Err(KeyError::Locked));

        shared.lock().unwrap().locked = false;
        assert_eq!(keys.find("cuenta").await.unwrap(), Some(key));
    }

    /// Un secreto que no escribió este servicio no se usa como clave.
    #[tokio::test]
    async fn un_secreto_que_no_es_clave_se_avisa_como_malformado() {
        let (keys, _server, shared) = fake_keyring().await;
        keys.store("cuenta", &StoreKey::generate().unwrap())
            .await
            .unwrap();
        for (_, value) in shared.lock().unwrap().items.values_mut() {
            *value = b"hunter2".to_vec();
        }
        assert_eq!(keys.find("cuenta").await, Err(KeyError::Malformed));
    }

    /// El aviso de desbloqueo llega por `PropertiesChanged`, y se reconoce.
    #[tokio::test]
    async fn el_cambio_de_locked_llega_como_aviso() {
        let (keys, server, shared) = fake_keyring().await;
        let mut changes = keys.lock_changes().await.unwrap();

        shared.lock().unwrap().locked = false;
        let iface = server
            .object_server()
            .interface::<_, FakeCollection>(COLLECTION_PATH)
            .await
            .unwrap();
        iface
            .get()
            .await
            .locked_changed(iface.signal_context())
            .await
            .unwrap();

        let message = tokio::time::timeout(std::time::Duration::from_secs(5), changes.next())
            .await
            .expect("el aviso no llegó")
            .unwrap()
            .unwrap();
        assert!(is_lock_change(&message));
    }

    /// Una colección por omisión que no existe es «no disponible», no «vacía».
    #[tokio::test]
    async fn sin_coleccion_por_omision_no_hay_llavero() {
        struct NoDefault;
        #[zbus::interface(name = "org.freedesktop.Secret.Service")]
        impl NoDefault {
            async fn read_alias(&self, _alias: &str) -> OwnedObjectPath {
                OwnedObjectPath::try_from("/").unwrap()
            }
        }

        let (server_end, client_end) = tokio::net::UnixStream::pair().unwrap();
        let server = zbus::connection::Builder::unix_stream(server_end)
            .server(zbus::Guid::generate())
            .unwrap()
            .p2p()
            .serve_at(SERVICE_PATH, NoDefault)
            .unwrap()
            .build();
        let client = zbus::connection::Builder::unix_stream(client_end)
            .p2p()
            .build();
        let (_server, client) = tokio::join!(server, client);
        let keys = SecretServiceKeys::peer(client.unwrap());

        assert!(matches!(
            keys.is_locked().await,
            Err(KeyError::Unavailable(_))
        ));
        assert!(matches!(
            keys.find("cuenta").await,
            Err(KeyError::Unavailable(_))
        ));
    }
}
