//! La clave de cada base, y el llavero donde vive.
//!
//! ── Qué es la clave ─────────────────────────────────────────────────────────
//!
//! 32 bytes al azar del generador del sistema, guardados en el llavero de la
//! sesión como 64 caracteres hexadecimales. Se le pasan a SQLCipher **crudos**
//! (`x'…'`), sin derivar nada de una contraseña: ya son una clave, y derivar en
//! cada apertura sería pagar un PBKDF2 por nada.
//!
//! De este lado vive en `Zeroizing`, que la pone en cero al soltarla, y sólo lo
//! que dura abrir la base. Se le entrega a SQLCipher con `sqlite3_key_v2` desde
//! un búfer del largo justo —sin `PRAGMA key`, cuyo texto copia el parser de
//! SQL en memoria que se libera sin borrar—; SQLCipher la copia a su montículo
//! privado, deriva la de las páginas y borra las dos al soltarlas, a más tardar
//! al cerrar la base.
//!
//! Lo que **no** se borra: la copia en el búfer del mensaje de D-Bus que la
//! trajo del llavero (es de zbus, y vive lo que el mensaje), y la clave de
//! páginas que SQLCipher tiene mientras la base está abierta. Por eso el
//! proceso no deja volcados de memoria: `LimitCORE=0` en la unidad y
//! `PR_SET_DUMPABLE` en cero al arrancar, que además le cierra `ptrace` a los
//! demás procesos de la persona.
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
//! en cualquier cliente que no negocie Diffie-Hellman. Lo ve el bus mismo
//! —`dbus-broker`, que lo copia de un proceso al otro— y cualquier proceso de la
//! persona que se ponga de monitor (`BecomeMonitor`, que el bus de sesión le
//! permite al mismo usuario). Ningún otro usuario lo ve. Negociar no sumaría una
//! biblioteca compartida —`libcrypto.so.3` ya está, por SQLCipher— pero sí
//! crates (`aes`, `cbc`, `hkdf`, `num-bigint`), y contra el mismo usuario no
//! gana nada: ese proceso le puede pedir la clave al llavero directamente (ver
//! la frontera del cifrado en `store/mod.rs`). Así que queda `plain`.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zbus::names::{OwnedUniqueName, UniqueName};
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

    /// La clave como se la entrega a SQLCipher: `x'…'`, la forma de clave
    /// cruda —sin derivar nada—, en memoria que se borra.
    ///
    /// **Del largo justo desde el principio.** Un búfer que crece copia lo que
    /// tiene a uno nuevo y suelta el viejo sin borrarlo; `Zeroizing` sólo
    /// borra el último. La clave se validó al crearla —sólo hexadecimal—, así
    /// que no hay comillas que cierren nada antes de tiempo.
    pub(super) fn sqlcipher_key(&self) -> Zeroizing<Vec<u8>> {
        let hex = self.hex().as_bytes();
        let mut literal = Zeroizing::new(Vec::with_capacity(hex.len() + 3));
        literal.extend_from_slice(b"x'");
        literal.extend_from_slice(hex);
        literal.push(b'\'');
        literal
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
    /// Resuelve la colección donde viven las claves —el alias `default`— y la
    /// **fija** para todo lo que siga, hasta la próxima vez que se llame.
    /// Devuelve su identidad: la ruta y su momento de creación (`Created`).
    ///
    /// Se llama una vez por vuelta de la tabla del ciclo de vida. Sin fijarla,
    /// un `SetAlias` —que puede mandar cualquier proceso de la sesión— a mitad
    /// de una vuelta partiría las claves entre dos colecciones; y comparando la
    /// identidad con la que creó cada clave, un alias que cambió o un llavero
    /// que se reemplazó no se confunden con «se perdieron todas las claves».
    fn pin_collection(&self) -> impl Future<Output = Result<String, KeyError>> + Send;

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
    /// El nombre único del dueño de `destination` la última vez que se
    /// preguntó, para saber de quién es una señal.
    owner: Arc<std::sync::Mutex<Option<OwnedUniqueName>>>,
    /// La colección fijada por [`KeySource::pin_collection`]. Mientras no se
    /// fije ninguna, cada operación lee el alias.
    pinned: Arc<std::sync::Mutex<Option<OwnedObjectPath>>>,
}

impl SecretServiceKeys {
    /// El llavero de la sesión, sobre una conexión al bus de sesión que ya
    /// existe.
    pub fn on_session_bus(connection: zbus::Connection) -> Self {
        Self {
            connection,
            destination: Some(SERVICE_NAME),
            owner: Arc::default(),
            pinned: Arc::default(),
        }
    }

    /// Un llavero del otro lado de una conexión punto a punto.
    #[cfg(test)]
    fn peer(connection: zbus::Connection) -> Self {
        Self {
            connection,
            destination: None,
            owner: Arc::default(),
            pinned: Arc::default(),
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

    /// La colección de las claves: la fijada, o si no hay ninguna, la del
    /// alias `default`.
    async fn default_collection(&self) -> Result<OwnedObjectPath, KeyError> {
        let pinned = self
            .pinned
            .lock()
            .map(|pinned| pinned.clone())
            .unwrap_or(None);
        match pinned {
            Some(path) => Ok(path),
            None => self.read_default_alias().await,
        }
    }

    /// La colección por omisión. Sin ella no hay dónde guardar, y crear una
    /// abriría un diálogo.
    async fn read_default_alias(&self) -> Result<OwnedObjectPath, KeyError> {
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

    /// `Created` de una colección, como texto para su identidad.
    ///
    /// `Created` es del estándar y `vasak-keyring` lo tiene. Un llavero que
    /// **no lo tiene** lo dice siempre igual —`UnknownProperty`, o
    /// `InvalidArgs` en GDBus, o que no tiene la interfaz o el método—, y da
    /// siempre la misma identidad: la ruta y `?`, que es lo que importa, que no
    /// cambie sola.
    ///
    /// **Cualquier otro error no es «no lo tiene»**: un llavero que se
    /// reinicia, uno que no contestó a tiempo, uno que dijo `Failed`. Tomarlo
    /// como `?` anotaba `ruta#?` en la vuelta en que se crea o se adopta una
    /// base, y en la siguiente, con `Created` contestando, la identidad pasaba
    /// a ser otra y la base quedaba `unavailable` para siempre. Así que es
    /// `Err`, y la vuelta se corta sin anotar nada: la próxima lo vuelve a
    /// intentar.
    async fn collection_created(&self, path: &OwnedObjectPath) -> Result<String, KeyError> {
        let reply = self
            .connection
            .call_method(
                self.destination,
                path.as_str(),
                Some(PROPERTIES_IFACE),
                "Get",
                &(COLLECTION_IFACE, "Created"),
            )
            .await;
        let reply = match reply {
            Ok(reply) => reply,
            Err(zbus::Error::MethodError(name, _, _)) if lacks_property(name.as_str()) => {
                return Ok("?".to_string());
            }
            Err(e) => return Err(classify("Get(Created)", e)),
        };
        let value: OwnedValue = reply
            .body()
            .deserialize()
            .map_err(|e| KeyError::Failed(format!("respuesta inválida de Get(Created): {e}")))?;
        // Un `Created` de otro tipo tampoco cambia solo: es siempre el mismo
        // llavero contestando lo mismo.
        Ok(u64::try_from(value).map_or_else(|_| "?".to_string(), |c| c.to_string()))
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
    /// recibe vuelve a leer la propiedad. Así una señal falsa no cambia nada, y
    /// una perdida la levanta la revisión por reloj. Y además se filtra por
    /// remitente, dos veces: la regla le pide al bus sólo las del dueño de
    /// `org.freedesktop.secrets`, y quien recibe mira [`Self::is_from_keyring`]
    /// —zbus reparte a cada flujo todo lo que llega a la conexión, y no puede
    /// comparar un nombre conocido—. Sin eso, cualquier proceso de la sesión
    /// podía hacer que el sync volviera a pasar la tabla —y a hablar con el
    /// llavero— tantas veces como señales mandara.
    pub async fn lock_changes(&self) -> Result<zbus::MessageStream, KeyError> {
        let rule = lock_change_rule(self.destination)?;
        zbus::MessageStream::for_match_rule(rule, &self.connection, None)
            .await
            .map_err(|e| KeyError::Unavailable(format!("no se puede escuchar al llavero: {e}")))
    }

    /// Si un mensaje lo mandó el llavero.
    ///
    /// En el bus, el remitente es el nombre único de quien lo mandó, y se
    /// compara con el dueño de `org.freedesktop.secrets`. Si no coincide con el
    /// que se sabía, se vuelve a preguntar: el llavero pudo haberse reiniciado
    /// con otro nombre único. En una conexión punto a punto no hay remitentes, y
    /// lo que llega es del otro lado.
    pub async fn is_from_keyring(&self, message: &zbus::Message) -> bool {
        let Some(name) = self.destination else {
            return true;
        };
        let header = message.header();
        let sender = header.sender();
        let known = self.owner.lock().map(|owner| owner.clone()).unwrap_or(None);
        if sent_by(sender, known.as_deref()) {
            return true;
        }

        let Ok(proxy) = zbus::fdo::DBusProxy::new(&self.connection).await else {
            return false;
        };
        let Ok(bus_name) = zbus::names::BusName::try_from(name) else {
            return false;
        };
        let Ok(current) = proxy.get_name_owner(bus_name).await else {
            return false;
        };
        let accepted = sent_by(sender, Some(&current));
        if let Ok(mut owner) = self.owner.lock() {
            *owner = Some(current);
        }
        accepted
    }
}

/// La regla de los cambios de `Locked`: señales `PropertiesChanged` de
/// `org.freedesktop.Secret.Collection`, y en el bus sólo del llavero.
fn lock_change_rule(sender: Option<&'static str>) -> Result<zbus::MatchRule<'static>, KeyError> {
    let mut builder = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface(PROPERTIES_IFACE)
        .and_then(|r| r.member("PropertiesChanged"))
        .and_then(|r| r.arg(0, COLLECTION_IFACE))
        .map_err(|e| KeyError::Failed(format!("no se pudo armar el filtro: {e}")))?;
    if let Some(sender) = sender {
        builder = builder
            .sender(sender)
            .map_err(|e| KeyError::Failed(format!("no se pudo armar el filtro: {e}")))?;
    }
    Ok(builder.build())
}

/// Si el remitente de un mensaje es el dueño que se conoce. Sin dueño conocido,
/// o sin remitente, no.
fn sent_by(sender: Option<&UniqueName<'_>>, owner: Option<&UniqueName<'_>>) -> bool {
    matches!((sender, owner), (Some(sender), Some(owner)) if sender == owner)
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
    async fn pin_collection(&self) -> Result<String, KeyError> {
        let path = self.read_default_alias().await?;
        let created = self.collection_created(&path).await?;
        let identity = format!("{}#{created}", path.as_str());
        if let Ok(mut pinned) = self.pinned.lock() {
            *pinned = Some(path);
        }
        Ok(identity)
    }

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
            // Cualquier proceso de la sesión puede plantar un ítem con este
            // esquema, y lo que devuelve esto termina en el diario y en una
            // ruta: un identificador que no es uno de los nuestros se descarta,
            // sin repetirlo.
            match item_attributes.get(ACCOUNT_ATTRIBUTE) {
                Some(account_id) if super::paths::validate_account_id(account_id).is_ok() => {
                    accounts.push(account_id.clone());
                }
                Some(_) => tracing::warn!(
                    "se descartó un ítem del almacén en el llavero con un identificador de cuenta inválido"
                ),
                None => {}
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

/// Si un error de `Properties.Get` quiere decir «esa propiedad no existe acá»:
/// una respuesta que el llavero da siempre igual, y no una falla pasajera.
fn lacks_property(error_name: &str) -> bool {
    [
        ".UnknownProperty",
        ".InvalidArgs",
        ".UnknownInterface",
        ".UnknownMethod",
        ".NotSupported",
    ]
    .iter()
    .any(|suffix| {
        error_name.starts_with("org.freedesktop.DBus.Error") && error_name.ends_with(suffix)
    })
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
        /// La identidad de la colección, como la da `pin_collection`. Vacía es
        /// `coleccion-a`.
        pub collection: String,
        /// Cuántas veces se fijó la colección.
        pub pins: usize,
        /// Cuántas veces `pin_collection` falla antes de contestar: un
        /// `Created` que no llegó.
        pub fail_pins: usize,
        /// Si está, cada `pin_collection` espera un permiso de acá: una vuelta
        /// de la tabla detenida a mitad de camino, con la cerradura tomada.
        pub pin_gate: Option<Arc<tokio::sync::Semaphore>>,
        /// Cuántos `pin_collection` están esperando en `pin_gate`.
        pub pins_waiting: usize,
    }

    #[derive(Clone, Default)]
    pub(crate) struct FakeKeys(pub Arc<Mutex<FakeState>>);

    impl FakeKeys {
        pub(crate) fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
            self.0.lock().unwrap()
        }
    }

    impl KeySource for FakeKeys {
        async fn pin_collection(&self) -> Result<String, KeyError> {
            let gate = self.state().pin_gate.clone();
            if let Some(gate) = gate {
                self.state().pins_waiting += 1;
                gate.acquire().await.unwrap().forget();
                self.state().pins_waiting -= 1;
            }
            let mut state = self.state();
            if state.unavailable {
                return Err(KeyError::Unavailable("sin llavero".into()));
            }
            if state.fail_pins > 0 {
                state.fail_pins -= 1;
                return Err(KeyError::Failed("Get(Created): no contestó".into()));
            }
            state.pins += 1;
            Ok(if state.collection.is_empty() {
                "coleccion-a".to_string()
            } else {
                state.collection.clone()
            })
        }

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

    /// La forma de clave cruda, y en un búfer que nunca creció: si hubiera
    /// crecido, el de antes —con la clave— se habría soltado sin borrar.
    #[test]
    fn la_clave_para_sqlcipher_es_cruda_y_del_largo_justo() {
        let key = StoreKey::from_secret(Zeroizing::new(vec![b'0'; 64])).unwrap();
        let literal = key.sqlcipher_key();
        assert_eq!(
            literal.as_slice(),
            format!("x'{}'", "0".repeat(64)).as_bytes()
        );
        assert_eq!(literal.capacity(), literal.len());
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
        /// `Created` de la colección.
        created: u64,
        /// Cuántas veces `Created` contesta `Failed` antes de contestar bien:
        /// un llavero que se está reiniciando.
        created_failures: u32,
        /// Que la colección no tenga `Created`: un llavero que no lo
        /// implementa.
        without_created: bool,
        /// Cuántas veces se leyó el alias.
        alias_reads: u32,
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
            self.0.lock().unwrap().alias_reads += 1;
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

        #[zbus(property)]
        async fn created(&self) -> zbus::fdo::Result<u64> {
            let mut state = self.0.lock().unwrap();
            if state.without_created {
                return Err(zbus::fdo::Error::UnknownProperty("Created".into()));
            }
            if state.created_failures > 0 {
                state.created_failures -= 1;
                return Err(zbus::fdo::Error::Failed("reiniciando".into()));
            }
            Ok(state.created)
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

    /// La identidad de la colección es su ruta y su `Created`, y una vez
    /// fijada las operaciones no vuelven a leer el alias: un `SetAlias` a mitad
    /// de una vuelta no parte las claves entre dos colecciones.
    #[tokio::test]
    async fn la_coleccion_se_fija_una_vez_por_vuelta() {
        let (keys, _server, shared) = fake_keyring().await;
        shared.lock().unwrap().created = 1700;

        let identity = keys.pin_collection().await.unwrap();
        assert_eq!(identity, format!("{COLLECTION_PATH}#1700"));
        let reads = shared.lock().unwrap().alias_reads;

        let key = StoreKey::generate().unwrap();
        keys.store("cuenta", &key).await.unwrap();
        assert_eq!(keys.find("cuenta").await.unwrap(), Some(key));
        assert!(!keys.is_locked().await.unwrap());
        assert_eq!(
            shared.lock().unwrap().alias_reads,
            reads,
            "con la colección fijada no se vuelve a leer el alias"
        );

        // La misma ruta, recreada: otra identidad.
        shared.lock().unwrap().created = 1800;
        assert_eq!(
            keys.pin_collection().await.unwrap(),
            format!("{COLLECTION_PATH}#1800")
        );
    }

    /// Un error pasajero al leer `Created` no es «este llavero no tiene
    /// `Created`»: la vuelta no fija nada y la siguiente lee la identidad de
    /// verdad. Anotado como `ruta#?`, la base quedaba `unavailable` en cuanto
    /// `Created` volvía a contestar.
    #[tokio::test]
    async fn un_error_al_leer_created_no_se_anota_como_coleccion() {
        let (keys, _server, shared) = fake_keyring().await;
        {
            let mut state = shared.lock().unwrap();
            state.created = 1700;
            state.created_failures = 1;
        }
        let first = keys.pin_collection().await;
        assert!(
            matches!(first, Err(KeyError::Failed(_))),
            "un Failed de Created tenía que cortar la vuelta"
        );
        assert!(
            keys.pinned.lock().unwrap().is_none(),
            "sin identidad no se fija ninguna colección"
        );
        assert_eq!(
            keys.pin_collection().await.unwrap(),
            format!("{COLLECTION_PATH}#1700"),
            "la vuelta siguiente lee la identidad de verdad"
        );
    }

    /// Un llavero que no tiene `Created` da siempre la misma identidad, la
    /// ruta y `?`: eso no cambia solo, y no es un error.
    #[tokio::test]
    async fn un_llavero_sin_created_da_siempre_la_misma_identidad() {
        let (keys, _server, shared) = fake_keyring().await;
        shared.lock().unwrap().without_created = true;
        for _ in 0..2 {
            assert_eq!(
                keys.pin_collection().await.unwrap(),
                format!("{COLLECTION_PATH}#?")
            );
        }
    }

    #[test]
    fn solo_lo_que_dice_que_no_hay_propiedad_es_no_tener_created() {
        for name in [
            "org.freedesktop.DBus.Error.UnknownProperty",
            "org.freedesktop.DBus.Error.InvalidArgs",
            "org.freedesktop.DBus.Error.UnknownInterface",
        ] {
            assert!(lacks_property(name), "{name}");
        }
        for name in [
            "org.freedesktop.DBus.Error.Failed",
            "org.freedesktop.DBus.Error.NoReply",
            "org.freedesktop.DBus.Error.ServiceUnknown",
            "org.freedesktop.DBus.Error.UnknownObject",
            "ar.net.vasak.Keyring.Error.InvalidArgs",
        ] {
            assert!(!lacks_property(name), "{name}");
        }
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

    /// Un ítem con el esquema del almacén lo puede plantar cualquiera: uno con
    /// un identificador que no es uno de los nuestros no sale de acá.
    #[tokio::test]
    async fn las_cuentas_del_llavero_descartan_identificadores_invalidos() {
        let (keys, server, shared) = fake_keyring().await;
        keys.store("cuenta", &StoreKey::generate().unwrap())
            .await
            .unwrap();
        {
            let mut state = shared.lock().unwrap();
            for (n, bad) in ["../x", "a\nfalso: se borró todo", ""]
                .into_iter()
                .enumerate()
            {
                state.items.insert(
                    format!("{COLLECTION_PATH}/items/plantado{n}"),
                    (
                        HashMap::from([
                            (SCHEMA_ATTRIBUTE.to_string(), SCHEMA.to_string()),
                            (ACCOUNT_ATTRIBUTE.to_string(), bad.to_string()),
                        ]),
                        vec![b'0'; 64],
                    ),
                );
            }
        }
        // Los ítems plantados también tienen que existir como objetos para que
        // se lea su propiedad `Attributes`.
        for n in 0..3 {
            let path = format!("{COLLECTION_PATH}/items/plantado{n}");
            server
                .object_server()
                .at(path.clone(), FakeItem(shared.clone(), path))
                .await
                .unwrap();
        }

        assert_eq!(
            keys.key_accounts().await.unwrap(),
            vec!["cuenta".to_string()]
        );
    }

    /// En el bus, la regla pide sólo las señales del llavero; y una señal se
    /// acepta sólo si la mandó su dueño.
    #[test]
    fn los_avisos_del_llavero_se_filtran_por_remitente() {
        let rule = lock_change_rule(Some(SERVICE_NAME)).unwrap();
        assert_eq!(
            rule.sender().map(|s| s.as_str()),
            Some("org.freedesktop.secrets")
        );
        assert!(lock_change_rule(None).unwrap().sender().is_none());

        let owner = UniqueName::try_from(":1.7").unwrap();
        let other = UniqueName::try_from(":1.42").unwrap();
        assert!(sent_by(Some(&owner), Some(&owner)));
        assert!(!sent_by(Some(&other), Some(&owner)));
        assert!(!sent_by(None, Some(&owner)));
        assert!(!sent_by(Some(&owner), None));
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
