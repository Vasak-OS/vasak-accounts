use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// CapabilityType — enum polimórfico snake_case
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityType {
    Email,
    Calendar,
    Contacts,
    Chat,
    Drive,
    Tasks,
}

impl CapabilityType {
    /// Todas, en el orden en que se muestran.
    ///
    /// Existe para que la lista de capacidades esté escrita **una vez**: estaba
    /// en el `match` de `permissions.rs` y en el `rename_all` de serde, y una
    /// séptima capacidad habría tenido que agregarse en los dos lugares sin que
    /// nada avisara si se olvidaba uno.
    pub const ALL: [CapabilityType; 6] = [
        CapabilityType::Email,
        CapabilityType::Calendar,
        CapabilityType::Contacts,
        CapabilityType::Chat,
        CapabilityType::Drive,
        CapabilityType::Tasks,
    ];

    /// El nombre con el que viaja por D-Bus, se guarda en `accounts.json` y lo
    /// espera el servicio de permisos. Un test comprueba que coincida con lo
    /// que serializa serde, que es la otra mitad de la misma verdad.
    pub fn as_id(&self) -> &'static str {
        match self {
            CapabilityType::Email => "email",
            CapabilityType::Calendar => "calendar",
            CapabilityType::Contacts => "contacts",
            CapabilityType::Chat => "chat",
            CapabilityType::Drive => "drive",
            CapabilityType::Tasks => "tasks",
        }
    }
}

/// Lo que devuelve un nombre de capacidad que no existe.
///
/// Nombra las válidas: el mensaje termina en el error de D-Bus que ve quien
/// llamó, y «capability inválida» a secas no le dice qué escribir.
#[derive(Debug, PartialEq, Eq)]
pub struct UnknownCapability(pub String);

impl std::fmt::Display for UnknownCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let validas: Vec<&str> = CapabilityType::ALL.iter().map(|c| c.as_id()).collect();
        write!(
            f,
            "capacidad '{}' desconocida; las válidas son: {}",
            self.0,
            validas.join(", "),
        )
    }
}

impl std::error::Error for UnknownCapability {}

/// Convierte el nombre que llegó por D-Bus en una capacidad.
///
/// Antes esto se hacía metiendo el texto recibido dentro de comillas y pasándolo
/// por `serde_json`. Funcionaba de casualidad: un nombre con una comilla o una
/// barra invertida producía JSON inválido, y la persona recibía un error de
/// sintaxis JSON por haber escrito mal «calendar».
impl std::str::FromStr for CapabilityType {
    type Err = UnknownCapability;

    fn from_str(nombre: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|capacidad| capacidad.as_id() == nombre)
            .ok_or_else(|| UnknownCapability(nombre.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Account — struct principal de cuenta
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub display_name: String,
    pub provider_type: String,
    pub capabilities: HashMap<CapabilityType, Value>,

    /// El proveedor dejó de aceptar el refresh_token y hay que volver a
    /// autorizar.
    ///
    /// Pasa cuando la persona revoca el acceso desde la web del proveedor, o
    /// cambia la contraseña, o el token caduca por no usarse. Sin esta marca la
    /// cuenta queda zombi: sigue en la lista, y cada intento de usarla falla
    /// con un error de red que no dice qué hacer.
    ///
    /// `default` porque los archivos escritos antes de que esto existiera no la
    /// tienen, y una cuenta sin la marca es una cuenta que anda.
    #[serde(default)]
    pub needs_reauth: bool,
}

impl Account {
    pub fn new(
        display_name: &str,
        provider_type: &str,
        capabilities: HashMap<CapabilityType, Value>,
    ) -> Self {
        Account {
            id: uuid::Uuid::new_v4().to_string(),
            display_name: display_name.to_string(),
            provider_type: provider_type.to_string(),
            capabilities,
            needs_reauth: false,
        }
    }

    /// Lo que se le cuenta a cualquiera que pregunte qué cuentas hay.
    ///
    /// `provider_unavailable` es lo que el proveedor de esta cuenta anuncia hoy
    /// como sin dirección de servicio (`Provider::unavailable_capabilities`).
    /// Llega de afuera y no se busca acá: así el resumen sigue siendo puro y se
    /// prueba sin catálogo ni D-Bus. Lo que se marca es la intersección con lo
    /// que la cuenta **tiene**: una capacidad que el proveedor no ofrece, o que
    /// la persona no conectó, no se inventa.
    pub fn summary(&self, provider_unavailable: &[CapabilityType]) -> AccountSummary {
        let mut capabilities: Vec<&'static str> = CapabilityType::ALL
            .into_iter()
            .filter(|c| self.capabilities.contains_key(c))
            .map(|c| c.as_id())
            .collect();
        capabilities.sort();

        let mut unavailable_capabilities: Vec<&'static str> = CapabilityType::ALL
            .into_iter()
            .filter(|c| self.capabilities.contains_key(c) && provider_unavailable.contains(c))
            .map(|c| c.as_id())
            .collect();
        unavailable_capabilities.sort();

        AccountSummary {
            id: self.id.clone(),
            display_name: self.display_name.clone(),
            provider_type: self.provider_type.clone(),
            capabilities,
            unavailable_capabilities,
            needs_reauth: self.needs_reauth,
        }
    }
}

/// La versión de una cuenta que `ListAccounts` entrega.
///
/// Es un resumen y no la cuenta entera por una razón concreta. Listar no pide
/// permiso —tiene que poder abrirse la pantalla de cuentas sin que aparezca un
/// diálogo por cada una—, así que lo que sale por ahí lo ve cualquier programa
/// del usuario. La configuración completa de una capacidad incluye a qué
/// servidor se habla, con qué `client_id` y con qué alcances, y eso sólo sale
/// por `GetAccountData`, que sí pregunta.
///
/// Lo que queda acá es lo que una aplicación necesita para dibujar una lista y
/// saber a qué cuenta pedirle permiso después.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AccountSummary {
    pub id: String,
    pub display_name: String,
    pub provider_type: String,
    pub capabilities: Vec<&'static str>,
    /// Las de `capabilities` que la cuenta tiene y **todavía no se pueden
    /// usar**, porque su proveedor no tiene dirección de servicio para ellas.
    ///
    /// Es un subconjunto de `capabilities` y no una resta: la capacidad sigue
    /// en la lista, apagada. Existe para que el gestor de archivos —que sólo
    /// llama `ListAccounts` para dibujar la barra lateral— pueda decir
    /// «todavía no disponible» en vez de «volvé a conectarla», que es falso.
    /// Un cliente viejo que no lo conoce lo ignora.
    pub unavailable_capabilities: Vec<&'static str>,
    pub needs_reauth: bool,
}

// ---------------------------------------------------------------------------
// StorageError
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Json(serde_json::Error),
    /// El archivo que guarda las cuentas **no se pudo leer**, y eso no es lo
    /// mismo que no haya cuentas.
    ///
    /// Existe para que la respuesta sea inequívoca. `ListAccounts` no pide
    /// permiso y la pantalla la dibuja con lo que conteste, así que una lista
    /// vacía significa «esta persona no conectó ninguna cuenta» y nada más. Si
    /// un `accounts.json` que no se puede leer se contestara como lista vacía,
    /// el sincronizador leería dos listados vacíos seguidos, concluiría que la
    /// persona borró sus cuentas y **podaría** las bases locales de correo,
    /// calendario y contactos: en cinco minutos, sin aviso y sin copia de la
    /// que volver. Un error, en cambio, el sincronizador ya lo trata como «no
    /// borrar nada».
    Unreadable {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "IO error: {}", e),
            StorageError::Json(e) => write!(f, "JSON error: {}", e),
            StorageError::Unreadable { path, source } => {
                write!(f, "no se pudo leer {}: {}", path.display(), source)
            }
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageError::Io(e) => Some(e),
            StorageError::Json(e) => Some(e),
            StorageError::Unreadable { source, .. } => Some(source),
        }
    }
}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError::Io(e)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        StorageError::Json(e)
    }
}

// ---------------------------------------------------------------------------
// El marcador de un usuario
// ---------------------------------------------------------------------------

/// El prefijo del archivo que dice que el directorio de una persona existió.
const MARKER_PREFIX: &str = ".instalado-";

/// El marcador de un directorio: **un archivo al lado**, no adentro.
///
/// `directory_existed` —en [`prepare_user_directory`]— dice si el directorio
/// estaba cuando se abrió la base, y no alcanza. Si el directorio entero desaparece —el disco no montó, alguien
/// limpió `/var/lib`, un sistema de archivos se rehízo— la próxima vez
/// `in_directory` lo **vuelve a crear** y `directory_existed` vuelve a decir
/// `false`, exactamente igual que en la primera instalación. De ahí sale una
/// lista vacía, y de ahí la poda.
///
/// El marcador vive en el padre —`/var/lib/vasak-accounts/`, que es de root y
/// que ningún programa de la sesión puede tocar— así que sobrevive a la pérdida
/// del directorio. Un archivo de largo cero: no dice nada, sólo está o no está.
///
/// **No reemplaza a `directory_existed`**: son las dos mitades. Ése dice
/// si el directorio estaba en esta llamada; el marcador dice si existió alguna
/// vez. Un directorio que aparece por primera vez no tiene marcador y no es un
/// error; uno que desaparece teniendo marcador sí lo es.
fn marker_for(directory: &Path) -> Option<PathBuf> {
    let nombre = directory.file_name()?.to_string_lossy().into_owned();
    Some(directory.with_file_name(format!("{MARKER_PREFIX}{nombre}")))
}

/// Deja el marcador puesto, **sin seguir enlaces**.
///
/// El demonio corre **como root**, así que escribir por un enlace simbólico en
/// esta ruta es escritura arbitraria como root: el contenido caería donde el
/// enlace apunte, y además quedaría con 0600 de root encima. Es la misma clase
/// de problema que la cola de salida y que la poda del almacén.
///
/// Por eso no se abre con `OpenOptions::open`, que sigue el enlace. Se abre con
/// **`create_new`**, que es `O_CREAT | O_EXCL` y **no sigue un enlace final**:
/// si ya hay algo con ese nombre —un symlink, un archivo, una carpeta— falla con
/// `AlreadyExists` en vez de escribir por encima. Es el `O_NOFOLLOW` de este
/// caso, sin sin traer la constante de plataforma.
///
/// Y si algo estaba ahí, **sólo se adopta si es un archivo regular**: un symlink
/// no se sigue y no se adopta en silencio. No se mira el dueño porque la carpeta
/// que lo contiene es de root y no hay otro programa que pueda escribir ahí;
/// lo que importa es el **tipo**, que es lo que decide si lo que hay es el
/// marcador o una entrada de la que se valió otro.
fn write_marker(marker: &Path) -> Result<(), StorageError> {
    let sits = |source: std::io::Error| StorageError::Unreadable {
        path: marker.to_path_buf(),
        source,
    };

    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(marker)
    {
        Ok(_) => return Ok(()),
        // Ya había algo con ese nombre: se mira qué es antes de adoptarlo.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => return Err(sits(source)),
    }

    match std::fs::symlink_metadata(marker) {
        Ok(meta) if meta.file_type().is_file() => Ok(()),
        Ok(_) => Err(sits(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{} ya existe y no es un archivo: no se adopta como marcador",
                marker.display()
            ),
        ))),
        Err(source) => Err(sits(source)),
    }
}

/// Si el marcador está, sin confundir «no está» con «no se pudo saber».
///
/// **`symlink_metadata` y no `metadata`**, y por la misma razón que
/// [`write_marker`]: este archivo decide si se pierde una cuenta, así que se
/// pregunta por **la entrada del directorio**, no por lo que haya detrás. Con
/// `metadata`, un symlink a cualquier archivo existente respondería que hay
/// marcador — y peor, uno apuntando a `/dev/null` contestaría que sí sin haber
/// persistido nada. Un symlink tampoco cuenta como marcador: lo que hay en ese
/// nombre no es nuestro, y [`write_marker`] va a fallar al poner el de verdad.
fn marker_exists(marker: &Path) -> Result<bool, StorageError> {
    match std::fs::symlink_metadata(marker) {
        Ok(meta) if meta.file_type().is_file() => Ok(true),
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(StorageError::Unreadable {
            path: marker.to_path_buf(),
            source,
        }),
    }
}

// ---------------------------------------------------------------------------
// AccountDatabase — contenedor con persistencia JSON
// ---------------------------------------------------------------------------

pub struct AccountDatabase {
    path: PathBuf,
    pub accounts: Vec<Account>,
}

/// Lo que [`prepare_user_directory`] encontró en el lugar de `accounts.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountsFile {
    /// Hay algo con ese nombre. Si es el archivo y se puede leer lo decide
    /// [`AccountDatabase::load`], que es quien lo lee.
    Present,
    /// No hay nada, en un directorio que ya tenía datos y en el que algo dice
    /// que hubo cuentas: es una pérdida, no una persona sin cuentas.
    Missing,
}

/// El directorio de una persona, listo para usar: creado si faltaba, con el
/// marcador al lado y **con `accounts.json` adentro**.
///
/// **Todo lo que crea el directorio pasa por acá**: la base de cuentas, las
/// credenciales propias de un proveedor (`SetProviderCredentials`) y el almacén
/// de secretos. Antes cada uno lo creaba por su cuenta con `create_dir_all`, y
/// ninguno escribía `accounts.json` — sólo `save()` lo hacía, y una lectura no
/// guarda. Así quedaba un directorio que existe, con marcador y sin archivo,
/// que es justo lo que la guardia de `vasak-accounts#56` lee como «el archivo
/// se perdió»: desde la segunda llamada, toda persona sin cuentas veía
/// «no se pudo leer accounts.json» para siempre (`vasak-accounts#66`).
///
/// La regla ahora es que **el directorio nunca existe sin `accounts.json` por
/// culpa nuestra**: el que lo crea escribe `[]` en el mismo paso, con la misma
/// escritura privada y atómica que `save()`. Con eso, «directorio sin archivo»
/// vuelve a significar una sola cosa —que algo se lo llevó— y la guardia de
/// `#56` queda igual de estricta.
///
/// `accounts.json` se escribe **antes** que el marcador: si el marcador falla,
/// la próxima apertura encuentra el archivo y lo vuelve a intentar; al revés,
/// quedaría marcador sin archivo, que es el estado roto.
pub fn prepare_user_directory(directory: &Path) -> Result<AccountsFile, StorageError> {
    // **Una preparación por vez.** El demonio atiende varios pedidos de D-Bus a
    // la vez, y lo de abajo es mirar y después escribir: sin esto, un pedido
    // puede ver que el directorio no existe, otro crearlo con su marcador, y el
    // primero leer después el marcador y contestar «el directorio se perdió»
    // — o ver el directorio ya creado, todavía sin `accounts.json`, y contestar
    // que falta. Son unas pocas llamadas al sistema, así que un candado de todo
    // el proceso no se nota. Envenenado no importa: no protege datos en
    // memoria, sólo ordena.
    static PREPARING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _turn = PREPARING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // Antes de crearla, y preguntando por el motivo: `Path::exists()`
    // devuelve `false` también cuando lo que falló fue un permiso o el
    // disco, así que un directorio al que no se puede leer se confunde con
    // uno que todavía no se creó — y esa confusión es la mitad del problema
    // que `load` resuelve.
    let directory_existed = match std::fs::metadata(directory) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(source) => {
            return Err(StorageError::Unreadable {
                path: directory.to_path_buf(),
                source,
            });
        }
    };

    // Y la otra mitad, la de afuera del directorio: alguien que ya tuvo
    // cuentas y a quien le desapareció el directorio entero. Sin esto,
    // `create_dir_all` de abajo lo volvería a crear y quedaría
    // indistinguible de una instalación nueva.
    let marker = marker_for(directory);
    let marked = match &marker {
        Some(marker) => marker_exists(marker)?,
        // Un directorio sin nombre —la raíz itself— no tiene dónde dejar el
        // marcador: se comporta como hasta ahora.
        None => false,
    };
    if marked && !directory_existed {
        return Err(StorageError::Unreadable {
            path: directory.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "el directorio no está, pero {} dice que existió; \
                     no se lo vuelve a crear en silencio",
                    marker.expect("marked implica que hay marcador").display()
                ),
            ),
        });
    }

    std::fs::create_dir_all(directory)?;
    // 0700: the listing alone says which accounts exist.
    let _ = std::fs::set_permissions(directory, PermissionsExt::from_mode(0o700));

    let accounts_path = directory.join(AccountDatabase::FILE_NAME);
    let state = if !directory_existed {
        // Recién creado: es el momento de dejar el archivo para que la
        // próxima apertura no lo eche de menos. **Sin pisar nada**: otro pedido
        // del mismo uid pudo haber pasado por acá al mismo tiempo y hasta
        // haber guardado ya una cuenta (ver [`create_private_new`]).
        create_private_new(&accounts_path, b"[]")?;
        AccountsFile::Present
    } else {
        match std::fs::symlink_metadata(&accounts_path) {
            // Cualquier cosa con ese nombre —también un symlink o una
            // carpeta— la juzga `load`, que la lee. Acá no se pisa nada.
            Ok(_) => AccountsFile::Present,
            // **Un directorio que ya estaba y no tiene el archivo es una
            // pérdida, siempre.** No se intenta adivinar si «nunca tuvo
            // cuentas»: desde este cambio, quien crea el directorio escribe
            // `[]` en el mismo paso, así que el estado no lo produce el
            // demonio; y para los que quedaron así antes (`vasak-accounts#66`)
            // no hay ninguna señal inequívoca que los separe de una pérdida
            // —una cuenta sin secretos que pierde `accounts.json` deja el
            // mismo directorio—. Equivocarse es la poda de `#56`, así que se
            // falla cerrado y la salida es a mano: ver el README.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(
                    "falta {} en un directorio que ya existía: no se contesta \
                     lista vacía. Si esta persona nunca tuvo cuentas, crearlo a \
                     mano con `[]` (root, 0600); ver el README",
                    accounts_path.display()
                );
                AccountsFile::Missing
            }
            Err(source) => {
                return Err(StorageError::Unreadable {
                    path: accounts_path,
                    source,
                });
            }
        }
    };

    // El marcador se deja puesto en los dos caminos en que puede faltar: una
    // instalación nueva y una vieja que todavía no lo tenía. Así, la
    // próxima vez que el directorio falte, el hueco se ve.
    //
    // **Si no se puede, es un error, y no se sigue.**
    //
    // La tentación es avisar en el diario y seguir, y parece inofensiva: el
    // padre es de root, y si no fuera escribible `create_dir_all` de arriba
    // ya habría fallado. Pero esa es justo la falsa tranquilidad. Lo que
    // queda es un symlink colgante en el nombre del marcador o un disco
    // lleno — `ENOSPC` — y en los dos casos **no** es un estado degradado
    // pero en servicio: es un estado en el que el demonio acaba de no poder
    // registrar que esta cuenta existe. Si se sigue, la próxima pérdida del
    // directorio se lee como instalación nueva, la carga contesta lista
    // vacía, y el podador borra las bases locales y la clave. Eso es
    // exactamente el bug de `vasak-accounts#56`, reintroducido por la puerta
    // de atrás: el marcador tiene que ser **fail closed**.
    //
    // Y el error no deja a nadie a la vista: el sincronizador trata un
    // `ListAccounts` fallido como `AccountListing::Failed`, que es
    // «no borrar nada». Lo que se pierde es la lista de cuentas en
    // Configuración, y eso se arregla mirando el diario; lo que se gana es
    // que no haya dos listados vacíos que borren el correo de la persona.
    if let Some(marker) = marker {
        if !marked {
            write_marker(&marker)?;
        }
    }

    Ok(state)
}

/// Lo mismo, para quien va a **escribir al lado** de las cuentas sin leerlas:
/// las credenciales de un proveedor y el almacén de secretos.
///
/// Un `accounts.json` que falta es un error también para ellos: al lado de una
/// pérdida no se escribe nada hasta que alguien la mire. Si no, un `client_id`
/// guardado encima de un directorio roto lo dejaría con cara de sano y movería
/// las fechas que quien lo revise a mano puede necesitar.
pub fn prepare_user_directory_for_write(directory: &Path) -> Result<(), StorageError> {
    match prepare_user_directory(directory)? {
        AccountsFile::Present => Ok(()),
        AccountsFile::Missing => Err(StorageError::Unreadable {
            path: directory.join(AccountDatabase::FILE_NAME),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "falta en un directorio que ya existía; no se escribe nada al \
                 lado hasta que se resuelva",
            ),
        }),
    }
}

impl AccountDatabase {
    /// Root-owned, one directory per user.
    ///
    /// This used to live in the user's own configuration directory, which meant
    /// the tokens beside it were reachable by anything running as that user.
    /// Now the daemon is the only way in, and the permission service decides
    /// who gets through.
    const ROOT: &'static str = "/var/lib/vasak-accounts";
    const FILE_NAME: &'static str = "accounts.json";

    /// Where one user's data lives. Nothing outside this directory is ever
    /// touched on their behalf, so one person's request cannot reach another
    /// person's accounts.
    pub fn directory_for(uid: u32) -> PathBuf {
        Self::root().join(uid.to_string())
    }

    fn root() -> PathBuf {
        // Development override, debug builds only: the released daemon has no
        // way to be pointed at a directory somebody else can write.
        #[cfg(debug_assertions)]
        if let Some(root) = std::env::var_os("VASAK_ACCOUNTS_TEST_ROOT") {
            return PathBuf::from(root);
        }
        PathBuf::from(Self::ROOT)
    }

    pub fn for_user(uid: u32) -> Result<Self, StorageError> {
        Self::in_directory(Self::directory_for(uid))
    }

    /// Opens a database in a specific directory. The per-user path resolves to
    /// this; tests use it directly so they do not have to share a process-wide
    /// setting and can run alongside each other.
    ///
    /// Un `accounts.json` que falta no es un error **acá**: lo es al leerlo,
    /// en [`AccountDatabase::load`], que es donde lo esperan quienes llaman.
    pub fn in_directory(directory: PathBuf) -> Result<Self, StorageError> {
        prepare_user_directory(&directory)?;
        Ok(AccountDatabase {
            path: directory.join(Self::FILE_NAME),
            accounts: Vec::new(),
        })
    }

    /// Lee `accounts.json` y carga las cuentas en memoria.
    ///
    /// **Un archivo que no se puede leer es un error, nunca una lista vacía.**
    /// La lista vacía dice una sola cosa: que esta persona todavía no conectó
    /// ninguna cuenta. Un `accounts.json` que falta —el disco no montó, cambió
    /// un permiso, algo se lo llevó— contestado como lista vacía le dice al
    /// sincronizador que la persona no tiene cuentas, y el sincronizador poda
    /// las bases locales de las que dejó de ver en dos listados seguidos. El
    /// resultado es que a los cinco minutos se borran el correo, el calendario y
    /// los contactos, y no queda copia de la que volver.
    ///
    /// El sincronizador ya trata un error como «no borrar nada»
    /// (`AccountListing::Failed`), así que el error es la respuesta segura.
    ///
    /// **Y ahora falta siempre es error**, también la primera vez:
    /// [`prepare_user_directory`] escribe `[]` al crear el directorio, así que
    /// una persona sin cuentas tiene el archivo. Antes la primera vez se
    /// distinguía por si el directorio se acababa de crear, y la segunda ya no
    /// (`vasak-accounts#66`).
    pub fn load(&mut self) -> Result<(), StorageError> {
        // Se lee y se pregunta por el motivo. `self.path.exists()` devolvía
        // `false` para todo lo que no sea «existe» —un permiso cambiado, un
        // directorio donde debería estar el archivo, un enlace roto— y cada uno
        // de esos casos terminaba en una lista vacía.
        let data = match std::fs::read(&self.path) {
            Ok(data) => data,
            Err(source) => {
                return Err(StorageError::Unreadable {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        self.accounts = serde_json::from_slice(&data)?;
        Ok(())
    }

    /// Persiste el estado actual de `accounts` a `accounts.json`.
    pub fn save(&self) -> Result<(), StorageError> {
        let data = serde_json::to_string_pretty(&self.accounts)?;
        write_private(&self.path, data.as_bytes())?;
        Ok(())
    }

    /// Agrega una cuenta, persiste y retorna el ID asignado.
    pub fn add(&mut self, account: Account) -> Result<String, StorageError> {
        let id = account.id.clone();
        self.accounts.push(account);
        self.save()?;
        Ok(id)
    }

    pub fn all(&self) -> &[Account] {
        &self.accounts
    }

    pub fn get(&self, id: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.id == id)
    }

    /// Sólo para los tests: la aplicación nunca pregunta cuántas cuentas hay.
    ///
    /// Con `#[cfg(test)]` en lugar de un `allow(dead_code)`: así no viaja en el
    /// binario y el aviso de código muerto sigue sirviendo para lo que de verdad
    /// no se usa.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    pub fn update_account(&mut self, updated: Account) -> Result<(), StorageError> {
        let id = updated.id.clone();
        let pos = self
            .accounts
            .iter()
            .position(|a| a.id == id)
            .ok_or_else(|| {
                StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Account '{}' not found for update", id),
                ))
            })?;
        self.accounts[pos] = updated;
        self.save()?;
        Ok(())
    }

    /// Marca —o desmarca— que una cuenta necesita volver a autorizarse.
    ///
    /// Devuelve si la marca **cambió**: quien llama usa eso para avisar por la
    /// señal sólo cuando hay algo nuevo, y no en cada refresco fallido de una
    /// cuenta que ya estaba marcada.
    pub fn set_needs_reauth(&mut self, id: &str, needs: bool) -> Result<bool, StorageError> {
        let Some(cuenta) = self.accounts.iter_mut().find(|a| a.id == id) else {
            return Ok(false);
        };
        if cuenta.needs_reauth == needs {
            return Ok(false);
        }
        cuenta.needs_reauth = needs;
        self.save()?;
        Ok(true)
    }

    pub fn remove(&mut self, id: &str) -> Result<bool, StorageError> {
        let len = self.accounts.len();
        self.accounts.retain(|a| a.id != id);
        if self.accounts.len() != len {
            self.save()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------------------
// SecretStore — tokens del lado de root
// ---------------------------------------------------------------------------

/// Where the tokens live now.
///
/// They used to be in the user's own keyring, which meant the permission check
/// in front of this daemon protected nothing: any program running as that user
/// could ask the keyring for the token directly and skip the question
/// entirely. Root-owned files make the daemon the only way to reach them.
///
/// The files are not encrypted on top of that, deliberately. A key the daemon
/// can read unattended has to sit next to what it protects, which buys nothing
/// against anyone who can already read the file — the same reasoning that has
/// NetworkManager keep Wi-Fi passwords as root-owned plain text. Protection
/// against a stolen disk is full-disk encryption's job, not this file's.
pub struct SecretStore;

impl SecretStore {
    const FILE_NAME: &'static str = "secrets.json";

    /// account id → (secret name → value).
    fn load(
        directory: &std::path::Path,
    ) -> Result<HashMap<String, HashMap<String, String>>, StorageError> {
        let path = directory.join(Self::FILE_NAME);
        if !path.exists() {
            return Ok(HashMap::new());
        }
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }

    fn persist(
        directory: &std::path::Path,
        secrets: &HashMap<String, HashMap<String, String>>,
    ) -> Result<(), StorageError> {
        // Por el mismo camino que la base: si este fuera el que crea el
        // directorio, lo dejaría sin `accounts.json` (`vasak-accounts#66`).
        prepare_user_directory_for_write(directory)?;

        write_private(
            &directory.join(Self::FILE_NAME),
            serde_json::to_string(secrets)?.as_bytes(),
        )
    }

    pub fn store_secret(
        uid: u32,
        account_id: &str,
        key: &str,
        secret: &str,
    ) -> Result<(), StorageError> {
        Self::store_secret_in(
            &AccountDatabase::directory_for(uid),
            account_id,
            key,
            secret,
        )
    }

    /// The per-user calls resolve to these; tests use them directly rather than
    /// sharing a process-wide setting.
    pub fn store_secret_in(
        directory: &std::path::Path,
        account_id: &str,
        key: &str,
        secret: &str,
    ) -> Result<(), StorageError> {
        let mut secrets = Self::load(directory)?;
        secrets
            .entry(account_id.to_string())
            .or_default()
            .insert(key.to_string(), secret.to_string());
        Self::persist(directory, &secrets)
    }

    pub fn get_secret(uid: u32, account_id: &str, key: &str) -> Result<String, StorageError> {
        Self::get_secret_in(&AccountDatabase::directory_for(uid), account_id, key)
    }

    pub fn get_secret_in(
        directory: &std::path::Path,
        account_id: &str,
        key: &str,
    ) -> Result<String, StorageError> {
        Self::load(directory)?
            .get(account_id)
            .and_then(|entry| entry.get(key))
            .cloned()
            .ok_or_else(|| {
                StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no hay '{key}' guardado para la cuenta '{account_id}'"),
                ))
            })
    }

    /// The access token, which is the secret asked for most often.
    pub fn store_token(uid: u32, account_id: &str, token: &str) -> Result<(), StorageError> {
        Self::store_secret(uid, account_id, "access", token)
    }

    pub fn get_token(uid: u32, account_id: &str) -> Result<String, StorageError> {
        Self::get_secret(uid, account_id, "access")
    }

    /// Removes everything held for one account.
    ///
    /// Called when the account is deleted: leaving the tokens behind would keep
    /// a live credential on disk for something the user believes is gone.
    pub fn forget_account(uid: u32, account_id: &str) -> Result<(), StorageError> {
        Self::forget_account_in(&AccountDatabase::directory_for(uid), account_id)
    }

    pub fn forget_account_in(
        directory: &std::path::Path,
        account_id: &str,
    ) -> Result<(), StorageError> {
        let mut secrets = Self::load(directory)?;
        if secrets.remove(account_id).is_some() {
            Self::persist(directory, &secrets)?;
        }
        Ok(())
    }
}

/// Un temporal **propio de este intento**, al lado de `path`.
///
/// Antes era siempre `<nombre>.tmp`, compartido: dos escrituras concurrentes
/// del mismo archivo —dos pedidos de D-Bus del mismo uid, que el demonio
/// atiende a la vez— truncaban y escribían el mismo temporal, y lo que llegaba
/// al `rename` podía ser una mezcla de las dos. Con un nombre por intento cada
/// una escribe el suyo, y lo que queda en su lugar es una de las dos entera.
/// Empieza con punto para no confundirse con un dato al listar el directorio.
fn unique_temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()))
}

/// El temporal con los datos, creado 0600 y **sin seguir enlaces**:
/// `create_new` es `O_CREAT | O_EXCL`, y el nombre es nuevo, así que nadie pudo
/// dejar nada esperando ahí.
fn write_temp(temp: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp)?;
    file.write_all(data).and_then(|_| file.sync_all())
}

/// Writes a file only its owner can read, replacing it in one step.
///
/// Created 0600 from the start rather than fixed up afterwards, so a token is
/// never briefly world-readable; and renamed into place so an interrupted write
/// cannot leave a half-written file where the credentials used to be.
///
/// El temporal es único por escritura: ver [`unique_temp_path`].
pub fn write_private(path: &std::path::Path, data: &[u8]) -> Result<(), StorageError> {
    let temp = unique_temp_path(path);
    match write_temp(&temp, data).and_then(|_| std::fs::rename(&temp, path)) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&temp);
            Err(StorageError::Io(error))
        }
    }
}

/// Escribe un archivo privado **sólo si no hay ninguno con ese nombre**.
///
/// Es la escritura inicial de `accounts.json`. Con `write_private` —que
/// reemplaza— había una carrera: dos pedidos del mismo uid ven a la vez que el
/// directorio no existía, uno guarda una cuenta, y el `rename` del `[]` del otro
/// la pisa sin error. Acá el temporal (único) se **enlaza** en su lugar con
/// `hard_link`, que es `link(2)`: falla con `AlreadyExists` si ya hay algo con
/// ese nombre —archivo, carpeta o symlink, sin seguirlo— y nunca reemplaza.
/// Y `AlreadyExists` no es un error: es que otro llegó primero, y lo que
/// dejó es lo que se lee.
///
/// Devuelve si lo creó esta llamada.
fn create_private_new(path: &Path, data: &[u8]) -> Result<bool, StorageError> {
    let temp = unique_temp_path(path);
    let linked = write_temp(&temp, data).and_then(|_| std::fs::hard_link(&temp, path));
    let _ = std::fs::remove_file(&temp);
    match linked {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(StorageError::Io(error)),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    fn sample_account() -> Account {
        let mut caps = HashMap::new();
        caps.insert(
            CapabilityType::Email,
            json!({
                "address": "alice@gmail.com",
                "imap_host": "imap.gmail.com",
                "imap_port": 993,
            }),
        );
        caps.insert(
            CapabilityType::Drive,
            json!({
                "root_folder": "/",
                "max_storage_gb": 15,
            }),
        );
        Account::new("Alice Google", "google", caps)
    }

    #[test]
    fn test_account_serde_roundtrip() {
        let account = sample_account();

        let json = serde_json::to_string_pretty(&account).unwrap();
        let deserialized: Account = serde_json::from_str(&json).unwrap();

        assert_eq!(account.id, deserialized.id);
        assert_eq!(account.display_name, deserialized.display_name);
        assert_eq!(account.provider_type, deserialized.provider_type);
        assert_eq!(
            account.capabilities.get(&CapabilityType::Email),
            deserialized.capabilities.get(&CapabilityType::Email),
        );
    }

    #[test]
    fn test_update_account() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        let id = db.add(sample_account()).unwrap();

        let mut updated = db.get(&id).unwrap().clone();
        updated.display_name = "Updated Name".into();
        db.update_account(updated).unwrap();

        let reloaded = db.get(&id).unwrap();
        assert_eq!(reloaded.display_name, "Updated Name");

        remove_test_database(&dir);
    }

    /// Las dos mitades de la misma verdad: `as_id()` es lo que se le manda al
    /// servicio de permisos y `Serialize` es lo que se escribe en
    /// `accounts.json`. Si se separan, un permiso concedido deja de encontrar
    /// la cuenta a la que corresponde y nadie se enteraría.
    #[test]
    fn el_nombre_de_la_capacidad_es_el_mismo_para_serde_y_para_los_permisos() {
        for capacidad in CapabilityType::ALL {
            let por_serde = serde_json::to_string(&capacidad).unwrap();
            assert_eq!(
                por_serde,
                format!("\"{}\"", capacidad.as_id()),
                "{capacidad:?} se serializa distinto de su as_id()",
            );
        }
    }

    #[test]
    fn se_reconocen_las_seis_capacidades_por_su_nombre() {
        for capacidad in CapabilityType::ALL {
            assert_eq!(capacidad.as_id().parse::<CapabilityType>(), Ok(capacidad));
        }
    }

    /// Antes el nombre recibido por D-Bus se metía entre comillas y se pasaba
    /// por `serde_json`, así que una comilla o una barra invertida producían
    /// JSON inválido y la persona recibía un error de sintaxis JSON. Ahora
    /// cualquier nombre que no esté en la lista da el mismo error claro.
    #[test]
    fn un_nombre_con_comillas_o_barras_es_un_nombre_desconocido_y_nada_mas() {
        for entrada in ["email\"", "\"email\"", "email\\", "e\"mail", "\\", "\""] {
            assert_eq!(
                entrada.parse::<CapabilityType>(),
                Err(UnknownCapability(entrada.to_string())),
                "{entrada:?} debía rechazarse como desconocido",
            );
        }
    }

    #[test]
    fn los_nombres_que_no_existen_se_rechazan() {
        // "Email" incluido: los identificadores son en minúscula y aceptar la
        // variante en mayúscula grabaría permisos contra un nombre que después
        // nadie vuelve a encontrar.
        for entrada in ["", "Email", "EMAIL", "emial", "correo", "account.email"] {
            assert!(
                entrada.parse::<CapabilityType>().is_err(),
                "{entrada:?} no debía aceptarse",
            );
        }
    }

    /// El mensaje va a parar al error de D-Bus que ve quien llamó, así que
    /// tiene que decirle qué escribir.
    #[test]
    fn el_error_nombra_las_capacidades_validas() {
        let mensaje = "emial".parse::<CapabilityType>().unwrap_err().to_string();
        assert!(
            mensaje.contains("emial"),
            "falta lo que se escribió: {mensaje}"
        );
        for capacidad in CapabilityType::ALL {
            assert!(
                mensaje.contains(capacidad.as_id()),
                "el mensaje no nombra '{}': {mensaje}",
                capacidad.as_id(),
            );
        }
    }

    #[test]
    fn test_capability_type_snake_case() {
        let json = serde_json::to_string(&CapabilityType::Email).unwrap();
        assert_eq!(json, "\"email\"");

        let json = serde_json::to_string(&CapabilityType::Calendar).unwrap();
        assert_eq!(json, "\"calendar\"");

        let json = serde_json::to_string(&CapabilityType::Contacts).unwrap();
        assert_eq!(json, "\"contacts\"");
    }

    #[test]
    fn test_database_load_save_roundtrip() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());

        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        assert!(db.is_empty());

        db.add(sample_account()).unwrap();
        assert_eq!(db.len(), 1);

        let mut db2 = AccountDatabase::in_directory(dir.clone()).unwrap();
        db2.load().unwrap();
        assert_eq!(db2.len(), 1);
        assert_eq!(
            db2.get(&db.accounts[0].id).unwrap().display_name,
            "Alice Google"
        );

        remove_test_database(&dir);
    }

    /// Borrar algo que ya no está no es un error, pero tampoco puede decir que
    /// borró: el llamante usa ese `bool` para avisarle a la persona.
    #[test]
    fn borrar_una_cuenta_que_no_existe_devuelve_false() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        let id = db.add(sample_account()).unwrap();

        assert!(!db.remove("no-existe").unwrap());
        assert!(db.get(&id).is_some(), "la otra cuenta tenía que quedar");
        assert!(db.remove(&id).unwrap());
        assert!(db.get(&id).is_none());

        remove_test_database(&dir);
    }

    /// Actualizar una cuenta que no está tiene que fallar y no agregarla en
    /// silencio: sería una cuenta nueva que nadie pidió.
    #[test]
    fn actualizar_una_cuenta_que_no_existe_falla() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();

        let huerfana = sample_account();
        assert!(db.update_account(huerfana).is_err());
        assert!(db.is_empty(), "no tenía que quedar ninguna cuenta");

        remove_test_database(&dir);
    }

    /// Un `accounts.json` ilegible tiene que dar error y **no** dejar la lista
    /// vacía: con una lista vacía el daemon diría que la persona no tiene
    /// cuentas, y el primer `save()` encima pisaría el archivo dañado con `[]`.
    #[test]
    fn un_accounts_json_corrupto_da_error_en_vez_de_lista_vacia() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        db.add(sample_account()).unwrap();

        std::fs::write(dir.join("accounts.json"), "{ esto no es json").unwrap();

        let mut otra = AccountDatabase::in_directory(dir.clone()).unwrap();
        assert!(matches!(otra.load(), Err(StorageError::Json(_))));

        remove_test_database(&dir);
    }

    /// Un directorio sin `accounts.json` es una cuenta nueva, no un fallo: es
    /// lo que se encuentra en el primer arranque.
    #[test]
    fn un_directorio_vacio_carga_sin_cuentas_y_sin_error() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        assert!(db.is_empty());
        assert!(db.get("cualquiera").is_none());

        remove_test_database(&dir);
    }

    /// Un `accounts.json` que **falta después de haber existido** es una pérdida
    /// de datos, no una cuenta nueva, y tiene que llegar como error.
    ///
    /// Es el caso que abre `Vasak-OS/vasak-accounts#56`, y el que borra el
    /// correo, el calendario y los contactos de la persona. El podador del
    /// sincronizador necesita dos listados seguidos para confirmar que una
    /// cuenta se fue, y dos listados vacíos confirman exactamente eso: en cinco
    /// minutos, todas las bases locales, sin aviso y sin copia.
    ///
    /// Borrar la última cuenta nunca borra el archivo —`remove()` escribe `[]` en
    /// él—, así que un directorio que ya estaba y no tiene `accounts.json` no es
    /// una persona sin cuentas: es un archivo que se perdió.
    #[test]
    fn un_accounts_json_que_falta_despues_de_haber_existido_da_error() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        db.add(sample_account()).unwrap();
        assert!(dir.join("accounts.json").exists());

        // El disco no montó, o algo se lo llevó.
        std::fs::remove_file(dir.join("accounts.json")).unwrap();

        let mut otra = AccountDatabase::in_directory(dir.clone()).unwrap();
        let error = otra
            .load()
            .expect_err("un archivo que falta no es una lista vacía");
        assert!(
            matches!(error, StorageError::Unreadable { .. }),
            "se esperaba Unreadable, vino {error:?}",
        );
        assert!(
            otra.is_empty(),
            "y aunque falle, no puede quedar una lista vacía por la cual pasar",
        );

        remove_test_database(&dir);
    }

    /// Un `accounts.json` que no se puede leer es un error, y lo mismo vale
    /// cuando lo que no se puede leer es **el directorio**: `Path::exists()` no
    /// distingue «no existe» de «no tengo permiso para saber si existe», así
    /// que ambos terminaban como lista vacía.
    ///
    /// Se le quita el acceso a la carpeta que **contiene** la de la persona, y
    /// no a la de la persona: `in_directory` vuelve a ponerla en 0700 en cada
    /// apertura, así que poniéndole el permiso a ella la prueba no probaría
    /// nada.
    #[test]
    fn un_directorio_que_no_se_puede_leer_da_error_y_no_una_lista_vacia() {
        if running_as_root() {
            // Root no lo bloquea un `chmod`: la prueba no probaría nada.
            return;
        }

        let raiz = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let dir = raiz.join("1000");
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        db.add(sample_account()).unwrap();

        std::fs::set_permissions(&raiz, std::fs::Permissions::from_mode(0o000)).unwrap();

        let error = AccountDatabase::in_directory(dir.clone())
            .and_then(|mut db| db.load())
            .expect_err("un directorio ilegible no es una lista vacía");
        assert!(
            matches!(error, StorageError::Unreadable { .. }),
            "se esperaba Unreadable, vino {error:?}",
        );

        std::fs::set_permissions(&raiz, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(raiz).unwrap_or_default();
    }

    /// Un directorio donde debería estar el archivo, o un archivo que es un
    /// directorio, tienen que caer en la misma variante que el resto de «no se
    /// pudo leer». Ya daban error antes —leer una carpeta da `EISDIR`— pero como
    /// un `Io` cualquiera, y quien lee el error no puede distinguir «el disco
    /// está mal» de «ahí hay algo que no es el archivo», que para esta persona
    /// es la misma noticia.
    #[test]
    fn algo_que_no_es_el_archivo_tampoco_da_una_lista_vacia() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        db.add(sample_account()).unwrap();

        std::fs::remove_file(dir.join("accounts.json")).unwrap();
        // El directorio de la persona sigue ahí, pero donde iba el archivo hay
        // una carpeta: leerla da EISDIR, no «no hay cuentas».
        std::fs::create_dir(dir.join("accounts.json")).unwrap();

        let mut otra = AccountDatabase::in_directory(dir.clone()).unwrap();
        let error = otra
            .load()
            .expect_err("una carpeta donde va el archivo no es una lista vacía");
        assert!(
            matches!(error, StorageError::Unreadable { .. }),
            "se esperaba Unreadable, vino {error:?}",
        );

        remove_test_database(&dir);
    }

    /// **Un directorio que se perdió es un error, no una instalación nueva.**
    ///
    /// Es la otra mitad de `directory_existed`, y el agujero que quedó después
    /// del primer arreglo de este mismo PR: `in_directory` crea el directorio si
    /// falta, así que un directorio entero que desaparece volvía a ser
    /// `directory_existed = false` — indistinguible de la primera vez —, la
    /// carga contestaba lista vacía y el podador del sincronizador borraba las
    /// bases locales y la clave, como en el caso del archivo perdido.
    ///
    /// Es un hueco **preexistente**: la implementación anterior respondía
    /// cualquier ausencia con lista vacía, así que este PR no lo introduce, lo
    /// cierra. Lo que lo distingue es que con el marcador el dato para saberlo
    /// existe, y está al lado del directorio, en una carpeta de root que ningún
    /// programa de la sesión puede tocar.
    ///
    /// Nótese que el directorio **no** se recrea: la respuesta es error, y el
    /// sincronizador trata un error como «no borrar nada».
    #[test]
    fn un_directorio_que_se_perdio_da_error_y_no_una_cuenta_nueva() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        db.add(sample_account()).unwrap();

        let marcador = marker_for(&dir).expect("un directorio con nombre tiene marcador");
        assert!(marcador.exists(), "el marcador no se dejó puesto");

        // El directorio entero se va: el marcador, que vive en el padre, no.
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!dir.exists());
        assert!(
            marcador.exists(),
            "el marcador no puede estar adentro del directorio"
        );

        let error = AccountDatabase::in_directory(dir.clone())
            .and_then(|mut db| db.load())
            .expect_err("un directorio perdido no es una instalación nueva");
        assert!(
            matches!(error, StorageError::Unreadable { .. }),
            "se esperaba Unreadable, vino {error:?}",
        );
        // Y el mensaje dice por qué, que es lo que hace falta para no mandarle
        // a la persona a revisar la cuenta.
        let mensaje = error.to_string();
        assert!(mensaje.contains(".instalado-"), "{mensaje}");

        // Lo que no puede pasar: que se lo vuelva a crear y quede en limpio.
        assert!(
            !dir.exists() || std::fs::read_dir(&dir).unwrap().next().is_none(),
            "se recreó el directorio perdido",
        );

        remove_test_database(&dir);
    }

    /// **Un symlink en el nombre del marcador no se sigue, y es un error.**
    ///
    /// El demonio corre **como root**: escribir por un enlace en
    /// `/var/lib/vasak-accounts/` es escritura arbitraria como root, y el
    /// contenido además quedaría con 0600 de root encima. Es la misma clase de
    /// problema que la cola de salida y que la poda del almacén, y es la misma
    /// solución: abrir sin seguir enlaces.
    ///
    /// Acá lo que se garantiza es que el archivo de la otra punta **no existe**: se
    /// abre con `create_new`, que es `O_CREAT | O_EXCL` y no sigue un enlace
    /// final, así que en vez de escribir por él falla.
    #[test]
    fn un_symlink_en_el_marcador_no_se_sigue_ni_se_adopta() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        AccountDatabase::in_directory(dir.clone()).unwrap();
        let marcador = marker_for(&dir).unwrap();
        // Lo que dejó la apertura, afuera: ahora le ponemos un symlink encima.
        let _ = std::fs::remove_file(&marcador);

        // A donde apunta el symlink: un archivo de otra cuenta, digamos.
        let objetivo = dir.with_file_name(format!(
            "ajeno-{}",
            dir.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&objetivo, "esto no es un marcador").unwrap();
        std::os::unix::fs::symlink(&objetivo, &marcador).unwrap();

        let error = match AccountDatabase::in_directory(dir.clone()) {
            Err(error) => error,
            Ok(_) => panic!("un symlink en el nombre del marcador no se adopta en silencio"),
        };
        assert!(
            matches!(error, StorageError::Unreadable { .. }),
            "se esperaba Unreadable, vino {error:?}",
        );
        assert!(error.to_string().contains("no es un archivo"), "{error}");

        // Y lo importante: lo que estaba del otro lado no se tocó.
        assert_eq!(
            std::fs::read_to_string(&objetivo).unwrap(),
            "esto no es un marcador",
            "se escribió por el symlink",
        );
        // Ni se lo volvió a crear encima como si fuera nuestro.
        assert!(
            std::fs::symlink_metadata(&marcador)
                .unwrap()
                .file_type()
                .is_symlink(),
            "el symlink se reemplazó en vez de fallar",
        );

        let _ = std::fs::remove_file(&objetivo);
        remove_test_database(&dir);
    }

    /// `marker_exists` pregunta por **la entrada del directorio**, no por lo que
    /// haya detrás. Con `metadata`, un symlink a cualquier archivo existente
    /// respondería que hay marcador — y uno a `/dev/null` contestaría que sí sin
    /// haber persistido nada, que es peor: la cuenta se daría por perdida
    /// solapada y sin registro.
    #[test]
    fn un_symlink_no_cuenta_como_marcador() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        AccountDatabase::in_directory(dir.clone()).unwrap();
        let marcador = marker_for(&dir).unwrap();
        let _ = std::fs::remove_file(&marcador);

        let objetivo = dir.with_file_name(format!(
            "existente-{}",
            dir.file_name().unwrap().to_string_lossy()
        ));
        std::fs::write(&objetivo, "soy un archivo cualquiera").unwrap();
        std::os::unix::fs::symlink(&objetivo, &marcador).unwrap();

        assert!(
            !marker_exists(&marcador).unwrap(),
            "un symlink se contó como marcador",
        );
        // Y un archivo de verdad sí cuenta.
        let _ = std::fs::remove_file(&marcador);
        std::fs::write(&marcador, "").unwrap();
        assert!(marker_exists(&marcador).unwrap());
        // Y una carpeta con el nombre del marcador tampoco.
        let _ = std::fs::remove_file(&marcador);
        std::fs::create_dir(&marcador).unwrap();
        assert!(!marker_exists(&marcador).unwrap());

        let _ = std::fs::remove_file(&objetivo);
        remove_test_database(&dir);
    }

    /// **El marcador no se puede escribir → error, no una lista vacía.**
    ///
    /// Este es el punto por el que la versión anterior **fallaba abierto**:
    /// avisaba en el diario y seguía con una base sin marcador, así que la
    /// próxima pérdida del directorio se leía como instalación nueva y la lista
    /// volvía a salir vacía. Con un symlink en el nombre se llega a ese estado
    /// sin perder nada: `create_dir_all` del directorio sí funciona.
    ///
    /// La única forma de provocar que el marcador no se pueda escribir en una
    /// carpeta normal es ocuparle el nombre con algo que no es un archivo —un
    /// symlink—, que es lo que hace esta prueba.
    #[test]
    fn si_el_marcador_no_se_puede_escribir_da_error_y_no_una_lista_vacia() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        AccountDatabase::in_directory(dir.clone()).unwrap();
        let marcador = marker_for(&dir).unwrap();
        let _ = std::fs::remove_file(&marcador);

        let dir_inexistente = dir.with_file_name(format!(
            "colgado-{}",
            dir.file_name().unwrap().to_string_lossy()
        ));
        std::os::unix::fs::symlink(&dir_inexistente, &marcador).unwrap();

        let error = match AccountDatabase::in_directory(dir.clone()) {
            Err(error) => error,
            Ok(_) => panic!("sin marcador no se sigue: el hueco volvería a abrirse"),
        };
        assert!(
            matches!(error, StorageError::Unreadable { .. }),
            "{error:?}"
        );

        // Y el mensaje dice qué pasó, que es lo que va a leer el diario.
        let mensaje = error.to_string();
        assert!(mensaje.contains(marcador.to_str().unwrap()), "{mensaje}");

        let _ = std::fs::remove_file(&marcador);
        remove_test_database(&dir);
    }

    /// La primera instalación: no hay directorio ni marcador, y eso **no** es un
    /// error. Es lo que se encuentra en el primer arranque, y contestarle error
    /// dejaría la cuenta sin poder conectarse nunca.
    #[test]
    fn una_instalacion_nueva_no_tiene_marcador_y_no_da_error() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        assert!(!marker_for(&dir).unwrap().exists());

        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load()
            .expect("una instalación nueva carga sin cuentas y sin error");
        assert!(db.is_empty());
        // Y deja el marcador puesto, para que la próxima pérdida se vea.
        assert!(marker_for(&dir).unwrap().exists(), "no se dejó el marcador");

        remove_test_database(&dir);
    }

    /// Una instalación de antes de este PR: hay directorio y no hay marcador.
    ///
    /// Es el caso que importa para no romper a nadie: tiene que cargar normal, y
    /// además tiene que **dejar el marcador**, porque si no la pérdida siguiente
    /// de ese directorio seguiría sin verse.
    #[test]
    fn una_instalacion_vieja_carga_normal_y_deja_el_marcador() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        db.add(sample_account()).unwrap();

        // Estado de una instalación que ya venía de antes: cuentas, y el
        // marcador que este PR todavía no tuvo ocasión de dejar.
        let marcador = marker_for(&dir).unwrap();
        std::fs::remove_file(&marcador).unwrap();
        assert!(!marcador.exists());

        let mut otra = AccountDatabase::in_directory(dir.clone()).unwrap();
        otra.load().expect("una instalación vieja no es un error");
        assert_eq!(otra.len(), 1);
        assert!(
            marcador.exists(),
            "no se aprovechar la apertura para dejar el marcador"
        );

        remove_test_database(&dir);
    }

    /// El marcador no se confunde con una entrada más de la base: no es una
    /// carpeta, no es un `accounts.json`, y `libretas_de` no lo liste nunca.
    /// El nombre tiene un punto adelante justamente para eso.
    #[test]
    fn el_marcador_no_se_confunde_con_una_cuenta() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        let id = db.add(sample_account()).unwrap();

        let marcador = marker_for(&dir).unwrap();
        let nombre = marcador.file_name().unwrap().to_string_lossy().into_owned();
        assert!(nombre.starts_with('.'), "{nombre}");
        assert_ne!(nombre, dir.file_name().unwrap().to_string_lossy());

        let mut otra = AccountDatabase::in_directory(dir.clone()).unwrap();
        otra.load().unwrap();
        assert_eq!(otra.len(), 1);
        assert!(otra.get(&id).is_some());

        remove_test_database(&dir);
    }

    /// El mensaje del error tiene que decir **qué** no se pudo leer, y no
    /// decir nada que sea la respuesta que no tiene que dar.
    #[test]
    fn el_error_de_lo_que_no_se_puede_leer_no_dice_que_no_hay_cuentas() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        db.add(sample_account()).unwrap();
        std::fs::remove_file(dir.join("accounts.json")).unwrap();

        let mut otra = AccountDatabase::in_directory(dir.clone()).unwrap();
        let mensaje = otra.load().unwrap_err().to_string();
        assert!(mensaje.contains("accounts.json"), "{mensaje}");
        assert!(!mensaje.contains("no hay cuentas"), "{mensaje}");

        remove_test_database(&dir);
    }

    /// Lo que ve quien llama por D-Bus, sin pasar por un bus: un archivo que no
    /// se puede leer tiene que volver como error de `ListAccounts`, y la
    /// respuesta tiene que ser distinguible de `[]`.
    #[test]
    fn un_error_de_lectura_no_se_puede_confundir_con_una_lista_vacia() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        db.add(sample_account()).unwrap();
        std::fs::remove_file(dir.join("accounts.json")).unwrap();

        // Esto es lo que hace `open_db`, que es el arranque de `ListAccounts`: el
        // error se traduce a un error de D-Bus y `ListAccounts` no llega a armar
        // ninguna lista.
        let mut otra = AccountDatabase::in_directory(dir.clone()).unwrap();
        let por_dbus = otra
            .load()
            .map_err(|e| format!("Error al cargar cuentas: {e}"));
        let texto = por_dbus.expect_err("ListAccounts no puede devolver una lista vacía");
        assert!(texto.starts_with("Error al cargar cuentas"), "{texto}");

        remove_test_database(&dir);
    }

    // -----------------------------------------------------------------------
    // vasak-accounts#66: el directorio nunca queda sin `accounts.json` por
    // culpa nuestra, y lo que ya quedó así falla cerrado.
    // -----------------------------------------------------------------------

    /// Un directorio nuevo en una carpeta de prueba, sin crearlo.
    fn new_directory() -> PathBuf {
        std::env::temp_dir().join(uuid::Uuid::new_v4().to_string())
    }

    /// El estado que dejaba la versión anterior: el directorio y el marcador,
    /// sin `accounts.json`.
    fn issue_66_state() -> PathBuf {
        let dir = new_directory();
        std::fs::create_dir(&dir).unwrap();
        write_marker(&marker_for(&dir).unwrap()).unwrap();
        dir
    }

    fn assert_unreadable(result: Result<(), StorageError>) {
        let error = result.expect_err("tenía que seguir siendo un error");
        assert!(
            matches!(error, StorageError::Unreadable { .. }),
            "se esperaba Unreadable, vino {error:?}",
        );
    }

    fn open_and_load(dir: &Path) -> Result<AccountDatabase, StorageError> {
        let mut db = AccountDatabase::in_directory(dir.to_path_buf())?;
        db.load()?;
        Ok(db)
    }

    /// Ningún temporal tiene que quedar al lado: el de cada escritura es único
    /// y se borra al terminar.
    fn temp_files_in(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect()
    }

    /// **El caso de #66.** La primera apertura creaba el directorio y contestaba
    /// vacío; la segunda encontraba el directorio sin archivo y daba error para
    /// siempre. La prueba de antes abría una sola vez.
    #[test]
    fn abrir_tres_veces_un_directorio_nuevo_carga_vacio_las_tres_veces() {
        let dir = new_directory();

        for vez in 1..=3 {
            let db = open_and_load(&dir)
                .unwrap_or_else(|e| panic!("apertura {vez}: no tenía que fallar: {e}"));
            assert!(db.is_empty());
        }

        // Y el archivo queda escrito como lo escribe `save()`: `[]`, 0600, y
        // sin temporales al lado.
        let accounts = dir.join("accounts.json");
        assert_eq!(std::fs::read_to_string(&accounts).unwrap(), "[]");
        let mode = std::fs::metadata(&accounts).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(temp_files_in(&dir).is_empty(), "{:?}", temp_files_in(&dir));

        remove_test_database(&dir);
    }

    /// `SetProviderCredentials` creaba el directorio con su `create_dir_all`, sin
    /// `accounts.json` y sin marcador: la primera lectura de cuentas ya veía un
    /// directorio que existía sin archivo.
    #[test]
    fn un_directorio_creado_por_las_credenciales_de_proveedor_carga_vacio() {
        let dir = new_directory();
        crate::providers::UserCredentials::store_in(
            &dir,
            "google",
            Some(crate::providers::UserCredentials {
                client_id: "el-mio".into(),
                client_secret: None,
            }),
        )
        .unwrap();

        assert!(dir.join("accounts.json").exists());
        assert!(marker_for(&dir).unwrap().exists());
        for _ in 0..2 {
            let db = open_and_load(&dir).expect("sin cuentas, la lista es vacía y no un error");
            assert!(db.is_empty());
        }

        remove_test_database(&dir);
    }

    /// El tercer camino que creaba el directorio: el almacén de secretos.
    #[test]
    fn el_almacen_de_secretos_no_deja_el_directorio_sin_accounts_json() {
        let dir = new_directory();
        SecretStore::store_secret_in(&dir, "acct-1", "access", "token").unwrap();

        assert!(dir.join("accounts.json").exists());
        open_and_load(&dir).unwrap();

        remove_test_database(&dir);
    }

    /// **Lo que ya quedó roto falla cerrado.** Un directorio vacío con marcador
    /// es lo que dejaba #66, pero también lo que deja una cuenta sin secretos
    /// que pierde `accounts.json`: no hay cómo separarlos sin adivinar, y
    /// adivinar mal es la poda de #56. No se escribe `[]`.
    ///
    /// Y la salida a mano que documenta el README funciona: `[]` con 0600.
    #[test]
    fn el_estado_de_66_falla_cerrado_y_sale_con_el_paso_a_mano() {
        let dir = issue_66_state();

        for _ in 0..2 {
            assert_unreadable(open_and_load(&dir).map(|_| ()));
        }
        assert!(
            !dir.join("accounts.json").exists(),
            "se escribió una lista vacía sin saber si hubo cuentas"
        );

        // El paso del README.
        std::fs::write(dir.join("accounts.json"), "[]").unwrap();
        std::fs::set_permissions(
            dir.join("accounts.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let db = open_and_load(&dir).expect("con el archivo puesto a mano, carga");
        assert!(db.is_empty());

        remove_test_database(&dir);
    }

    /// Lo mismo cuando lo que hay adentro es sólo `providers.json`: tampoco
    /// prueba que no haya habido cuentas.
    #[test]
    fn el_estado_de_66_con_credenciales_de_proveedor_tambien_falla_cerrado() {
        let dir = issue_66_state();
        write_private(
            &dir.join("providers.json"),
            br#"{"google":{"client_id":"x"}}"#,
        )
        .unwrap();

        assert_unreadable(open_and_load(&dir).map(|_| ()));
        assert!(!dir.join("accounts.json").exists());
        assert!(std::fs::read_to_string(dir.join("providers.json"))
            .unwrap()
            .contains("client_id"));

        remove_test_database(&dir);
    }

    /// Un `secrets.json` al lado: el error de #56 sigue, y no se escribe nada.
    #[test]
    fn con_secretos_al_lado_falta_accounts_json_sigue_siendo_error() {
        let dir = issue_66_state();
        write_private(&dir.join("secrets.json"), br#"{"acct-1":{"access":"t"}}"#).unwrap();

        assert_unreadable(open_and_load(&dir).map(|_| ()));
        assert!(!dir.join("accounts.json").exists());

        remove_test_database(&dir);
    }

    /// Una cuenta sin secretos —`RegisterAccount` lo permite— que pierde
    /// `accounts.json` deja un directorio vacío, igual al de #66. Es el caso
    /// que hace imposible recuperar este último sin adivinar.
    #[test]
    fn una_cuenta_sin_secretos_que_pierde_accounts_json_sigue_siendo_error() {
        let dir = new_directory();
        let mut db = open_and_load(&dir).unwrap();
        db.add(sample_account()).unwrap();

        std::fs::remove_file(dir.join("accounts.json")).unwrap();
        assert!(std::fs::read_dir(&dir).unwrap().next().is_none());

        assert_unreadable(open_and_load(&dir).map(|_| ()));
        assert!(!dir.join("accounts.json").exists());

        remove_test_database(&dir);
    }

    /// **Con `accounts.json` perdido, al lado no se escribe nada**: ni
    /// credenciales de proveedor ni secretos. Y la pérdida se sigue viendo.
    #[test]
    fn con_accounts_json_perdido_no_se_guardan_credenciales_ni_secretos() {
        let dir = new_directory();
        let mut db = open_and_load(&dir).unwrap();
        db.add(sample_account()).unwrap();
        std::fs::remove_file(dir.join("accounts.json")).unwrap();

        let credentials = crate::providers::UserCredentials::store_in(
            &dir,
            "google",
            Some(crate::providers::UserCredentials {
                client_id: "el-mio".into(),
                client_secret: None,
            }),
        );
        assert!(
            credentials.is_err(),
            "se guardaron credenciales al lado de una pérdida"
        );
        assert!(!dir.join("providers.json").exists());

        assert!(SecretStore::store_secret_in(&dir, "acct-1", "access", "t").is_err());
        assert!(!dir.join("secrets.json").exists());

        assert_unreadable(open_and_load(&dir).map(|_| ()));

        remove_test_database(&dir);
    }

    /// Un symlink en el nombre de `accounts.json` no es «no hay archivo»: no se
    /// reemplaza, y sobre todo no se escribe por él — el demonio es root.
    #[test]
    fn un_symlink_colgante_en_accounts_json_no_se_reemplaza_ni_se_sigue() {
        let dir = issue_66_state();
        let target = dir.with_file_name(format!(
            "destino-{}",
            dir.file_name().unwrap().to_string_lossy()
        ));
        std::os::unix::fs::symlink(&target, dir.join("accounts.json")).unwrap();

        assert_unreadable(open_and_load(&dir).map(|_| ()));
        assert!(!target.exists(), "se escribió por el symlink");

        // Y la escritura inicial tampoco lo pisa ni lo sigue.
        assert!(!create_private_new(&dir.join("accounts.json"), b"[]").unwrap());
        assert!(!target.exists(), "se escribió por el symlink");
        assert!(std::fs::symlink_metadata(dir.join("accounts.json"))
            .unwrap()
            .file_type()
            .is_symlink());

        remove_test_database(&dir);
    }

    /// **La escritura inicial nunca reemplaza.** Es lo que cierra la carrera
    /// entre dos pedidos del mismo uid: si otro ya guardó una cuenta, el `[]`
    /// de éste no la pisa. Con `write_private` —que hace `rename`— la cuenta se
    /// perdía sin error.
    #[test]
    fn la_escritura_inicial_no_pisa_un_accounts_json_existente() {
        let dir = new_directory();
        let mut db = open_and_load(&dir).unwrap();
        let id = db.add(sample_account()).unwrap();
        let path = dir.join("accounts.json");
        let before = std::fs::read_to_string(&path).unwrap();

        assert!(
            !create_private_new(&path, b"[]").unwrap(),
            "dijo que lo creó, y ya había uno"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert!(open_and_load(&dir).unwrap().get(&id).is_some());
        assert!(temp_files_in(&dir).is_empty(), "{:?}", temp_files_in(&dir));

        remove_test_database(&dir);
    }

    /// La carrera de verdad, con hilos: muchos pedidos abren a la vez un
    /// directorio que no existe, y uno guarda una cuenta apenas abre. La
    /// cuenta tiene que estar al final, en todas las vueltas.
    #[test]
    fn abrir_a_la_vez_desde_muchos_hilos_no_pisa_la_cuenta_guardada() {
        const THREADS: usize = 8;
        for _ in 0..200 {
            let dir = new_directory();
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(THREADS));
            let handles: Vec<_> = (0..THREADS)
                .map(|n| {
                    let dir = dir.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        let mut db = AccountDatabase::in_directory(dir).unwrap();
                        if n == 0 {
                            db.load().unwrap();
                            Some(db.add(sample_account()).unwrap())
                        } else {
                            None
                        }
                    })
                })
                .collect();
            let ids: Vec<String> = handles
                .into_iter()
                .filter_map(|h| h.join().unwrap())
                .collect();

            let db = open_and_load(&dir).expect("después de la carrera, carga");
            assert!(
                db.get(&ids[0]).is_some(),
                "una apertura concurrente pisó la cuenta recién guardada"
            );
            assert!(temp_files_in(&dir).is_empty(), "{:?}", temp_files_in(&dir));
            remove_test_database(&dir);
        }
    }

    /// Dos escrituras a la vez del mismo archivo dejan **una de las dos
    /// entera**. Con el temporal compartido de antes (`<nombre>.tmp`) las dos
    /// truncaban y escribían el mismo archivo, y lo que se renombraba podía ser
    /// una mezcla.
    #[test]
    fn dos_escrituras_a_la_vez_dejan_una_entera() {
        let dir = new_directory();
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("secrets.json");
        let payloads = [vec![b'a'; 1 << 20], vec![b'b'; 1 << 19]];

        for _ in 0..30 {
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let handles: Vec<_> = payloads
                .iter()
                .cloned()
                .map(|data| {
                    let path = path.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        // Una puede perder la carrera del `rename` contra la
                        // otra; lo que importa es lo que queda.
                        let _ = write_private(&path, &data);
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }

            let written = std::fs::read(&path).unwrap();
            assert!(
                payloads.contains(&written),
                "quedó una mezcla de {} bytes",
                written.len()
            );
        }
        assert!(temp_files_in(&dir).is_empty(), "{:?}", temp_files_in(&dir));

        remove_test_database(&dir);
    }

    /// Borra la base de una prueba y el marcador que dejó **al lado**.
    ///
    /// El marcador es la mitad de afuera del `directory_existed` de adentro, así
    /// que vive en el padre y `remove_dir_all` del directorio no se lo lleva.
    /// Sin esto, cada prueba deja un `.instalado-<uuid>` en `/tmp`.
    pub(crate) fn remove_test_database(directory: &Path) {
        if let Some(marker) = marker_for(directory) {
            let _ = std::fs::remove_file(marker);
        }
        let _ = std::fs::remove_dir_all(directory);
    }

    /// Sólo para el caso de permisos: root no lo bloquea un `chmod`, y una
    /// prueba que no bloquea nada no prueba nada. `libc` no está en las
    /// dependencias del demonio y no se agrega por esto.
    fn running_as_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|estado| {
                estado
                    .lines()
                    .find_map(|l| l.strip_prefix("Uid:").map(str::to_string))
            })
            .and_then(|uids| uids.split_whitespace().next().map(str::to_string))
            .is_some_and(|uid| uid == "0")
    }

    /// El directorio guarda los tokens de una persona: que otra pueda listarlo
    /// ya dice qué cuentas tiene.
    #[test]
    fn el_directorio_de_la_base_es_solo_para_su_dueno() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        AccountDatabase::in_directory(dir.clone()).unwrap();

        let modo = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(modo, 0o700);

        remove_test_database(&dir);
    }

    /// Lo que sale por `ListAccounts`, que no pide permiso: tiene que alcanzar
    /// para dibujar una lista y **no** incluir la configuración de la cuenta.
    #[test]
    fn el_resumen_no_lleva_la_configuracion_de_la_cuenta() {
        let cuenta = sample_account();
        let resumen = cuenta.summary(&[]);

        assert_eq!(resumen.display_name, "Alice Google");
        assert_eq!(resumen.provider_type, "google");
        assert_eq!(resumen.capabilities, vec!["drive", "email"]);
        assert!(resumen.unavailable_capabilities.is_empty());
        assert!(!resumen.needs_reauth);

        // El servidor de correo, el client_id y los alcances quedan detrás de
        // GetAccountData, que sí pregunta. Que no se filtren por acá es el
        // motivo de que el resumen exista.
        let json = serde_json::to_string(&resumen).unwrap();
        for secreto in ["imap.gmail.com", "alice@gmail.com", "max_storage_gb"] {
            assert!(
                !json.contains(secreto),
                "el resumen filtró '{secreto}': {json}"
            );
        }
    }

    /// Las capacidades del resumen van ordenadas y sin depender del recorrido de
    /// un HashMap, o la lista de la pantalla se reordenaría sola entre lecturas.
    #[test]
    fn las_capacidades_del_resumen_van_ordenadas() {
        let mut caps = HashMap::new();
        for capacidad in CapabilityType::ALL {
            caps.insert(capacidad, json!({}));
        }
        let resumen = Account::new("Todas", "prueba", caps).summary(&[]);

        let mut esperado = resumen.capabilities.clone();
        esperado.sort();
        assert_eq!(resumen.capabilities, esperado);
        assert_eq!(resumen.capabilities.len(), 6);
    }

    /// Lo que el gestor de archivos necesita para decir «todavía no
    /// disponible» en vez de «volvé a conectarla»: de lo que el proveedor
    /// anuncia sin dirección, sólo lo que la cuenta **tiene**.
    #[test]
    fn el_resumen_marca_lo_que_la_cuenta_tiene_y_no_se_puede_usar() {
        // La cuenta tiene email y drive. El proveedor dice que drive y
        // calendar no tienen dirección: calendar no cuenta, porque la cuenta
        // no lo tiene, y no se inventa.
        let resumen = sample_account().summary(&[CapabilityType::Drive, CapabilityType::Calendar]);

        assert_eq!(resumen.unavailable_capabilities, vec!["drive"]);
        // Y sigue en la lista: es un subconjunto, no una resta. La pantalla la
        // muestra apagada, no la esconde.
        assert_eq!(resumen.capabilities, vec!["drive", "email"]);
    }

    /// Sin nada anunciado —o con un proveedor que ya no está en el catálogo,
    /// que llega igual, como lista vacía— no se marca nada.
    #[test]
    fn el_resumen_sin_proveedor_no_marca_nada() {
        let resumen = sample_account().summary(&[]);
        assert!(resumen.unavailable_capabilities.is_empty());
    }

    /// Ordenadas y sin depender del recorrido de un HashMap, por el mismo
    /// motivo que `capabilities`: la barra lateral no se puede reordenar sola.
    #[test]
    fn las_no_disponibles_del_resumen_van_ordenadas() {
        let mut caps = HashMap::new();
        for capacidad in CapabilityType::ALL {
            caps.insert(capacidad, json!({}));
        }
        let resumen = Account::new("Todas", "prueba", caps).summary(&[
            CapabilityType::Tasks,
            CapabilityType::Calendar,
            CapabilityType::Drive,
        ]);

        assert_eq!(
            resumen.unavailable_capabilities,
            vec!["calendar", "drive", "tasks"]
        );
    }

    /// El campo viaja por D-Bus con ese nombre exacto: es lo que los clientes
    /// van a leer, y cambiarlo los deja mudos sin error.
    #[test]
    fn el_resumen_serializa_las_no_disponibles_con_su_nombre() {
        let resumen = sample_account().summary(&[CapabilityType::Drive]);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&resumen).unwrap()).unwrap();

        assert_eq!(json["unavailable_capabilities"], json!(["drive"]));
        assert_eq!(json["capabilities"], json!(["drive", "email"]));
    }

    #[test]
    fn marcar_reauth_solo_avisa_cuando_cambia() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        let id = db.add(sample_account()).unwrap();

        assert!(
            db.set_needs_reauth(&id, true).unwrap(),
            "el primer cambio avisa"
        );
        // Y el segundo no: si no, cada refresco fallido de una cuenta ya marcada
        // emitiría una señal y despertaría a todas las aplicaciones.
        assert!(!db.set_needs_reauth(&id, true).unwrap());
        assert!(db.get(&id).unwrap().needs_reauth);

        assert!(
            db.set_needs_reauth(&id, false).unwrap(),
            "volver a andar avisa"
        );
        assert!(!db.get(&id).unwrap().needs_reauth);

        // Y una cuenta que no existe no es un error: puede haberse borrado
        // mientras se hablaba con el proveedor.
        assert!(!db.set_needs_reauth("no-existe", true).unwrap());

        remove_test_database(&dir);
    }

    /// La marca tiene que sobrevivir al disco, o la pantalla diría que todo
    /// está bien después de reiniciar el servicio.
    #[test]
    fn la_marca_de_reauth_se_persiste() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        let id = db.add(sample_account()).unwrap();
        db.set_needs_reauth(&id, true).unwrap();

        let mut otra = AccountDatabase::in_directory(dir.clone()).unwrap();
        otra.load().unwrap();
        assert!(otra.get(&id).unwrap().needs_reauth);

        remove_test_database(&dir);
    }

    /// Los archivos escritos antes de que la marca existiera no la tienen, y una
    /// cuenta sin marca es una cuenta que anda. Sin el `default` de serde, el
    /// servicio no podría leer ningún accounts.json anterior.
    #[test]
    fn una_cuenta_sin_la_marca_se_lee_como_que_anda() {
        let viejo = r#"[{
            "id": "abc",
            "display_name": "Vieja",
            "provider_type": "custom",
            "capabilities": {}
        }]"#;

        let cuentas: Vec<Account> = serde_json::from_str(viejo).unwrap();
        assert!(!cuentas[0].needs_reauth);
    }

    /// Sin crearlo: lo crea el almacén al guardar, por el mismo camino que la
    /// base. Un directorio vacío creado a mano es, desde #66, un directorio
    /// sin `accounts.json`, y ahí no se escribe nada.
    fn temp_dir() -> std::path::PathBuf {
        new_directory()
    }

    #[test]
    fn a_secret_survives_being_written_and_read_back() {
        let dir = temp_dir();

        SecretStore::store_secret_in(&dir, "acct-1", "access", "token-abc").unwrap();
        SecretStore::store_secret_in(&dir, "acct-1", "refresh", "refresh-xyz").unwrap();

        assert_eq!(
            SecretStore::get_secret_in(&dir, "acct-1", "access").unwrap(),
            "token-abc"
        );
        assert_eq!(
            SecretStore::get_secret_in(&dir, "acct-1", "refresh").unwrap(),
            "refresh-xyz"
        );

        remove_test_database(&dir);
    }

    /// The file holds live credentials, so nobody but its owner may read it.
    /// This is the whole point of moving them out of the user's keyring.
    #[test]
    fn the_secret_file_is_readable_only_by_its_owner() {
        let dir = temp_dir();
        SecretStore::store_secret_in(&dir, "acct-1", "access", "token").unwrap();

        let mode = std::fs::metadata(dir.join("secrets.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert!(
            temp_files_in(&dir).is_empty(),
            "no temporary file should be left holding a token"
        );

        remove_test_database(&dir);
    }

    #[test]
    fn accounts_do_not_see_each_others_secrets() {
        let dir = temp_dir();
        SecretStore::store_secret_in(&dir, "acct-1", "access", "one").unwrap();
        SecretStore::store_secret_in(&dir, "acct-2", "access", "two").unwrap();

        assert_eq!(
            SecretStore::get_secret_in(&dir, "acct-1", "access").unwrap(),
            "one"
        );
        assert_eq!(
            SecretStore::get_secret_in(&dir, "acct-2", "access").unwrap(),
            "two"
        );

        remove_test_database(&dir);
    }

    /// Deleting an account has to take its credentials with it, or a working
    /// token stays on disk for something the user believes is gone.
    #[test]
    fn deleting_an_account_removes_its_secrets() {
        let dir = temp_dir();
        SecretStore::store_secret_in(&dir, "acct-1", "access", "one").unwrap();
        SecretStore::store_secret_in(&dir, "acct-2", "access", "two").unwrap();

        SecretStore::forget_account_in(&dir, "acct-1").unwrap();

        assert!(SecretStore::get_secret_in(&dir, "acct-1", "access").is_err());
        assert_eq!(
            SecretStore::get_secret_in(&dir, "acct-2", "access").unwrap(),
            "two",
            "the other account must be untouched"
        );

        remove_test_database(&dir);
    }

    #[test]
    fn a_secret_that_was_never_stored_is_an_error_not_an_empty_string() {
        let dir = temp_dir();
        assert!(SecretStore::get_secret_in(&dir, "missing", "access").is_err());
        remove_test_database(&dir);
    }

    /// One person's request must never reach another person's directory.
    #[test]
    fn each_user_gets_their_own_directory() {
        assert_ne!(
            AccountDatabase::directory_for(1000),
            AccountDatabase::directory_for(1001)
        );
        assert!(AccountDatabase::directory_for(1000)
            .to_string_lossy()
            .ends_with("/1000"));
    }
}
