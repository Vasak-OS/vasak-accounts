//! El almacén local: una base cifrada por cuenta.
//!
//! ── Qué hay acá, y qué todavía no ───────────────────────────────────────────
//!
//! La base: su clave en el llavero, su archivo cifrado, el esquema —dónde quedó
//! la sincronización, una bitácora y, desde la v2, **los contactos** (ver
//! `migrations.rs` y `contacts.rs`)— y el ciclo de vida entero (crear, abrir,
//! cerrar al bloquear, rehacer si se perdió la clave, apagar, vaciar, borrar al
//! quitar la cuenta). El calendario y el correo llegan después, de a uno, con
//! su propia migración. Ver `vasak-accounts#23`.
//!
//! ── Qué protege el cifrado, y qué no ────────────────────────────────────────
//!
//! Protege **en reposo**: el disco robado, la copia de seguridad, otra cuenta
//! del mismo equipo. Los primeros bytes del archivo no dicen ni que es SQLite.
//!
//! **No** protege contra un proceso que corre como la misma persona. La clave
//! vive en el llavero de la sesión, y el llavero es un Secret Service estándar:
//! cualquier proceso de la persona puede pedirle todos los secretos. El permiso
//! por D-Bus para leer el almacén (`store.contacts`, ver `access.rs`) es
//! consentimiento y visibilidad, no una frontera. La frontera de verdad —control por ítem en el llavero— es
//! otro trabajo, y hasta que exista hay que decirlo así.
//!
//! ── Por qué SQLCipher compilado, y OpenSSL del sistema ──────────────────────
//!
//! `rusqlite` con `bundled-sqlcipher`: la versión de SQLCipher la fija el
//! `Cargo.lock` y se compila con el programa, y la criptografía es la
//! `libcrypto.so.3` del sistema, que sigue recibiendo los parches de la
//! distribución. El `sqlcipher` de los repositorios arrastra `tcl` y
//! `readline`; la variante con OpenSSL embebido congelaría la criptografía en
//! lo que diga el candado.
//!
//! **Un solo dueño de cada base: este proceso.** El demonio de root no la toca
//! —la clave vive en el llavero de la sesión, y parsear lo que llega de la red
//! tiene que pasar como la persona— y con un solo escritor no hay carreras.

pub mod contacts;
pub mod contacts_read;
pub mod key;
pub mod lifecycle;
pub mod migrations;
pub mod paths;
pub mod readers;

use std::collections::BTreeMap;
use std::sync::Arc;

use rusqlite::{Connection, OpenFlags, OptionalExtension};

use key::{KeyError, StoreKey};
use paths::StorePaths;
use readers::ReadPool;

/// Lo que puede salir mal con una base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// No hay un directorio base absoluto para los datos o la configuración.
    NoBaseDir,
    /// El identificador de cuenta no se puede usar como nombre de carpeta.
    InvalidAccountId(String),
    /// La clave no abre la base, o el archivo no es una base: SQLite contesta
    /// lo mismo en los dos casos (`SQLITE_NOTADB`).
    WrongKey,
    /// La base se abrió pero no está cifrada: esta compilación no trae
    /// SQLCipher. No se sigue.
    NotEncrypted,
    /// No hay base para abrir.
    Missing,
    /// El esquema no se pudo llevar a la última versión, o la base es de una
    /// versión más nueva que este programa.
    Schema(String),
    /// El disco: permisos, espacio, lo que sea. **Nunca** lleva a borrar.
    Io(String),
    Sqlite(String),
    Key(KeyError),
    /// Lo decidido por cuenta (`stores.json`) no se entiende.
    Settings(String),
    /// La cuenta no tiene almacén: no existe, o no tiene nada que guardar.
    UnknownAccount(String),
    /// La colección del llavero no es en la que se guardó la clave de esta
    /// base: el alias `default` cambió, o el llavero es otro. La base no se
    /// rehace.
    CollectionChanged,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NoBaseDir => {
                f.write_str("no hay un directorio de datos absoluto para el almacén")
            }
            StoreError::InvalidAccountId(id) => {
                write!(f, "«{id}» no es un identificador de cuenta válido")
            }
            StoreError::WrongKey => f.write_str("la clave no abre la base"),
            StoreError::NotEncrypted => {
                f.write_str("esta compilación no cifra la base; no se usa sin cifrar")
            }
            StoreError::Missing => f.write_str("no hay base"),
            StoreError::Schema(d) => write!(f, "el esquema de la base: {d}"),
            StoreError::Io(d) | StoreError::Sqlite(d) => write!(f, "{d}"),
            StoreError::Key(e) => write!(f, "{e}"),
            StoreError::Settings(d) => write!(f, "stores.json: {d}"),
            StoreError::UnknownAccount(id) => write!(f, "la cuenta «{id}» no tiene almacén"),
            StoreError::CollectionChanged => f.write_str(COLLECTION_CHANGED),
        }
    }
}

const COLLECTION_CHANGED: &str = "la colección del llavero no es en la que se guardó la clave \
                                  de esta base; no se rehace hasta que vuelva, o hasta vaciarla";

impl StoreError {
    /// Lo que se puede mostrar en el estado: **un texto fijo por clase de
    /// error**, sin rutas bajo `$HOME`, sin identificadores y sin nada que haya
    /// escrito el llavero o un servidor. El detalle entero va sólo al diario.
    pub fn public_detail(&self) -> &'static str {
        match self {
            StoreError::NoBaseDir => "no hay un directorio de datos para el almacén",
            StoreError::InvalidAccountId(_) => "el identificador de la cuenta no es válido",
            StoreError::WrongKey => "la clave no abre la base",
            StoreError::NotEncrypted => "esta compilación no cifra la base; no se usa sin cifrar",
            StoreError::Missing => "no hay base",
            StoreError::Schema(_) => "el esquema de la base no se pudo poner al día",
            StoreError::Io(_) => "no se pudo usar el disco",
            StoreError::Sqlite(_) => "la base dio un error",
            StoreError::Key(KeyError::Unavailable(_)) => "el llavero no está disponible",
            StoreError::Key(KeyError::Locked) => "el llavero está bloqueado",
            StoreError::Key(KeyError::PromptRequired) => {
                "el llavero pidió un diálogo, y este servicio no los abre"
            }
            StoreError::Key(KeyError::Malformed) => {
                "lo guardado en el llavero no es una clave válida"
            }
            StoreError::Key(KeyError::Failed(_)) => "el llavero no pudo hacer lo que se le pidió",
            StoreError::Settings(_) => "no se pudo leer lo decidido por cuenta (stores.json)",
            StoreError::UnknownAccount(_) => "la cuenta no tiene almacén",
            StoreError::CollectionChanged => COLLECTION_CHANGED,
        }
    }
}

impl std::error::Error for StoreError {}

impl From<KeyError> for StoreError {
    fn from(error: KeyError) -> Self {
        StoreError::Key(error)
    }
}

/// Separa «la clave no abre» del resto.
///
/// Es la distinción que decide si se borra: `SQLITE_NOTADB` lleva a rehacer la
/// base, y cualquier otro error —un disco lleno, un permiso, una base
/// ocupada— la deja como está.
fn classify(error: rusqlite::Error) -> StoreError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::NotADatabase) => StoreError::WrongKey,
        _ => StoreError::Sqlite(error.to_string()),
    }
}

/// Abre el archivo de una base.
///
/// Sin `SQLITE_OPEN_CREATE`: el archivo lo creó `create_empty_db` con 0600, y
/// abrir no tiene por qué crear nada. Con `SQLITE_OPEN_NOFOLLOW`: si entre la
/// revisión de permisos y acá alguien cambió `store.db` —o una carpeta del
/// camino— por un enlace, SQLite no abre. Sin la bandera, SQLite resuelve los
/// enlaces del camino y abre lo apuntado. Como la bandera rechaza un enlace en
/// **cualquier** componente, la ruta llega con lo de la persona ya resuelto
/// ([`StorePaths::db_to_open`]).
fn open_connection(db: &std::path::Path) -> Result<Connection, StoreError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    Connection::open_with_flags(db, flags).map_err(classify)
}

/// Le da la clave a SQLCipher sin pasar por el parser de SQL.
///
/// `PRAGMA key = "x'…'"` hace lo mismo, pero el parser copia el texto de la
/// orden —con la clave— a memoria de SQLite que se libera sin borrar
/// (`cipher_memory_security` viene apagado). `sqlite3_key_v2` recibe los bytes
/// tal cual, desde el búfer `Zeroizing` de [`StoreKey::sqlcipher_key`], y
/// SQLCipher los copia a su montículo privado, que borra al soltar. Con la
/// misma forma `x'…'`, que es la de clave cruda: las bases abren igual que con
/// el `PRAGMA`.
fn apply_key(connection: &Connection, key: &StoreKey) -> Result<(), StoreError> {
    let literal = key.sqlcipher_key();
    let length = std::ffi::c_int::try_from(literal.len())
        .map_err(|_| StoreError::Sqlite("la clave es demasiado larga".into()))?;
    // SAFETY: `handle()` es el puntero de la conexión abierta de `connection`,
    // que vive más que esta llamada y no se usa desde otro hilo mientras tanto
    // (`Connection` no es `Sync`, y acá se la presta). `c"main"` es una cadena
    // C estática. `literal` son `length` bytes válidos hasta el final de la
    // función; SQLCipher sólo los lee durante la llamada —los copia a memoria
    // propia— y no guarda ningún puntero a ellos.
    let code = unsafe {
        rusqlite::ffi::sqlite3_key_v2(
            connection.handle(),
            c"main".as_ptr(),
            literal.as_ptr().cast(),
            length,
        )
    };
    if code != rusqlite::ffi::SQLITE_OK {
        return Err(StoreError::Sqlite(format!(
            "SQLCipher no aceptó la clave (código {code})"
        )));
    }
    Ok(())
}

/// Qué tan grave es una línea de la bitácora.
///
/// Por ahora sólo escribe el ciclo de vida, y sólo avisos. La columna acepta
/// también `info` y `error`, que van a llegar con las áreas que sincronizan;
/// se suman acá cuando haya quien las use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Warn,
}

impl LogLevel {
    fn as_str(self) -> &'static str {
        match self {
            LogLevel::Warn => "warn",
        }
    }
}

/// Una base abierta.
///
/// Dueña de su conexión de escritura y de las de lectura ([`ReadPool`]), y sin
/// la clave: SQLCipher ya la tiene, y guardarla acá también sería tenerla dos
/// veces en memoria sin ganar nada. Por eso las de lectura se abren junto con
/// la de escritura, mientras la clave todavía está a mano.
///
/// Soltarla cierra las tres: la de escritura al soltarse, y las de lectura con
/// [`ReadPool::close`], aunque alguien tenga todavía el grupo prestado.
pub struct Store {
    connection: Connection,
    readers: Arc<ReadPool>,
    /// Lo que cambió desde la última vez que se preguntó: la última generación
    /// de cada área que se escribió y se confirmó. Ver [`Store::take_changes`].
    changes: BTreeMap<&'static str, u64>,
}

impl Drop for Store {
    fn drop(&mut self) {
        self.readers.close();
    }
}

/// La clave de `store_meta` donde vive la generación de un área.
fn generation_key(area: &str) -> String {
    format!("generation.{area}")
}

/// La generación de un área: cuántas veces cambió lo que se guarda de ella, en
/// un número que sólo crece.
///
/// **Persistida en `store_meta`**, y en la misma transacción que el cambio: una
/// lectura que ve la generación N ve los datos de la N, y reiniciar el servicio
/// no la vuelve a cero. Cada cambio la lleva a `max(anterior + 1, ahora en
/// microsegundos)`: dentro de una base crece de a uno como mínimo, y una base
/// rehecha —vaciada, o con la clave perdida— empieza más arriba que la que
/// reemplazó, salvo que el reloj haya vuelto atrás.
pub fn read_generation(connection: &Connection, area: &str) -> Result<u64, StoreError> {
    let value: Option<String> = connection
        .query_row(
            "SELECT value FROM store_meta WHERE key = ?1",
            [generation_key(area)],
            |row| row.get(0),
        )
        .optional()
        .map_err(classify)?;
    Ok(value.and_then(|v| v.parse().ok()).unwrap_or(0))
}

/// Sube la generación de un área, dentro de la transacción del cambio.
/// Devuelve la nueva.
fn bump_generation(connection: &Connection, area: &str) -> Result<u64, StoreError> {
    let previous = read_generation(connection, area)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
    let next = previous.saturating_add(1).max(now);
    connection
        .execute(
            "INSERT INTO store_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            rusqlite::params![generation_key(area), next.to_string()],
        )
        .map_err(classify)?;
    Ok(next)
}

impl Store {
    /// Abre una base que ya existe.
    pub fn open(paths: &StorePaths, key: &StoreKey) -> Result<Self, StoreError> {
        Self::connect(paths, key, false)
    }

    /// Crea una base nueva. Falla si ya había una.
    pub fn create(paths: &StorePaths, key: &StoreKey) -> Result<Self, StoreError> {
        let store = Self::connect(paths, key, true)?;
        store
            .connection
            .execute(
                "INSERT OR IGNORE INTO store_meta (key, value) VALUES ('created_at', ?1)",
                [chrono::Utc::now().to_rfc3339()],
            )
            .map_err(classify)?;
        Ok(store)
    }

    fn connect(paths: &StorePaths, key: &StoreKey, create: bool) -> Result<Self, StoreError> {
        paths.prepare_dir()?;
        if create {
            paths.create_empty_db()?;
        } else if !paths.db_exists()? {
            return Err(StoreError::Missing);
        }
        paths.tighten_files()?;

        let mut connection = open_connection(&paths.db_to_open()?)?;

        apply_key(&connection, key)?;
        // Los parámetros del cifrado, fijos en los de SQLCipher 4. Sin esto, una
        // versión futura con otros valores por omisión no abriría las bases de
        // hoy, y el ciclo de vida lo tomaría por una clave que no abre: las
        // borraría todas.
        connection
            .execute_batch("PRAGMA cipher_compatibility = 4;")
            .map_err(classify)?;

        let cipher: Option<String> = connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .optional()
            .map_err(classify)?;
        if cipher.unwrap_or_default().is_empty() {
            return Err(StoreError::NotEncrypted);
        }

        // La comprobación de la clave: recién leer una página la pone a prueba.
        connection
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(classify)?;

        let mode: String = connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
            .map_err(classify)?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::Sqlite(format!(
                "la base quedó en modo «{mode}» y no en WAL"
            )));
        }
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(classify)?;

        migrations::apply(&mut connection)?;

        // Otra vez: el `-wal` y el `-shm` recién aparecen al escribir.
        paths.tighten_files()?;

        let readers = Arc::new(ReadPool::open(&paths.db_to_open()?, key)?);

        Ok(Self {
            connection,
            readers,
            changes: BTreeMap::new(),
        })
    }

    /// Las conexiones de lectura de esta base.
    pub fn readers(&self) -> Arc<ReadPool> {
        Arc::clone(&self.readers)
    }

    /// Anota que un área cambió y quedó en `generation`. Se llama **después**
    /// del `commit`: una transacción que se deshizo no cambió nada.
    fn note_change(&mut self, area: &'static str, generation: u64) {
        self.changes.insert(area, generation);
    }

    /// Lo que cambió desde la última vez, un área por vez con su última
    /// generación, y se olvida. Es lo que `with_store` anuncia con `Changed`
    /// después de cada lote: una vez por área que cambió, y nada si no cambió
    /// ninguna.
    pub fn take_changes(&mut self) -> Vec<(&'static str, u64)> {
        std::mem::take(&mut self.changes).into_iter().collect()
    }

    /// Marca un área como cambiada aunque no se haya escrito nada en ella: la
    /// base se vació, y lo que alguien tenía leído ya no está.
    pub fn touch(&mut self, area: &'static str) -> Result<u64, StoreError> {
        let generation = bump_generation(&self.connection, area)?;
        self.note_change(area, generation);
        Ok(generation)
    }

    /// Anota algo en la bitácora de la base.
    pub fn log(
        &self,
        level: LogLevel,
        area: Option<&str>,
        message: &str,
    ) -> Result<(), StoreError> {
        self.connection
            .execute(
                "INSERT INTO sync_log (at, level, area, message) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    chrono::Utc::now().to_rfc3339(),
                    level.as_str(),
                    area,
                    message
                ],
            )
            .map(|_| ())
            .map_err(classify)
    }

    #[cfg(test)]
    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use zeroize::Zeroizing;

    use super::paths::tests::TempDir;
    use super::*;

    fn key_of(c: u8) -> StoreKey {
        StoreKey::from_secret(Zeroizing::new(vec![c; 64])).unwrap()
    }

    fn mode(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn abre_con_la_clave_correcta_y_no_con_otra() {
        let temp = TempDir::new("clave");
        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        let store = Store::create(&paths, &key_of(b'a')).unwrap();
        store.log(LogLevel::Warn, None, "hola").unwrap();
        drop(store);

        assert_eq!(
            Store::open(&paths, &key_of(b'b')).err(),
            Some(StoreError::WrongKey)
        );

        let store = Store::open(&paths, &key_of(b'a')).unwrap();
        let message: String = store
            .connection()
            .query_row("SELECT message FROM sync_log", [], |row| row.get(0))
            .unwrap();
        assert_eq!(message, "hola");
    }

    /// La clave va por `sqlite3_key_v2` y no por `PRAGMA key`, pero es la
    /// misma clave cruda: una base creada con la orden de antes abre, y una
    /// creada ahora abre con la orden. Si la forma `x'…'` se tomara por una
    /// contraseña, SQLCipher derivaría otra clave y ninguna de las dos abriría.
    #[test]
    fn la_clave_por_la_api_es_la_misma_que_por_pragma() {
        let temp = TempDir::new("pragma");
        let with_pragma = |paths: &StorePaths, c: u8| {
            let connection = Connection::open(&paths.db).unwrap();
            connection
                .execute_batch(&format!(
                    "PRAGMA key = \"x'{}'\"; PRAGMA cipher_compatibility = 4;",
                    (c as char).to_string().repeat(64)
                ))
                .unwrap();
            connection
        };

        let old = StorePaths::new(&temp.0, "vieja").unwrap();
        old.prepare_dir().unwrap();
        with_pragma(&old, b'a')
            .execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1);")
            .unwrap();
        let store = Store::open(&old, &key_of(b'a')).unwrap();
        let x: i64 = store
            .connection()
            .query_row("SELECT x FROM t", [], |row| row.get(0))
            .unwrap();
        assert_eq!(x, 1);

        let new = StorePaths::new(&temp.0, "nueva").unwrap();
        drop(Store::create(&new, &key_of(b'b')).unwrap());
        let count: i64 = with_pragma(&new, b'b')
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
            .unwrap();
        assert!(count > 0);
    }

    /// SQLite no abre una base que es un enlace: `tighten_files` ya lo
    /// rechaza antes, y esto cubre el rato entre esa revisión y la apertura.
    #[test]
    fn abrir_no_sigue_un_enlace_en_lugar_de_la_base() {
        let temp = TempDir::new("enlace-base");
        let real = StorePaths::new(&temp.0, "real").unwrap();
        drop(Store::create(&real, &key_of(b'a')).unwrap());
        let link = temp.0.join("enlace.db");
        std::os::unix::fs::symlink(&real.db, &link).unwrap();

        assert!(open_connection(&real.db).is_ok());
        assert!(open_connection(&link).is_err());
    }

    /// Un `HOME` o una `XDG_DATA_HOME` que son un enlace son de la persona, y
    /// la base abre igual: el enlace se resuelve antes de la carpeta del
    /// servicio, y lo nuestro sigue sin poder serlo.
    #[test]
    fn la_base_abre_con_la_carpeta_de_datos_enlazada() {
        let temp = TempDir::new("datos-enlazados");
        std::fs::create_dir_all(temp.0.join("disco/datos")).unwrap();
        std::os::unix::fs::symlink(temp.0.join("disco/datos"), temp.0.join("datos")).unwrap();
        let root = temp.0.join("datos/vasak-accounts-sync/stores");
        let paths = StorePaths::new(&root, "cuenta").unwrap();

        drop(Store::create(&paths, &key_of(b'a')).unwrap());
        assert!(Store::open(&paths, &key_of(b'a')).is_ok());
        assert!(temp
            .0
            .join("disco/datos/vasak-accounts-sync/stores/cuenta/store.db")
            .exists());
    }

    /// Lo que se ve desde afuera: ni siquiera la firma de SQLite.
    #[test]
    fn el_archivo_no_empieza_como_una_base_sqlite() {
        let temp = TempDir::new("cabecera");
        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        let store = Store::create(&paths, &key_of(b'c')).unwrap();
        store
            .log(LogLevel::Warn, None, "un texto que no se tiene que ver")
            .unwrap();
        drop(store);

        let bytes = std::fs::read(&paths.db).unwrap();
        assert!(bytes.len() >= 16);
        assert_ne!(&bytes[..16], b"SQLite format 3\0");
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("un texto que no se tiene que ver"));
        assert!(!text.contains("sync_log"));
    }

    /// Que la compilación trae SQLCipher, y FTS5 con el tokenizador que va a
    /// usar la búsqueda: si alguno falta, esto lo dice antes que la receta.
    #[test]
    fn sqlcipher_y_fts5_estan_disponibles() {
        let temp = TempDir::new("fts5");
        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        let store = Store::create(&paths, &key_of(b'd')).unwrap();

        let version: String = store
            .connection()
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))
            .unwrap();
        assert!(!version.is_empty());

        store
            .connection()
            .execute_batch(
                "CREATE VIRTUAL TABLE prueba USING fts5(texto, tokenize = 'unicode61 remove_diacritics 2');
                 INSERT INTO prueba (texto) VALUES ('Reunión en Córdoba');",
            )
            .unwrap();
        let found: i64 = store
            .connection()
            .query_row(
                "SELECT count(*) FROM prueba WHERE prueba MATCH 'reunion cordoba'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(found, 1, "la búsqueda sin acentos tiene que encontrar");
    }

    #[test]
    fn la_base_queda_en_wal_y_con_claves_foraneas() {
        let temp = TempDir::new("wal");
        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        let store = Store::create(&paths, &key_of(b'e')).unwrap();
        let mode: String = store
            .connection()
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let foreign: i64 = store
            .connection()
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(foreign, 1);
        let version: i64 = store
            .connection()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 2);
    }

    /// 0700 la carpeta y 0600 los tres archivos, y otra vez en cada apertura si
    /// alguien los abrió.
    /// En el orden de [`StorePaths::files`].
    const STORE_FILE_NAMES: [&str; 3] = ["store.db", "store.db-wal", "store.db-shm"];

    #[test]
    fn los_permisos_se_ponen_y_se_reaplican() {
        let temp = TempDir::new("permisos");
        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        let store = Store::create(&paths, &key_of(b'f')).unwrap();

        // Con la base abierta en WAL están los tres.
        assert_eq!(mode(&paths.dir), 0o700);
        // Los mensajes nombran el archivo por su posición y no por su ruta: la
        // ruta lleva el identificador de la cuenta, y CodeQL marca cualquier
        // camino de ese dato a una salida aunque sea el texto de una prueba.
        for (file, name) in paths.files().into_iter().zip(STORE_FILE_NAMES) {
            assert!(file.exists(), "{name} tendría que existir");
            assert_eq!(mode(file), 0o600, "{name}");
        }

        for file in paths.files() {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        std::fs::set_permissions(&paths.dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let again = Store::open(&paths, &key_of(b'f')).unwrap();
        assert_eq!(mode(&paths.dir), 0o700);
        for (file, name) in paths.files().into_iter().zip(STORE_FILE_NAMES) {
            assert_eq!(mode(file), 0o600, "{name}");
        }
        drop(again);
        drop(store);
    }

    #[test]
    fn abrir_una_base_que_no_esta_no_la_crea() {
        let temp = TempDir::new("falta");
        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        assert_eq!(
            Store::open(&paths, &key_of(b'a')).err(),
            Some(StoreError::Missing)
        );
        assert!(!paths.db_exists().unwrap());
    }

    #[test]
    fn crear_no_pisa_una_base_que_ya_existe() {
        let temp = TempDir::new("pisar");
        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        drop(Store::create(&paths, &key_of(b'a')).unwrap());
        assert!(Store::create(&paths, &key_of(b'b')).is_err());
        assert!(Store::open(&paths, &key_of(b'a')).is_ok());
    }

    /// Un archivo que no es una base se lee igual que una clave equivocada:
    /// SQLite no distingue, y el ciclo de vida hace lo mismo con los dos.
    #[test]
    fn un_archivo_basura_se_ve_como_clave_que_no_abre() {
        let temp = TempDir::new("basura");
        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        paths.prepare_dir().unwrap();
        std::fs::write(&paths.db, vec![0x5a; 8192]).unwrap();
        assert_eq!(
            Store::open(&paths, &key_of(b'a')).err(),
            Some(StoreError::WrongKey)
        );
    }
}
