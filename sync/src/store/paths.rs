//! Dónde vive cada base, y quién puede leerla.
//!
//! `$XDG_DATA_HOME/vasak-accounts-sync/stores/<account_id>/store.db`, más el
//! `-wal` y el `-shm` que SQLite deja al lado. En *data* y no en *cache*: una
//! caché se puede borrar entera sin avisar, y desde que la base guarde la cola
//! de operaciones —marcar, mover, borrar— ahí va a haber intención de la persona
//! que no se recupera del servidor.
//!
//! **Directorio 0700 y archivos 0600, reaplicados en cada apertura** y no sólo
//! al crear: una base que ya existía con permisos abiertos —de una copia de
//! seguridad restaurada, de alguien que hizo `chmod` a mano— quedaría legible
//! para otra cuenta del equipo. El cifrado cubre ese caso igual, pero que otra
//! cuenta no pueda ni leer el archivo cifrado es gratis y se suma.

use std::fs;
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::StoreError;

/// La carpeta del servicio, la misma que ya usa la cola de salida.
const APP_DIR: &str = "vasak-accounts-sync";
/// Adentro, una carpeta por cuenta.
const STORES_DIR: &str = "stores";
/// El archivo de la base, dentro de la carpeta de su cuenta.
const DB_FILE: &str = "store.db";
/// Lo que la persona decidió por cuenta: apagado, encendido.
const SETTINGS_FILE: &str = "stores.json";
/// Un tope para el identificador. Los que da el servicio de cuentas son UUID
/// (36 caracteres); esto es para que un nombre absurdo no llegue al disco.
const MAX_ACCOUNT_ID_LEN: usize = 128;

/// La carpeta donde viven todas las bases.
///
/// Sale de `dirs`, como la cola de salida y las preferencias: la regla del
/// estándar —una `XDG_DATA_HOME` relativa o vacía se ignora— vive ahí y no en
/// una copia más. `dirs` no filtra `HOME` por absoluta, así que esa mitad se
/// mira acá, con el mismo criterio que `cola.rs`.
///
/// **Sin un lugar de repuesto.** La cola cae a `/tmp` cuando no hay base, porque
/// perder un correo sin mandar es peor; una base cifrada en `/tmp` no gana nada
/// y deja el archivo donde lo ve cualquiera. Sin base absoluta, no hay almacén.
pub fn stores_root() -> Result<PathBuf, StoreError> {
    stores_root_under(dirs::data_dir()).ok_or(StoreError::NoBaseDir)
}

/// La misma decisión sin leer el entorno, para poder probarla: el entorno es
/// global al proceso y las pruebas corren en paralelo.
fn stores_root_under(base: Option<PathBuf>) -> Option<PathBuf> {
    base.filter(|base| base.is_absolute())
        .map(|base| base.join(APP_DIR).join(STORES_DIR))
}

/// El archivo con lo decidido por cuenta, en `$XDG_CONFIG_HOME`.
///
/// En *config* y no junto a las bases: es una preferencia de la persona, y
/// borrar los datos del servicio no tiene por qué volver a encender algo que
/// ella apagó.
pub fn settings_file() -> Result<PathBuf, StoreError> {
    settings_file_under(dirs::config_dir()).ok_or(StoreError::NoBaseDir)
}

fn settings_file_under(base: Option<PathBuf>) -> Option<PathBuf> {
    base.filter(|base| base.is_absolute())
        .map(|base| base.join(APP_DIR).join(SETTINGS_FILE))
}

/// Comprueba que un identificador de cuenta se pueda usar como nombre de
/// carpeta.
///
/// Letras ASCII, dígitos y guiones, nada más. El identificador llega por D-Bus
/// desde cualquier proceso de la sesión y se convierte en una ruta: sin esto,
/// un `../../algo` borraría lo que quisiera de la carpeta de la persona al
/// pedir «vaciar». La lista es de lo que se acepta y no de lo que se rechaza,
/// porque la de lo que se rechaza siempre se queda corta.
pub fn validate_account_id(account_id: &str) -> Result<(), StoreError> {
    let valid = !account_id.is_empty()
        && account_id.len() <= MAX_ACCOUNT_ID_LEN
        && account_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if valid {
        Ok(())
    } else {
        Err(StoreError::InvalidAccountId(account_id.to_string()))
    }
}

/// Las rutas de la base de una cuenta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePaths {
    pub dir: PathBuf,
    pub db: PathBuf,
    pub wal: PathBuf,
    pub shm: PathBuf,
}

impl StorePaths {
    /// Las rutas de una cuenta bajo `root`. Falla si el identificador no se
    /// puede usar como nombre de carpeta.
    pub fn new(root: &Path, account_id: &str) -> Result<Self, StoreError> {
        validate_account_id(account_id)?;
        let dir = root.join(account_id);
        Ok(Self {
            db: dir.join(DB_FILE),
            wal: dir.join(format!("{DB_FILE}-wal")),
            shm: dir.join(format!("{DB_FILE}-shm")),
            dir,
        })
    }

    /// Los tres archivos que forman la base.
    pub fn files(&self) -> [&Path; 3] {
        [&self.db, &self.wal, &self.shm]
    }

    /// Si hay una base en el disco. Un enlace simbólico no cuenta como base.
    pub fn db_exists(&self) -> bool {
        fs::symlink_metadata(&self.db).is_ok_and(|m| m.file_type().is_file())
    }

    /// Crea la carpeta de la cuenta, y la de todas las bases, cerradas.
    ///
    /// Si ya existían se cierran igual. Si no se puede cerrar el acceso **no se
    /// sigue**: una base que anda y que otra cuenta del equipo puede leer, sin
    /// que nada lo diga, es peor que no tener base.
    pub fn prepare_dir(&self) -> Result<(), StoreError> {
        if let Some(root) = self.dir.parent() {
            create_private_dir(root)?;
        }
        create_private_dir(&self.dir)
    }

    /// Crea el archivo de la base vacío y con 0600, **antes** de que SQLite lo
    /// abra.
    ///
    /// SQLite crea el `-wal` y el `-shm` copiando los permisos del archivo
    /// principal, así que un `store.db` que nace 0600 hace que los otros dos
    /// nazcan 0600 también. Si lo creara SQLite, nacería con la máscara del
    /// proceso —casi siempre 0644— y quedaría un rato abierto hasta el
    /// siguiente `chmod`. Un archivo de largo cero es, para SQLCipher, una base
    /// nueva.
    pub fn create_empty_db(&self) -> Result<(), StoreError> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.db)
            .map(|_| ())
            .map_err(|e| io_error(&self.db, "crear", e))
    }

    /// Pone 0600 en los archivos de la base que existan.
    pub fn tighten_files(&self) -> Result<(), StoreError> {
        for file in self.files() {
            match fs::symlink_metadata(file) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(StoreError::Io(format!(
                        "{} es un enlace simbólico; no se usa como base",
                        file.display()
                    )));
                }
                Ok(meta) if meta.permissions().mode() & 0o777 != 0o600 => {
                    fs::set_permissions(file, fs::Permissions::from_mode(0o600))
                        .map_err(|e| io_error(file, "cerrar el acceso a", e))?;
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_error(file, "mirar", e)),
            }
        }
        Ok(())
    }

    /// Borra la base de la cuenta entera, con su carpeta.
    ///
    /// La carpeta entera y no los tres archivos: si quedó un `-journal` de una
    /// versión vieja, o cualquier otro resto, también es de esta base. Que no
    /// exista no es un error — borrar algo que ya no está es haberlo borrado.
    ///
    /// `remove_dir_all` no sigue enlaces simbólicos: si alguien cambió la
    /// carpeta por un enlace, se va el enlace y no lo que apunta.
    pub fn remove(&self) -> Result<(), StoreError> {
        match fs::symlink_metadata(&self.dir) {
            Ok(meta) if meta.file_type().is_symlink() => fs::remove_file(&self.dir),
            Ok(_) => fs::remove_dir_all(&self.dir),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
        .map_err(|e| io_error(&self.dir, "borrar", e))
    }

    /// Cuánto ocupa la base en el disco, con el `-wal` y el `-shm`.
    pub fn size_bytes(&self) -> u64 {
        self.files()
            .iter()
            .filter_map(|file| fs::symlink_metadata(file).ok())
            .filter(|meta| meta.file_type().is_file())
            .map(|meta| meta.len())
            .sum()
    }
}

/// Las cuentas que tienen una carpeta en `root`.
///
/// Sólo las carpetas cuyo nombre es un identificador válido: lo demás que haya
/// ahí no lo puso este servicio y no es suyo para borrar. Que `root` no exista
/// quiere decir que no hay ninguna.
pub fn list_store_ids(root: &Path) -> Result<Vec<String>, StoreError> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_error(root, "leer", e)),
    };

    let mut ids: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| validate_account_id(name).is_ok())
        .collect();
    ids.sort();
    Ok(ids)
}

/// Crea una carpeta —y las de arriba— y la deja en 0700.
pub(super) fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    if fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(StoreError::Io(format!(
            "{} es un enlace simbólico; no se usa para guardar",
            dir.display()
        )));
    }
    fs::create_dir_all(dir).map_err(|e| io_error(dir, "crear", e))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| io_error(dir, "cerrar el acceso a", e))
}

fn io_error(path: &Path, what: &str, error: io::Error) -> StoreError {
    StoreError::Io(format!("no se pudo {what} {}: {error}", path.display()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Una carpeta temporal propia de cada prueba, que se borra sola.
    pub(crate) struct TempDir(pub PathBuf);

    impl TempDir {
        pub(crate) fn new(label: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "vasak-store-{label}-{}-{unique}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn las_bases_cuelgan_del_directorio_de_datos() {
        assert_eq!(
            stores_root_under(Some(PathBuf::from("/home/ana/.local/share"))),
            Some(PathBuf::from(
                "/home/ana/.local/share/vasak-accounts-sync/stores"
            ))
        );
        assert_eq!(
            settings_file_under(Some(PathBuf::from("/home/ana/.config"))),
            Some(PathBuf::from(
                "/home/ana/.config/vasak-accounts-sync/stores.json"
            ))
        );
    }

    /// Una base relativa no se usa, y no hay lugar de repuesto: una base
    /// cifrada en `/tmp` no gana nada y deja el archivo donde lo ve cualquiera.
    #[test]
    fn una_base_relativa_no_da_almacen() {
        for relative in ["", "datos", "./datos", "../datos"] {
            assert_eq!(
                stores_root_under(Some(PathBuf::from(relative))),
                None,
                "una base de {relative:?} no tiene que usarse"
            );
            assert_eq!(settings_file_under(Some(PathBuf::from(relative))), None);
        }
        assert_eq!(stores_root_under(None), None);
    }

    #[test]
    fn la_base_de_una_cuenta_tiene_sus_tres_archivos() {
        let paths = StorePaths::new(Path::new("/r"), "a1-b2").unwrap();
        assert_eq!(paths.dir, PathBuf::from("/r/a1-b2"));
        assert_eq!(paths.db, PathBuf::from("/r/a1-b2/store.db"));
        assert_eq!(paths.wal, PathBuf::from("/r/a1-b2/store.db-wal"));
        assert_eq!(paths.shm, PathBuf::from("/r/a1-b2/store.db-shm"));
    }

    /// El identificador llega por D-Bus de cualquier proceso de la sesión y se
    /// convierte en una ruta. Una barra, un punto o el vacío tienen que quedar
    /// afuera, o «vaciar» borraría lo que quien llama elija.
    #[test]
    fn un_identificador_que_no_es_un_nombre_de_carpeta_se_rechaza() {
        let long = "a".repeat(MAX_ACCOUNT_ID_LEN + 1);
        for bad in [
            "",
            "/",
            "a/b",
            "../a",
            "..",
            ".",
            "a.b",
            "a b",
            "a\0b",
            "a\\b",
            "ñandú",
            "~",
            long.as_str(),
        ] {
            assert!(
                matches!(
                    validate_account_id(bad),
                    Err(StoreError::InvalidAccountId(_))
                ),
                "{bad:?} tenía que rechazarse"
            );
            assert!(StorePaths::new(Path::new("/r"), bad).is_err());
        }
        for good in [
            "a",
            "0f8b7c1e-2d3a-4b5c-9e8f-112233445566",
            "Cuenta-1",
            &"a".repeat(MAX_ACCOUNT_ID_LEN),
        ] {
            assert!(validate_account_id(good).is_ok(), "{good:?} es válido");
        }
    }

    #[test]
    fn la_carpeta_nace_cerrada_y_se_vuelve_a_cerrar() {
        let temp = TempDir::new("carpeta");
        let root = temp.0.join("stores");
        let paths = StorePaths::new(&root, "cuenta").unwrap();

        paths.prepare_dir().unwrap();
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&paths.dir), 0o700);

        // Alguien la abrió: la próxima apertura la vuelve a cerrar.
        fs::set_permissions(&paths.dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        paths.prepare_dir().unwrap();
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&paths.dir), 0o700);
    }

    #[test]
    fn la_base_vacia_nace_con_0600() {
        let temp = TempDir::new("vacia");
        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        paths.prepare_dir().unwrap();
        paths.create_empty_db().unwrap();
        assert_eq!(mode(&paths.db), 0o600);
        assert!(paths.db_exists());
        // Y no pisa una que ya existe.
        assert!(paths.create_empty_db().is_err());
    }

    #[test]
    fn un_enlace_simbolico_no_se_usa_como_carpeta() {
        let temp = TempDir::new("enlace");
        let elsewhere = temp.0.join("otro-lado");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, temp.0.join("cuenta")).unwrap();

        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        assert!(paths.prepare_dir().is_err());
        // Y lo que apuntaba quedó como estaba.
        assert_eq!(mode(&elsewhere), 0o755);

        // Borrar se lleva el enlace y no lo apuntado.
        fs::write(elsewhere.join("algo"), "x").unwrap();
        paths.remove().unwrap();
        assert!(elsewhere.join("algo").exists());
        assert!(fs::symlink_metadata(temp.0.join("cuenta")).is_err());
    }

    #[test]
    fn borrar_se_lleva_la_carpeta_entera_y_no_falla_si_no_esta() {
        let temp = TempDir::new("borrar");
        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        paths.prepare_dir().unwrap();
        for file in paths.files() {
            fs::write(file, "x").unwrap();
        }
        fs::write(paths.dir.join("store.db-journal"), "resto").unwrap();
        assert_eq!(paths.size_bytes(), 3);

        paths.remove().unwrap();
        assert!(!paths.dir.exists());
        assert_eq!(paths.size_bytes(), 0);
        paths.remove().unwrap();
    }

    #[test]
    fn solo_se_listan_las_carpetas_con_nombre_de_cuenta() {
        let temp = TempDir::new("listar");
        assert!(list_store_ids(&temp.0.join("no-existe"))
            .unwrap()
            .is_empty());

        for dir in ["b", "a", "no.es.cuenta", ".oculta"] {
            fs::create_dir_all(temp.0.join(dir)).unwrap();
        }
        fs::write(temp.0.join("archivo"), "x").unwrap();
        assert_eq!(list_store_ids(&temp.0).unwrap(), vec!["a", "b"]);
    }
}
