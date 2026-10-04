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
//!
//! **Borrar nunca sigue un enlace, y nunca se lleva algo que no sea una base.**
//! Todo lo que se borra bajo `stores/` —vaciar, apagar, rehacer, podar— pasa por
//! [`StoresRoot`]: `vasak-accounts-sync/` y `stores/` se abren con
//! `O_NOFOLLOW|O_DIRECTORY`, y lo de adentro se borra relativo a ese
//! descriptor, sin recursión. Si alguien cambió `stores/` por un enlace a la
//! carpeta de la persona, la poda no llega ni a leerla; y una carpeta con nombre
//! de cuenta que no tiene una base adentro —ni está vacía— no se toca.

use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, CWD};
use rustix::io::Errno;

use super::StoreError;
use crate::xdg::APP_DIR;

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
/// una copia más. `dirs` no filtra `HOME` por absoluta, así que esa mitad la
/// mira `xdg.rs`, el mismo filtro que usan los otros dos.
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
    crate::xdg::path_under(base, Path::new(APP_DIR).join(STORES_DIR))
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
    crate::xdg::path_under(base, Path::new(APP_DIR).join(SETTINGS_FILE))
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
    /// La carpeta de todas las bases, y el nombre de ésta adentro: lo que hace
    /// falta para borrarla relativo a un descriptor y no por la ruta.
    root: PathBuf,
    account_id: String,
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
            root: root.to_path_buf(),
            account_id: account_id.to_string(),
        })
    }

    /// La ruta de la base para abrirla con `SQLITE_OPEN_NOFOLLOW`.
    ///
    /// SQLite, con esa bandera, rechaza la ruta si **cualquier** componente es
    /// un enlace, no sólo el último. Lo de más arriba de `vasak-accounts-sync/`
    /// —la `XDG_DATA_HOME` de la persona, o su `HOME`— puede serlo a propósito,
    /// así que eso se resuelve acá una vez; lo nuestro —`vasak-accounts-sync/`,
    /// `stores/`, la carpeta de la cuenta y `store.db`— va tal cual, y si
    /// alguno es un enlace SQLite no abre.
    pub fn db_to_open(&self) -> Result<PathBuf, StoreError> {
        let missing = || StoreError::Io(format!("{} no es una ruta de base", self.db.display()));
        let app_dir = self.root.parent().ok_or_else(missing)?;
        let base = app_dir.parent().ok_or_else(missing)?;
        let app_name = app_dir.file_name().ok_or_else(missing)?;
        let root_name = self.root.file_name().ok_or_else(missing)?;
        let base = fs::canonicalize(base).map_err(|e| io_error(base, "resolver", e))?;
        Ok(base
            .join(app_name)
            .join(root_name)
            .join(&self.account_id)
            .join(DB_FILE))
    }

    /// Los tres archivos que forman la base.
    pub fn files(&self) -> [&Path; 3] {
        [&self.db, &self.wal, &self.shm]
    }

    /// Si hay una base en el disco.
    ///
    /// `Ok(false)` **sólo** si el archivo no está. Cualquier otra cosa —un
    /// error de E/S, un permiso, un enlace simbólico donde iría la base— es un
    /// error y no «no hay base»: el ciclo de vida lee «no hay base» como permiso
    /// para crear una encima, y crear empieza por barrer la carpeta.
    pub fn db_exists(&self) -> Result<bool, StoreError> {
        match fs::symlink_metadata(&self.db) {
            Ok(meta) if meta.file_type().is_file() => Ok(true),
            Ok(_) => Err(StoreError::Io(format!(
                "{} no es un archivo regular; no se usa como base",
                self.db.display()
            ))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io_error(&self.db, "mirar", e)),
        }
    }

    /// Crea la carpeta de la cuenta, y la de todas las bases, cerradas.
    ///
    /// Si ya existían se cierran igual. Si no se puede cerrar el acceso **no se
    /// sigue**: una base que anda y que otra cuenta del equipo puede leer, sin
    /// que nada lo diga, es peor que no tener base.
    ///
    /// Tampoco se sigue si `vasak-accounts-sync/` es un enlace: la poda no lo
    /// seguiría para borrar, y una base que se crea donde después no se puede
    /// borrar es una base que sobrevive a «vaciar».
    pub fn prepare_dir(&self) -> Result<(), StoreError> {
        if let Some(app_dir) = self.root.parent() {
            reject_symlink(app_dir, "guardar")?;
        }
        create_private_dir(&self.root)?;
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
    /// Relativo a un descriptor de `stores/` abierto sin seguir enlaces, y sólo
    /// si la carpeta parece una base (ver [`StoresRoot::remove`]). Si alguien
    /// cambió la carpeta por un enlace, se va el enlace y no lo que apunta.
    pub fn remove(&self) -> Result<(), StoreError> {
        match StoresRoot::open(&self.root)? {
            Some(root) => root.remove(&self.account_id),
            None => Ok(()),
        }
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

/// `stores/`, abierta sin seguir enlaces.
///
/// Se abren `vasak-accounts-sync/` y `stores/` con `O_NOFOLLOW|O_DIRECTORY`, así
/// que ninguna de las dos puede ser un enlace; lo de más arriba —la
/// `XDG_DATA_HOME` de la persona— sí se sigue, porque es suyo y lo puede tener
/// donde quiera. Después, todo se hace relativo al descriptor: listar, mirar y
/// borrar. Cambiar `stores/` por un enlace a mitad de camino no cambia a qué
/// carpeta apunta el descriptor.
pub struct StoresRoot {
    fd: OwnedFd,
    path: PathBuf,
}

impl StoresRoot {
    /// Abre `root`. `None` si no existe —no hay bases—; un error si alguno de
    /// los dos últimos componentes es un enlace o no es una carpeta.
    pub fn open(root: &Path) -> Result<Option<Self>, StoreError> {
        let (Some(app_dir), Some(name)) = (root.parent(), root.file_name()) else {
            return Err(StoreError::Io(format!(
                "{} no es una carpeta de bases",
                root.display()
            )));
        };
        let app_fd = match open_dir_at(CWD, app_dir) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(dir_error(app_dir, e)),
        };
        match open_dir_at(&app_fd, name) {
            Ok(fd) => Ok(Some(Self {
                fd,
                path: root.to_path_buf(),
            })),
            Err(Errno::NOENT) => Ok(None),
            Err(e) => Err(dir_error(root, e)),
        }
    }

    /// Las cuentas que tienen una base acá.
    pub fn store_ids(&self) -> Result<Vec<String>, StoreError> {
        let entries = read_entries(&self.fd).map_err(|e| errno_error(&self.path, "leer", e))?;
        let mut ids: Vec<String> = entries
            .into_iter()
            .filter(|(_, kind)| *kind == FileType::Directory)
            .filter_map(|(name, _)| name.into_string().ok())
            .filter(|name| validate_account_id(name).is_ok())
            .filter(|name| {
                open_dir_at(&self.fd, name.as_str())
                    .and_then(|dir| read_entries(&dir))
                    .is_ok_and(|entries| looks_like_store(&entries))
            })
            .collect();
        ids.sort();
        Ok(ids)
    }

    /// Borra la carpeta de una cuenta.
    ///
    /// Sólo si **parece una base**: vacía, o con un `store.db` que es un archivo
    /// regular, o con nada más que restos `store.db*` regulares —un `-wal`
    /// suelto de una base anterior—. Y nunca con una carpeta adentro: una base
    /// no tiene subcarpetas, y lo que no es una base no se borra. Sin recursión:
    /// se borran los archivos de adentro, relativos al descriptor de la carpeta,
    /// y después la carpeta, que si ganó algo mientras tanto no se va.
    ///
    /// Si en lugar de la carpeta hay un enlace, se va el enlace.
    pub fn remove(&self, account_id: &str) -> Result<(), StoreError> {
        validate_account_id(account_id)?;
        let shown = self.path.join(account_id);

        let stat = match rustix::fs::statat(&self.fd, account_id, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(()),
            Err(e) => return Err(errno_error(&shown, "mirar", e)),
        };
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Symlink => {
                return ignore_missing(rustix::fs::unlinkat(
                    &self.fd,
                    account_id,
                    AtFlags::empty(),
                ))
                .map_err(|e| errno_error(&shown, "borrar", e));
            }
            FileType::Directory => {}
            _ => {
                return Err(StoreError::Io(format!(
                    "{} no es una carpeta; no se borra",
                    shown.display()
                )))
            }
        }

        let dir = open_dir_at(&self.fd, account_id).map_err(|e| dir_error(&shown, e))?;
        let entries = read_entries(&dir).map_err(|e| errno_error(&shown, "leer", e))?;
        if !looks_like_store(&entries) {
            return Err(StoreError::Io(format!(
                "{} no parece una base del almacén; no se borra",
                shown.display()
            )));
        }
        for (name, _) in &entries {
            ignore_missing(rustix::fs::unlinkat(
                &dir,
                name.as_c_str(),
                AtFlags::empty(),
            ))
            .map_err(|e| errno_error(&shown, "borrar lo que hay en", e))?;
        }
        ignore_missing(rustix::fs::unlinkat(
            &self.fd,
            account_id,
            AtFlags::REMOVEDIR,
        ))
        .map_err(|e| errno_error(&shown, "borrar", e))
    }
}

pub(crate) fn open_dir_at<Fd: AsFd, P: rustix::path::Arg>(
    dir: Fd,
    path: P,
) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat(
        dir,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// Lo que hay en una carpeta abierta, con el tipo de cada cosa **sin seguir
/// enlaces**. Sin `.` ni `..`.
pub(crate) fn read_entries(dir: &OwnedFd) -> rustix::io::Result<Vec<(CString, FileType)>> {
    let mut reader = rustix::fs::Dir::read_from(dir)?;
    let mut entries = Vec::new();
    while let Some(entry) = reader.read() {
        let entry = entry?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        let kind = match entry.file_type() {
            FileType::Unknown => rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
                .map(|stat| FileType::from_raw_mode(stat.st_mode))?,
            kind => kind,
        };
        entries.push((name.to_owned(), kind));
    }
    Ok(entries)
}

/// Si lo que hay en una carpeta es una base, o lo que queda de una.
fn looks_like_store(entries: &[(CString, FileType)]) -> bool {
    let db = CString::new(DB_FILE).expect("sin ceros");
    let is_store_file = |name: &CStr| name.to_bytes().starts_with(DB_FILE.as_bytes());
    if entries.iter().any(|(_, kind)| *kind == FileType::Directory) {
        return false;
    }
    entries.is_empty()
        || entries
            .iter()
            .any(|(name, kind)| *name == db && *kind == FileType::RegularFile)
        || entries
            .iter()
            .all(|(name, kind)| *kind == FileType::RegularFile && is_store_file(name))
}

fn ignore_missing(result: rustix::io::Result<()>) -> rustix::io::Result<()> {
    match result {
        Err(Errno::NOENT) => Ok(()),
        other => other,
    }
}

/// El motivo de una apertura fallida, según sea.
///
/// **No hay un errno único para «es un enlace simbólico»**: `ELOOP` en Linux,
/// `ENOTDIR` en Darwin, `EMLINK` en FreeBSD. La lista lleva las tres por eso, no
/// por olvidarse una.
fn dir_error(path: &Path, error: Errno) -> StoreError {
    if matches!(error, Errno::LOOP | Errno::NOTDIR | Errno::MLINK) {
        return StoreError::Io(format!(
            "{} es un enlace simbólico o no es una carpeta; no se usa",
            path.display()
        ));
    }
    errno_error(path, "abrir", error)
}

fn errno_error(path: &Path, what: &str, error: Errno) -> StoreError {
    io_error(path, what, io::Error::from(error))
}

/// Falla si `path` es un enlace simbólico.
fn reject_symlink(path: &Path, what: &str) -> Result<(), StoreError> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(StoreError::Io(format!(
            "{} es un enlace simbólico; no se usa para {what}",
            path.display()
        )));
    }
    Ok(())
}

/// Crea una carpeta —y las de arriba— y la deja en 0700.
pub(super) fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    reject_symlink(dir, "guardar")?;
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

    /// El motivo de una apertura fallida se distingue antes de escribir el
    /// mensaje, y el de un enlace son **tres**, no uno: `ELOOP` en Linux,
    /// `ENOTDIR` en Darwin, `EMLINK` en FreeBSD.
    ///
    /// La diferencia importa porque el mensaje manda a la persona a mirar una
    /// cosa u otra: si lo que se le acabaron fueron los descriptores, ir a
    /// buscar un enlace en la carpeta es tiempo perdido.
    #[test]
    fn un_enlace_se_dice_y_el_resto_no() {
        let ruta = Path::new("/var/lib/vasak-accounts/1000");

        for e in [Errno::LOOP, Errno::NOTDIR, Errno::MLINK] {
            let error = dir_error(ruta, e).to_string();
            assert!(error.contains("enlace simbólico"), "{e:?}: {error}");
        }

        for e in [Errno::NOENT, Errno::ACCESS, Errno::MFILE, Errno::PERM] {
            let error = dir_error(ruta, e).to_string();
            assert!(
                !error.contains("enlace simbólico"),
                "{e:?} no es un enlace y se lo culpa como tal: {error}",
            );
            // El genérico dice qué se estaba haciendo, que es lo que sirve.
            assert!(error.contains("abrir"), "{e:?}: {error}");
        }
    }

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

    /// Las cuentas con base en `root`, o ninguna si `root` no está.
    fn list_store_ids(root: &Path) -> Result<Vec<String>, StoreError> {
        match StoresRoot::open(root)? {
            Some(root) => root.store_ids(),
            None => Ok(Vec::new()),
        }
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
        assert!(paths.db_exists().unwrap());
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

    /// Borrar no se lleva lo que no es una base: ni una carpeta sin `store.db`
    /// con archivos ajenos, ni una con una subcarpeta aunque tenga `store.db`.
    #[test]
    fn borrar_no_se_lleva_una_carpeta_que_no_es_una_base() {
        let temp = TempDir::new("ajena");
        let paths = StorePaths::new(&temp.0, "Fotos").unwrap();
        fs::create_dir_all(&paths.dir).unwrap();
        fs::write(paths.dir.join("importante.txt"), "x").unwrap();
        assert!(matches!(paths.remove(), Err(StoreError::Io(_))));
        assert!(paths.dir.join("importante.txt").exists());

        let paths = StorePaths::new(&temp.0, "Trabajo").unwrap();
        fs::create_dir_all(paths.dir.join("sub")).unwrap();
        fs::write(&paths.db, "x").unwrap();
        fs::write(paths.dir.join("sub/informe.txt"), "x").unwrap();
        assert!(matches!(paths.remove(), Err(StoreError::Io(_))));
        assert!(paths.dir.join("sub/informe.txt").exists());
        assert!(paths.db.exists());
    }

    /// «No hay base» es sólo que el archivo no esté. Un error al mirar —acá
    /// un `ENOTDIR`, porque donde va la carpeta hay un archivo— o un enlace
    /// donde va la base son errores, no «no hay base».
    #[test]
    fn mirar_si_hay_base_no_confunde_un_error_con_que_no_esta() {
        let temp = TempDir::new("existe");
        let paths = StorePaths::new(&temp.0, "cuenta").unwrap();
        assert_eq!(paths.db_exists(), Ok(false));

        paths.prepare_dir().unwrap();
        paths.create_empty_db().unwrap();
        assert_eq!(paths.db_exists(), Ok(true));

        fs::remove_file(&paths.db).unwrap();
        std::os::unix::fs::symlink(temp.0.join("otro"), &paths.db).unwrap();
        assert!(matches!(paths.db_exists(), Err(StoreError::Io(_))));

        let file = StorePaths::new(&temp.0, "archivo").unwrap();
        fs::write(&file.dir, "no soy una carpeta").unwrap();
        assert!(matches!(file.db_exists(), Err(StoreError::Io(_))));
    }

    /// Si la carpeta de todas las bases es un enlace, borrar no lo sigue.
    #[test]
    fn borrar_no_sigue_una_carpeta_de_bases_enlazada() {
        let temp = TempDir::new("raiz-enlazada");
        let elsewhere = temp.0.join("Documentos");
        fs::create_dir_all(elsewhere.join("cuenta")).unwrap();
        fs::write(elsewhere.join("cuenta/store.db"), "x").unwrap();
        fs::create_dir_all(temp.0.join("data")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, temp.0.join("data/stores")).unwrap();

        let paths = StorePaths::new(&temp.0.join("data/stores"), "cuenta").unwrap();
        assert!(matches!(paths.remove(), Err(StoreError::Io(_))));
        assert!(elsewhere.join("cuenta/store.db").exists());
        // Y tampoco se crea nada del otro lado.
        assert!(paths.prepare_dir().is_err());
    }

    /// `vasak-accounts-sync/` enlazado tampoco se usa para guardar: lo que se
    /// crea ahí, la poda no lo podría borrar después.
    #[test]
    fn la_carpeta_del_servicio_enlazada_no_se_usa() {
        let temp = TempDir::new("servicio-enlazado");
        let elsewhere = temp.0.join("Documentos");
        fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, temp.0.join("vasak-accounts-sync")).unwrap();

        let root = temp.0.join("vasak-accounts-sync/stores");
        let paths = StorePaths::new(&root, "cuenta").unwrap();
        assert!(paths.prepare_dir().is_err());
        assert!(!elsewhere.join("stores").exists());
        assert!(StoresRoot::open(&root).is_err());
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
