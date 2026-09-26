//! La cola de salida: lo que se escribió y todavía no salió.
//!
//! ── Por qué ésta sí va al disco ─────────────────────────────────────────────
//!
//! La lista de mensajes recibidos vive en memoria a propósito: guardarla sería
//! dejar el remitente y el asunto de todo el correo de la persona en un archivo
//! para siempre, a cambio de ahorrar dos segundos.
//!
//! Con lo que sale es al revés, y no es una inconsistencia. Un mensaje que la
//! persona **escribió** y mandó a enviar no se puede perder porque se cortó la
//! luz, porque se cerró la sesión o porque el servidor no contestaba en ese
//! momento. Perder algo que alguien escribió es de las peores cosas que puede
//! hacer un programa, y la diferencia con el otro caso es que acá el archivo
//! **se borra en cuanto el mensaje sale**: no es un registro, es una escala.
//!
//! ── Dónde y con qué permisos ────────────────────────────────────────────────
//!
//! En los datos del usuario y no en la caché: una caché se puede borrar entera
//! sin avisar, y con ella se iría un correo sin mandar.
//!
//! El directorio va en 0700 y cada archivo en 0600, porque adentro hay el texto
//! completo de mensajes privados. En un equipo compartido, el valor por omisión
//! los dejaría legibles para cualquier otra cuenta.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::compose::Draft;

/// Cuántos mensajes se aceptan sin mandar.
///
/// Sin tope, una cuenta cuyo servidor rechaza todo puede llenar el disco de la
/// persona con reintentos. Doscientos es más de lo que nadie tiene esperando.
const MAX_QUEUED: usize = 200;

/// Cuántas veces se reintenta antes de dejar de hacerlo.
///
/// Con la espera que crece, diez intentos cubren más de un día. Después de eso
/// el problema no se va a arreglar solo y lo que corresponde es decírselo a la
/// persona en vez de seguir golpeando el servidor de alguien.
pub const MAX_ATTEMPTS: u32 = 10;

/// En qué anda un mensaje de la cola.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryState {
    /// Esperando su turno, o entre reintentos.
    #[default]
    #[serde(rename = "pendiente")]
    Pending,
    /// Se le acabaron los intentos, o el servidor dijo que no definitivamente.
    /// No se vuelve a intentar solo: hace falta que la persona haga algo.
    #[serde(rename = "trabado")]
    Stuck,
}

/// Un mensaje esperando salir.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outgoing {
    pub id: String,
    pub account_id: String,
    #[serde(rename = "borrador")]
    pub draft: Draft,
    /// El identificador del mensaje, decidido **al encolarlo** y no al mandarlo.
    ///
    /// Si se calculara en cada intento, un mensaje que se entrega y cuya
    /// confirmación se pierde entraría dos veces en el buzón de quien lo recibe,
    /// con dos identificadores distintos, y ningún cliente podría darse cuenta
    /// de que es el mismo. Con el identificador fijo, los clientes que
    /// deduplican lo hacen.
    #[serde(rename = "identificador")]
    pub message_id: String,
    /// La fecha de la cabecera, también fija por lo mismo: un mensaje escrito
    /// anoche que sale a la mañana tiene que decir que se escribió anoche.
    #[serde(rename = "fecha")]
    pub date: String,
    #[serde(default, rename = "intentos")]
    pub attempts: u32,
    #[serde(default, rename = "estado")]
    pub state: DeliveryState,
    /// Qué pasó la última vez. Vacío si todavía no se intentó.
    #[serde(default, rename = "ultimo_error")]
    pub last_error: String,
    /// A partir de cuándo **la persona** pidió que salga, en RFC 3339.
    ///
    /// Vacío quiere decir «cuando se pueda», que es lo de siempre. Lo usan dos
    /// cosas que son la misma por dentro: el envío programado, con la hora que
    /// alguien eligió, y la ventana para deshacer, que es `now` más unos
    /// segundos.
    ///
    /// Aparte de `proximo_intento` a propósito, aunque los dos sean momentos:
    /// uno lo pone la persona y el otro lo pone un fallo. Con un solo campo, un
    /// mensaje programado para las nueve que falla a las nueve se reintentaría
    /// a las nueve y treinta — y ya no saldría a la hora que se pidió.
    ///
    /// `#[serde(default)]` no es adorno: la cola vive en disco, y sin eso un
    /// mensaje encolado por una versión anterior no se podría leer. Un mensaje
    /// que alguien escribió y no se puede leer es un mensaje perdido.
    #[serde(default, rename = "programado_para")]
    pub scheduled_for: String,
    /// A partir de cuándo se puede volver a intentar, en ISO 8601.
    ///
    /// Se guarda el **momento** y no se calcula desde la fecha del mensaje: así
    /// la espera sobrevive a un reinicio del servicio —un mensaje que falló hace
    /// diez segundos no se reintenta en el acto porque el proceso arrancó de
    /// nuevo— y quien mire el archivo entiende qué está esperando sin tener que
    /// rehacer la cuenta.
    #[serde(default, rename = "proximo_intento")]
    pub next_attempt: String,
}

/// Si un momento guardado ya pasó.
///
/// Vacío quiere decir «no hay nada que esperar». Una fecha que no se entiende
/// **también**: un campo ilegible no puede dejar encerrado para siempre un
/// mensaje que alguien escribió.
fn has_passed(moment: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    if moment.is_empty() {
        return true;
    }
    match chrono::DateTime::parse_from_rfc3339(moment) {
        Ok(at) => now >= at.with_timezone(&chrono::Utc),
        Err(_) => true,
    }
}

impl Outgoing {
    /// Cuánto esperar antes del próximo intento.
    ///
    /// La espera se duplica: medio minuto, uno, dos, cuatro… hasta una hora. Un
    /// servidor que está caído no mejora porque se le insista cada treinta
    /// segundos, y insistir así es cómo una dirección termina en una lista
    /// negra.
    pub fn backoff(&self) -> std::time::Duration {
        const BASE: u64 = 30;
        const MAX_SECS: u64 = 3600;
        let factor = 1u64.checked_shl(self.attempts.min(20)).unwrap_or(u64::MAX);
        std::time::Duration::from_secs(BASE.saturating_mul(factor).min(MAX_SECS))
    }

    /// Si ya le toca volver a intentar.
    ///
    /// Sin `proximo_intento` —un mensaje recién encolado, o uno guardado por una
    /// versión anterior— le toca ya: es preferible un intento de más a un
    /// mensaje que no sale nunca.
    pub fn is_due(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        // **Las dos condiciones**, y por separado. `proximo_intento` quiere
        // decir «esperá antes de reintentar» y `programado_para` quiere decir
        // «no lo mandes antes de esta hora»: son cosas distintas y sumarlas en
        // un solo campo hace que un programado que falla una vez se corra de
        // hora — la espera exponencial se apilaría encima de la hora elegida.
        has_passed(&self.scheduled_for, now) && has_passed(&self.next_attempt, now)
    }

    /// Si un mensaje está esperando una hora que todavía no llegó.
    ///
    /// Es lo que la ventana necesita para mostrarlo como programado y no como
    /// «saliendo»: son dos cosas distintas y se ven igual si no se pregunta.
    pub fn is_scheduled(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        !has_passed(&self.scheduled_for, now)
    }

    /// Anota que falló y cuándo se vuelve a probar.
    pub fn record_failure(&mut self, reason: String, now: chrono::DateTime<chrono::Utc>) {
        self.attempts += 1;
        self.last_error = reason;
        let delay = chrono::Duration::from_std(self.backoff())
            .unwrap_or_else(|_| chrono::Duration::hours(1));
        self.next_attempt = (now + delay).to_rfc3339();
    }
}

/// Dónde vive la cola.
///
/// En los datos del usuario, no en la caché: una caché se puede borrar entera
/// sin avisar, y con ella se iría un correo sin mandar.
pub fn outbox_dir() -> PathBuf {
    // Por `dirs` y no leyendo el entorno acá, y con el filtro de `xdg.rs`: la
    // regla —absoluta o nada, que el estándar pide y que de paso cubre la
    // variable vacía— vive en un solo lugar en vez de en una copia por módulo.
    //
    // Antes esto filtraba `XDG_DATA_HOME` por absoluta y **no** `HOME`, así que
    // la mitad del agujero seguía abierta: con un `HOME` relativo la cola de
    // salida se escribía bajo el directorio de trabajo del daemon. El filtro
    // cierra esa otra mitad, que es la que `dirs` no mira.
    outbox_dir_under(dirs::data_dir())
}

/// La misma decisión sin leer el entorno, para poder probarla.
fn outbox_dir_under(base: Option<PathBuf>) -> PathBuf {
    app_data_dir_under(base).join(OUTBOX_DIR)
}

/// La carpeta del servicio en los datos del usuario, de donde cuelga la cola.
pub fn app_data_dir() -> PathBuf {
    app_data_dir_under(dirs::data_dir())
}

/// Sin base absoluta, `/tmp`: perder un correo sin mandar es peor que dejarlo
/// ahí, en 0600. (El almacén no tiene repuesto, ver `store/paths.rs`.)
fn app_data_dir_under(base: Option<PathBuf>) -> PathBuf {
    crate::xdg::absolute_base(base)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(crate::xdg::APP_DIR)
}

/// La carpeta de la cola, dentro de la del servicio.
const OUTBOX_DIR: &str = "outbox";

/// Donde vivía la cola hasta la 0.16.0.
const LEGACY_OUTBOX_DIR: &str = "salientes";

/// Qué hizo la mudanza de `salientes/` a `outbox/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Migration {
    /// No había `salientes/`: no hay nada que mudar.
    NothingToMove,
    /// `outbox/` no estaba y `salientes/` pasó entera, de un solo renombre.
    Renamed,
    /// Estaban las dos. Pasaron los archivos que no chocaban con uno de
    /// `outbox/`; los que chocaban —o no eran archivos— siguen en
    /// `salientes/`, con sus nombres acá. `salientes/` se borró sólo si quedó
    /// vacía.
    Merged { moved: usize, kept: Vec<String> },
}

/// Muda la cola de `salientes/` a `outbox/`, al arrancar.
///
/// Hasta la 0.16.0 la cola vivía en `$XDG_DATA_HOME/vasak-accounts-sync/
/// salientes/`. Un mensaje que quedó ahí sin salir lo escribió alguien, y
/// tiene que salir igual después de actualizar: por eso se muda la carpeta y
/// no se cambia sólo la ruta.
///
/// - Si `outbox/` no está, `salientes/` se renombra entera, que es atómico: o
///   pasa todo o no pasa nada.
/// - **Si están las dos** —se volvió a una versión anterior y se la usó, o se
///   restauró una copia de seguridad— no se pisa nada. Cada archivo pasa de
///   una a otra con `renameat2(RENAME_NOREPLACE)`, que falla en vez de
///   reemplazar; uno que ya existe en `outbox/` con el mismo nombre se queda en
///   `salientes/`, y se dice en el diario. Los nombres son el identificador del
///   mensaje, que empieza con la hora en microsegundos: dos iguales son el
///   mismo mensaje, y el de `outbox/` es el que la versión de ahora ya estuvo
///   intentando. `salientes/` se borra sólo si quedó vacía.
/// - **Ningún enlace simbólico se sigue**: ni `vasak-accounts-sync/`, ni
///   `salientes/`, ni `outbox/`, ni lo que hay adentro. Todo se hace relativo a
///   descriptores abiertos con `O_NOFOLLOW`, como la poda del almacén; lo de
///   más arriba —la `XDG_DATA_HOME` de la persona— sí se sigue, porque es suyo.
///   Un enlace en cualquiera de las dos carpetas es un error y no se toca nada.
/// - Sólo se mueve lo que es **de esta persona**: la carpeta vieja, la nueva y
///   cada archivo tienen que ser suyos. En `/tmp` —el repuesto sin base
///   absoluta— otra cuenta del equipo podría haber dejado una `salientes/`
///   propia, y mudarla sería mandar correo que escribió otro.
/// - `outbox/` queda en 0700, como la deja `Outbox::open`.
///
/// Un error no borra nada ni tiene que impedir que arranque el servicio: quien
/// llama lo anota y sigue, y lo que haya quedado en `salientes/` espera ahí.
pub fn migrate_legacy_outbox(app_dir: &Path) -> Result<Migration, String> {
    use rustix::fs::{AtFlags, FileType, Mode, RenameFlags, CWD};
    use rustix::io::Errno;

    use crate::store::paths::{open_dir_at, read_entries};

    let shown = |name: &str| app_dir.join(name).display().to_string();
    let errno = |what: &str, name: &str, e: Errno| {
        format!(
            "no se pudo {what} {}: {}",
            shown(name),
            std::io::Error::from(e)
        )
    };
    let not_ours = |name: &str| format!("{} no es de esta cuenta; no se muda la cola", shown(name));
    let me = rustix::process::getuid();
    let owned = |stat: &rustix::fs::Stat| rustix::process::Uid::from_raw(stat.st_uid) == me;

    let app_fd = match open_dir_at(CWD, app_dir) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(Migration::NothingToMove),
        Err(Errno::LOOP) | Err(Errno::NOTDIR) => {
            return Err(format!(
                "{} es un enlace simbólico o no es una carpeta; no se muda la cola",
                app_dir.display()
            ))
        }
        Err(e) => return Err(errno("abrir", "", e)),
    };

    let legacy = match rustix::fs::statat(&app_fd, LEGACY_OUTBOX_DIR, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return Ok(Migration::NothingToMove),
        Err(e) => return Err(errno("mirar", LEGACY_OUTBOX_DIR, e)),
    };
    if FileType::from_raw_mode(legacy.st_mode) != FileType::Directory {
        return Err(format!(
            "{} es un enlace simbólico o no es una carpeta; no se muda la cola",
            shown(LEGACY_OUTBOX_DIR)
        ));
    }
    if !owned(&legacy) {
        return Err(not_ours(LEGACY_OUTBOX_DIR));
    }

    let close_outbox = |app_fd: &std::os::fd::OwnedFd| -> Result<(), String> {
        let outbox = open_dir_at(app_fd, OUTBOX_DIR).map_err(|e| errno("abrir", OUTBOX_DIR, e))?;
        rustix::fs::fchmod(&outbox, Mode::from_raw_mode(0o700))
            .map_err(|e| errno("cerrar el acceso a", OUTBOX_DIR, e))?;
        rustix::fs::fsync(&outbox).map_err(|e| errno("asegurar en el disco", OUTBOX_DIR, e))?;
        rustix::fs::fsync(app_fd).map_err(|e| errno("asegurar en el disco", "", e))
    };

    match rustix::fs::statat(&app_fd, OUTBOX_DIR, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => {
            let renamed = match rustix::fs::renameat_with(
                &app_fd,
                LEGACY_OUTBOX_DIR,
                &app_fd,
                OUTBOX_DIR,
                RenameFlags::NOREPLACE,
            ) {
                // Un sistema de archivos que no conoce la bandera: el renombre
                // de siempre sirve igual, porque una carpeta sólo reemplaza a
                // otra **vacía**, y una con algo adentro lo hace fallar.
                Err(Errno::INVAL) | Err(Errno::NOSYS) => {
                    rustix::fs::renameat(&app_fd, LEGACY_OUTBOX_DIR, &app_fd, OUTBOX_DIR)
                }
                other => other,
            };
            match renamed {
                Ok(()) => {
                    close_outbox(&app_fd)?;
                    return Ok(Migration::Renamed);
                }
                // Apareció `outbox/` entre la mirada y el renombre: se juntan.
                Err(Errno::EXIST) | Err(Errno::NOTEMPTY) => {}
                Err(e) => return Err(errno("renombrar", LEGACY_OUTBOX_DIR, e)),
            }
        }
        Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Directory => {}
        Ok(_) => {
            return Err(format!(
                "{} es un enlace simbólico o no es una carpeta; no se muda la cola",
                shown(OUTBOX_DIR)
            ))
        }
        Err(e) => return Err(errno("mirar", OUTBOX_DIR, e)),
    }

    // Las dos existen: archivo por archivo, sin pisar ninguno.
    let old_fd = open_dir_at(&app_fd, LEGACY_OUTBOX_DIR)
        .map_err(|e| errno("abrir", LEGACY_OUTBOX_DIR, e))?;
    let new_fd = open_dir_at(&app_fd, OUTBOX_DIR).map_err(|e| errno("abrir", OUTBOX_DIR, e))?;
    // Otra vez, sobre lo que quedó abierto: lo que se miró antes por el nombre
    // lo pudo haber cambiado otro entre medio.
    let old_stat = rustix::fs::fstat(&old_fd).map_err(|e| errno("mirar", LEGACY_OUTBOX_DIR, e))?;
    if !owned(&old_stat) {
        return Err(not_ours(LEGACY_OUTBOX_DIR));
    }
    let new_stat = rustix::fs::fstat(&new_fd).map_err(|e| errno("mirar", OUTBOX_DIR, e))?;
    if !owned(&new_stat) {
        return Err(not_ours(OUTBOX_DIR));
    }

    let entries = read_entries(&old_fd).map_err(|e| errno("leer", LEGACY_OUTBOX_DIR, e))?;
    let mut moved = 0;
    let mut kept = Vec::new();
    for (name, _) in entries {
        let file_name = name.to_string_lossy().into_owned();
        // El tipo y el dueño salen del mismo `statat`: el tipo que trajo la
        // lectura de la carpeta es de otro momento, y entre los dos la entrada
        // se puede cambiar por un enlace.
        let movable = rustix::fs::statat(&old_fd, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
            .is_ok_and(|stat| is_movable(&stat, me));
        if !movable {
            tracing::warn!(
                "{file_name} no es un archivo de esta cuenta; se queda en {}",
                shown(LEGACY_OUTBOX_DIR)
            );
            kept.push(file_name);
            continue;
        }
        match move_without_replacing(&old_fd, &new_fd, name.as_c_str()) {
            Ok(()) => moved += 1,
            Err(Errno::EXIST) => {
                tracing::warn!(
                    "{file_name} ya está en {}; el de {} se queda donde está",
                    shown(OUTBOX_DIR),
                    shown(LEGACY_OUTBOX_DIR)
                );
                kept.push(file_name);
            }
            Err(e) => {
                tracing::warn!(
                    "no se pudo mover {file_name} a {}: {}; se queda en {}",
                    shown(OUTBOX_DIR),
                    std::io::Error::from(e),
                    shown(LEGACY_OUTBOX_DIR)
                );
                kept.push(file_name);
            }
        }
    }
    rustix::fs::fsync(&old_fd).map_err(|e| errno("asegurar en el disco", LEGACY_OUTBOX_DIR, e))?;
    drop(old_fd);
    drop(new_fd);
    close_outbox(&app_fd)?;

    if kept.is_empty() {
        match rustix::fs::unlinkat(&app_fd, LEGACY_OUTBOX_DIR, AtFlags::REMOVEDIR) {
            // Ganó algo entre medio: se queda, con eso adentro.
            Ok(()) | Err(Errno::NOTEMPTY) | Err(Errno::EXIST) | Err(Errno::NOENT) => {}
            Err(e) => return Err(errno("borrar", LEGACY_OUTBOX_DIR, e)),
        }
        rustix::fs::fsync(&app_fd).map_err(|e| errno("asegurar en el disco", "", e))?;
    }

    Ok(Migration::Merged { moved, kept })
}

/// Si una entrada de `salientes/` se puede mudar: un archivo regular, no un
/// enlace ni una carpeta, y de quien corre el servicio. Se decide con un solo
/// `stat` (sin seguir enlaces), así el tipo y el dueño son del mismo momento.
fn is_movable(stat: &rustix::fs::Stat, me: rustix::process::Uid) -> bool {
    rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::RegularFile
        && rustix::process::Uid::from_raw(stat.st_uid) == me
}

/// Mueve un archivo de una carpeta a otra **sin reemplazar** uno que ya esté.
///
/// `renameat2(RENAME_NOREPLACE)`; en un sistema de archivos que no conoce la
/// bandera, un enlace duro nuevo —que tampoco reemplaza: falla con `EEXIST`— y
/// después se borra el viejo. Nunca el renombre de siempre, que pisaría.
fn move_without_replacing(
    from: &std::os::fd::OwnedFd,
    to: &std::os::fd::OwnedFd,
    name: &std::ffi::CStr,
) -> rustix::io::Result<()> {
    use rustix::fs::{AtFlags, RenameFlags};
    use rustix::io::Errno;

    match rustix::fs::renameat_with(from, name, to, name, RenameFlags::NOREPLACE) {
        Err(Errno::INVAL) | Err(Errno::NOSYS) => {
            rustix::fs::linkat(from, name, to, name, AtFlags::empty())?;
            rustix::fs::unlinkat(from, name, AtFlags::empty())
        }
        other => other,
    }
}

/// La cola en el disco.
pub struct Outbox {
    root: PathBuf,
}

impl Outbox {
    pub fn open(root: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&root)
            .map_err(|e| format!("no se pudo crear {}: {e}", root.display()))?;
        // 0700 **siempre**, no sólo al crear: un directorio que ya existía con
        // permisos abiertos —de una versión anterior, de una copia de
        // seguridad restaurada— dejaría el correo de la persona legible para
        // cualquier otra cuenta del equipo.
        //
        // Y si no se puede, **no se sigue**. Tragarse el fallo dejaba una cola
        // que anda perfectamente y que cualquiera del equipo puede leer, sin
        // que nada lo diga: es peor que no tener cola.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            format!(
                "no se pudo cerrar el acceso a {}: {e}. \
                 Sin eso el correo sin mandar quedaría legible para otras cuentas del equipo",
                root.display()
            )
        })?;
        Ok(Outbox { root })
    }

    fn path_of(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }

    /// Guarda un mensaje para mandarlo.
    pub fn enqueue(&self, outgoing: &Outgoing) -> Result<(), String> {
        if self.count()? >= MAX_QUEUED {
            return Err(format!(
                "ya hay {MAX_QUEUED} mensajes esperando salir; \
                 revisá la carpeta de salida antes de escribir otro"
            ));
        }
        self.save(outgoing)
    }

    /// Escribe o reemplaza un mensaje de la cola.
    ///
    /// **A un archivo temporal y después renombrado.** Escribir encima del
    /// bueno deja el mensaje a medias si se corta la luz en el medio, y lo que
    /// queda no es ni el de antes ni el de ahora: un renombre, en cambio, o pasa
    /// entero o no pasa.
    pub fn save(&self, outgoing: &Outgoing) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(outgoing)
            .map_err(|e| format!("no se pudo serializar el mensaje: {e}"))?;

        let temp_path = self.root.join(format!(".{}.tmp", outgoing.id));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            // 0600: adentro está el texto completo de un mensaje privado.
            .mode(0o600)
            .open(&temp_path)
            .map_err(|e| format!("no se pudo escribir el mensaje: {e}"))?;

        file.write_all(&json)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("no se pudo escribir el mensaje: {e}"))?;
        drop(file);

        std::fs::rename(&temp_path, self.path_of(&outgoing.id))
            .map_err(|e| format!("no se pudo guardar el mensaje: {e}"))?;

        self.sync_dir()
    }

    /// Fuerza al disco el **directorio**, no el archivo.
    ///
    /// El contenido ya está en disco: eso lo hizo el `sync_all` del temporal.
    /// Lo que falta es la entrada del directorio, que es lo que dice que el
    /// archivo se llama así. Sin esto, un corte de luz justo después del
    /// renombre puede dejar el contenido escrito y el nombre no — o sea, un
    /// mensaje aceptado que al arrancar no está, o uno ya entregado que
    /// reaparece y se manda dos veces.
    fn sync_dir(&self) -> Result<(), String> {
        std::fs::File::open(&self.root)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("no se pudo asegurar la cola en el disco: {e}"))
    }

    /// Saca un mensaje de la cola. Se llama cuando salió.
    pub fn remove(&self, id: &str) -> Result<(), String> {
        match std::fs::remove_file(self.path_of(id)) {
            Ok(()) => self.sync_dir(),
            // Que ya no esté es el resultado que se buscaba.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("no se pudo quitar el mensaje: {e}")),
        }
    }

    /// Todo lo que hay esperando, del más viejo al más nuevo.
    ///
    /// Un archivo que no se puede leer **se saltea** en vez de tirar la lista:
    /// uno corrupto —de un corte de luz de antes del renombre atómico, de una
    /// versión anterior— no puede impedir que salgan los demás.
    pub fn all(&self) -> Result<Vec<Outgoing>, String> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("no se pudo leer la cola: {e}")),
        };

        let mut queued: Vec<Outgoing> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .filter_map(|p| read_outgoing(&p))
            .collect();

        // Por identificador, que empieza con la hora: la cola sale en el orden
        // en que se escribió, que es el que espera quien la mira.
        queued.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(queued)
    }

    fn count(&self) -> Result<usize, String> {
        Ok(self.all()?.len())
    }
}

fn read_outgoing(path: &Path) -> Option<Outgoing> {
    let text = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str(&text) {
        Ok(outgoing) => Some(outgoing),
        Err(e) => {
            tracing::warn!("no se pudo leer {}: {e}", path.display());
            None
        }
    }
}

/// Lo que el despachador intenta mandar en esta vuelta, en el orden de la cola.
///
/// Se saltean los trabados —hace falta que la persona haga algo— y los que
/// todavía no les toca: la espera crece con cada intento fallido, y un
/// programado espera su hora.
pub fn ready_to_send(queued: Vec<Outgoing>, now: chrono::DateTime<chrono::Utc>) -> Vec<Outgoing> {
    queued
        .into_iter()
        .filter(|outgoing| outgoing.state != DeliveryState::Stuck && outgoing.is_due(now))
        .collect()
}

/// Lo que contesta `ListOutbox`: cada mensaje como está en el archivo, más
/// `esperando_su_hora`.
///
/// Se agrega si está esperando su hora, que no es un campo del archivo sino una
/// pregunta sobre el reloj. Calcularlo acá y no en la ventana deja la regla
/// —vacío, ilegible, o ya pasó— en un solo lugar; hacerlo en los dos es tener
/// dos reglas que se pueden separar.
pub fn view(queued: Vec<Outgoing>, now: chrono::DateTime<chrono::Utc>) -> Vec<serde_json::Value> {
    queued
        .into_iter()
        .map(|outgoing| {
            let waiting = outgoing.is_scheduled(now);
            let mut json = serde_json::to_value(outgoing).unwrap_or_default();
            if let Some(object) = json.as_object_mut() {
                object.insert("esperando_su_hora".into(), waiting.into());
            }
            json
        })
        .collect()
}

/// Un identificador para un mensaje de la cola.
///
/// Empieza con la hora en microsegundos para que ordenar por nombre sea ordenar
/// por antigüedad, y termina con un número que sube para que dos mensajes del
/// mismo microsegundo no se pisen.
pub fn new_id(moment: chrono::DateTime<chrono::Utc>, unique: u64) -> String {
    format!("{:016x}-{unique:08x}", moment.timestamp_micros())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "vasak-cola-{unique}-{:?}",
            std::thread::current().id()
        ))
    }

    fn outgoing(id: &str) -> Outgoing {
        Outgoing {
            id: id.into(),
            account_id: "cuenta".into(),
            draft: Draft {
                from: "ana@ejemplo.com".into(),
                to: vec!["juan@otro.com".into()],
                subject: "Hola".into(),
                body: "Buenas.".into(),
                ..Default::default()
            },
            message_id: "<x@ejemplo.com>".into(),
            date: "Thu, 10 Sep 2026 12:00:00 +0000".into(),
            attempts: 0,
            state: DeliveryState::Pending,
            last_error: String::new(),
            scheduled_for: String::new(),
            next_attempt: String::new(),
        }
    }

    /// Si no se puede cerrar el acceso, **no se sigue**. Una cola que anda
    /// perfectamente y que cualquiera del equipo puede leer, sin que nada lo
    /// diga, es peor que no tener cola.
    #[test]
    fn una_cola_que_no_se_puede_cerrar_no_se_abre() {
        // Un archivo donde tendría que ir el directorio: `create_dir_all`
        // falla, que es el otro camino de salida del constructor.
        let root = temp_root();
        std::fs::write(&root, "no soy un directorio").unwrap();
        assert!(Outbox::open(root.clone()).is_err());
        let _ = std::fs::remove_file(&root);
    }

    /// Lo que se escribió tiene que seguir ahí después de reiniciar. Es la
    /// razón entera de que esta cola exista en el disco.
    #[test]
    fn lo_encolado_sobrevive() {
        let root = temp_root();
        let outbox = Outbox::open(root.clone()).unwrap();
        outbox.enqueue(&outgoing("0001")).unwrap();

        // Otra instancia, como después de reiniciar el servicio.
        let another = Outbox::open(root.clone()).unwrap();
        let all = another.all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].draft.subject, "Hola");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Adentro está el texto completo de mensajes privados. En un equipo
    /// compartido, los permisos por omisión los dejarían legibles para
    /// cualquier otra cuenta.
    #[test]
    fn el_correo_sin_mandar_no_lo_lee_nadie_mas() {
        let root = temp_root();
        let outbox = Outbox::open(root.clone()).unwrap();
        outbox.enqueue(&outgoing("0001")).unwrap();

        let dir_mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "el directorio quedó en {dir_mode:o}");

        let file_mode = std::fs::metadata(outbox.path_of("0001"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "el archivo quedó en {file_mode:o}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Un directorio que ya existía con permisos abiertos —de una versión
    /// anterior, de una copia de seguridad restaurada— tiene que quedar cerrado
    /// igual.
    #[test]
    fn un_directorio_abierto_se_cierra() {
        let root = temp_root();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();

        let _ = Outbox::open(root.clone()).unwrap();
        let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "quedó en {mode:o}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Un archivo corrupto —de un corte de luz, de una versión anterior— no
    /// puede impedir que salgan los demás mensajes.
    #[test]
    fn un_archivo_ilegible_no_tira_la_cola() {
        let root = temp_root();
        let outbox = Outbox::open(root.clone()).unwrap();
        outbox.enqueue(&outgoing("0002")).unwrap();
        std::fs::write(root.join("0001.json"), "{ esto no es json").unwrap();

        let all = outbox.all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "0002");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// La cola sale en el orden en que se escribió, que es el que espera quien
    /// la mira.
    #[test]
    fn la_cola_sale_en_orden() {
        let root = temp_root();
        let outbox = Outbox::open(root.clone()).unwrap();
        for id in ["0003", "0001", "0002"] {
            outbox.enqueue(&outgoing(id)).unwrap();
        }

        let ids: Vec<String> = outbox.all().unwrap().into_iter().map(|s| s.id).collect();
        assert_eq!(ids, vec!["0001", "0002", "0003"]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lo_que_sale_se_va_de_la_cola() {
        let root = temp_root();
        let outbox = Outbox::open(root.clone()).unwrap();
        outbox.enqueue(&outgoing("0001")).unwrap();
        outbox.remove("0001").unwrap();

        assert!(outbox.all().unwrap().is_empty());
        // Y quitarlo de nuevo no falla: puede pasar si un reintento y el envío
        // se cruzan.
        assert!(outbox.remove("0001").is_ok());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Sin tope, una cuenta cuyo servidor rechaza todo puede llenar el disco de
    /// la persona con mensajes que nunca van a salir.
    #[test]
    fn hay_un_tope_de_mensajes_en_cola() {
        let root = temp_root();
        let outbox = Outbox::open(root.clone()).unwrap();
        for i in 0..MAX_QUEUED {
            outbox.enqueue(&outgoing(&format!("{i:04}"))).unwrap();
        }

        let error = outbox.enqueue(&outgoing("9999")).unwrap_err();
        assert!(error.contains("esperando salir"), "{error}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Un servidor caído no mejora porque se le insista cada treinta segundos, y
    /// insistir así es cómo una dirección termina en una lista negra.
    #[test]
    fn la_espera_crece_y_tiene_tope() {
        let mut s = outgoing("0001");
        let mut previous = std::time::Duration::ZERO;

        for attempts in 0..MAX_ATTEMPTS {
            s.attempts = attempts;
            let now = s.backoff();
            assert!(now >= previous, "la espera bajó en el intento {attempts}");
            assert!(now <= std::time::Duration::from_secs(3600));
            previous = now;
        }

        // Y no se desborda con un número absurdo, que es lo que pasaría con un
        // archivo tocado a mano.
        s.attempts = u32::MAX;
        assert_eq!(s.backoff(), std::time::Duration::from_secs(3600));
    }

    /// La espera tiene que sobrevivir a un reinicio del servicio: un mensaje
    /// que falló hace diez segundos no se puede reintentar en el acto porque el
    /// proceso arrancó de nuevo, o un servidor caído recibiría un intento por
    /// cada arranque.
    #[test]
    fn la_espera_sobrevive_a_un_reinicio() {
        let now = chrono::Utc::now();
        let mut s = outgoing("0001");

        // Recién encolado: le toca ya.
        assert!(s.is_due(now));

        s.record_failure("el servidor no contestó".into(), now);
        assert_eq!(s.attempts, 1);
        assert!(!s.is_due(now), "no tendría que tocarle todavía");
        assert!(s.is_due(now + chrono::Duration::hours(2)));
    }

    /// Mandar varios mensajes contra un servidor que no contesta tarda minutos.
    /// Con la hora del principio de la vuelta, el último quedaría con su
    /// próximo intento ya cumplido — o sea, reintentos seguidos contra un
    /// servidor que justamente no está.
    #[test]
    fn el_proximo_intento_se_cuenta_desde_que_fallo() {
        let started = chrono::Utc::now();
        let ten_minutes_later = started + chrono::Duration::minutes(10);

        let mut s = outgoing("0001");
        s.record_failure("el servidor no contestó".into(), ten_minutes_later);

        assert!(!s.is_due(ten_minutes_later), "no tendría que tocarle ya");
    }

    /// Una fecha que no se entiende —un archivo tocado a mano, una versión
    /// anterior— no puede dejar un mensaje encerrado para siempre.
    #[test]
    fn una_fecha_de_reintento_rota_no_encierra_el_mensaje() {
        let mut s = outgoing("0001");
        s.next_attempt = "el jueves".into();
        assert!(s.is_due(chrono::Utc::now()));
    }

    /// Ordenar por nombre tiene que ser ordenar por antigüedad, y dos mensajes
    /// del mismo microsegundo no se pueden pisar.
    #[test]
    fn los_identificadores_ordenan_por_antiguedad_y_no_chocan() {
        let before = chrono::DateTime::from_timestamp(1_757_500_000, 0).unwrap();
        let after = chrono::DateTime::from_timestamp(1_757_500_001, 0).unwrap();

        assert!(new_id(before, 1) < new_id(after, 1));
        assert_ne!(new_id(before, 1), new_id(before, 2));
    }

    /// El identificador del mensaje se decide al encolarlo. Si se calculara en
    /// cada intento, un mensaje que se entrega y cuya confirmación se pierde
    /// entraría dos veces en el buzón de quien lo recibe, con dos
    /// identificadores distintos, y ningún cliente podría deduplicarlo.
    #[test]
    fn el_identificador_del_mensaje_no_cambia_entre_intentos() {
        let root = temp_root();
        let outbox = Outbox::open(root.clone()).unwrap();

        let mut s = outgoing("0001");
        outbox.enqueue(&s).unwrap();
        s.attempts = 3;
        s.last_error = "el servidor no contestó".into();
        outbox.save(&s).unwrap();

        let reread = &outbox.all().unwrap()[0];
        assert_eq!(reread.message_id, "<x@ejemplo.com>");
        assert_eq!(reread.date, "Thu, 10 Sep 2026 12:00:00 +0000");
        assert_eq!(reread.attempts, 3);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Las dos condiciones, por separado. Con un solo campo, un programado que
    /// falla una vez se corre de hora: la espera exponencial del reintento se
    /// apila encima de la hora que alguien eligió.
    #[test]
    fn un_programado_que_falla_no_se_corre_de_hora() {
        let nine = chrono::DateTime::parse_from_rfc3339("2026-09-12T09:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let mut s = outgoing("uno");
        s.scheduled_for = "2026-09-12T09:00:00Z".into();

        // Antes de la hora, no le toca.
        assert!(!s.is_due(nine - chrono::Duration::minutes(1)));
        // A la hora, sí.
        assert!(s.is_due(nine));

        // Falla: el reintento lo corre media hora.
        s.record_failure("el servidor no contestó".into(), nine);
        assert!(!s.is_due(nine));
        // Pero la hora que pidió la persona sigue siendo las nueve: pasado el
        // reintento sale, y no una hora más tarde por haberse sumado las dos.
        assert!(s.is_due(nine + chrono::Duration::hours(2)));
    }

    #[test]
    fn sin_hora_pedida_sale_cuando_se_pueda() {
        let now = chrono::Utc::now();
        let s = outgoing("uno");
        assert!(s.is_due(now));
        assert!(!s.is_scheduled(now));
    }

    /// Un campo ilegible no puede dejar encerrado para siempre un mensaje que
    /// alguien escribió.
    #[test]
    fn una_hora_que_no_se_entiende_no_encierra_el_mensaje() {
        let now = chrono::Utc::now();
        let mut s = outgoing("uno");
        s.scheduled_for = "el jueves".into();
        assert!(s.is_due(now));
        assert!(!s.is_scheduled(now));
    }

    /// Esperar una hora y estar saliendo son dos cosas distintas, y se ven
    /// igual si no se pregunta.
    #[test]
    fn se_puede_saber_si_esta_esperando_su_hora() {
        let now = chrono::Utc::now();
        let mut s = outgoing("uno");
        s.scheduled_for = (now + chrono::Duration::hours(3)).to_rfc3339();
        assert!(s.is_scheduled(now));
        assert!(!s.is_due(now));
    }

    /// La cola vive en disco. Un mensaje encolado por una versión anterior no
    /// tiene el campo nuevo, y no poder leerlo es perder un mensaje que alguien
    /// escribió.
    #[test]
    fn un_mensaje_de_una_version_anterior_se_sigue_leyendo() {
        let old = r#"{
            "id": "uno",
            "account_id": "cuenta",
            "borrador": {"de": "a@b.c", "para": ["d@e.f"], "asunto": "x", "cuerpo": "y"},
            "identificador": "<x@b.c>",
            "fecha": "Thu, 10 Sep 2026 12:00:00 +0000"
        }"#;
        let parsed: Outgoing = serde_json::from_str(old).expect("tiene que poder leerse");
        assert_eq!(parsed.id, "uno");
        assert!(parsed.scheduled_for.is_empty());
        assert!(parsed.is_due(chrono::Utc::now()));
    }

    #[test]
    fn la_cola_cuelga_del_directorio_de_datos() {
        assert_eq!(
            outbox_dir_under(Some(PathBuf::from("/home/pato/.local/share"))),
            PathBuf::from("/home/pato/.local/share/vasak-accounts-sync/outbox")
        );
    }

    #[test]
    fn una_base_relativa_no_se_usa() {
        // Antes esto filtraba `XDG_DATA_HOME` por absoluta y no `HOME`, así que
        // con un `HOME` relativo la cola de salida se escribía bajo el
        // directorio de trabajo del daemon — que en una unidad de systemd no es
        // el home de nadie, y los correos sin mandar quedaban ahí.
        //
        // Las cuatro formas de no ser absoluta: la del nombre suelto es la que
        // se escapa cuando uno se acuerda sólo de la vacía.
        for relative in ["", "datos", "./datos", "../datos"] {
            assert_eq!(
                outbox_dir_under(Some(PathBuf::from(relative))),
                PathBuf::from("/tmp/vasak-accounts-sync/outbox"),
                "una base de {relative:?} no tiene que usarse"
            );
        }
    }

    /// La forma en el disco, y en `ListOutbox`, que la manda tal cual.
    ///
    /// Los campos de Rust están en inglés y los del archivo no cambiaron: un
    /// mensaje encolado por esta versión lo tiene que poder leer la anterior
    /// —si alguien vuelve atrás el paquete— y `vasak-mail` lo lee por el bus.
    /// Un renombre que se olvide del `rename` rompe acá y no en la cola de
    /// alguien.
    #[test]
    fn un_mensaje_encolado_conserva_las_claves_del_archivo() {
        let mut o = outgoing("0001");
        o.draft.attachments.push(crate::compose::Attachment {
            name: "x.pdf".into(),
            content_type: "application/pdf".into(),
            content: "aG9sYQ==".into(),
        });
        let json = serde_json::to_value(&o).unwrap();
        assert_eq!(
            crate::test_support::json_keys(&json),
            [
                "account_id",
                "borrador",
                "estado",
                "fecha",
                "id",
                "identificador",
                "intentos",
                "programado_para",
                "proximo_intento",
                "ultimo_error"
            ]
        );
        assert_eq!(
            crate::test_support::json_keys(&json["borrador"]),
            [
                "adjuntos",
                "asunto",
                "cc",
                "cuerpo",
                "de",
                "en_respuesta_a",
                "nombre",
                "para",
                "referencias"
            ]
        );
        assert_eq!(
            crate::test_support::json_keys(&json["borrador"]["adjuntos"][0]),
            ["contenido", "nombre", "tipo"]
        );
        assert_eq!(json["estado"], "pendiente");

        o.state = DeliveryState::Stuck;
        assert_eq!(serde_json::to_value(&o).unwrap()["estado"], "trabado");
    }

    /// Un archivo de la versión anterior con **todos** los campos se lee
    /// entero: ninguno cae en su valor por omisión porque cambió de nombre.
    #[test]
    fn un_mensaje_de_antes_con_todos_los_campos_se_lee_entero() {
        let old = r#"{
            "id": "0001",
            "account_id": "cuenta",
            "borrador": {
                "de": "ana@ejemplo.com", "nombre": "Ana", "para": ["juan@otro.com"],
                "cc": ["eva@otro.com"], "asunto": "Hola", "cuerpo": "Buenas.",
                "en_respuesta_a": "<r@x>", "referencias": ["<r@x>"],
                "adjuntos": [{"nombre": "x.pdf", "tipo": "application/pdf", "contenido": "aG9sYQ=="}]
            },
            "identificador": "<x@ejemplo.com>",
            "fecha": "Thu, 10 Sep 2026 12:00:00 +0000",
            "intentos": 3,
            "estado": "trabado",
            "ultimo_error": "el servidor no contestó",
            "programado_para": "2026-09-12T09:00:00Z",
            "proximo_intento": "2026-09-12T09:30:00Z"
        }"#;
        let o: Outgoing = serde_json::from_str(old).unwrap();

        assert_eq!(o.draft.from, "ana@ejemplo.com");
        assert_eq!(o.draft.name, "Ana");
        assert_eq!(o.draft.to, ["juan@otro.com"]);
        assert_eq!(o.draft.cc, ["eva@otro.com"]);
        assert_eq!(o.draft.subject, "Hola");
        assert_eq!(o.draft.body, "Buenas.");
        assert_eq!(o.draft.in_reply_to, "<r@x>");
        assert_eq!(o.draft.references, ["<r@x>"]);
        assert_eq!(o.draft.attachments[0].name, "x.pdf");
        assert_eq!(o.draft.attachments[0].content_type, "application/pdf");
        assert_eq!(o.draft.attachments[0].content, "aG9sYQ==");
        assert_eq!(o.message_id, "<x@ejemplo.com>");
        assert_eq!(o.date, "Thu, 10 Sep 2026 12:00:00 +0000");
        assert_eq!(o.attempts, 3);
        assert_eq!(o.state, DeliveryState::Stuck);
        assert_eq!(o.last_error, "el servidor no contestó");
        assert_eq!(o.scheduled_for, "2026-09-12T09:00:00Z");
        assert_eq!(o.next_attempt, "2026-09-12T09:30:00Z");

        // Y escrito de nuevo, es el mismo archivo.
        let again: serde_json::Value = serde_json::to_value(&o).unwrap();
        let original: serde_json::Value = serde_json::from_str(old).unwrap();
        assert_eq!(again, original);
    }

    /// `ListOutbox` suma `esperando_su_hora` a las claves del archivo.
    #[test]
    fn la_lista_de_salida_suma_si_espera_su_hora() {
        let now = chrono::Utc::now();
        let mut later = outgoing("0002");
        later.scheduled_for = (now + chrono::Duration::hours(3)).to_rfc3339();

        let listed = view(vec![outgoing("0001"), later], now);
        let keys = crate::test_support::json_keys(&listed[0]);
        assert!(keys.contains(&"esperando_su_hora".to_string()), "{keys:?}");
        assert_eq!(keys.len(), 11, "{keys:?}");
        assert_eq!(listed[0]["esperando_su_hora"], false);
        assert_eq!(listed[1]["esperando_su_hora"], true);
    }

    /// Lo que sale en una vuelta: ni los trabados ni los que esperan, y en el
    /// orden de la cola.
    #[test]
    fn en_cada_vuelta_salen_los_que_ya_les_toca() {
        let now = chrono::Utc::now();
        let mut stuck = outgoing("0002");
        stuck.state = DeliveryState::Stuck;
        let mut waiting = outgoing("0003");
        waiting.record_failure("el servidor no contestó".into(), now);
        let mut scheduled = outgoing("0004");
        scheduled.scheduled_for = (now + chrono::Duration::hours(1)).to_rfc3339();

        let ready = ready_to_send(
            vec![
                outgoing("0001"),
                stuck,
                waiting,
                scheduled,
                outgoing("0005"),
            ],
            now,
        );
        let ids: Vec<&str> = ready.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["0001", "0005"]);
    }

    // ── La mudanza de `salientes/` a `outbox/` ──────────────────────────────

    use crate::store::paths::tests::TempDir;

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    /// Una carpeta del servicio con `salientes/` en 0700, como la dejaba la
    /// versión anterior, y los archivos que se le pidan en 0600.
    fn legacy_app_dir(label: &str, files: &[(&str, &str)]) -> TempDir {
        let temp = TempDir::new(label);
        let legacy = temp.0.join(LEGACY_OUTBOX_DIR);
        std::fs::create_dir(&legacy).unwrap();
        std::fs::set_permissions(&legacy, std::fs::Permissions::from_mode(0o700)).unwrap();
        for (name, content) in files {
            std::fs::write(legacy.join(name), content).unwrap();
            std::fs::set_permissions(legacy.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        temp
    }

    /// Lo de siempre: sólo está la vieja, y pasa entera de un renombre.
    #[test]
    fn la_cola_vieja_pasa_entera_de_un_renombre() {
        let temp = legacy_app_dir(
            "mudanza-simple",
            &[("0001.json", "uno"), (".0002.tmp", "x")],
        );
        // Abierta de más, como la podía dejar una copia de seguridad: la nueva
        // queda en 0700.
        std::fs::set_permissions(
            temp.0.join(LEGACY_OUTBOX_DIR),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();

        assert_eq!(migrate_legacy_outbox(&temp.0), Ok(Migration::Renamed));

        let outbox = temp.0.join(OUTBOX_DIR);
        assert_eq!(
            std::fs::read_to_string(outbox.join("0001.json")).unwrap(),
            "uno"
        );
        assert!(outbox.join(".0002.tmp").exists());
        assert!(!temp.0.join(LEGACY_OUTBOX_DIR).exists());
        assert_eq!(mode_of(&outbox), 0o700);
        assert_eq!(mode_of(&outbox.join("0001.json")), 0o600);

        // Y la segunda vez no hay nada que hacer.
        assert_eq!(migrate_legacy_outbox(&temp.0), Ok(Migration::NothingToMove));
    }

    /// Las dos existen: pasa lo que no choca, lo que choca se queda en la vieja
    /// sin tocar la nueva, y la vieja no se borra porque no quedó vacía.
    #[test]
    fn si_estan_las_dos_no_se_pisa_nada() {
        let temp = legacy_app_dir(
            "mudanza-doble",
            &[("0001.json", "el de antes"), ("0002.json", "dos")],
        );
        let outbox = temp.0.join(OUTBOX_DIR);
        std::fs::create_dir(&outbox).unwrap();
        std::fs::write(outbox.join("0001.json"), "el de ahora").unwrap();

        assert_eq!(
            migrate_legacy_outbox(&temp.0),
            Ok(Migration::Merged {
                moved: 1,
                kept: vec!["0001.json".into()]
            })
        );

        let legacy = temp.0.join(LEGACY_OUTBOX_DIR);
        assert_eq!(
            std::fs::read_to_string(outbox.join("0001.json")).unwrap(),
            "el de ahora"
        );
        assert_eq!(
            std::fs::read_to_string(outbox.join("0002.json")).unwrap(),
            "dos"
        );
        assert_eq!(
            std::fs::read_to_string(legacy.join("0001.json")).unwrap(),
            "el de antes"
        );
        assert!(!legacy.join("0002.json").exists());
        assert_eq!(mode_of(&outbox), 0o700);
    }

    /// Las dos existen y nada choca: pasa todo y la vieja se va, vacía.
    #[test]
    fn si_estan_las_dos_y_nada_choca_la_vieja_se_va() {
        let temp = legacy_app_dir(
            "mudanza-junta",
            &[("0002.json", "dos"), ("0003.json", "tres")],
        );
        let outbox = temp.0.join(OUTBOX_DIR);
        std::fs::create_dir(&outbox).unwrap();
        std::fs::write(outbox.join("0001.json"), "uno").unwrap();

        assert_eq!(
            migrate_legacy_outbox(&temp.0),
            Ok(Migration::Merged {
                moved: 2,
                kept: Vec::new()
            })
        );
        assert!(!temp.0.join(LEGACY_OUTBOX_DIR).exists());
        let mut names: Vec<String> = std::fs::read_dir(&outbox)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["0001.json", "0002.json", "0003.json"]);
    }

    /// Lo que no es un archivo —una carpeta, un enlace— no se mueve, y por eso
    /// la vieja no queda vacía y no se borra.
    /// Lo que decide la mudanza de cada entrada sale de un solo `stat`: el
    /// archivo propio pasa; un enlace, una carpeta o un archivo de otro, no.
    #[test]
    fn solo_se_muda_un_archivo_regular_propio() {
        use rustix::fs::{statat, AtFlags, CWD};
        let temp = TempDir::new("mudanza-quien");
        let file = temp.0.join("0001.json");
        std::fs::write(&file, "uno").unwrap();
        let link = temp.0.join("0002.json");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let dir = temp.0.join("sub");
        std::fs::create_dir(&dir).unwrap();
        let me = rustix::process::getuid();
        let other = rustix::process::Uid::from_raw(me.as_raw().wrapping_add(1));
        let stat = |path: &std::path::Path| statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW).unwrap();

        assert!(is_movable(&stat(&file), me), "un archivo propio se muda");
        assert!(!is_movable(&stat(&link), me), "un enlace no se muda");
        assert!(!is_movable(&stat(&dir), me), "una carpeta no se muda");
        assert!(
            !is_movable(&stat(&file), other),
            "un archivo de otro no se muda"
        );
    }

    #[test]
    fn lo_que_no_es_un_archivo_se_queda_en_la_vieja() {
        let temp = legacy_app_dir("mudanza-rara", &[("0002.json", "dos")]);
        let legacy = temp.0.join(LEGACY_OUTBOX_DIR);
        let elsewhere = temp.0.join("Documentos");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("carta.json"), "ajena").unwrap();
        std::os::unix::fs::symlink(elsewhere.join("carta.json"), legacy.join("0003.json")).unwrap();
        std::fs::create_dir(legacy.join("sub")).unwrap();
        std::fs::create_dir(temp.0.join(OUTBOX_DIR)).unwrap();

        let Ok(Migration::Merged { moved, mut kept }) = migrate_legacy_outbox(&temp.0) else {
            panic!("tenía que juntarlas");
        };
        kept.sort();
        assert_eq!(moved, 1);
        assert_eq!(kept, ["0003.json", "sub"]);
        assert!(std::fs::symlink_metadata(legacy.join("0003.json"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!temp.0.join(OUTBOX_DIR).join("0003.json").exists());
        assert_eq!(
            std::fs::read_to_string(elsewhere.join("carta.json")).unwrap(),
            "ajena"
        );
    }

    /// Sin la vieja no hay nada que hacer, esté o no la nueva, y esté o no la
    /// carpeta del servicio.
    #[test]
    fn sin_la_carpeta_vieja_no_se_hace_nada() {
        let temp = TempDir::new("mudanza-nada");
        assert_eq!(
            migrate_legacy_outbox(&temp.0.join("no-existe")),
            Ok(Migration::NothingToMove)
        );
        assert_eq!(migrate_legacy_outbox(&temp.0), Ok(Migration::NothingToMove));
        assert!(!temp.0.join(OUTBOX_DIR).exists(), "no se crea nada");

        std::fs::create_dir(temp.0.join(OUTBOX_DIR)).unwrap();
        std::fs::write(temp.0.join(OUTBOX_DIR).join("0001.json"), "uno").unwrap();
        assert_eq!(migrate_legacy_outbox(&temp.0), Ok(Migration::NothingToMove));
        assert_eq!(
            std::fs::read_to_string(temp.0.join(OUTBOX_DIR).join("0001.json")).unwrap(),
            "uno"
        );
    }

    /// Un enlace en lugar de cualquiera de las carpetas no se sigue: es un
    /// error, y no se mueve ni se borra nada de ningún lado.
    #[test]
    fn un_enlace_en_lugar_de_una_carpeta_no_se_sigue() {
        // `salientes/` es un enlace.
        let temp = TempDir::new("mudanza-enlace-vieja");
        let elsewhere = temp.0.join("Documentos");
        std::fs::create_dir(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("0001.json"), "ajeno").unwrap();
        std::os::unix::fs::symlink(&elsewhere, temp.0.join(LEGACY_OUTBOX_DIR)).unwrap();
        assert!(migrate_legacy_outbox(&temp.0).is_err());
        assert!(!temp.0.join(OUTBOX_DIR).exists());
        assert!(std::fs::symlink_metadata(temp.0.join(LEGACY_OUTBOX_DIR))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(elsewhere.join("0001.json").exists());

        // `outbox/` es un enlace.
        let temp = legacy_app_dir("mudanza-enlace-nueva", &[("0001.json", "uno")]);
        let elsewhere = temp.0.join("Documentos");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, temp.0.join(OUTBOX_DIR)).unwrap();
        assert!(migrate_legacy_outbox(&temp.0).is_err());
        assert!(temp.0.join(LEGACY_OUTBOX_DIR).join("0001.json").exists());
        assert!(!elsewhere.join("0001.json").exists());

        // La carpeta del servicio es un enlace.
        let temp = TempDir::new("mudanza-enlace-servicio");
        let real = legacy_app_dir("mudanza-enlace-real", &[("0001.json", "uno")]);
        let linked = temp.0.join("vasak-accounts-sync");
        std::os::unix::fs::symlink(&real.0, &linked).unwrap();
        assert!(migrate_legacy_outbox(&linked).is_err());
        assert!(real.0.join(LEGACY_OUTBOX_DIR).join("0001.json").exists());
        assert!(!real.0.join(OUTBOX_DIR).exists());
    }

    /// **Lo que importa de la mudanza.** Un mensaje que la versión anterior
    /// encoló en `salientes/` —con su formato, las claves en español— aparece
    /// en la lista de salida después de mudar y es de los que el despachador
    /// toma en la vuelta siguiente, entero.
    #[test]
    fn un_mensaje_encolado_en_la_ruta_vieja_sobrevive_y_sale() {
        // Tal cual lo escribía la 0.16.0: `to_vec_pretty` de su `Salida`.
        let written_by_0_16_0 = r#"{
  "id": "00063f0a5b1c2d3e-00000007",
  "account_id": "7f3a",
  "borrador": {
    "de": "ana@ejemplo.com",
    "nombre": "Ana",
    "para": [
      "juan@otro.com"
    ],
    "cc": [],
    "asunto": "La factura",
    "cuerpo": "Va adjunta.",
    "en_respuesta_a": "",
    "referencias": [],
    "adjuntos": []
  },
  "identificador": "<1757500000000000.0000000000000007@ejemplo.com>",
  "fecha": "Thu, 10 Sep 2026 12:00:00 +0000",
  "intentos": 0,
  "estado": "pendiente",
  "ultimo_error": "",
  "programado_para": "",
  "proximo_intento": ""
}"#;
        let temp = legacy_app_dir(
            "mudanza-mensaje",
            &[("00063f0a5b1c2d3e-00000007.json", written_by_0_16_0)],
        );

        assert_eq!(migrate_legacy_outbox(&temp.0), Ok(Migration::Renamed));

        let queued = Outbox::open(temp.0.join(OUTBOX_DIR))
            .unwrap()
            .all()
            .unwrap();
        assert_eq!(queued.len(), 1);
        let listed = view(queued.clone(), chrono::Utc::now());
        assert_eq!(listed[0]["id"], "00063f0a5b1c2d3e-00000007");
        assert_eq!(listed[0]["borrador"]["asunto"], "La factura");

        let ready = ready_to_send(queued, chrono::Utc::now());
        assert_eq!(ready.len(), 1, "el despachador tiene que tomarlo");
        let next = &ready[0];
        assert_eq!(next.account_id, "7f3a");
        assert_eq!(next.draft.from, "ana@ejemplo.com");
        assert_eq!(next.draft.to, ["juan@otro.com"]);
        assert_eq!(next.draft.subject, "La factura");
        assert_eq!(next.draft.body, "Va adjunta.");
        assert_eq!(
            next.message_id,
            "<1757500000000000.0000000000000007@ejemplo.com>"
        );
        assert_eq!(next.state, DeliveryState::Pending);

        // Y lo que se mandaría es el mensaje que se escribió, con su
        // identificador y su fecha de entonces.
        let message =
            crate::compose::build_message(&next.draft, &next.message_id, &next.date).unwrap();
        assert!(message.contains("Subject: La factura"), "{message}");
        assert!(
            message.contains("Message-ID: <1757500000000000.0000000000000007@ejemplo.com>"),
            "{message}"
        );
        assert!(
            message.contains("Date: Thu, 10 Sep 2026 12:00:00 +0000"),
            "{message}"
        );
    }

    /// Lo mismo cuando están las dos: lo que pasó desde la vieja sale igual.
    #[test]
    fn un_mensaje_que_pasa_al_juntarlas_tambien_sale() {
        let old = serde_json::to_vec_pretty(&outgoing("0002")).unwrap();
        let temp = legacy_app_dir(
            "mudanza-mensaje-junta",
            &[("0002.json", std::str::from_utf8(&old).unwrap())],
        );
        let outbox = Outbox::open(temp.0.join(OUTBOX_DIR)).unwrap();
        outbox.enqueue(&outgoing("0001")).unwrap();

        assert_eq!(
            migrate_legacy_outbox(&temp.0),
            Ok(Migration::Merged {
                moved: 1,
                kept: Vec::new()
            })
        );
        let ids: Vec<String> = ready_to_send(outbox.all().unwrap(), chrono::Utc::now())
            .into_iter()
            .map(|o| o.id)
            .collect();
        assert_eq!(ids, ["0001", "0002"]);
    }
}
