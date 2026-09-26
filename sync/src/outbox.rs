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
    // Por `dirs` y no leyendo el entorno acá: la regla —absoluta o nada, que el
    // estándar pide y que de paso cubre la variable vacía, porque la cadena
    // vacía tampoco es absoluta— vive en un solo lugar en vez de en una copia
    // por programa.
    //
    // Antes esto filtraba `XDG_DATA_HOME` por absoluta y **no** `HOME`, así que
    // la mitad del agujero seguía abierta: con un `HOME` relativo la cola de
    // salida se escribía bajo el directorio de trabajo del daemon. El filtro de
    // acá cierra esa otra mitad, que es la que `dirs` no mira.
    outbox_dir_under(dirs::data_dir())
}

/// La misma decisión sin leer el entorno.
///
/// Aparte para poder probarla: el entorno es global al proceso y las pruebas
/// corren en paralelo, así que una que escriba una variable decide al azar el
/// resultado de otra.
fn outbox_dir_under(base: Option<PathBuf>) -> PathBuf {
    let base = base
        .filter(|base| base.is_absolute())
        .unwrap_or_else(|| PathBuf::from("/tmp"));

    base.join("vasak-accounts-sync/salientes")
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
            PathBuf::from("/home/pato/.local/share/vasak-accounts-sync/salientes")
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
                PathBuf::from("/tmp/vasak-accounts-sync/salientes"),
                "una base de {relative:?} no tiene que usarse"
            );
        }
    }
}
