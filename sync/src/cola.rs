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

use crate::redactar::Borrador;

/// Cuántos mensajes se aceptan sin mandar.
///
/// Sin tope, una cuenta cuyo servidor rechaza todo puede llenar el disco de la
/// persona con reintentos. Doscientos es más de lo que nadie tiene esperando.
const MAX_EN_COLA: usize = 200;

/// Cuántas veces se reintenta antes de dejar de hacerlo.
///
/// Con la espera que crece, diez intentos cubren más de un día. Después de eso
/// el problema no se va a arreglar solo y lo que corresponde es decírselo a la
/// persona en vez de seguir golpeando el servidor de alguien.
pub const MAX_INTENTOS: u32 = 10;

/// En qué anda un mensaje de la cola.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Estado {
    /// Esperando su turno, o entre reintentos.
    #[default]
    Pendiente,
    /// Se le acabaron los intentos, o el servidor dijo que no definitivamente.
    /// No se vuelve a intentar solo: hace falta que la persona haga algo.
    Trabado,
}

/// Un mensaje esperando salir.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Salida {
    pub id: String,
    pub account_id: String,
    pub borrador: Borrador,
    /// El identificador del mensaje, decidido **al encolarlo** y no al mandarlo.
    ///
    /// Si se calculara en cada intento, un mensaje que se entrega y cuya
    /// confirmación se pierde entraría dos veces en el buzón de quien lo recibe,
    /// con dos identificadores distintos, y ningún cliente podría darse cuenta
    /// de que es el mismo. Con el identificador fijo, los clientes que
    /// deduplican lo hacen.
    pub identificador: String,
    /// La fecha de la cabecera, también fija por lo mismo: un mensaje escrito
    /// anoche que sale a la mañana tiene que decir que se escribió anoche.
    pub fecha: String,
    #[serde(default)]
    pub intentos: u32,
    #[serde(default)]
    pub estado: Estado,
    /// Qué pasó la última vez. Vacío si todavía no se intentó.
    #[serde(default)]
    pub ultimo_error: String,
    /// A partir de cuándo se puede volver a intentar, en ISO 8601.
    ///
    /// Se guarda el **momento** y no se calcula desde la fecha del mensaje: así
    /// la espera sobrevive a un reinicio del servicio —un mensaje que falló hace
    /// diez segundos no se reintenta en el acto porque el proceso arrancó de
    /// nuevo— y quien mire el archivo entiende qué está esperando sin tener que
    /// rehacer la cuenta.
    #[serde(default)]
    pub proximo_intento: String,
}

impl Salida {
    /// Cuánto esperar antes del próximo intento.
    ///
    /// La espera se duplica: medio minuto, uno, dos, cuatro… hasta una hora. Un
    /// servidor que está caído no mejora porque se le insista cada treinta
    /// segundos, y insistir así es cómo una dirección termina en una lista
    /// negra.
    pub fn espera(&self) -> std::time::Duration {
        const BASE: u64 = 30;
        const TOPE: u64 = 3600;
        let factor = 1u64.checked_shl(self.intentos.min(20)).unwrap_or(u64::MAX);
        std::time::Duration::from_secs(BASE.saturating_mul(factor).min(TOPE))
    }

    /// Si ya le toca volver a intentar.
    ///
    /// Sin `proximo_intento` —un mensaje recién encolado, o uno guardado por una
    /// versión anterior— le toca ya: es preferible un intento de más a un
    /// mensaje que no sale nunca.
    pub fn le_toca(&self, ahora: chrono::DateTime<chrono::Utc>) -> bool {
        if self.proximo_intento.is_empty() {
            return true;
        }
        match chrono::DateTime::parse_from_rfc3339(&self.proximo_intento) {
            Ok(cuando) => ahora >= cuando.with_timezone(&chrono::Utc),
            // Una fecha que no se entiende no puede dejar un mensaje encerrado
            // para siempre.
            Err(_) => true,
        }
    }

    /// Anota que falló y cuándo se vuelve a probar.
    pub fn fallo(&mut self, motivo: String, ahora: chrono::DateTime<chrono::Utc>) {
        self.intentos += 1;
        self.ultimo_error = motivo;
        let espera = chrono::Duration::from_std(self.espera())
            .unwrap_or_else(|_| chrono::Duration::hours(1));
        self.proximo_intento = (ahora + espera).to_rfc3339();
    }
}

/// Dónde vive la cola.
///
/// En los datos del usuario, no en la caché: una caché se puede borrar entera
/// sin avisar, y con ella se iría un correo sin mandar.
pub fn directorio() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));

    base.join("vasak-accounts-sync/salientes")
}

/// La cola en el disco.
pub struct Cola {
    raiz: PathBuf,
}

impl Cola {
    pub fn nueva(raiz: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&raiz)
            .map_err(|e| format!("no se pudo crear {}: {e}", raiz.display()))?;
        // 0700 **siempre**, no sólo al crear: un directorio que ya existía con
        // permisos abiertos —de una versión anterior, de una copia de
        // seguridad restaurada— dejaría el correo de la persona legible para
        // cualquier otra cuenta del equipo.
        //
        // Y si no se puede, **no se sigue**. Tragarse el fallo dejaba una cola
        // que anda perfectamente y que cualquiera del equipo puede leer, sin
        // que nada lo diga: es peor que no tener cola.
        std::fs::set_permissions(&raiz, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            format!(
                "no se pudo cerrar el acceso a {}: {e}. \
                 Sin eso el correo sin mandar quedaría legible para otras cuentas del equipo",
                raiz.display()
            )
        })?;
        Ok(Cola { raiz })
    }

    fn ruta(&self, id: &str) -> PathBuf {
        self.raiz.join(format!("{id}.json"))
    }

    /// Guarda un mensaje para mandarlo.
    pub fn encolar(&self, salida: &Salida) -> Result<(), String> {
        if self.contar()? >= MAX_EN_COLA {
            return Err(format!(
                "ya hay {MAX_EN_COLA} mensajes esperando salir; \
                 revisá la carpeta de salida antes de escribir otro"
            ));
        }
        self.guardar(salida)
    }

    /// Escribe o reemplaza un mensaje de la cola.
    ///
    /// **A un archivo temporal y después renombrado.** Escribir encima del
    /// bueno deja el mensaje a medias si se corta la luz en el medio, y lo que
    /// queda no es ni el de antes ni el de ahora: un renombre, en cambio, o pasa
    /// entero o no pasa.
    pub fn guardar(&self, salida: &Salida) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(salida)
            .map_err(|e| format!("no se pudo serializar el mensaje: {e}"))?;

        let temporal = self.raiz.join(format!(".{}.tmp", salida.id));
        let mut archivo = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            // 0600: adentro está el texto completo de un mensaje privado.
            .mode(0o600)
            .open(&temporal)
            .map_err(|e| format!("no se pudo escribir el mensaje: {e}"))?;

        archivo
            .write_all(&json)
            .and_then(|()| archivo.sync_all())
            .map_err(|e| format!("no se pudo escribir el mensaje: {e}"))?;
        drop(archivo);

        std::fs::rename(&temporal, self.ruta(&salida.id))
            .map_err(|e| format!("no se pudo guardar el mensaje: {e}"))?;

        self.sincronizar_directorio()
    }

    /// Fuerza al disco el **directorio**, no el archivo.
    ///
    /// El contenido ya está en disco: eso lo hizo el `sync_all` del temporal.
    /// Lo que falta es la entrada del directorio, que es lo que dice que el
    /// archivo se llama así. Sin esto, un corte de luz justo después del
    /// renombre puede dejar el contenido escrito y el nombre no — o sea, un
    /// mensaje aceptado que al arrancar no está, o uno ya entregado que
    /// reaparece y se manda dos veces.
    fn sincronizar_directorio(&self) -> Result<(), String> {
        std::fs::File::open(&self.raiz)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("no se pudo asegurar la cola en el disco: {e}"))
    }

    /// Saca un mensaje de la cola. Se llama cuando salió.
    pub fn quitar(&self, id: &str) -> Result<(), String> {
        match std::fs::remove_file(self.ruta(id)) {
            Ok(()) => self.sincronizar_directorio(),
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
    pub fn todos(&self) -> Result<Vec<Salida>, String> {
        let entradas = match std::fs::read_dir(&self.raiz) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("no se pudo leer la cola: {e}")),
        };

        let mut salidas: Vec<Salida> = entradas
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .filter_map(|p| leer(&p))
            .collect();

        // Por identificador, que empieza con la hora: la cola sale en el orden
        // en que se escribió, que es el que espera quien la mira.
        salidas.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(salidas)
    }

    fn contar(&self) -> Result<usize, String> {
        Ok(self.todos()?.len())
    }
}

fn leer(ruta: &Path) -> Option<Salida> {
    let texto = std::fs::read_to_string(ruta).ok()?;
    match serde_json::from_str(&texto) {
        Ok(salida) => Some(salida),
        Err(e) => {
            tracing::warn!("no se pudo leer {}: {e}", ruta.display());
            None
        }
    }
}

/// Un identificador para un mensaje de la cola.
///
/// Empieza con la hora en microsegundos para que ordenar por nombre sea ordenar
/// por antigüedad, y termina con un número que sube para que dos mensajes del
/// mismo microsegundo no se pisen.
pub fn nuevo_id(momento: chrono::DateTime<chrono::Utc>, unico: u64) -> String {
    format!("{:016x}-{unico:08x}", momento.timestamp_micros())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporal() -> PathBuf {
        let unico = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("vasak-cola-{unico}-{:?}", std::thread::current().id()))
    }

    fn salida(id: &str) -> Salida {
        Salida {
            id: id.into(),
            account_id: "cuenta".into(),
            borrador: Borrador {
                de: "ana@ejemplo.com".into(),
                para: vec!["juan@otro.com".into()],
                asunto: "Hola".into(),
                cuerpo: "Buenas.".into(),
                ..Default::default()
            },
            identificador: "<x@ejemplo.com>".into(),
            fecha: "Thu, 10 Sep 2026 12:00:00 +0000".into(),
            intentos: 0,
            estado: Estado::Pendiente,
            ultimo_error: String::new(),
            proximo_intento: String::new(),
        }
    }

    /// Si no se puede cerrar el acceso, **no se sigue**. Una cola que anda
    /// perfectamente y que cualquiera del equipo puede leer, sin que nada lo
    /// diga, es peor que no tener cola.
    #[test]
    fn una_cola_que_no_se_puede_cerrar_no_se_abre() {
        // Un archivo donde tendría que ir el directorio: `create_dir_all`
        // falla, que es el otro camino de salida del constructor.
        let raiz = temporal();
        std::fs::write(&raiz, "no soy un directorio").unwrap();
        assert!(Cola::nueva(raiz.clone()).is_err());
        let _ = std::fs::remove_file(&raiz);
    }

    /// Lo que se escribió tiene que seguir ahí después de reiniciar. Es la
    /// razón entera de que esta cola exista en el disco.
    #[test]
    fn lo_encolado_sobrevive() {
        let raiz = temporal();
        let cola = Cola::nueva(raiz.clone()).unwrap();
        cola.encolar(&salida("0001")).unwrap();

        // Otra instancia, como después de reiniciar el servicio.
        let otra = Cola::nueva(raiz.clone()).unwrap();
        let todos = otra.todos().unwrap();
        assert_eq!(todos.len(), 1);
        assert_eq!(todos[0].borrador.asunto, "Hola");

        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// Adentro está el texto completo de mensajes privados. En un equipo
    /// compartido, los permisos por omisión los dejarían legibles para
    /// cualquier otra cuenta.
    #[test]
    fn el_correo_sin_mandar_no_lo_lee_nadie_mas() {
        let raiz = temporal();
        let cola = Cola::nueva(raiz.clone()).unwrap();
        cola.encolar(&salida("0001")).unwrap();

        let del_directorio = std::fs::metadata(&raiz).unwrap().permissions().mode() & 0o777;
        assert_eq!(del_directorio, 0o700, "el directorio quedó en {del_directorio:o}");

        let del_archivo = std::fs::metadata(cola.ruta("0001")).unwrap().permissions().mode() & 0o777;
        assert_eq!(del_archivo, 0o600, "el archivo quedó en {del_archivo:o}");

        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// Un directorio que ya existía con permisos abiertos —de una versión
    /// anterior, de una copia de seguridad restaurada— tiene que quedar cerrado
    /// igual.
    #[test]
    fn un_directorio_abierto_se_cierra() {
        let raiz = temporal();
        std::fs::create_dir_all(&raiz).unwrap();
        std::fs::set_permissions(&raiz, std::fs::Permissions::from_mode(0o755)).unwrap();

        let _ = Cola::nueva(raiz.clone()).unwrap();
        let modo = std::fs::metadata(&raiz).unwrap().permissions().mode() & 0o777;
        assert_eq!(modo, 0o700, "quedó en {modo:o}");

        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// Un archivo corrupto —de un corte de luz, de una versión anterior— no
    /// puede impedir que salgan los demás mensajes.
    #[test]
    fn un_archivo_ilegible_no_tira_la_cola() {
        let raiz = temporal();
        let cola = Cola::nueva(raiz.clone()).unwrap();
        cola.encolar(&salida("0002")).unwrap();
        std::fs::write(raiz.join("0001.json"), "{ esto no es json").unwrap();

        let todos = cola.todos().unwrap();
        assert_eq!(todos.len(), 1);
        assert_eq!(todos[0].id, "0002");

        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// La cola sale en el orden en que se escribió, que es el que espera quien
    /// la mira.
    #[test]
    fn la_cola_sale_en_orden() {
        let raiz = temporal();
        let cola = Cola::nueva(raiz.clone()).unwrap();
        for id in ["0003", "0001", "0002"] {
            cola.encolar(&salida(id)).unwrap();
        }

        let ids: Vec<String> = cola.todos().unwrap().into_iter().map(|s| s.id).collect();
        assert_eq!(ids, vec!["0001", "0002", "0003"]);

        let _ = std::fs::remove_dir_all(&raiz);
    }

    #[test]
    fn lo_que_sale_se_va_de_la_cola() {
        let raiz = temporal();
        let cola = Cola::nueva(raiz.clone()).unwrap();
        cola.encolar(&salida("0001")).unwrap();
        cola.quitar("0001").unwrap();

        assert!(cola.todos().unwrap().is_empty());
        // Y quitarlo de nuevo no falla: puede pasar si un reintento y el envío
        // se cruzan.
        assert!(cola.quitar("0001").is_ok());

        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// Sin tope, una cuenta cuyo servidor rechaza todo puede llenar el disco de
    /// la persona con mensajes que nunca van a salir.
    #[test]
    fn hay_un_tope_de_mensajes_en_cola() {
        let raiz = temporal();
        let cola = Cola::nueva(raiz.clone()).unwrap();
        for i in 0..MAX_EN_COLA {
            cola.encolar(&salida(&format!("{i:04}"))).unwrap();
        }

        let error = cola.encolar(&salida("9999")).unwrap_err();
        assert!(error.contains("esperando salir"), "{error}");

        let _ = std::fs::remove_dir_all(&raiz);
    }

    /// Un servidor caído no mejora porque se le insista cada treinta segundos, y
    /// insistir así es cómo una dirección termina en una lista negra.
    #[test]
    fn la_espera_crece_y_tiene_tope() {
        let mut s = salida("0001");
        let mut anterior = std::time::Duration::ZERO;

        for intentos in 0..MAX_INTENTOS {
            s.intentos = intentos;
            let ahora = s.espera();
            assert!(ahora >= anterior, "la espera bajó en el intento {intentos}");
            assert!(ahora <= std::time::Duration::from_secs(3600));
            anterior = ahora;
        }

        // Y no se desborda con un número absurdo, que es lo que pasaría con un
        // archivo tocado a mano.
        s.intentos = u32::MAX;
        assert_eq!(s.espera(), std::time::Duration::from_secs(3600));
    }

    /// La espera tiene que sobrevivir a un reinicio del servicio: un mensaje
    /// que falló hace diez segundos no se puede reintentar en el acto porque el
    /// proceso arrancó de nuevo, o un servidor caído recibiría un intento por
    /// cada arranque.
    #[test]
    fn la_espera_sobrevive_a_un_reinicio() {
        let ahora = chrono::Utc::now();
        let mut s = salida("0001");

        // Recién encolado: le toca ya.
        assert!(s.le_toca(ahora));

        s.fallo("el servidor no contestó".into(), ahora);
        assert_eq!(s.intentos, 1);
        assert!(!s.le_toca(ahora), "no tendría que tocarle todavía");
        assert!(s.le_toca(ahora + chrono::Duration::hours(2)));
    }

    /// Mandar varios mensajes contra un servidor que no contesta tarda minutos.
    /// Con la hora del principio de la vuelta, el último quedaría con su
    /// próximo intento ya cumplido — o sea, reintentos seguidos contra un
    /// servidor que justamente no está.
    #[test]
    fn el_proximo_intento_se_cuenta_desde_que_fallo() {
        let empezo = chrono::Utc::now();
        let diez_minutos_despues = empezo + chrono::Duration::minutes(10);

        let mut s = salida("0001");
        s.fallo("el servidor no contestó".into(), diez_minutos_despues);

        assert!(!s.le_toca(diez_minutos_despues), "no tendría que tocarle ya");
    }

    /// Una fecha que no se entiende —un archivo tocado a mano, una versión
    /// anterior— no puede dejar un mensaje encerrado para siempre.
    #[test]
    fn una_fecha_de_reintento_rota_no_encierra_el_mensaje() {
        let mut s = salida("0001");
        s.proximo_intento = "el jueves".into();
        assert!(s.le_toca(chrono::Utc::now()));
    }

    /// Ordenar por nombre tiene que ser ordenar por antigüedad, y dos mensajes
    /// del mismo microsegundo no se pueden pisar.
    #[test]
    fn los_identificadores_ordenan_por_antiguedad_y_no_chocan() {
        let antes = chrono::DateTime::from_timestamp(1_757_500_000, 0).unwrap();
        let despues = chrono::DateTime::from_timestamp(1_757_500_001, 0).unwrap();

        assert!(nuevo_id(antes, 1) < nuevo_id(despues, 1));
        assert_ne!(nuevo_id(antes, 1), nuevo_id(antes, 2));
    }

    /// El identificador del mensaje se decide al encolarlo. Si se calculara en
    /// cada intento, un mensaje que se entrega y cuya confirmación se pierde
    /// entraría dos veces en el buzón de quien lo recibe, con dos
    /// identificadores distintos, y ningún cliente podría deduplicarlo.
    #[test]
    fn el_identificador_del_mensaje_no_cambia_entre_intentos() {
        let raiz = temporal();
        let cola = Cola::nueva(raiz.clone()).unwrap();

        let mut s = salida("0001");
        cola.encolar(&s).unwrap();
        s.intentos = 3;
        s.ultimo_error = "el servidor no contestó".into();
        cola.guardar(&s).unwrap();

        let releida = &cola.todos().unwrap()[0];
        assert_eq!(releida.identificador, "<x@ejemplo.com>");
        assert_eq!(releida.fecha, "Thu, 10 Sep 2026 12:00:00 +0000");
        assert_eq!(releida.intentos, 3);

        let _ = std::fs::remove_dir_all(&raiz);
    }
}
