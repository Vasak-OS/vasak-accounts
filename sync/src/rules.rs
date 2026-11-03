//! Reglas para el correo entrante: el modelo, la evaluación y dónde se guardan.
//!
//! ── Qué es esto y qué **no** es ─────────────────────────────────────────────
//!
//! Una regla mira un mensaje que llega —de quién viene, de qué se trata, cuánto
//! pesa— y, si coincide, dice qué hacer con él: moverlo, marcarlo leído,
//! destacarlo o borrarlo. Acá está sólo esa decisión, **pura**: dado un conjunto
//! de reglas y las cabeceras de un mensaje, qué acciones corresponden. Nada de
//! red, nada de D-Bus, nada de tocar el buzón.
//!
//! Aplicar esas acciones por IMAP es otro trabajo (`vasak-accounts#20`, PR 3), y
//! el contrato de D-Bus para editarlas, otro más (PR 4). Separarlo así es lo que
//! hace que la parte con lógica —cuál coincide y en qué orden— se pueda probar
//! sin un servidor ni un bus, que es donde está el riesgo de equivocarse.
//!
//! ── Sin expresiones regulares en la v1 ──────────────────────────────────────
//!
//! A propósito: `Contiene`, `Igual` y `Empieza con` alcanzan para lo que la
//! gente arma, y evitan la familia de ataques de denegación por expresión
//! regular (ReDoS) sin tener que acotar un motor. Se puede sumar después.
//!
//! ── La evaluación no distingue mayúsculas en el texto ────────────────────────
//!
//! Las direcciones y los asuntos se comparan en minúsculas: una regla «de
//! contiene BANCO.com» tiene que agarrar «soporte@Banco.com». El número del
//! tamaño y el booleano de los adjuntos no son texto y no entran en esto.
//!
//! ── En claro, como la cola de salida ────────────────────────────────────────
//!
//! El archivo de reglas no se cifra, y es deliberado: una regla no es un secreto
//! —es «mové lo de la lista X a la carpeta Y»—, y cifrarlo sumaría la llave del
//! llavero a algo que no la necesita. Es el mismo criterio que la `outbox`. Lo
//! que sí se respeta son los permisos (0700/0600) y no seguir enlaces, porque un
//! enlace puesto donde va el archivo es escritura arbitraria en la ruta que el
//! atacante controle: el molde entero es el de [`crate::outbox::Outbox`].

use std::io::{Read as _, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use rustix::fs::{AtFlags, Mode, OFlags, CWD};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use crate::imap::HeaderRecord;
use crate::message::Headers;
use crate::outbox::{entry_name, es_enlace, reject_symlink};
use crate::store::paths::{open_dir_at, validate_account_id};

// ---------------------------------------------------------------------------
// Modelo
// ---------------------------------------------------------------------------

/// La versión del formato de un conjunto de reglas recién creado.
///
/// Se guarda en el archivo para que una versión futura que cambie la forma sepa
/// qué está leyendo. Un conjunto que viene de un archivo conserva la suya.
pub const RULESET_VERSION: u32 = 1;

/// Todas las reglas de una cuenta, **en orden de prioridad**.
///
/// El orden importa: se evalúan de la primera a la última, y una con `stop` que
/// coincide corta la lista. Por eso es un `Vec` y no un conjunto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSet {
    #[serde(rename = "cuenta")]
    pub account_id: String,
    #[serde(default, rename = "version")]
    pub version: u32,
    #[serde(default, rename = "reglas")]
    pub rules: Vec<Rule>,
    /// Hasta dónde ya se aplicó, para no barrer el backlog hacia atrás. Un
    /// archivo viejo que no lo trae queda en `None` —inerte— hasta que PR4 lo
    /// escriba por primera vez. PR3a no lo escribe nunca: sólo lo respeta.
    #[serde(default, rename = "marca_de_agua")]
    pub watermark: Option<Watermark>,
}

/// La frontera de aplicación de las reglas: desde qué UID, en qué encarnación
/// de la casilla.
///
/// `UIDVALIDITY` es la identidad de esa encarnación: si el servidor la cambia,
/// los UID se reinician y los viejos ya no significan lo mismo. Por eso la marca
/// guarda las dos cosas y no sólo el UID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Watermark {
    #[serde(rename = "uidvalidity")]
    pub uidvalidity: u32,
    #[serde(rename = "uid_desde")]
    pub uid_from: u32,
}

impl RuleSet {
    /// Un conjunto vacío para una cuenta que todavía no tiene reglas.
    pub fn empty(account_id: &str) -> Self {
        RuleSet {
            account_id: account_id.to_string(),
            version: RULESET_VERSION,
            rules: Vec::new(),
            watermark: None,
        }
    }
}

/// Una regla: a qué mensajes mira y qué les hace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Lo asigna el servicio, no la ventana: al crear una regla el id que venga
    /// se ignora y se pone uno nuevo. Por omisión vacío para poder interpretar
    /// el JSON de una regla que todavía no lo tiene (ver [`parse_rule`]).
    #[serde(default)]
    pub id: String,
    #[serde(default, rename = "nombre")]
    pub name: String,
    /// Una regla apagada no se evalúa. Por omisión está encendida: un archivo de
    /// una versión anterior que no traía el campo tenía reglas que funcionaban.
    #[serde(default = "default_true", rename = "activa")]
    pub enabled: bool,
    #[serde(default, rename = "coincidencia")]
    pub match_: Match,
    #[serde(default, rename = "acciones")]
    pub actions: Vec<Action>,
    /// Si esta regla coincide, no se evalúan las siguientes.
    #[serde(default, rename = "detener")]
    pub stop: bool,
}

/// Cuándo se considera que una regla coincide: si **todas** sus condiciones, o
/// si **cualquiera**.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Match {
    #[serde(default, rename = "operador")]
    pub op: MatchOp,
    #[serde(default, rename = "condiciones")]
    pub conditions: Vec<Condition>,
}

/// `Todas` (Y lógico) o `Cualquiera` (O lógico) de las condiciones.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchOp {
    #[default]
    #[serde(rename = "todas")]
    All,
    #[serde(rename = "cualquiera")]
    Any,
}

/// Una condición: un campo del mensaje, una prueba, un valor, y si se niega.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    #[serde(rename = "campo")]
    pub field: Field,
    #[serde(rename = "prueba")]
    pub test: Test,
    #[serde(default, rename = "valor")]
    pub value: String,
    /// Invierte el resultado: «el asunto **no** contiene factura».
    #[serde(default, rename = "negar")]
    pub negate: bool,
}

/// Qué campo del mensaje mira una condición.
///
/// Los de texto salen de [`Headers`] ya parseado y decodificado. `Size` es el
/// tamaño en bytes que informa el servidor (no está en las cabeceras, lo pasa
/// quien evalúa) y `HasAttachment` se deduce del `Content-Type`, igual que lo
/// hace la fila del almacén.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Field {
    #[serde(rename = "de")]
    From,
    #[serde(rename = "para")]
    To,
    #[serde(rename = "cc")]
    Cc,
    #[serde(rename = "asunto")]
    Subject,
    #[serde(rename = "responder_a")]
    ReplyTo,
    #[serde(rename = "list_id")]
    ListId,
    #[serde(rename = "tamano")]
    Size,
    #[serde(rename = "tiene_adjuntos")]
    HasAttachment,
}

/// Cómo se compara el campo con el valor.
///
/// `Contiene`/`Igual`/`EmpiezaCon` son para texto; `Mayor`/`Menor` son para el
/// tamaño. Una prueba que no le corresponde a su campo —`Mayor` sobre el asunto,
/// `Contiene` sobre el tamaño— no coincide, en vez de inventar un resultado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Test {
    #[serde(rename = "contiene")]
    Contains,
    #[serde(rename = "igual")]
    Equals,
    #[serde(rename = "empieza_con")]
    StartsWith,
    #[serde(rename = "mayor")]
    Gt,
    #[serde(rename = "menor")]
    Lt,
}

/// Qué se le hace a un mensaje que coincide.
///
/// `Delete` es a la papelera, no un borrado definitivo: el que aplica decide qué
/// hacer si la cuenta no tiene papelera (`vasak-accounts#20`, PR 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    #[serde(rename = "mover_a")]
    MoveToFolder(String),
    #[serde(rename = "marcar_leido")]
    MarkRead,
    #[serde(rename = "destacar")]
    Flag,
    #[serde(rename = "borrar")]
    Delete,
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Evaluación — pura, sin red ni E/S
// ---------------------------------------------------------------------------

/// Las acciones que corresponden a un mensaje, recorriendo las reglas en orden.
///
/// Se saltean las apagadas; de las que coinciden se juntan las acciones en el
/// orden en que aparecen; y una con `stop` que coincide corta el recorrido. El
/// tamaño en bytes lo pasa quien evalúa porque no está en las cabeceras.
pub fn actions_for(ruleset: &RuleSet, headers: &Headers, size: u64) -> Vec<Action> {
    let mut actions = Vec::new();
    for rule in &ruleset.rules {
        if !rule.enabled {
            continue;
        }
        if matches(rule, headers, size) {
            actions.extend(rule.actions.iter().cloned());
            if rule.stop {
                break;
            }
        }
    }
    actions
}

/// Si una regla coincide con un mensaje.
///
/// Una regla **sin condiciones no coincide**: una regla vacía que coincidiera
/// con todo movería —o borraría— el correo entero de la persona, y eso no puede
/// pasar por un descuido. Validar que una regla traiga al menos una condición es
/// del contrato de D-Bus (PR 4); acá la red de seguridad es no actuar.
pub fn matches(rule: &Rule, headers: &Headers, size: u64) -> bool {
    let conditions = &rule.match_.conditions;
    if conditions.is_empty() {
        return false;
    }
    match rule.match_.op {
        MatchOp::All => conditions
            .iter()
            .all(|c| condition_matches(c, headers, size)),
        MatchOp::Any => conditions
            .iter()
            .any(|c| condition_matches(c, headers, size)),
    }
}

/// Si una condición se cumple para el mensaje, con `negate` ya aplicado.
fn condition_matches(condition: &Condition, headers: &Headers, size: u64) -> bool {
    let plain = match condition.field {
        Field::Size => return condition.negate ^ size_matches(condition, size),
        Field::HasAttachment => {
            return condition.negate ^ (parse_bool(&condition.value) == has_attachment(headers))
        }
        Field::From => headers.decoded("From"),
        Field::To => headers.decoded("To"),
        Field::Cc => headers.decoded("Cc"),
        Field::Subject => headers.decoded("Subject"),
        Field::ReplyTo => headers.decoded("Reply-To"),
        Field::ListId => headers.decoded("List-Id"),
    };
    condition.negate ^ text_matches(condition, &plain)
}

/// La comparación de texto, sin distinguir mayúsculas.
fn text_matches(condition: &Condition, value: &str) -> bool {
    let haystack = value.to_lowercase();
    let needle = condition.value.to_lowercase();
    match condition.test {
        Test::Contains => haystack.contains(&needle),
        Test::Equals => haystack == needle,
        Test::StartsWith => haystack.starts_with(&needle),
        // Un `Mayor`/`Menor` sobre texto no quiere decir nada: no coincide.
        Test::Gt | Test::Lt => false,
    }
}

/// La comparación de tamaño: el valor es un número de bytes.
///
/// Un valor que no es un número —un archivo tocado a mano, un campo vacío— **no
/// coincide**, en vez de tratarlo como cero y mover todo lo que pese algo.
fn size_matches(condition: &Condition, size: u64) -> bool {
    let Ok(threshold) = condition.value.trim().parse::<u64>() else {
        return false;
    };
    match condition.test {
        Test::Gt => size > threshold,
        Test::Lt => size < threshold,
        // Para el tamaño sólo hay mayor y menor; el resto no coincide.
        _ => false,
    }
}

/// Lee el valor de una condición de adjuntos como un booleano.
///
/// Lo que no se reconoce es `false`: una condición rota no dice «tiene
/// adjuntos».
fn parse_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "si" | "sí" | "yes"
    )
}

/// Si el mensaje trae adjuntos, por el `Content-Type`.
///
/// La misma deducción que hace `email_sync::message_row` al armar la fila del
/// almacén: así una regla «tiene adjuntos» coincide con lo que la ventana le
/// muestra a la persona como «con adjuntos», y no con otra cosa.
fn has_attachment(headers: &Headers) -> bool {
    headers
        .get("Content-Type")
        .is_some_and(|v| v.to_ascii_lowercase().contains("multipart/mixed"))
}

// ---------------------------------------------------------------------------
// Planificación — de reglas a operaciones concretas, todavía pura
// ---------------------------------------------------------------------------

/// Una operación resuelta, lista para que PR3b la ejecute por IMAP.
///
/// Ya no hay `Delete`: sin papelera no se borra, y con papelera `Delete` es un
/// `MoveTo` a ella. Todas llevan el UID del mensaje en INBOX sobre el que actúan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailOp {
    MarkRead(u32),
    Flag(u32),
    MoveTo(u32, String),
}

/// Si un mensaje entra en la ventana que las reglas pueden tocar.
///
/// Esta es la guarda que impide el barrido retroactivo. Sin marca de agua no se
/// aplica nada (inerte, como queda PR3a). Si la `UIDVALIDITY` de ahora no es la
/// de la marca, la casilla se reinició y los UID ya no son los de antes:
/// aplicar barrería el backlog recién re-descargado, así que tampoco. Dentro de
/// la misma encarnación, sólo lo que está en el UID de la marca o más nuevo.
fn is_eligible(watermark: Option<Watermark>, now_uidvalidity: u32, uid: u32) -> bool {
    match watermark {
        // `uid_from >= 1` como defensa en profundidad: `initial_watermark` nunca
        // guarda 0, pero el archivo de reglas vive en el perfil del usuario y una
        // app del mismo usuario podría escribir `uid_desde: 0`, que con `uid >= 0`
        // barrería todo el backlog. La lectura mantiene el invariante pase lo que
        // pase con la procedencia del archivo.
        Some(w) => w.uidvalidity == now_uidvalidity && w.uid_from >= 1 && uid >= w.uid_from,
        None => false,
    }
}

/// Las operaciones a ejecutar para un lote de mensajes, resueltas y en orden.
///
/// Puro: no habla con la red ni arma comandos IMAP —el destino es el nombre de
/// la casilla a secas; citarlo es trabajo de PR3b—. Por cada mensaje elegible se
/// evalúan las reglas y se traducen sus acciones:
///
/// - `MarkRead`/`Flag` son in-situ y van **siempre antes** de la terminal.
/// - `MoveToFolder`/`Delete` sacan el mensaje de INBOX: son terminales y sólo
///   cuenta la primera —el mensaje ya se fue—, haya emitido operación o no.
/// - Un `MoveToFolder` a una casilla desconocida o a INBOX es un no-op; un
///   `Delete` sin papelera, también. Nunca un EXPUNGE.
pub fn plan_ops(
    ruleset: &RuleSet,
    now_uidvalidity: u32,
    records: &[HeaderRecord],
    known_mailboxes: &std::collections::HashSet<String>,
    trash: Option<&str>,
) -> Vec<MailOp> {
    let mut ops = Vec::new();
    for record in records {
        if !is_eligible(ruleset.watermark, now_uidvalidity, record.uid) {
            continue;
        }
        let actions = actions_for(ruleset, &Headers::parse(&record.headers), record.size);

        let mut inplace = Vec::new();
        let mut terminal = None;
        let mut terminal_seen = false;
        for action in actions {
            match action {
                Action::MarkRead => inplace.push(MailOp::MarkRead(record.uid)),
                Action::Flag => inplace.push(MailOp::Flag(record.uid)),
                // La primera terminal consume el lugar; las siguientes se
                // descartan aunque la primera no haya emitido nada.
                Action::MoveToFolder(_) | Action::Delete if terminal_seen => {}
                Action::MoveToFolder(dest) => {
                    terminal_seen = true;
                    // INBOX es especial y no distingue mayúsculas (RFC 3501);
                    // mover a INBOX es un no-op. El resto de los nombres son
                    // sensibles a mayúsculas, así que se comparan exactos.
                    if !dest.eq_ignore_ascii_case("INBOX") && known_mailboxes.contains(&dest) {
                        terminal = Some(MailOp::MoveTo(record.uid, dest));
                    }
                }
                Action::Delete => {
                    terminal_seen = true;
                    // Sin papelera no se borra: se saltea. Con papelera, borrar
                    // es mover a ella.
                    if let Some(t) = trash {
                        terminal = Some(MailOp::MoveTo(record.uid, t.to_string()));
                    }
                }
            }
        }

        ops.append(&mut inplace);
        ops.extend(terminal);
    }
    ops
}

// ---------------------------------------------------------------------------
// El almacén — un JSON por cuenta, molde de `outbox.rs`
// ---------------------------------------------------------------------------

/// La carpeta de las reglas, dentro de la del servicio.
const RULES_DIR: &str = "rules";

/// Dónde viven las reglas: `$XDG_DATA_HOME/vasak-accounts-sync/rules/`.
///
/// En los datos del usuario y no en la caché, por lo mismo que la cola de
/// salida: una caché se borra entera sin avisar, y con ella se irían las reglas.
pub fn rules_dir() -> PathBuf {
    crate::outbox::app_data_dir().join(RULES_DIR)
}

/// Las reglas en el disco, una base por cuenta.
///
/// Todo lo que hace —leer, escribir, renombrar— es relativo a un descriptor
/// abierto **sin seguir enlaces**, no a la ruta: un enlace puesto donde va la
/// carpeta no cambia a dónde se escribe. Es el molde de [`crate::outbox::Outbox`].
pub struct RuleStore {
    fd: OwnedFd,
    /// La ruta, sólo para los mensajes de error. Por acá no se escribe.
    root: PathBuf,
}

impl RuleStore {
    /// Abre —o crea— la carpeta de reglas en `root`, cerrada en 0700.
    ///
    /// `root` se inyecta para poder probarla contra una carpeta temporal; en
    /// producción es [`rules_dir`].
    pub fn open(root: PathBuf) -> Result<Self, String> {
        // Ni `rules/` ni la carpeta del servicio pueden ser enlaces. Lo de más
        // arriba —la `XDG_DATA_HOME` de la persona— sí se sigue, porque es suyo.
        if let Some(app_dir) = root.parent() {
            reject_symlink(app_dir, "guardar")?;
        }
        reject_symlink(&root, "guardar")?;

        std::fs::create_dir_all(&root)
            .map_err(|e| format!("no se pudo crear {}: {e}", root.display()))?;
        // 0700 siempre, no sólo al crear: una carpeta que ya existía con permisos
        // abiertos dejaría las reglas de la persona legibles para otras cuentas
        // del equipo. Y si no se puede, no se sigue.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("no se pudo cerrar el acceso a {}: {e}", root.display()))?;

        let fd = match open_dir_at(CWD, &root) {
            Ok(fd) => fd,
            Err(e) if es_enlace(e) => {
                return Err(format!(
                    "{} es un enlace simbólico o no es una carpeta; no se usa para las reglas: {}",
                    root.display(),
                    std::io::Error::from(e)
                ));
            }
            Err(e) => {
                return Err(format!(
                    "no se pudo abrir {}: {}",
                    root.display(),
                    std::io::Error::from(e)
                ));
            }
        };

        // Que lo que se abrió sea esto: entre el `chmod` y esta apertura la ruta
        // pudo cambiar de mano. El inodo se mira por el descriptor y por el
        // nombre —sin seguir enlaces— y tienen que ser el mismo.
        let opened = rustix::fs::fstat(&fd).map_err(|e| {
            format!(
                "no se pudo mirar {}: {}",
                root.display(),
                std::io::Error::from(e)
            )
        })?;
        let named = rustix::fs::statat(CWD, &root, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| {
            format!(
                "no se pudo mirar {}: {}",
                root.display(),
                std::io::Error::from(e)
            )
        })?;
        if opened.st_dev != named.st_dev || opened.st_ino != named.st_ino {
            return Err(format!(
                "{} cambió mientras se abría; no se usa para las reglas",
                root.display()
            ));
        }

        Ok(RuleStore { fd, root })
    }

    /// Las reglas de una cuenta. Si todavía no hay archivo, un conjunto vacío.
    pub fn load(&self, account_id: &str) -> Result<RuleSet, String> {
        valid_account_id(account_id)?;
        let name = entry_name(&format!("{account_id}.json"))?;

        let file = match rustix::fs::openat(
            &self.fd,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(file) => file,
            // Sin archivo, sin reglas: la cuenta no configuró ninguna.
            Err(Errno::NOENT) => return Ok(RuleSet::empty(account_id)),
            Err(e) if es_enlace(e) => {
                return Err(format!(
                    "el archivo de reglas de {account_id} es un enlace simbólico; no se lee"
                ));
            }
            Err(e) => {
                return Err(format!(
                    "no se pudieron leer las reglas de {account_id}: {}",
                    std::io::Error::from(e)
                ));
            }
        };

        let mut text = String::new();
        std::fs::File::from(file)
            .read_to_string(&mut text)
            .map_err(|e| format!("no se pudieron leer las reglas de {account_id}: {e}"))?;
        serde_json::from_str(&text)
            .map_err(|e| format!("no se pudieron interpretar las reglas de {account_id}: {e}"))
    }

    /// Escribe las reglas de una cuenta, a un temporal y después renombrado.
    ///
    /// Escribir encima del bueno deja el archivo a medias si se corta la luz en
    /// el medio; un renombre, en cambio, o pasa entero o no pasa.
    pub fn save(&self, ruleset: &RuleSet) -> Result<(), String> {
        valid_account_id(&ruleset.account_id)?;
        let json = serde_json::to_vec_pretty(ruleset)
            .map_err(|e| format!("no se pudieron serializar las reglas: {e}"))?;

        let temp = entry_name(&format!(".{}.tmp", ruleset.account_id))?;
        let dest = entry_name(&format!("{}.json", ruleset.account_id))?;

        // `O_NOFOLLOW` también en el temporal: si alguien puso un enlace con ese
        // nombre, `openat` falla en vez de escribir por él. 0600 porque adentro
        // está a quién le escribe y con quién habla la persona.
        let opened = rustix::fs::openat(
            &self.fd,
            &temp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| {
            format!(
                "no se pudieron escribir las reglas: {}",
                std::io::Error::from(e)
            )
        })?;
        let mut file = std::fs::File::from(opened);
        file.write_all(&json)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("no se pudieron escribir las reglas: {e}"))?;
        drop(file);

        rustix::fs::renameat(&self.fd, &temp, &self.fd, &dest).map_err(|e| {
            format!(
                "no se pudieron guardar las reglas: {}",
                std::io::Error::from(e)
            )
        })?;

        // Fuerza al disco la entrada del directorio, no el contenido: eso ya lo
        // hizo el `sync_all` del temporal. Sin esto, un corte justo después del
        // renombre puede dejar el contenido escrito y el nombre no.
        rustix::fs::fsync(&self.fd).map_err(|e| {
            format!(
                "no se pudo asegurar las reglas en el disco: {}",
                std::io::Error::from(e)
            )
        })
    }

    /// La ruta del archivo de una cuenta, para los mensajes de error y las
    /// pruebas. Por acá no se abre ni se escribe nada.
    pub fn path_of(&self, account_id: &str) -> PathBuf {
        self.root.join(format!("{account_id}.json"))
    }
}

/// El identificador de cuenta se vuelve un nombre de archivo, así que pasa por
/// el mismo filtro que las carpetas del almacén: un `../../algo` escribiría
/// fuera de la carpeta de reglas.
fn valid_account_id(account_id: &str) -> Result<(), String> {
    validate_account_id(account_id)
        .map_err(|_| format!("el identificador de cuenta {account_id:?} no sirve como archivo"))
}

// ---------------------------------------------------------------------------
// CRUD — mutaciones validadas, el cuerpo del contrato de D-Bus (PR 4)
// ---------------------------------------------------------------------------

/// Tope de reglas por cuenta.
///
/// Un número holgado para lo que arma una persona, y a la vez un techo a lo que
/// la ventana puede empujar: cada regla se evalúa por cada mensaje de cada
/// vuelta, así que una lista sin límite es un pie de denegación de servicio
/// contra el propio sync. 100 alcanza de sobra; si hiciera falta más, se sube
/// acá a conciencia.
pub const MAX_RULES: usize = 100;

/// Topes por regla, además de [`MAX_RULES`], que sólo limita el conteo.
///
/// Cada condición se evalúa por cada mensaje de cada vuelta del sync, así que una
/// regla gigante —miles de condiciones, o valores enormes— es una denegación de
/// servicio **persistente** contra el propio sync: no un pico pasajero, sino un
/// costo que se paga en cada vuelta mientras la regla exista. `MAX_RULES` topa
/// cuántas reglas hay, no cuántos bytes pesa cada una; estos topan la regla.
/// Números holgados para cualquier regla que arme una persona.
pub const MAX_CONDITIONS_PER_RULE: usize = 100;
pub const MAX_ACTIONS_PER_RULE: usize = 20;
pub const MAX_CONDITION_VALUE_BYTES: usize = 1024;
pub const MAX_RULE_NAME_BYTES: usize = 256;
/// Tope del nombre de casilla destino de una acción `MoverA`.
///
/// Entra por el mismo contrato no confiable que el valor de una condición y el
/// nombre de la regla, así que se acota igual. 256 bytes es holgado para
/// cualquier ruta de casilla IMAP real (`INBOX/Proyectos/2026`, etc.).
pub const MAX_FOLDER_NAME_BYTES: usize = 256;

/// Interpreta el JSON de una regla que manda la ventana, como dato no confiable.
///
/// Rechaza lo que no parsea y la regla sin condiciones: una regla vacía hoy
/// coincide con nada (la evaluación la trata como no-coincide), pero guardarla
/// no tiene sentido y confunde. **No** valida el destino de un `MoverA`: la
/// ejecución ya saltea una casilla que no existe, y acá no se tiene la lista de
/// casillas a mano sin una vuelta al servidor.
pub fn parse_rule(json: &str) -> Result<Rule, String> {
    let rule: Rule =
        serde_json::from_str(json).map_err(|e| format!("no se pudo interpretar la regla: {e}"))?;
    if rule.match_.conditions.is_empty() {
        return Err("una regla necesita al menos una condición".into());
    }
    // Topes por regla: una regla gigante es un DoS persistente del sync —cada
    // condición se evalúa por mensaje por vuelta— y `MAX_RULES` sólo topa el
    // conteo, no los bytes por regla (ver las constantes).
    if rule.match_.conditions.len() > MAX_CONDITIONS_PER_RULE {
        return Err(format!(
            "una regla no puede tener más de {MAX_CONDITIONS_PER_RULE} condiciones"
        ));
    }
    if rule.actions.len() > MAX_ACTIONS_PER_RULE {
        return Err(format!(
            "una regla no puede tener más de {MAX_ACTIONS_PER_RULE} acciones"
        ));
    }
    if rule
        .match_
        .conditions
        .iter()
        .any(|c| c.value.len() > MAX_CONDITION_VALUE_BYTES)
    {
        return Err(format!(
            "el valor de una condición no puede superar {MAX_CONDITION_VALUE_BYTES} bytes"
        ));
    }
    if rule.name.len() > MAX_RULE_NAME_BYTES {
        return Err(format!(
            "el nombre de una regla no puede superar {MAX_RULE_NAME_BYTES} bytes"
        ));
    }
    if rule.actions.iter().any(|a| match a {
        Action::MoveToFolder(dest) => dest.len() > MAX_FOLDER_NAME_BYTES,
        _ => false,
    }) {
        return Err(format!(
            "el nombre de la casilla destino no puede superar {MAX_FOLDER_NAME_BYTES} bytes"
        ));
    }
    Ok(rule)
}

/// Agrega una regla al final y le asigna un id nuevo. Devuelve el id asignado.
///
/// El id es un UUID v4: estable (nunca cambia una vez puesto), único dentro de
/// la cuenta y sin depender de un contador que haya que guardar ni reutilizar un
/// id borrado —que colisionaría con una referencia vieja de la ventana—. El id
/// que trajera `rule` se descarta. Rechaza si ya se llegó al [`MAX_RULES`].
pub fn add_rule(ruleset: &mut RuleSet, mut rule: Rule) -> Result<String, String> {
    if ruleset.rules.len() >= MAX_RULES {
        return Err(format!(
            "no se pueden tener más de {MAX_RULES} reglas en una cuenta"
        ));
    }
    let id = uuid::Uuid::new_v4().to_string();
    rule.id = id.clone();
    ruleset.rules.push(rule);
    Ok(id)
}

/// Reemplaza la regla que tiene el id de `rule`. Error si no existe: la ventana
/// y el servicio quedaron desfasados, y avisar es mejor que crear una regla
/// sorpresa. No toca la marca de agua (se fija una sola vez, al crear).
pub fn replace_rule(ruleset: &mut RuleSet, rule: Rule) -> Result<(), String> {
    if rule.id.is_empty() {
        return Err("la regla a editar no trae id".into());
    }
    let slot = ruleset
        .rules
        .iter_mut()
        .find(|r| r.id == rule.id)
        .ok_or_else(|| format!("no hay una regla con id {}", rule.id))?;
    *slot = rule;
    Ok(())
}

/// Saca la regla con ese id. Error si no existe. No toca la marca de agua.
pub fn remove_rule(ruleset: &mut RuleSet, id: &str) -> Result<(), String> {
    let before = ruleset.rules.len();
    ruleset.rules.retain(|r| r.id != id);
    if ruleset.rules.len() == before {
        return Err(format!("no hay una regla con id {id}"));
    }
    Ok(())
}

/// Reordena las reglas según `ids` (el orden = prioridad). No toca la marca.
///
/// `ids` tiene que ser **exactamente** el conjunto de ids actuales, sin faltar,
/// sobrar ni repetir: un reordenamiento parcial perdería o duplicaría reglas.
///
/// **Valida antes de mutar**: resuelve la posición de cada id y marca las usadas
/// para rechazar repetidos, sin tocar `ruleset.rules` hasta estar seguro de que
/// el reordenamiento no va a fallar. Así un `Err` deja el conjunto intacto, en vez
/// de dejarlo a medio vaciar si un id posterior no existe.
pub fn reorder_rules(ruleset: &mut RuleSet, ids: &[String]) -> Result<(), String> {
    if ids.len() != ruleset.rules.len() {
        return Err("la lista de ids no coincide con las reglas de la cuenta".into());
    }
    let mut used = vec![false; ruleset.rules.len()];
    let mut positions = Vec::with_capacity(ids.len());
    for id in ids {
        let pos = ruleset
            .rules
            .iter()
            .position(|r| &r.id == id)
            .ok_or_else(|| format!("no hay una regla con id {id} para reordenar"))?;
        if std::mem::replace(&mut used[pos], true) {
            return Err(format!("el id {id} aparece más de una vez"));
        }
        positions.push(pos);
    }
    // Validado el conjunto, recién ahora se arma el nuevo orden.
    ruleset.rules = positions
        .iter()
        .map(|&p| ruleset.rules[p].clone())
        .collect();
    Ok(())
}

/// La marca de agua inicial a partir de lo que el almacén sabe de INBOX.
///
/// `uid_next` es el UID que el servidor le dará al próximo mensaje: desde ahí
/// para adelante están los que llegan después de crear la primera regla, que es
/// justo la ventana que las reglas pueden tocar sin barrer el backlog. Un
/// `uid_from` de 0 barrería todo el backlog —lo marcó `security`—, así que si
/// `uid_next` falta o es 0 no hay marca segura y se devuelve `None`.
pub fn initial_watermark(uidvalidity: u32, uid_next: Option<u32>) -> Option<Watermark> {
    match uid_next {
        Some(uid_from) if uid_from >= 1 => Some(Watermark {
            uidvalidity,
            uid_from,
        }),
        _ => None,
    }
}

/// Fija la marca de agua **la primera vez**, con el estado de INBOX que da el
/// almacén (`uidvalidity` y `uid_next`, o `None` si INBOX no se sincronizó).
///
/// Si el conjunto ya tiene marca, no la toca: se fija una sola vez, al crear la
/// primera regla; editar, borrar y reordenar nunca la cambian. Si hay que
/// fijarla y no hay una marca segura, **rechaza**: una regla con marca `None`
/// nunca actúa, y crear una regla inerte confunde más que pedir que se espere a
/// que la bandeja de entrada termine de sincronizarse.
pub fn ensure_watermark(
    ruleset: &mut RuleSet,
    inbox: Option<(u32, Option<u32>)>,
) -> Result<(), String> {
    if ruleset.watermark.is_some() {
        return Ok(());
    }
    match inbox.and_then(|(uidvalidity, uid_next)| initial_watermark(uidvalidity, uid_next)) {
        Some(watermark) => {
            ruleset.watermark = Some(watermark);
            Ok(())
        }
        None => Err("esperá a que se sincronice la bandeja de entrada para crear reglas".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cabeceras de un mensaje de prueba: de un banco, con asunto y adjunto.
    fn headers_banco() -> Headers {
        Headers::parse(
            "From: Soporte <soporte@Banco.com>\r\n\
             To: ana@ejemplo.org\r\n\
             Cc: equipo@ejemplo.org\r\n\
             Subject: Factura 123\r\n\
             Reply-To: no-reply@banco.com\r\n\
             List-Id: Avisos <avisos.banco.com>\r\n\
             Content-Type: multipart/mixed; boundary=xyz\r\n",
        )
    }

    /// Una condición suelta, sin negar.
    fn cond(field: Field, test: Test, value: &str) -> Condition {
        Condition {
            field,
            test,
            value: value.to_string(),
            negate: false,
        }
    }

    /// Una regla con una sola condición y una sola acción de mover.
    fn regla(id: &str, condition: Condition) -> Rule {
        Rule {
            id: id.to_string(),
            name: String::new(),
            enabled: true,
            match_: Match {
                op: MatchOp::All,
                conditions: vec![condition],
            },
            actions: vec![Action::MoveToFolder("Destino".into())],
            stop: false,
        }
    }

    fn solo(account_id: &str, rules: Vec<Rule>) -> RuleSet {
        RuleSet {
            account_id: account_id.into(),
            version: RULESET_VERSION,
            rules,
            watermark: None,
        }
    }

    // ── Evaluación ──────────────────────────────────────────────────────────

    #[test]
    fn una_regla_sin_condiciones_no_coincide() {
        let mut r = regla("1", cond(Field::Subject, Test::Contains, "x"));
        r.match_.conditions.clear();
        assert!(!matches(&r, &headers_banco(), 100));
    }

    #[test]
    fn los_campos_de_texto_salen_de_las_cabeceras() {
        let h = headers_banco();
        assert!(matches(
            &regla("", cond(Field::From, Test::Contains, "banco")),
            &h,
            0
        ));
        assert!(matches(
            &regla("", cond(Field::To, Test::Equals, "ana@ejemplo.org")),
            &h,
            0
        ));
        assert!(matches(
            &regla("", cond(Field::Cc, Test::Contains, "equipo")),
            &h,
            0
        ));
        assert!(matches(
            &regla("", cond(Field::Subject, Test::StartsWith, "Factura")),
            &h,
            0
        ));
        assert!(matches(
            &regla("", cond(Field::ReplyTo, Test::Contains, "no-reply")),
            &h,
            0
        ));
        assert!(matches(
            &regla("", cond(Field::ListId, Test::Contains, "avisos")),
            &h,
            0
        ));
        assert!(!matches(
            &regla("", cond(Field::Subject, Test::Equals, "otra cosa")),
            &h,
            0
        ));
    }

    #[test]
    fn el_texto_no_distingue_mayusculas() {
        // La regla dice BANCO.COM y el From trae Banco.com.
        let r = regla("", cond(Field::From, Test::Contains, "BANCO.COM"));
        assert!(matches(&r, &headers_banco(), 0));
    }

    #[test]
    fn op_todas_exige_todas_y_cualquiera_con_una_basta() {
        let h = headers_banco();
        let dos = |op| Rule {
            match_: Match {
                op,
                conditions: vec![
                    cond(Field::From, Test::Contains, "banco"),
                    cond(Field::Subject, Test::Contains, "no-esta"),
                ],
            },
            ..regla("", cond(Field::From, Test::Contains, "banco"))
        };
        // Una de dos: con Todas no alcanza, con Cualquiera sí.
        assert!(!matches(&dos(MatchOp::All), &h, 0));
        assert!(matches(&dos(MatchOp::Any), &h, 0));
    }

    #[test]
    fn negar_invierte_la_condicion() {
        let mut c = cond(Field::Subject, Test::Contains, "factura");
        c.negate = true;
        // El asunto SÍ contiene «factura», así que negada no coincide.
        assert!(!matches(&regla("", c), &headers_banco(), 0));
    }

    #[test]
    fn el_tamano_usa_mayor_y_menor_y_rechaza_lo_que_no_es_numero() {
        let h = headers_banco();
        assert!(matches(
            &regla("", cond(Field::Size, Test::Gt, "1000")),
            &h,
            5000
        ));
        assert!(matches(
            &regla("", cond(Field::Size, Test::Lt, "1000")),
            &h,
            500
        ));
        assert!(!matches(
            &regla("", cond(Field::Size, Test::Gt, "1000")),
            &h,
            500
        ));
        // Un valor que no es número no coincide, en vez de mover todo.
        assert!(!matches(
            &regla("", cond(Field::Size, Test::Gt, "mucho")),
            &h,
            5000
        ));
        // Una prueba de texto sobre el tamaño no quiere decir nada.
        assert!(!matches(
            &regla("", cond(Field::Size, Test::Contains, "5000")),
            &h,
            5000
        ));
    }

    #[test]
    fn tiene_adjuntos_mira_el_content_type() {
        let h = headers_banco(); // multipart/mixed → con adjuntos
        assert!(matches(
            &regla("", cond(Field::HasAttachment, Test::Equals, "si")),
            &h,
            0
        ));
        assert!(!matches(
            &regla("", cond(Field::HasAttachment, Test::Equals, "no")),
            &h,
            0
        ));
        let sin = Headers::parse("Subject: Hola\r\nContent-Type: text/plain\r\n");
        assert!(!matches(
            &regla("", cond(Field::HasAttachment, Test::Equals, "si")),
            &sin,
            0
        ));
    }

    #[test]
    fn una_prueba_que_no_corresponde_al_campo_no_coincide() {
        // Mayor sobre el asunto no significa nada.
        assert!(!matches(
            &regla("", cond(Field::Subject, Test::Gt, "A")),
            &headers_banco(),
            0
        ));
    }

    #[test]
    fn detener_corta_las_reglas_siguientes() {
        let mut r1 = regla("1", cond(Field::From, Test::Contains, "banco"));
        r1.stop = true;
        r1.actions = vec![Action::MarkRead];
        let r2 = regla("2", cond(Field::From, Test::Contains, "banco")); // también coincidiría
        let acciones = actions_for(&solo("a", vec![r1, r2]), &headers_banco(), 0);
        assert_eq!(acciones, vec![Action::MarkRead]);
    }

    #[test]
    fn una_regla_apagada_no_se_evalua() {
        let mut r = regla("1", cond(Field::From, Test::Contains, "banco"));
        r.enabled = false;
        assert!(actions_for(&solo("a", vec![r]), &headers_banco(), 0).is_empty());
    }

    #[test]
    fn actions_for_junta_las_acciones_en_orden() {
        let mut r1 = regla("1", cond(Field::From, Test::Contains, "banco"));
        r1.actions = vec![Action::Flag];
        let mut r2 = regla("2", cond(Field::Subject, Test::Contains, "factura"));
        r2.actions = vec![Action::MarkRead, Action::MoveToFolder("Bancos".into())];
        let acciones = actions_for(&solo("a", vec![r1, r2]), &headers_banco(), 0);
        assert_eq!(
            acciones,
            vec![
                Action::Flag,
                Action::MarkRead,
                Action::MoveToFolder("Bancos".into())
            ]
        );
    }

    // ── Almacén ─────────────────────────────────────────────────────────────

    /// Una carpeta de servicio temporal con `rules/` adentro, lista para abrir.
    fn temp_rules_dir() -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let app = std::env::temp_dir().join(format!(
            "vasak-reglas-{unique}-{:?}",
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&app).unwrap();
        app.join(RULES_DIR)
    }

    #[test]
    fn guardar_y_leer_devuelve_las_mismas_reglas() {
        let store = RuleStore::open(temp_rules_dir()).unwrap();
        let rs = solo(
            "ana",
            vec![regla("1", cond(Field::From, Test::Contains, "banco"))],
        );
        store.save(&rs).unwrap();
        assert_eq!(store.load("ana").unwrap(), rs);
    }

    #[test]
    fn sin_archivo_las_reglas_estan_vacias() {
        let store = RuleStore::open(temp_rules_dir()).unwrap();
        assert_eq!(store.load("nadie").unwrap(), RuleSet::empty("nadie"));
    }

    #[test]
    fn un_id_de_cuenta_invalido_no_toca_el_disco() {
        let store = RuleStore::open(temp_rules_dir()).unwrap();
        assert!(store.load("../otra").is_err());
        assert!(store.save(&RuleSet::empty("../otra")).is_err());
    }

    // ── Planificación de operaciones (pura) ───────────────────────────────────

    use crate::imap::HeaderRecord;
    use std::collections::HashSet;

    /// Un registro de INBOX con las cabeceras del banco (From banco, asunto
    /// «Factura», multipart/mixed), para que una regla «de contiene banco»
    /// coincida.
    fn rec(uid: u32, size: u64) -> HeaderRecord {
        HeaderRecord {
            uid,
            flags: Vec::new(),
            size,
            headers: "From: Soporte <soporte@Banco.com>\r\n\
                      Subject: Factura 123\r\n\
                      Content-Type: multipart/mixed; boundary=xyz\r\n"
                .to_string(),
        }
    }

    /// Un `RuleSet` con watermark y una regla de las condiciones/acciones dadas.
    fn con_marca(uidvalidity: u32, uid_from: u32, actions: Vec<Action>) -> RuleSet {
        let rule = Rule {
            id: "1".into(),
            name: String::new(),
            enabled: true,
            match_: Match {
                op: MatchOp::All,
                conditions: vec![cond(Field::From, Test::Contains, "banco")],
            },
            actions,
            stop: false,
        };
        RuleSet {
            account_id: "a".into(),
            version: RULESET_VERSION,
            rules: vec![rule],
            watermark: Some(Watermark {
                uidvalidity,
                uid_from,
            }),
        }
    }

    fn casillas(nombres: &[&str]) -> HashSet<String> {
        nombres.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn el_backlog_anterior_al_watermark_no_se_barre() {
        // Watermark en uid 100; el 50 es backlog → ninguna acción, aunque coincida.
        let rs = con_marca(1, 100, vec![Action::MoveToFolder("Bancos".into())]);
        let ops = plan_ops(&rs, 1, &[rec(50, 0)], &casillas(&["Bancos"]), None);
        assert!(ops.is_empty());
    }

    #[test]
    fn el_correo_posterior_al_watermark_si_se_actua() {
        let rs = con_marca(1, 100, vec![Action::MoveToFolder("Bancos".into())]);
        let ops = plan_ops(&rs, 1, &[rec(150, 0)], &casillas(&["Bancos"]), None);
        assert_eq!(ops, vec![MailOp::MoveTo(150, "Bancos".into())]);
    }

    #[test]
    fn sin_watermark_no_se_actua() {
        let mut rs = con_marca(1, 100, vec![Action::MoveToFolder("Bancos".into())]);
        rs.watermark = None;
        let ops = plan_ops(&rs, 1, &[rec(150, 0)], &casillas(&["Bancos"]), None);
        assert!(ops.is_empty());
    }

    #[test]
    fn con_uidvalidity_distinto_no_se_actua() {
        // Watermark de otra uidvalidity: los UID se reiniciaron, no se aplica.
        let rs = con_marca(1, 100, vec![Action::MoveToFolder("Bancos".into())]);
        let ops = plan_ops(&rs, 2, &[rec(150, 0)], &casillas(&["Bancos"]), None);
        assert!(ops.is_empty());
    }

    #[test]
    fn las_acciones_en_sitio_van_antes_de_la_terminal() {
        // La regla las trae al revés (mover primero); la terminal va al final.
        let rs = con_marca(
            1,
            1,
            vec![Action::MoveToFolder("Bancos".into()), Action::Flag],
        );
        let ops = plan_ops(&rs, 1, &[rec(5, 0)], &casillas(&["Bancos"]), None);
        assert_eq!(
            ops,
            vec![MailOp::Flag(5), MailOp::MoveTo(5, "Bancos".into())]
        );
    }

    #[test]
    fn de_dos_terminales_sale_solo_la_primera() {
        let rs = con_marca(
            1,
            1,
            vec![Action::MoveToFolder("Bancos".into()), Action::Delete],
        );
        let ops = plan_ops(
            &rs,
            1,
            &[rec(5, 0)],
            &casillas(&["Bancos"]),
            Some("Papelera"),
        );
        assert_eq!(ops, vec![MailOp::MoveTo(5, "Bancos".into())]);
    }

    #[test]
    fn borrar_es_a_la_papelera_y_sin_papelera_se_saltea() {
        let rs = con_marca(1, 1, vec![Action::Delete]);
        // Con papelera: borrar = mover a ella.
        let ops = plan_ops(&rs, 1, &[rec(5, 0)], &casillas(&[]), Some("Papelera"));
        assert_eq!(ops, vec![MailOp::MoveTo(5, "Papelera".into())]);
        // Sin papelera: no se borra.
        let ops = plan_ops(&rs, 1, &[rec(5, 0)], &casillas(&[]), None);
        assert!(ops.is_empty());
    }

    #[test]
    fn mover_a_una_casilla_desconocida_o_a_inbox_se_saltea() {
        let rs = con_marca(1, 1, vec![Action::MoveToFolder("NoExiste".into())]);
        assert!(plan_ops(&rs, 1, &[rec(5, 0)], &casillas(&["Bancos"]), None).is_empty());
        let rs = con_marca(1, 1, vec![Action::MoveToFolder("inbox".into())]);
        assert!(plan_ops(&rs, 1, &[rec(5, 0)], &casillas(&["Bancos"]), None).is_empty());
    }

    #[test]
    fn marcar_leido_y_destacar_son_las_dos_en_sitio() {
        let rs = con_marca(1, 1, vec![Action::MarkRead, Action::Flag]);
        let ops = plan_ops(&rs, 1, &[rec(5, 0)], &casillas(&[]), None);
        assert_eq!(ops, vec![MailOp::MarkRead(5), MailOp::Flag(5)]);
    }

    #[test]
    fn un_watermark_con_uid_desde_cero_no_barre_nada() {
        // El CRUD nunca escribe uid_from=0, pero un archivo del perfil del usuario
        // podría traerlo; el piso de is_eligible lo trata como no elegible en vez
        // de dejar pasar todo el backlog (uid >= 0 sería siempre verdadero).
        let rs = con_marca(1, 0, vec![Action::MoveToFolder("Bancos".into())]);
        assert!(plan_ops(&rs, 1, &[rec(5, 0)], &casillas(&["Bancos"]), None).is_empty());
    }

    // ── CRUD y marca de agua ──────────────────────────────────────────────────

    #[test]
    fn parse_rule_rechaza_lo_que_no_sirve_y_acepta_lo_valido() {
        assert!(parse_rule("no es json").is_err());
        // Una regla sin condiciones no se guarda.
        let vacia = serde_json::to_string(&Rule {
            match_: Match {
                op: MatchOp::All,
                conditions: vec![],
            },
            ..regla("x", cond(Field::From, Test::Contains, "banco"))
        })
        .unwrap();
        assert!(parse_rule(&vacia).is_err());
        let buena =
            serde_json::to_string(&regla("x", cond(Field::From, Test::Contains, "banco"))).unwrap();
        assert!(parse_rule(&buena).is_ok());
    }

    #[test]
    fn add_rule_asigna_un_id_propio_y_respeta_el_tope() {
        let mut rs = RuleSet::empty("a");
        let id = add_rule(
            &mut rs,
            regla("ignorame", cond(Field::From, Test::Contains, "x")),
        )
        .unwrap();
        assert!(!id.is_empty());
        assert_ne!(id, "ignorame", "el id que trae la regla se descarta");
        assert_eq!(rs.rules.len(), 1);
        assert_eq!(rs.rules[0].id, id);
        // Lleno hasta el tope y la siguiente se rechaza.
        while rs.rules.len() < MAX_RULES {
            add_rule(&mut rs, regla("", cond(Field::From, Test::Contains, "x"))).unwrap();
        }
        assert!(add_rule(&mut rs, regla("", cond(Field::From, Test::Contains, "x"))).is_err());
    }

    #[test]
    fn replace_y_remove_por_id() {
        let mut rs = RuleSet::empty("a");
        let id = add_rule(
            &mut rs,
            regla("", cond(Field::Subject, Test::Contains, "a")),
        )
        .unwrap();
        let mut editada = regla("", cond(Field::Subject, Test::Contains, "b"));
        editada.id = id.clone();
        replace_rule(&mut rs, editada).unwrap();
        assert_eq!(rs.rules[0].match_.conditions[0].value, "b");
        // Id inexistente o vacío → error.
        assert!(replace_rule(
            &mut rs,
            regla("noexiste", cond(Field::Subject, Test::Contains, "c"))
        )
        .is_err());
        assert!(remove_rule(&mut rs, "noexiste").is_err());
        remove_rule(&mut rs, &id).unwrap();
        assert!(rs.rules.is_empty());
    }

    #[test]
    fn reorder_exige_el_mismo_conjunto() {
        let mut rs = RuleSet::empty("a");
        let a = add_rule(&mut rs, regla("", cond(Field::From, Test::Contains, "a"))).unwrap();
        let b = add_rule(&mut rs, regla("", cond(Field::From, Test::Contains, "b"))).unwrap();
        reorder_rules(&mut rs, &[b.clone(), a.clone()]).unwrap();
        assert_eq!(rs.rules[0].id, b);
        assert_eq!(rs.rules[1].id, a);
        // Faltante, sobrante o repetido → error, sin tocar las reglas.
        assert!(reorder_rules(&mut rs, &[a.clone()]).is_err());
        assert!(reorder_rules(&mut rs, &[a.clone(), a.clone()]).is_err());
        assert!(reorder_rules(&mut rs, &[a, b, "extra".into()]).is_err());
    }

    #[test]
    fn initial_watermark_exige_uid_desde_uno() {
        assert_eq!(
            initial_watermark(7, Some(100)),
            Some(Watermark {
                uidvalidity: 7,
                uid_from: 100
            })
        );
        // uid_next ausente o 0 → sin marca segura (un 0 barrería el backlog).
        assert_eq!(initial_watermark(7, None), None);
        assert_eq!(initial_watermark(7, Some(0)), None);
    }

    #[test]
    fn parse_rule_topa_cada_regla() {
        // Una sola regla gigante esquivaría MAX_RULES (que topa el conteo) y sería
        // DoS persistente del sync: cada condición se evalúa por mensaje por vuelta.
        let con_condiciones = |n: usize| {
            serde_json::to_string(&Rule {
                match_: Match {
                    op: MatchOp::All,
                    conditions: vec![cond(Field::From, Test::Contains, "x"); n],
                },
                ..regla("x", cond(Field::From, Test::Contains, "x"))
            })
            .unwrap()
        };
        assert!(parse_rule(&con_condiciones(MAX_CONDITIONS_PER_RULE)).is_ok());
        assert!(parse_rule(&con_condiciones(MAX_CONDITIONS_PER_RULE + 1)).is_err());

        let con_acciones = |n: usize| {
            serde_json::to_string(&Rule {
                actions: vec![Action::MarkRead; n],
                ..regla("x", cond(Field::From, Test::Contains, "x"))
            })
            .unwrap()
        };
        assert!(parse_rule(&con_acciones(MAX_ACTIONS_PER_RULE)).is_ok());
        assert!(parse_rule(&con_acciones(MAX_ACTIONS_PER_RULE + 1)).is_err());

        let con_valor = |n: usize| {
            serde_json::to_string(&regla(
                "x",
                cond(Field::From, Test::Contains, &"a".repeat(n)),
            ))
            .unwrap()
        };
        assert!(parse_rule(&con_valor(MAX_CONDITION_VALUE_BYTES)).is_ok());
        assert!(parse_rule(&con_valor(MAX_CONDITION_VALUE_BYTES + 1)).is_err());

        let con_nombre = |n: usize| {
            let mut r = regla("x", cond(Field::From, Test::Contains, "x"));
            r.name = "a".repeat(n);
            serde_json::to_string(&r).unwrap()
        };
        assert!(parse_rule(&con_nombre(MAX_RULE_NAME_BYTES)).is_ok());
        assert!(parse_rule(&con_nombre(MAX_RULE_NAME_BYTES + 1)).is_err());
    }

    #[test]
    fn ensure_watermark_fija_una_vez_y_rechaza_sin_inbox() {
        // Sin INBOX sincronizada → rechaza (no crea una regla inerte).
        let mut rs = RuleSet::empty("a");
        assert!(ensure_watermark(&mut rs, None).is_err());
        assert!(ensure_watermark(&mut rs, Some((7, Some(0)))).is_err());
        assert_eq!(rs.watermark, None);
        // Con estado bueno → la fija.
        ensure_watermark(&mut rs, Some((7, Some(100)))).unwrap();
        assert_eq!(
            rs.watermark,
            Some(Watermark {
                uidvalidity: 7,
                uid_from: 100
            })
        );
        // Ya fijada → no la toca, aunque INBOX haya cambiado.
        ensure_watermark(&mut rs, Some((9, Some(500)))).unwrap();
        assert_eq!(
            rs.watermark,
            Some(Watermark {
                uidvalidity: 7,
                uid_from: 100
            })
        );
    }
}
