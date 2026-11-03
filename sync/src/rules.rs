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
}

impl RuleSet {
    /// Un conjunto vacío para una cuenta que todavía no tiene reglas.
    pub fn empty(account_id: &str) -> Self {
        RuleSet {
            account_id: account_id.to_string(),
            version: RULESET_VERSION,
            rules: Vec::new(),
        }
    }
}

/// Una regla: a qué mensajes mira y qué les hace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
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
