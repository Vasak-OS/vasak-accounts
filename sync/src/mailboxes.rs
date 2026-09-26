//! Las casillas del servidor: enumerarlas, nombrarlas y saber cuál es cuál.
//!
//! Hasta ahora el escritorio abría `INBOX` y nada más, escrito a mano en tres
//! lugares. O sea que el correo enviado, el archivado, el spam y la papelera
//! **no existían**: un mensaje se podía leer y marcar como leído, y nada más.
//!
//! Acá está lo que se puede resolver sin hablar con ningún servidor —que es
//! todo el análisis— para que se pueda probar de verdad. Lo que va y viene por
//! la red vive en `imap.rs`.
//!
//! # Lo que este módulo **no** hace
//!
//! Mover y borrar. No por falta de ganas: el issue que pide esto dice que la
//! fase entera está sin verificar contra un servidor real, y mover y borrar
//! **escriben correo ajeno de lugar**. Enumerar y nombrar sólo leen, así que se
//! pueden soltar antes; escribir espera a que haya una casilla de prueba.

use base64::alphabet::Alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine;

/// Para qué sirve una casilla.
///
/// Sale de `SPECIAL-USE` (RFC 6154) cuando el servidor lo anuncia, que es la
/// única forma de saberlo **sin adivinar**. Cuando no, se cae a comparar
/// nombres conocidos, que es lo que hay con los servidores viejos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxRole {
    #[serde(rename = "entrada")]
    Inbox,
    #[serde(rename = "enviados")]
    Sent,
    #[serde(rename = "borradores")]
    Drafts,
    #[serde(rename = "papelera")]
    Trash,
    Spam,
    #[serde(rename = "archivo")]
    Archive,
    /// Todo el correo junto, como el «All Mail» de Gmail.
    #[serde(rename = "todo")]
    All,
    #[serde(rename = "ninguno")]
    Other,
}

/// Una casilla tal como la describe el servidor.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Mailbox {
    /// El nombre como se escribe en los comandos: en UTF-7 modificado si hace
    /// falta. Es el que hay que mandarle al servidor.
    #[serde(rename = "ruta")]
    pub path: String,
    /// El mismo nombre para mostrar, ya decodificado.
    #[serde(rename = "nombre")]
    pub name: String,
    /// El separador de la jerarquía. **No siempre es `/`**: hay servidores que
    /// usan `.` y alguno que no tiene jerarquía y manda `NIL`.
    #[serde(rename = "separador")]
    pub delimiter: Option<char>,
    #[serde(rename = "uso")]
    pub role: MailboxRole,
    /// Si el servidor dice que no se puede abrir. Las casillas
    /// `\Noselect` existen sólo como rama de la jerarquía; ofrecerlas para
    /// abrir es ofrecer un error.
    #[serde(rename = "seleccionable")]
    pub selectable: bool,
}

/// El alfabeto del BASE64 modificado de IMAP: igual al de siempre pero con
/// `,` en lugar de `/`, porque `/` es separador de jerarquía en muchos
/// servidores.
fn utf7_engine() -> GeneralPurpose {
    let alphabet =
        Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,")
            .expect("el alfabeto es válido");
    // Sin relleno: el estándar lo prohíbe acá.
    let config = GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent);
    GeneralPurpose::new(&alphabet, config)
}

/// Pasa un nombre de casilla de UTF-7 modificado a texto (RFC 3501 §5.1.3).
///
/// `~peter/mail/&U,BTFw-/&ZeVnLIqe-` es `~peter/mail/台北/日本語`. Sin esto una
/// carpeta con acentos aparece como basura, que es exactamente lo que veía
/// cualquiera con una casilla llamada «Elementos enviados» en un servidor viejo.
///
/// Lo que no se entiende se deja como está en vez de descartarlo: un nombre
/// raro se puede leer igual y sigue sirviendo para abrir la casilla; uno vacío
/// no sirve para nada.
pub fn from_utf7(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != b'&' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }

        // `&-` es un `&` literal.
        if bytes.get(i + 1) == Some(&b'-') {
            out.push('&');
            i += 2;
            continue;
        }

        let Some(end) = bytes[i + 1..].iter().position(|b| *b == b'-') else {
            // Un `&` sin su `-` de cierre: el nombre está mal formado. Se copia
            // tal cual y se sigue.
            out.push_str(&text[i..]);
            break;
        };
        let chunk = &text[i + 1..i + 1 + end];
        match decode_chunk(chunk) {
            Some(decoded_text) => out.push_str(&decoded_text),
            // No se pudo: se deja el original, con sus delimitadores, para que
            // el nombre siga sirviendo aunque se lea feo.
            None => out.push_str(&text[i..i + 2 + end]),
        }
        i += 2 + end;
    }

    out
}

/// Un trozo entre `&` y `-`: BASE64 modificado de UTF-16BE.
fn decode_chunk(chunk: &str) -> Option<String> {
    let raw = utf7_engine().decode(chunk).ok()?;
    if raw.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

/// Pasa un nombre de casilla a UTF-7 modificado, para poder mandárselo al
/// servidor.
///
/// Todavía no lo llama nadie, y está igual por dos motivos. Es la inversa de
/// `from_utf7`, así que la prueba de ida y vuelta es lo que demuestra que el
/// decodificador está bien — sin ella habría que confiar en ejemplos escritos a
/// mano. Y hace falta en cuanto haya que nombrar una casilla que no vino de un
/// `LIST`: crear una carpeta, o mover un mensaje a una que escribió la persona.
#[allow(dead_code)]
pub fn to_utf7(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending: Vec<u16> = Vec::new();

    let flush_pending = |pending: &mut Vec<u16>, out: &mut String| {
        if pending.is_empty() {
            return;
        }
        let bytes: Vec<u8> = pending.iter().flat_map(|u| u.to_be_bytes()).collect();
        out.push('&');
        out.push_str(&utf7_engine().encode(bytes));
        out.push('-');
        pending.clear();
    };

    for c in text.chars() {
        match c {
            // El `&` es el que abre una secuencia, así que se escapa siempre.
            '&' => {
                flush_pending(&mut pending, &mut out);
                out.push_str("&-");
            }
            // ASCII imprimible se escribe tal cual.
            ' '..='~' => {
                flush_pending(&mut pending, &mut out);
                out.push(c);
            }
            other => {
                let mut buf = [0u16; 2];
                pending.extend_from_slice(other.encode_utf16(&mut buf));
            }
        }
    }
    flush_pending(&mut pending, &mut out);

    out
}

/// Lee una línea `* LIST` o `* LSUB`.
///
/// El formato es `* LIST (atributos) "separador" nombre`, con el nombre entre
/// comillas, sin comillas, o como literal `{N}` — este último no se resuelve
/// acá porque necesita leer más líneas de la red; lo resuelve quien llama.
pub fn mailbox_from_list(line: &str) -> Option<Mailbox> {
    let rest = line.strip_prefix("* ")?;
    let rest = ["LIST ", "LSUB ", "XLIST "]
        .iter()
        .find_map(|c| rest.strip_prefix(c))?;

    // Los atributos, entre paréntesis.
    let rest = rest.trim_start();
    let closing = rest.find(')')?;
    let attributes: Vec<&str> = rest.get(1..closing)?.split_whitespace().collect();
    let rest = rest.get(closing + 1..)?.trim_start();

    // El separador: `"/"`, `"."`, o `NIL` cuando no hay jerarquía.
    let (delimiter, rest) = if let Some(after_nil) = rest.strip_prefix("NIL") {
        (None, after_nil)
    } else {
        let after_quote = rest.strip_prefix('"')?;
        let closing = after_quote.find('"')?;
        // El separador puede venir escapado (`"\\"`), que es un servidor con
        // jerarquía por barra invertida.
        let raw = after_quote.get(..closing)?;
        let c = raw.trim_start_matches('\\').chars().next();
        (c, after_quote.get(closing + 1..)?)
    };

    let path = mailbox_name(rest.trim())?;
    if path.is_empty() {
        return None;
    }

    Some(Mailbox {
        name: from_utf7(&path),
        role: role_from(&attributes, &from_utf7(&path)),
        selectable: !attributes
            .iter()
            .any(|a| a.eq_ignore_ascii_case("\\Noselect")),
        delimiter,
        path,
    })
}

/// El nombre del final de la línea, con o sin comillas.
fn mailbox_name(rest: &str) -> Option<String> {
    if let Some(after_quote) = rest.strip_prefix('"') {
        let closing = after_quote.rfind('"')?;
        return Some(
            after_quote
                .get(..closing)?
                .replace("\\\"", "\"")
                .replace("\\\\", "\\"),
        );
    }
    // Un literal `{N}` lo resuelve quien llama: necesita leer más de la red.
    if rest.starts_with('{') {
        return None;
    }
    Some(rest.to_string())
}

/// Para qué sirve la casilla, por sus atributos y —si no hay— por su nombre.
fn role_from(attributes: &[&str], name: &str) -> MailboxRole {
    for attribute in attributes {
        // `SPECIAL-USE` (RFC 6154). Es lo que dice cuál es cuál **sin
        // adivinar**, y por eso va primero.
        let role = match attribute
            .trim_start_matches('\\')
            .to_ascii_lowercase()
            .as_str()
        {
            "sent" => MailboxRole::Sent,
            "drafts" => MailboxRole::Drafts,
            "trash" => MailboxRole::Trash,
            "junk" => MailboxRole::Spam,
            "archive" => MailboxRole::Archive,
            "all" => MailboxRole::All,
            _ => continue,
        };
        return role;
    }

    role_by_name(name)
}

/// El respaldo para los servidores que no anuncian `SPECIAL-USE`.
///
/// Adivinar por el nombre es peor que leer el atributo y por eso va segundo,
/// pero sin esto una cuenta en un servidor viejo no tiene papelera y «borrar»
/// no tiene a dónde mover. Se compara la última parte de la ruta, porque en
/// Gmail las carpetas cuelgan de `[Gmail]/`.
fn role_by_name(name: &str) -> MailboxRole {
    let leaf = name
        .rsplit(['/', '.'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();

    match leaf.as_str() {
        "inbox" | "entrada" | "bandeja de entrada" => MailboxRole::Inbox,
        "sent" | "sent mail" | "sent items" | "enviados" | "elementos enviados" => {
            MailboxRole::Sent
        }
        "drafts" | "borradores" => MailboxRole::Drafts,
        "trash" | "deleted items" | "papelera" | "elementos eliminados" => MailboxRole::Trash,
        "junk" | "junk e-mail" | "spam" | "correo no deseado" => MailboxRole::Spam,
        "archive" | "archivo" | "archivados" => MailboxRole::Archive,
        "all mail" | "todos" => MailboxRole::All,
        _ => MailboxRole::Other,
    }
}

/// El `UIDVALIDITY` de una respuesta a abrir una casilla.
///
/// Importa más de lo que parece. Si el servidor lo cambia, **todos los UID
/// guardados dejan de valer**: el 412 de ayer no es el 412 de hoy. Sin
/// compararlo, un «borrar» puede caerle a otro mensaje.
pub fn uidvalidity_from(line: &str) -> Option<u32> {
    let from = line.find("[UIDVALIDITY ")? + "[UIDVALIDITY ".len();
    let rest = line.get(from..)?;
    let end = rest.find(']')?;
    rest.get(..end)?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El ejemplo del RFC 3501 §5.1.3, letra por letra.
    #[test]
    fn el_ejemplo_del_estandar() {
        assert_eq!(
            from_utf7("~peter/mail/&U,BTFw-/&ZeVnLIqe-"),
            "~peter/mail/台北/日本語"
        );
        assert_eq!(
            to_utf7("~peter/mail/台北/日本語"),
            "~peter/mail/&U,BTFw-/&ZeVnLIqe-"
        );
    }

    /// El caso que se ve todos los días: una casilla en español en un servidor
    /// que no anuncia UTF8=ACCEPT. Sin esto aparece como basura.
    #[test]
    fn una_casilla_con_acentos() {
        for name in [
            "Elementos enviados",
            "Días",
            "Año pasado",
            "Ñandú",
            "Correo·raro",
        ] {
            let encoded = to_utf7(name);
            assert_eq!(from_utf7(&encoded), name, "no volvió igual: {encoded}");
        }
    }

    #[test]
    fn el_ampersand_se_escapa() {
        assert_eq!(to_utf7("Trabajo & Casa"), "Trabajo &- Casa");
        assert_eq!(from_utf7("Trabajo &- Casa"), "Trabajo & Casa");
        // Y el ASCII de siempre no se toca.
        assert_eq!(to_utf7("INBOX"), "INBOX");
        assert_eq!(from_utf7("INBOX"), "INBOX");
    }

    /// Un nombre mal formado se deja como está y no se descarta: uno raro se
    /// puede leer igual y sigue sirviendo para abrir la casilla; uno vacío no
    /// sirve para nada.
    #[test]
    fn lo_que_no_se_entiende_se_deja() {
        assert_eq!(from_utf7("roto&sin cierre"), "roto&sin cierre");
        assert_eq!(from_utf7("&&&-"), "&&&-");
        assert_eq!(from_utf7(""), "");
        // BASE64 que no es UTF-16 válido: queda el original con sus delimitadores.
        assert_eq!(from_utf7("&AAAA"), "&AAAA");
    }

    /// Respuestas de servidores reales, con su forma tal cual.
    #[test]
    fn una_linea_de_list_se_lee_entera() {
        let c = mailbox_from_list(r#"* LIST (\HasNoChildren \Sent) "/" "Sent Mail""#).unwrap();
        assert_eq!(c.path, "Sent Mail");
        assert_eq!(c.name, "Sent Mail");
        assert_eq!(c.delimiter, Some('/'));
        assert_eq!(c.role, MailboxRole::Sent);
        assert!(c.selectable);
    }

    #[test]
    fn el_separador_no_siempre_es_una_barra() {
        // Courier y Dovecot con `.` como separador.
        let c = mailbox_from_list(r#"* LIST (\HasNoChildren) "." INBOX.Trabajo"#).unwrap();
        assert_eq!(c.delimiter, Some('.'));
        assert_eq!(c.path, "INBOX.Trabajo");

        // Y hay servidores sin jerarquía.
        let c = mailbox_from_list(r#"* LIST (\HasNoChildren) NIL "Todo""#).unwrap();
        assert_eq!(c.delimiter, None);
        assert_eq!(c.path, "Todo");
    }

    #[test]
    fn una_casilla_que_no_se_puede_abrir_se_marca() {
        // Existe sólo como rama de la jerarquía. Ofrecerla para abrir es
        // ofrecer un error.
        let c = mailbox_from_list(r#"* LIST (\Noselect \HasChildren) "/" "[Gmail]""#).unwrap();
        assert!(!c.selectable);

        let c = mailbox_from_list(r#"* LIST (\HasNoChildren) "/" "INBOX""#).unwrap();
        assert!(c.selectable);
    }

    /// SPECIAL-USE es lo que dice cuál es cuál sin adivinar, así que gana sobre
    /// el nombre aunque el nombre diga otra cosa.
    #[test]
    fn el_atributo_le_gana_al_nombre() {
        let c = mailbox_from_list(r#"* LIST (\Trash) "/" "Cualquier Cosa""#).unwrap();
        assert_eq!(c.role, MailboxRole::Trash);

        // Y al revés: sin atributo, se cae al nombre.
        let c = mailbox_from_list(r#"* LIST (\HasNoChildren) "/" "Papelera""#).unwrap();
        assert_eq!(c.role, MailboxRole::Trash);
    }

    #[test]
    fn los_seis_usos_especiales_se_reconocen() {
        for (attribute, expected) in [
            ("\\Sent", MailboxRole::Sent),
            ("\\Drafts", MailboxRole::Drafts),
            ("\\Trash", MailboxRole::Trash),
            ("\\Junk", MailboxRole::Spam),
            ("\\Archive", MailboxRole::Archive),
            ("\\All", MailboxRole::All),
        ] {
            let line = format!(r#"* LIST ({attribute}) "/" "X""#);
            assert_eq!(
                mailbox_from_list(&line).unwrap().role,
                expected,
                "{attribute}"
            );
        }
    }

    /// En Gmail las carpetas cuelgan de `[Gmail]/`, así que comparar la ruta
    /// entera no encontraría nada. Se compara la última parte.
    #[test]
    fn en_gmail_las_carpetas_cuelgan_de_otra() {
        let c = mailbox_from_list(r#"* LIST (\HasNoChildren) "/" "[Gmail]/Sent Mail""#).unwrap();
        assert_eq!(c.role, MailboxRole::Sent);

        let c = mailbox_from_list(r#"* LIST (\HasNoChildren) "." "INBOX.Papelera""#).unwrap();
        assert_eq!(c.role, MailboxRole::Trash);
    }

    #[test]
    fn el_nombre_se_muestra_decodificado_y_la_ruta_no() {
        // La ruta es lo que se le manda al servidor; el nombre es lo que se ve.
        let c = mailbox_from_list(r#"* LIST (\HasNoChildren) "/" "&AOE-rbol""#).unwrap();
        assert_eq!(c.path, "&AOE-rbol");
        assert_eq!(c.name, "árbol");
    }

    #[test]
    fn un_nombre_en_utf7_igual_se_reconoce_por_su_uso() {
        // «Elementos eliminados» de un Exchange viejo, en UTF-7.
        let encoded = to_utf7("Elementos eliminados");
        let line = format!(r#"* LIST (\HasNoChildren) "/" "{encoded}""#);
        assert_eq!(mailbox_from_list(&line).unwrap().role, MailboxRole::Trash);
    }

    #[test]
    fn lo_que_no_es_una_linea_de_list_se_descarta() {
        for another in [
            "* 12 EXISTS",
            "a1 OK LIST completado",
            "* LIST",
            "",
            "* LISTA (\\X) \"/\" \"Y\"",
            // Un literal `{N}` lo resuelve quien llama: necesita más red.
            "* LIST (\\HasNoChildren) \"/\" {12}",
        ] {
            assert!(mailbox_from_list(another).is_none(), "{another:?}");
        }
    }

    #[test]
    fn el_uidvalidity_se_lee_de_donde_viene() {
        assert_eq!(
            uidvalidity_from("* OK [UIDVALIDITY 3857529045] UIDs valid"),
            Some(3857529045)
        );
        assert_eq!(uidvalidity_from("* OK [UIDVALIDITY 1] x"), Some(1));
        assert_eq!(
            uidvalidity_from("* OK [UIDNEXT 4392] Predicted next UID"),
            None
        );
        assert_eq!(uidvalidity_from("* 12 EXISTS"), None);
        assert_eq!(uidvalidity_from("* OK [UIDVALIDITY ] x"), None);
        // Más grande que un u32: se descarta en vez de quedarse con un número
        // que no es el que mandó el servidor.
        assert_eq!(uidvalidity_from("* OK [UIDVALIDITY 99999999999] x"), None);
    }

    /// Una vuelta completa sobre los nombres que aparecen de verdad, para que
    /// el par de funciones no se separe.
    #[test]
    fn la_ida_y_la_vuelta_coinciden() {
        for name in [
            "INBOX",
            "INBOX.Sent",
            "[Gmail]/All Mail",
            "Año/Días raros",
            "日本語",
            "Trabajo & Casa",
            "~peter/mail/台北/日本語",
            "",
        ] {
            assert_eq!(from_utf7(&to_utf7(name)), name, "{name:?}");
        }
    }

    /// `ListMailboxes`: cada casilla con las claves que lee `vasak-mail`, y el
    /// uso con los valores de siempre —la ventana compara contra ellos—.
    #[test]
    fn una_casilla_conserva_las_claves_y_los_usos_del_bus() {
        let mailbox =
            mailbox_from_list(r#"* LIST (\HasNoChildren \Trash) "/" "Papelera""#).unwrap();
        let json = serde_json::to_value(&mailbox).unwrap();
        assert_eq!(
            crate::test_support::json_keys(&json),
            ["nombre", "ruta", "seleccionable", "separador", "uso"]
        );
        assert_eq!(json["uso"], "papelera");
        assert_eq!(json["separador"], "/");

        for (role, wire) in [
            (MailboxRole::Inbox, "entrada"),
            (MailboxRole::Sent, "enviados"),
            (MailboxRole::Drafts, "borradores"),
            (MailboxRole::Trash, "papelera"),
            (MailboxRole::Spam, "spam"),
            (MailboxRole::Archive, "archivo"),
            (MailboxRole::All, "todo"),
            (MailboxRole::Other, "ninguno"),
        ] {
            assert_eq!(serde_json::to_value(role).unwrap(), wire, "{role:?}");
        }
    }
}
