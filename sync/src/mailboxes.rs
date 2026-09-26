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
pub enum Uso {
    Entrada,
    Enviados,
    Borradores,
    Papelera,
    Spam,
    Archivo,
    /// Todo el correo junto, como el «All Mail» de Gmail.
    Todo,
    Ninguno,
}

/// Una casilla tal como la describe el servidor.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Casilla {
    /// El nombre como se escribe en los comandos: en UTF-7 modificado si hace
    /// falta. Es el que hay que mandarle al servidor.
    pub ruta: String,
    /// El mismo nombre para mostrar, ya decodificado.
    pub nombre: String,
    /// El separador de la jerarquía. **No siempre es `/`**: hay servidores que
    /// usan `.` y alguno que no tiene jerarquía y manda `NIL`.
    pub separador: Option<char>,
    pub uso: Uso,
    /// Si el servidor dice que no se puede abrir. Las casillas
    /// `\Noselect` existen sólo como rama de la jerarquía; ofrecerlas para
    /// abrir es ofrecer un error.
    pub seleccionable: bool,
}

/// El alfabeto del BASE64 modificado de IMAP: igual al de siempre pero con
/// `,` en lugar de `/`, porque `/` es separador de jerarquía en muchos
/// servidores.
fn motor() -> GeneralPurpose {
    let alfabeto =
        Alphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,")
            .expect("el alfabeto es válido");
    // Sin relleno: el estándar lo prohíbe acá.
    let config = GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent);
    GeneralPurpose::new(&alfabeto, config)
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
pub fn de_utf7(texto: &str) -> String {
    let mut salida = String::with_capacity(texto.len());
    let bytes = texto.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != b'&' {
            salida.push(bytes[i] as char);
            i += 1;
            continue;
        }

        // `&-` es un `&` literal.
        if bytes.get(i + 1) == Some(&b'-') {
            salida.push('&');
            i += 2;
            continue;
        }

        let Some(fin) = bytes[i + 1..].iter().position(|b| *b == b'-') else {
            // Un `&` sin su `-` de cierre: el nombre está mal formado. Se copia
            // tal cual y se sigue.
            salida.push_str(&texto[i..]);
            break;
        };
        let trozo = &texto[i + 1..i + 1 + fin];
        match decodificar_trozo(trozo) {
            Some(texto_decodificado) => salida.push_str(&texto_decodificado),
            // No se pudo: se deja el original, con sus delimitadores, para que
            // el nombre siga sirviendo aunque se lea feo.
            None => salida.push_str(&texto[i..i + 2 + fin]),
        }
        i += 2 + fin;
    }

    salida
}

/// Un trozo entre `&` y `-`: BASE64 modificado de UTF-16BE.
fn decodificar_trozo(trozo: &str) -> Option<String> {
    let crudo = motor().decode(trozo).ok()?;
    if crudo.len() % 2 != 0 {
        return None;
    }
    let unidades: Vec<u16> = crudo
        .chunks_exact(2)
        .map(|par| u16::from_be_bytes([par[0], par[1]]))
        .collect();
    String::from_utf16(&unidades).ok()
}

/// Pasa un nombre de casilla a UTF-7 modificado, para poder mandárselo al
/// servidor.
///
/// Todavía no lo llama nadie, y está igual por dos motivos. Es la inversa de
/// `de_utf7`, así que la prueba de ida y vuelta es lo que demuestra que el
/// decodificador está bien — sin ella habría que confiar en ejemplos escritos a
/// mano. Y hace falta en cuanto haya que nombrar una casilla que no vino de un
/// `LIST`: crear una carpeta, o mover un mensaje a una que escribió la persona.
#[allow(dead_code)]
pub fn a_utf7(texto: &str) -> String {
    let mut salida = String::with_capacity(texto.len());
    let mut pendientes: Vec<u16> = Vec::new();

    let volcar = |pendientes: &mut Vec<u16>, salida: &mut String| {
        if pendientes.is_empty() {
            return;
        }
        let bytes: Vec<u8> = pendientes.iter().flat_map(|u| u.to_be_bytes()).collect();
        salida.push('&');
        salida.push_str(&motor().encode(bytes));
        salida.push('-');
        pendientes.clear();
    };

    for c in texto.chars() {
        match c {
            // El `&` es el que abre una secuencia, así que se escapa siempre.
            '&' => {
                volcar(&mut pendientes, &mut salida);
                salida.push_str("&-");
            }
            // ASCII imprimible se escribe tal cual.
            ' '..='~' => {
                volcar(&mut pendientes, &mut salida);
                salida.push(c);
            }
            otro => {
                let mut buf = [0u16; 2];
                pendientes.extend_from_slice(otro.encode_utf16(&mut buf));
            }
        }
    }
    volcar(&mut pendientes, &mut salida);

    salida
}

/// Lee una línea `* LIST` o `* LSUB`.
///
/// El formato es `* LIST (atributos) "separador" nombre`, con el nombre entre
/// comillas, sin comillas, o como literal `{N}` — este último no se resuelve
/// acá porque necesita leer más líneas de la red; lo resuelve quien llama.
pub fn casilla_de_list(linea: &str) -> Option<Casilla> {
    let resto = linea.strip_prefix("* ")?;
    let resto = ["LIST ", "LSUB ", "XLIST "]
        .iter()
        .find_map(|c| resto.strip_prefix(c))?;

    // Los atributos, entre paréntesis.
    let resto = resto.trim_start();
    let cierre = resto.find(')')?;
    let atributos: Vec<&str> = resto.get(1..cierre)?.split_whitespace().collect();
    let resto = resto.get(cierre + 1..)?.trim_start();

    // El separador: `"/"`, `"."`, o `NIL` cuando no hay jerarquía.
    let (separador, resto) = if let Some(sin_nil) = resto.strip_prefix("NIL") {
        (None, sin_nil)
    } else {
        let sin_comilla = resto.strip_prefix('"')?;
        let cierre = sin_comilla.find('"')?;
        // El separador puede venir escapado (`"\\"`), que es un servidor con
        // jerarquía por barra invertida.
        let crudo = sin_comilla.get(..cierre)?;
        let c = crudo.trim_start_matches('\\').chars().next();
        (c, sin_comilla.get(cierre + 1..)?)
    };

    let ruta = nombre_de(resto.trim())?;
    if ruta.is_empty() {
        return None;
    }

    Some(Casilla {
        nombre: de_utf7(&ruta),
        uso: uso_de(&atributos, &de_utf7(&ruta)),
        seleccionable: !atributos
            .iter()
            .any(|a| a.eq_ignore_ascii_case("\\Noselect")),
        separador,
        ruta,
    })
}

/// El nombre del final de la línea, con o sin comillas.
fn nombre_de(resto: &str) -> Option<String> {
    if let Some(sin_comilla) = resto.strip_prefix('"') {
        let cierre = sin_comilla.rfind('"')?;
        return Some(
            sin_comilla
                .get(..cierre)?
                .replace("\\\"", "\"")
                .replace("\\\\", "\\"),
        );
    }
    // Un literal `{N}` lo resuelve quien llama: necesita leer más de la red.
    if resto.starts_with('{') {
        return None;
    }
    Some(resto.to_string())
}

/// Para qué sirve la casilla, por sus atributos y —si no hay— por su nombre.
fn uso_de(atributos: &[&str], nombre: &str) -> Uso {
    for atributo in atributos {
        // `SPECIAL-USE` (RFC 6154). Es lo que dice cuál es cuál **sin
        // adivinar**, y por eso va primero.
        let uso = match atributo
            .trim_start_matches('\\')
            .to_ascii_lowercase()
            .as_str()
        {
            "sent" => Uso::Enviados,
            "drafts" => Uso::Borradores,
            "trash" => Uso::Papelera,
            "junk" => Uso::Spam,
            "archive" => Uso::Archivo,
            "all" => Uso::Todo,
            _ => continue,
        };
        return uso;
    }

    por_el_nombre(nombre)
}

/// El respaldo para los servidores que no anuncian `SPECIAL-USE`.
///
/// Adivinar por el nombre es peor que leer el atributo y por eso va segundo,
/// pero sin esto una cuenta en un servidor viejo no tiene papelera y «borrar»
/// no tiene a dónde mover. Se compara la última parte de la ruta, porque en
/// Gmail las carpetas cuelgan de `[Gmail]/`.
fn por_el_nombre(nombre: &str) -> Uso {
    let hoja = nombre
        .rsplit(['/', '.'])
        .next()
        .unwrap_or(nombre)
        .to_ascii_lowercase();

    match hoja.as_str() {
        "inbox" | "entrada" | "bandeja de entrada" => Uso::Entrada,
        "sent" | "sent mail" | "sent items" | "enviados" | "elementos enviados" => Uso::Enviados,
        "drafts" | "borradores" => Uso::Borradores,
        "trash" | "deleted items" | "papelera" | "elementos eliminados" => Uso::Papelera,
        "junk" | "junk e-mail" | "spam" | "correo no deseado" => Uso::Spam,
        "archive" | "archivo" | "archivados" => Uso::Archivo,
        "all mail" | "todos" => Uso::Todo,
        _ => Uso::Ninguno,
    }
}

/// El `UIDVALIDITY` de una respuesta a abrir una casilla.
///
/// Importa más de lo que parece. Si el servidor lo cambia, **todos los UID
/// guardados dejan de valer**: el 412 de ayer no es el 412 de hoy. Sin
/// compararlo, un «borrar» puede caerle a otro mensaje.
pub fn uidvalidity_de(linea: &str) -> Option<u32> {
    let desde = linea.find("[UIDVALIDITY ")? + "[UIDVALIDITY ".len();
    let resto = linea.get(desde..)?;
    let hasta = resto.find(']')?;
    resto.get(..hasta)?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El ejemplo del RFC 3501 §5.1.3, letra por letra.
    #[test]
    fn el_ejemplo_del_estandar() {
        assert_eq!(
            de_utf7("~peter/mail/&U,BTFw-/&ZeVnLIqe-"),
            "~peter/mail/台北/日本語"
        );
        assert_eq!(
            a_utf7("~peter/mail/台北/日本語"),
            "~peter/mail/&U,BTFw-/&ZeVnLIqe-"
        );
    }

    /// El caso que se ve todos los días: una casilla en español en un servidor
    /// que no anuncia UTF8=ACCEPT. Sin esto aparece como basura.
    #[test]
    fn una_casilla_con_acentos() {
        for nombre in [
            "Elementos enviados",
            "Días",
            "Año pasado",
            "Ñandú",
            "Correo·raro",
        ] {
            let ida = a_utf7(nombre);
            assert_eq!(de_utf7(&ida), nombre, "no volvió igual: {ida}");
        }
    }

    #[test]
    fn el_ampersand_se_escapa() {
        assert_eq!(a_utf7("Trabajo & Casa"), "Trabajo &- Casa");
        assert_eq!(de_utf7("Trabajo &- Casa"), "Trabajo & Casa");
        // Y el ASCII de siempre no se toca.
        assert_eq!(a_utf7("INBOX"), "INBOX");
        assert_eq!(de_utf7("INBOX"), "INBOX");
    }

    /// Un nombre mal formado se deja como está y no se descarta: uno raro se
    /// puede leer igual y sigue sirviendo para abrir la casilla; uno vacío no
    /// sirve para nada.
    #[test]
    fn lo_que_no_se_entiende_se_deja() {
        assert_eq!(de_utf7("roto&sin cierre"), "roto&sin cierre");
        assert_eq!(de_utf7("&&&-"), "&&&-");
        assert_eq!(de_utf7(""), "");
        // BASE64 que no es UTF-16 válido: queda el original con sus delimitadores.
        assert_eq!(de_utf7("&AAAA"), "&AAAA");
    }

    /// Respuestas de servidores reales, con su forma tal cual.
    #[test]
    fn una_linea_de_list_se_lee_entera() {
        let c = casilla_de_list(r#"* LIST (\HasNoChildren \Sent) "/" "Sent Mail""#).unwrap();
        assert_eq!(c.ruta, "Sent Mail");
        assert_eq!(c.nombre, "Sent Mail");
        assert_eq!(c.separador, Some('/'));
        assert_eq!(c.uso, Uso::Enviados);
        assert!(c.seleccionable);
    }

    #[test]
    fn el_separador_no_siempre_es_una_barra() {
        // Courier y Dovecot con `.` como separador.
        let c = casilla_de_list(r#"* LIST (\HasNoChildren) "." INBOX.Trabajo"#).unwrap();
        assert_eq!(c.separador, Some('.'));
        assert_eq!(c.ruta, "INBOX.Trabajo");

        // Y hay servidores sin jerarquía.
        let c = casilla_de_list(r#"* LIST (\HasNoChildren) NIL "Todo""#).unwrap();
        assert_eq!(c.separador, None);
        assert_eq!(c.ruta, "Todo");
    }

    #[test]
    fn una_casilla_que_no_se_puede_abrir_se_marca() {
        // Existe sólo como rama de la jerarquía. Ofrecerla para abrir es
        // ofrecer un error.
        let c = casilla_de_list(r#"* LIST (\Noselect \HasChildren) "/" "[Gmail]""#).unwrap();
        assert!(!c.seleccionable);

        let c = casilla_de_list(r#"* LIST (\HasNoChildren) "/" "INBOX""#).unwrap();
        assert!(c.seleccionable);
    }

    /// SPECIAL-USE es lo que dice cuál es cuál sin adivinar, así que gana sobre
    /// el nombre aunque el nombre diga otra cosa.
    #[test]
    fn el_atributo_le_gana_al_nombre() {
        let c = casilla_de_list(r#"* LIST (\Trash) "/" "Cualquier Cosa""#).unwrap();
        assert_eq!(c.uso, Uso::Papelera);

        // Y al revés: sin atributo, se cae al nombre.
        let c = casilla_de_list(r#"* LIST (\HasNoChildren) "/" "Papelera""#).unwrap();
        assert_eq!(c.uso, Uso::Papelera);
    }

    #[test]
    fn los_seis_usos_especiales_se_reconocen() {
        for (atributo, esperado) in [
            ("\\Sent", Uso::Enviados),
            ("\\Drafts", Uso::Borradores),
            ("\\Trash", Uso::Papelera),
            ("\\Junk", Uso::Spam),
            ("\\Archive", Uso::Archivo),
            ("\\All", Uso::Todo),
        ] {
            let linea = format!(r#"* LIST ({atributo}) "/" "X""#);
            assert_eq!(casilla_de_list(&linea).unwrap().uso, esperado, "{atributo}");
        }
    }

    /// En Gmail las carpetas cuelgan de `[Gmail]/`, así que comparar la ruta
    /// entera no encontraría nada. Se compara la última parte.
    #[test]
    fn en_gmail_las_carpetas_cuelgan_de_otra() {
        let c = casilla_de_list(r#"* LIST (\HasNoChildren) "/" "[Gmail]/Sent Mail""#).unwrap();
        assert_eq!(c.uso, Uso::Enviados);

        let c = casilla_de_list(r#"* LIST (\HasNoChildren) "." "INBOX.Papelera""#).unwrap();
        assert_eq!(c.uso, Uso::Papelera);
    }

    #[test]
    fn el_nombre_se_muestra_decodificado_y_la_ruta_no() {
        // La ruta es lo que se le manda al servidor; el nombre es lo que se ve.
        let c = casilla_de_list(r#"* LIST (\HasNoChildren) "/" "&AOE-rbol""#).unwrap();
        assert_eq!(c.ruta, "&AOE-rbol");
        assert_eq!(c.nombre, "árbol");
    }

    #[test]
    fn un_nombre_en_utf7_igual_se_reconoce_por_su_uso() {
        // «Elementos eliminados» de un Exchange viejo, en UTF-7.
        let codificado = a_utf7("Elementos eliminados");
        let linea = format!(r#"* LIST (\HasNoChildren) "/" "{codificado}""#);
        assert_eq!(casilla_de_list(&linea).unwrap().uso, Uso::Papelera);
    }

    #[test]
    fn lo_que_no_es_una_linea_de_list_se_descarta() {
        for otra in [
            "* 12 EXISTS",
            "a1 OK LIST completado",
            "* LIST",
            "",
            "* LISTA (\\X) \"/\" \"Y\"",
            // Un literal `{N}` lo resuelve quien llama: necesita más red.
            "* LIST (\\HasNoChildren) \"/\" {12}",
        ] {
            assert!(casilla_de_list(otra).is_none(), "{otra:?}");
        }
    }

    #[test]
    fn el_uidvalidity_se_lee_de_donde_viene() {
        assert_eq!(
            uidvalidity_de("* OK [UIDVALIDITY 3857529045] UIDs valid"),
            Some(3857529045)
        );
        assert_eq!(uidvalidity_de("* OK [UIDVALIDITY 1] x"), Some(1));
        assert_eq!(
            uidvalidity_de("* OK [UIDNEXT 4392] Predicted next UID"),
            None
        );
        assert_eq!(uidvalidity_de("* 12 EXISTS"), None);
        assert_eq!(uidvalidity_de("* OK [UIDVALIDITY ] x"), None);
        // Más grande que un u32: se descarta en vez de quedarse con un número
        // que no es el que mandó el servidor.
        assert_eq!(uidvalidity_de("* OK [UIDVALIDITY 99999999999] x"), None);
    }

    /// Una vuelta completa sobre los nombres que aparecen de verdad, para que
    /// el par de funciones no se separe.
    #[test]
    fn la_ida_y_la_vuelta_coinciden() {
        for nombre in [
            "INBOX",
            "INBOX.Sent",
            "[Gmail]/All Mail",
            "Año/Días raros",
            "日本語",
            "Trabajo & Casa",
            "~peter/mail/台北/日本語",
            "",
        ] {
            assert_eq!(de_utf7(&a_utf7(nombre)), nombre, "{nombre:?}");
        }
    }
}
