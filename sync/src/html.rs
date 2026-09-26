//! Dejar el HTML de un mensaje en condiciones de mostrarse.
//!
//! # De dónde viene esto y por qué no se muestra tal cual
//!
//! El cuerpo de un correo lo escribió cualquiera que sepa la dirección de la
//! persona. Mostrarlo como página web —que es lo que la gente espera, porque un
//! boletín o una factura sin formato quedan como una lista de palabras sueltas—
//! es dibujar el documento de un desconocido adentro de la aplicación más
//! expuesta del escritorio.
//!
//! Hasta ahora no se mostraba: `message::strip_tags` saca las etiquetas y
//! deja el texto. Eso se queda como la vista segura de siempre; esto es lo otro.
//!
//! # Dos cosas distintas, y las dos hacen falta
//!
//! **Sanear** es sacar lo que ejecuta o navega: `<script>`, `on*`, `<iframe>`,
//! `<form>`, `javascript:`. Eso se hace acá.
//!
//! **Aislar** es que lo que quede no pueda tocar la aplicación aunque algo se
//! haya escapado: va en un contenedor cerrado del lado de la ventana, con su
//! propia política de contenido. Eso **no** se hace acá, y ninguna de las dos
//! reemplaza a la otra — sanear sin aislar apuesta todo a que este archivo no
//! tenga un agujero.
//!
//! # Por qué una biblioteca y no un recortador propio
//!
//! Porque acá el que escribe es un atacante. Un recortador escrito a mano
//! trabaja sobre el texto; el motor que después dibuja eso trabaja sobre el
//! **árbol** que sale de parsear ese texto, y los dos no siempre coinciden. De
//! esa diferencia vive una familia entera de ataques (*mutation XSS*):
//! `<svg><style><img src=x onerror=...>` y parientes, que un recortador por
//! texto deja pasar porque nunca vio un `<script>`.
//!
//! `ammonia` parsea con el mismo motor que un navegador y **reescribe desde el
//! árbol**: lo que sale no es el texto original con cosas tachadas, es el
//! documento serializado de nuevo. Con lista blanca, además: lo que no está
//! nombrado no pasa, así que una etiqueta nueva del estándar no es un agujero.
//!
//! `strip_tags` se queda igual y no tiene este problema: su salida es texto,
//! no se dibuja como documento.
//!
//! # Las imágenes no se cargan
//!
//! Un píxel de seguimiento es un `<img>` que apunta al servidor de quien mandó
//! el correo: pedirlo le avisa que el mensaje se abrió, cuándo, y desde qué
//! dirección IP. Hoy eso no pasa porque no se dibuja nada; que empiece a pasar
//! al mostrar HTML sería cambiar una función por una filtración.
//!
//! Así que cada `src` remoto se guarda aparte —en `data-vsk-src`— y se cuentan.
//! Lo que queda no pide nada solo, y la ventana puede decir «este mensaje quiere
//! cargar 4 imágenes de un servidor externo» y ofrecer hacerlo, que es una
//! decisión de la persona y no del que escribió el correo.

use std::collections::HashSet;

/// Tope de lo que se devuelve saneado.
///
/// El mismo orden que el del texto. Un mensaje con un megabyte de HTML ya es
/// raro; lo que esto evita es que uno armado a propósito haga crecer la memoria
/// de la ventana sin freno.
const MAX_HTML: usize = 1024 * 1024;

/// Dónde se guarda la dirección de una imagen que no se cargó.
///
/// Se conserva en vez de tirarla para que mostrarla después no obligue a ir a
/// buscar el mensaje de nuevo. Es un atributo cualquiera: nada la pide sola.
pub const REMOTE_SRC_ATTRIBUTE: &str = "data-vsk-src";

/// El HTML listo para mostrar, y qué se dejó afuera.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Sanitized {
    pub html: String,
    /// Cuántas imágenes remotas se bloquearon.
    ///
    /// Se cuenta para poder **decirlo**: una imagen que no aparece y nadie
    /// explica se lee como un mensaje roto, no como una decisión.
    #[serde(rename = "imagenes_bloqueadas")]
    pub blocked_images: usize,
    /// Si hubo que cortar el HTML por largo.
    #[serde(rename = "recortado")]
    pub truncated: bool,
}

/// Las etiquetas que pasan.
///
/// Lista blanca y corta: lo que hace falta para que un correo con formato se
/// lea. Lo que no está nombrado no pasa, así que una etiqueta nueva del estándar
/// no entra sola.
///
/// **No están** `script`, `style`, `iframe`, `object`, `embed`, `form`,
/// `input`, `button`, `link`, `meta` ni `base`. Las tres últimas no ejecutan
/// nada pero cargan o redirigen: un `<link rel=stylesheet>` es una petición al
/// servidor de quien mandó el correo igual que un píxel, y un `<base>` cambia a
/// dónde van todos los enlaces del documento de una sola vez.
const ALLOWED_TAGS: &[&str] = &[
    "a",
    "abbr",
    "b",
    "blockquote",
    "br",
    "caption",
    "cite",
    "code",
    "col",
    "colgroup",
    "dd",
    "del",
    "div",
    "dl",
    "dt",
    "em",
    "figcaption",
    "figure",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "i",
    "img",
    "ins",
    "li",
    "ol",
    "p",
    "pre",
    "q",
    "s",
    "small",
    "span",
    "strong",
    "sub",
    "sup",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "u",
    "ul",
];

/// Los esquemas que puede tener un enlace.
///
/// `javascript:` y `data:` afuera, que es lo obvio. `cid:` también: apunta a una
/// parte del propio mensaje, y mientras no haya de dónde sacarla es un enlace
/// roto que además revela cómo está armado el correo.
const ALLOWED_SCHEMES: &[&str] = &["http", "https", "mailto"];

/// Deja el HTML en condiciones de mostrarse.
pub fn sanitize(html: &str) -> Sanitized {
    let tags: HashSet<&str> = ALLOWED_TAGS.iter().copied().collect();
    let schemes: HashSet<&str> = ALLOWED_SCHEMES.iter().copied().collect();

    let mut builder = ammonia::Builder::default();
    builder
        .tags(tags)
        .url_schemes(schemes)
        // Los atributos, también por lista blanca. Que `style` **no** esté es
        // deliberado: `background: url(...)` es una petición a un servidor ajeno
        // con otro nombre, y `position: fixed` deja al mensaje dibujarse encima
        // de la aplicación.
        .generic_attributes(["title", "dir", "lang"].into_iter().collect())
        .tag_attributes(
            [
                ("a", ["href", "title"].into_iter().collect()),
                (
                    "img",
                    ["alt", "title", "width", "height", REMOTE_SRC_ATTRIBUTE]
                        .into_iter()
                        .collect(),
                ),
                ("td", ["colspan", "rowspan"].into_iter().collect()),
                ("th", ["colspan", "rowspan", "scope"].into_iter().collect()),
            ]
            .into_iter()
            .collect(),
        )
        // Un enlace que se abre no puede llevarse el contexto de la aplicación,
        // ni decirle al destino de dónde viene: el `Referer` de un correo es la
        // confirmación de que se abrió.
        .link_rel(Some("noopener noreferrer nofollow"))
        // Las relativas no tienen contra qué resolverse —esto no es una página
        // servida desde ningún lado— así que se tiran en vez de quedar rotas.
        .url_relative(ammonia::UrlRelative::Deny)
        // Acá está la decisión: **ninguna imagen se pide**. El `src` se va
        // entero, venga de donde venga; la dirección de las remotas ya quedó
        // guardada con otro nombre, que nada carga solo.
        .attribute_filter(|tag, attribute, value| {
            if tag == "img" && attribute == "src" {
                return None;
            }
            Some(value.into())
        });

    // En dos pasadas, y no con un contador adentro del filtro: el saneador exige
    // que su filtro se pueda compartir entre hilos, y además el filtro no puede
    // cambiarle el nombre a un atributo — que es justo lo que hay que hacer con
    // el `src`. La pasada de abajo guarda la dirección y cuenta; ésta borra.
    let (stashed, blocked) = stash_remote_sources(html);
    let mut cleaned = builder.clean(&stashed).to_string();

    let truncated = cleaned.len() > MAX_HTML;
    if truncated {
        // Se corta y se vuelve a sanear: un corte a la mitad deja etiquetas sin
        // cerrar, y el saneador las cierra al serializar de nuevo. Cortar y
        // mostrar sin esto es entregar HTML roto al navegador, que lo va a
        // arreglar como se le ocurra.
        cleaned.truncate(floor_char_boundary(&cleaned, MAX_HTML));
        cleaned = builder.clean(&cleaned).to_string();
    }

    Sanitized {
        html: cleaned,
        blocked_images: blocked,
        truncated,
    }
}

/// Copia cada `src` de imagen a [`REMOTE_SRC_ATTRIBUTE`] antes de sanear, y cuenta
/// cuántas eran remotas.
///
/// Con una expresión regular y a propósito: no se está interpretando el
/// documento —de eso se encarga el saneador un paso después, y lo que salga de
/// acá pasa entero por él—, sólo se está duplicando un atributo. Si esta pasada
/// se equivoca, lo peor que produce es un atributo de más con una dirección que
/// nadie carga.
fn stash_remote_sources(html: &str) -> (String, usize) {
    let pattern =
        regex::Regex::new(r#"(?is)(<img\b[^>]*?)\bsrc\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))"#)
            .expect("el patrón es válido");

    let mut blocked = 0usize;
    let out = pattern
        .replace_all(html, |caps: &regex::Captures| {
            let address = caps
                .get(3)
                .or_else(|| caps.get(4))
                .or_else(|| caps.get(5))
                .map(|m| m.as_str())
                .unwrap_or_default();

            if !is_remote(address) {
                // Lo que no es remoto no se guarda ni se cuenta: un `cid:` o un
                // `data:` no hay de dónde cargarlos, y ofrecerlos sería prometer
                // un botón que no puede hacer nada.
                return caps.get(0).map(|m| m.as_str()).unwrap_or("").to_string();
            }
            blocked += 1;
            format!(
                r#"{} {}="{}" src={}"#,
                &caps[1],
                REMOTE_SRC_ATTRIBUTE,
                address.replace('"', "&quot;"),
                &caps[2]
            )
        })
        .into_owned();

    (out, blocked)
}

/// Si una dirección va a buscar algo a otro servidor.
fn is_remote(address: &str) -> bool {
    let d = address.trim().to_ascii_lowercase();
    d.starts_with("http://") || d.starts_with("https://") || d.starts_with("//")
}

/// El corte más cercano que no parte un carácter por la mitad.
fn floor_char_boundary(text: &str, limit: usize) -> usize {
    let mut cut = limit.min(text.len());
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    cut
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lo que tiene que desaparecer sí o sí.
    ///
    /// Cada caso es una forma conocida de ejecutar código adentro de la ventana
    /// que lee el correo de alguien.
    #[test]
    fn nada_que_ejecute_sobrevive() {
        for hostile in [
            r#"<script>alert(1)</script>"#,
            r#"<img src=x onerror="alert(1)">"#,
            r#"<div onclick="alert(1)">hola</div>"#,
            r#"<a href="javascript:alert(1)">clic</a>"#,
            r#"<iframe src="https://ejemplo.com"></iframe>"#,
            r#"<object data="x.swf"></object>"#,
            r#"<embed src="x.swf">"#,
            r#"<form action="https://ejemplo.com"><input name="clave"></form>"#,
            // La familia que un recortador por texto deja pasar: el motor cierra
            // el `<style>` de otra manera y el `<img>` vuelve a la vida.
            r#"<svg><style><img src=x onerror=alert(1)></style></svg>"#,
            r#"<math><mtext><script>alert(1)</script></mtext></math>"#,
        ] {
            let out = sanitize(hostile).html.to_ascii_lowercase();
            assert!(!out.contains("<script"), "{hostile:?} → {out:?}");
            assert!(!out.contains("onerror"), "{hostile:?} → {out:?}");
            assert!(!out.contains("onclick"), "{hostile:?} → {out:?}");
            assert!(!out.contains("javascript:"), "{hostile:?} → {out:?}");
            assert!(!out.contains("<iframe"), "{hostile:?} → {out:?}");
            assert!(!out.contains("<form"), "{hostile:?} → {out:?}");
            assert!(!out.contains("<object"), "{hostile:?} → {out:?}");
            assert!(!out.contains("<embed"), "{hostile:?} → {out:?}");
        }
    }

    /// Lo que carga o redirige sin ejecutar nada, que es igual de grave.
    #[test]
    fn nada_que_cargue_solo_sobrevive() {
        // Una hoja de estilos es una petición al servidor de quien escribió el
        // correo, igual que un píxel de seguimiento.
        let with_leaf = sanitize(r#"<link rel="stylesheet" href="https://ejemplo.com/x.css">"#);
        assert!(!with_leaf.html.to_ascii_lowercase().contains("<link"));

        // Un `<base>` cambia a dónde van **todos** los enlaces del documento de
        // una sola vez.
        let with_base = sanitize(r#"<base href="https://ejemplo.com/"><a href="/x">ir</a>"#);
        assert!(!with_base.html.to_ascii_lowercase().contains("<base"));

        // `style` no está en la lista blanca: `background: url(...)` es una
        // petición con otro nombre, y `position: fixed` deja al mensaje
        // dibujarse encima de la aplicación.
        let with_style =
            sanitize(r#"<div style="background:url(https://ejemplo.com/p.gif)">x</div>"#);
        assert!(!with_style.html.contains("background"));
        assert!(!with_style.html.contains("ejemplo.com"));
    }

    /// El formato que sí se quiere ver sobrevive: si no, esto no sirve para
    /// nada y más vale seguir mostrando texto pelado.
    #[test]
    fn el_formato_de_un_correo_normal_sobrevive() {
        let newsletter = r#"<h1>Novedades</h1><p><strong>Hola</strong> <em>Ana</em>,</p>
            <ul><li>Uno</li><li>Dos</li></ul>
            <table><tr><td>A</td><td>B</td></tr></table>
            <blockquote>lo que dijo</blockquote>"#;
        let out = sanitize(newsletter).html;

        for tag in [
            "<h1>",
            "<strong>",
            "<em>",
            "<ul>",
            "<li>",
            "<table>",
            "<blockquote>",
        ] {
            assert!(out.contains(tag), "se perdió {tag}: {out}");
        }
    }

    /// Un enlace normal se queda, y sale con las protecciones puestas.
    #[test]
    fn un_enlace_normal_se_queda_y_no_filtra_de_donde_viene() {
        let out = sanitize(r#"<a href="https://ejemplo.com/x">ir</a>"#).html;
        assert!(out.contains(r#"href="https://ejemplo.com/x""#), "{out}");
        // `noreferrer` porque el `Referer` de un correo es la confirmación de
        // que se abrió.
        assert!(out.contains("noreferrer"), "{out}");
        assert!(out.contains("noopener"), "{out}");
    }

    /// **Ninguna imagen se pide sola.** Es lo que hace que mostrar el formato no
    /// se convierta en avisarle a quien escribió que abriste el mensaje.
    #[test]
    fn las_imagenes_remotas_no_se_cargan_pero_se_cuentan() {
        let with_pixel = r#"<p>hola</p><img src="https://rastreo.ejemplo/p.gif?id=42" alt="">
            <img src='https://otro.ejemplo/b.png'>"#;
        let out = sanitize(with_pixel);

        assert_eq!(out.blocked_images, 2);
        // No queda ningún `src` que el navegador vaya a pedir.
        //
        // Se busca **con el espacio adelante**, que no es quisquillosidad:
        // `data-vsk-src="https…` contiene `src="https`, así que la comprobación
        // sin el espacio pasa siempre y no comprueba nada. El espacio es lo que
        // distingue el atributo de verdad del que lo lleva adentro del nombre.
        assert!(!out.html.contains(" src=\""), "{}", out.html);
        assert!(!out.html.contains(" src='"), "{}", out.html);
        // …pero la dirección se conserva, para poder mostrarla si la persona lo
        // pide sin volver a buscar el mensaje.
        assert!(out.html.contains(REMOTE_SRC_ATTRIBUTE), "{}", out.html);
        assert!(out.html.contains("rastreo.ejemplo"), "{}", out.html);
    }

    /// Las que no son remotas no se cuentan ni se guardan: no hay de dónde
    /// cargarlas, y ofrecerlas sería prometer un botón que no puede hacer nada.
    #[test]
    fn lo_que_no_es_remoto_no_cuenta_como_imagen_bloqueada() {
        let out =
            sanitize(r#"<img src="cid:parte1@ejemplo"><img src="data:image/gif;base64,R0lGOD">"#);
        assert_eq!(out.blocked_images, 0);
        assert!(!out.html.contains(REMOTE_SRC_ATTRIBUTE), "{}", out.html);
        // Y el `src` se va igual: `data:` puede llevar un SVG con script adentro.
        assert!(!out.html.contains(" src="), "{}", out.html);
    }

    /// Una relativa tampoco: no hay contra qué resolverla, esto no es una página
    /// servida desde ningún lado.
    #[test]
    fn una_direccion_relativa_no_queda_a_medias() {
        let out = sanitize(r#"<a href="/x">ir</a><img src="/p.gif">"#);
        assert!(!out.html.contains(r#"href="/x""#), "{}", out.html);
        assert_eq!(out.blocked_images, 0);
    }

    /// Un mensaje enorme no hace crecer la memoria de la ventana sin freno, y lo
    /// que se devuelve sigue siendo HTML entero y no uno cortado a la mitad.
    #[test]
    fn un_html_enorme_se_recorta_y_sigue_cerrado() {
        let huge = format!("<p>{}</p>", "a".repeat(MAX_HTML * 2));
        let out = sanitize(&huge);

        assert!(out.truncated);
        assert!(out.html.len() <= MAX_HTML + 64, "{}", out.html.len());
        // Cortar y ya dejaría un `<p>` sin cerrar; el saneador lo cierra al
        // serializar de nuevo.
        assert_eq!(
            out.html.matches("<p").count(),
            out.html.matches("</p>").count()
        );
    }

    #[test]
    fn un_html_normal_no_se_marca_como_recortado() {
        assert!(!sanitize("<p>corto</p>").truncated);
    }

    /// El texto se escapa, no se pierde: un mensaje que habla de HTML se tiene
    /// que poder leer.
    #[test]
    fn el_texto_sobrevive_escapado() {
        let out = sanitize("<p>usá &lt;script&gt; con cuidado</p>").html;
        assert!(out.contains("script"), "{out}");
        assert!(!out.contains("<script"), "{out}");
    }

    /// Entrada vacía o basura no rompe nada.
    #[test]
    fn lo_que_no_es_html_no_rompe() {
        assert_eq!(sanitize("").html, "");
        assert_eq!(sanitize("<<<>>>").blocked_images, 0);
        assert!(!sanitize("sólo texto").html.is_empty());
    }
}
