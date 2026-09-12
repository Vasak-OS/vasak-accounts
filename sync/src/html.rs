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
//! Hasta ahora no se mostraba: `mensaje::sin_etiquetas` saca las etiquetas y
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
//! `sin_etiquetas` se queda igual y no tiene este problema: su salida es texto,
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
pub const ATRIBUTO_REMOTO: &str = "data-vsk-src";

/// El HTML listo para mostrar, y qué se dejó afuera.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Saneado {
    pub html: String,
    /// Cuántas imágenes remotas se bloquearon.
    ///
    /// Se cuenta para poder **decirlo**: una imagen que no aparece y nadie
    /// explica se lee como un mensaje roto, no como una decisión.
    pub imagenes_bloqueadas: usize,
    /// Si hubo que cortar el HTML por largo.
    pub recortado: bool,
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
const ETIQUETAS: &[&str] = &[
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
const ESQUEMAS: &[&str] = &["http", "https", "mailto"];

/// Deja el HTML en condiciones de mostrarse.
pub fn sanear(html: &str) -> Saneado {
    let etiquetas: HashSet<&str> = ETIQUETAS.iter().copied().collect();
    let esquemas: HashSet<&str> = ESQUEMAS.iter().copied().collect();

    let mut constructor = ammonia::Builder::default();
    constructor
        .tags(etiquetas)
        .url_schemes(esquemas)
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
                    ["alt", "title", "width", "height", ATRIBUTO_REMOTO]
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
        .attribute_filter(|etiqueta, atributo, valor| {
            if etiqueta == "img" && atributo == "src" {
                return None;
            }
            Some(valor.into())
        });

    // En dos pasadas, y no con un contador adentro del filtro: el saneador exige
    // que su filtro se pueda compartir entre hilos, y además el filtro no puede
    // cambiarle el nombre a un atributo — que es justo lo que hay que hacer con
    // el `src`. La pasada de abajo guarda la dirección y cuenta; ésta borra.
    let (con_la_direccion_guardada, bloqueadas) = guardar_direcciones(html);
    let mut limpio = constructor.clean(&con_la_direccion_guardada).to_string();

    let recortado = limpio.len() > MAX_HTML;
    if recortado {
        // Se corta y se vuelve a sanear: un corte a la mitad deja etiquetas sin
        // cerrar, y el saneador las cierra al serializar de nuevo. Cortar y
        // mostrar sin esto es entregar HTML roto al navegador, que lo va a
        // arreglar como se le ocurra.
        limpio.truncate(corte_valido(&limpio, MAX_HTML));
        limpio = constructor.clean(&limpio).to_string();
    }

    Saneado {
        html: limpio,
        imagenes_bloqueadas: bloqueadas,
        recortado,
    }
}

/// Copia cada `src` de imagen a [`ATRIBUTO_REMOTO`] antes de sanear, y cuenta
/// cuántas eran remotas.
///
/// Con una expresión regular y a propósito: no se está interpretando el
/// documento —de eso se encarga el saneador un paso después, y lo que salga de
/// acá pasa entero por él—, sólo se está duplicando un atributo. Si esta pasada
/// se equivoca, lo peor que produce es un atributo de más con una dirección que
/// nadie carga.
fn guardar_direcciones(html: &str) -> (String, usize) {
    let patron =
        regex::Regex::new(r#"(?is)(<img\b[^>]*?)\bsrc\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))"#)
            .expect("el patrón es válido");

    let mut bloqueadas = 0usize;
    let salida = patron
        .replace_all(html, |captura: &regex::Captures| {
            let direccion = captura
                .get(3)
                .or_else(|| captura.get(4))
                .or_else(|| captura.get(5))
                .map(|m| m.as_str())
                .unwrap_or_default();

            if !es_remota(direccion) {
                // Lo que no es remoto no se guarda ni se cuenta: un `cid:` o un
                // `data:` no hay de dónde cargarlos, y ofrecerlos sería prometer
                // un botón que no puede hacer nada.
                return captura.get(0).map(|m| m.as_str()).unwrap_or("").to_string();
            }
            bloqueadas += 1;
            format!(
                r#"{} {}="{}" src={}"#,
                &captura[1],
                ATRIBUTO_REMOTO,
                direccion.replace('"', "&quot;"),
                &captura[2]
            )
        })
        .into_owned();

    (salida, bloqueadas)
}

/// Si una dirección va a buscar algo a otro servidor.
fn es_remota(direccion: &str) -> bool {
    let d = direccion.trim().to_ascii_lowercase();
    d.starts_with("http://") || d.starts_with("https://") || d.starts_with("//")
}

/// El corte más cercano que no parte un carácter por la mitad.
fn corte_valido(texto: &str, tope: usize) -> usize {
    let mut corte = tope.min(texto.len());
    while corte > 0 && !texto.is_char_boundary(corte) {
        corte -= 1;
    }
    corte
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
        for hostil in [
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
            let salida = sanear(hostil).html.to_ascii_lowercase();
            assert!(!salida.contains("<script"), "{hostil:?} → {salida:?}");
            assert!(!salida.contains("onerror"), "{hostil:?} → {salida:?}");
            assert!(!salida.contains("onclick"), "{hostil:?} → {salida:?}");
            assert!(!salida.contains("javascript:"), "{hostil:?} → {salida:?}");
            assert!(!salida.contains("<iframe"), "{hostil:?} → {salida:?}");
            assert!(!salida.contains("<form"), "{hostil:?} → {salida:?}");
            assert!(!salida.contains("<object"), "{hostil:?} → {salida:?}");
            assert!(!salida.contains("<embed"), "{hostil:?} → {salida:?}");
        }
    }

    /// Lo que carga o redirige sin ejecutar nada, que es igual de grave.
    #[test]
    fn nada_que_cargue_solo_sobrevive() {
        // Una hoja de estilos es una petición al servidor de quien escribió el
        // correo, igual que un píxel de seguimiento.
        let con_hoja = sanear(r#"<link rel="stylesheet" href="https://ejemplo.com/x.css">"#);
        assert!(!con_hoja.html.to_ascii_lowercase().contains("<link"));

        // Un `<base>` cambia a dónde van **todos** los enlaces del documento de
        // una sola vez.
        let con_base = sanear(r#"<base href="https://ejemplo.com/"><a href="/x">ir</a>"#);
        assert!(!con_base.html.to_ascii_lowercase().contains("<base"));

        // `style` no está en la lista blanca: `background: url(...)` es una
        // petición con otro nombre, y `position: fixed` deja al mensaje
        // dibujarse encima de la aplicación.
        let con_estilo =
            sanear(r#"<div style="background:url(https://ejemplo.com/p.gif)">x</div>"#);
        assert!(!con_estilo.html.contains("background"));
        assert!(!con_estilo.html.contains("ejemplo.com"));
    }

    /// El formato que sí se quiere ver sobrevive: si no, esto no sirve para
    /// nada y más vale seguir mostrando texto pelado.
    #[test]
    fn el_formato_de_un_correo_normal_sobrevive() {
        let boletin = r#"<h1>Novedades</h1><p><strong>Hola</strong> <em>Ana</em>,</p>
            <ul><li>Uno</li><li>Dos</li></ul>
            <table><tr><td>A</td><td>B</td></tr></table>
            <blockquote>lo que dijo</blockquote>"#;
        let salida = sanear(boletin).html;

        for etiqueta in [
            "<h1>",
            "<strong>",
            "<em>",
            "<ul>",
            "<li>",
            "<table>",
            "<blockquote>",
        ] {
            assert!(salida.contains(etiqueta), "se perdió {etiqueta}: {salida}");
        }
    }

    /// Un enlace normal se queda, y sale con las protecciones puestas.
    #[test]
    fn un_enlace_normal_se_queda_y_no_filtra_de_donde_viene() {
        let salida = sanear(r#"<a href="https://ejemplo.com/x">ir</a>"#).html;
        assert!(
            salida.contains(r#"href="https://ejemplo.com/x""#),
            "{salida}"
        );
        // `noreferrer` porque el `Referer` de un correo es la confirmación de
        // que se abrió.
        assert!(salida.contains("noreferrer"), "{salida}");
        assert!(salida.contains("noopener"), "{salida}");
    }

    /// **Ninguna imagen se pide sola.** Es lo que hace que mostrar el formato no
    /// se convierta en avisarle a quien escribió que abriste el mensaje.
    #[test]
    fn las_imagenes_remotas_no_se_cargan_pero_se_cuentan() {
        let con_pixel = r#"<p>hola</p><img src="https://rastreo.ejemplo/p.gif?id=42" alt="">
            <img src='https://otro.ejemplo/b.png'>"#;
        let salida = sanear(con_pixel);

        assert_eq!(salida.imagenes_bloqueadas, 2);
        // No queda ningún `src` que el navegador vaya a pedir.
        //
        // Se busca **con el espacio adelante**, que no es quisquillosidad:
        // `data-vsk-src="https…` contiene `src="https`, así que la comprobación
        // sin el espacio pasa siempre y no comprueba nada. El espacio es lo que
        // distingue el atributo de verdad del que lo lleva adentro del nombre.
        assert!(!salida.html.contains(" src=\""), "{}", salida.html);
        assert!(!salida.html.contains(" src='"), "{}", salida.html);
        // …pero la dirección se conserva, para poder mostrarla si la persona lo
        // pide sin volver a buscar el mensaje.
        assert!(salida.html.contains(ATRIBUTO_REMOTO), "{}", salida.html);
        assert!(salida.html.contains("rastreo.ejemplo"), "{}", salida.html);
    }

    /// Las que no son remotas no se cuentan ni se guardan: no hay de dónde
    /// cargarlas, y ofrecerlas sería prometer un botón que no puede hacer nada.
    #[test]
    fn lo_que_no_es_remoto_no_cuenta_como_imagen_bloqueada() {
        let salida =
            sanear(r#"<img src="cid:parte1@ejemplo"><img src="data:image/gif;base64,R0lGOD">"#);
        assert_eq!(salida.imagenes_bloqueadas, 0);
        assert!(!salida.html.contains(ATRIBUTO_REMOTO), "{}", salida.html);
        // Y el `src` se va igual: `data:` puede llevar un SVG con script adentro.
        assert!(!salida.html.contains(" src="), "{}", salida.html);
    }

    /// Una relativa tampoco: no hay contra qué resolverla, esto no es una página
    /// servida desde ningún lado.
    #[test]
    fn una_direccion_relativa_no_queda_a_medias() {
        let salida = sanear(r#"<a href="/x">ir</a><img src="/p.gif">"#);
        assert!(!salida.html.contains(r#"href="/x""#), "{}", salida.html);
        assert_eq!(salida.imagenes_bloqueadas, 0);
    }

    /// Un mensaje enorme no hace crecer la memoria de la ventana sin freno, y lo
    /// que se devuelve sigue siendo HTML entero y no uno cortado a la mitad.
    #[test]
    fn un_html_enorme_se_recorta_y_sigue_cerrado() {
        let gigante = format!("<p>{}</p>", "a".repeat(MAX_HTML * 2));
        let salida = sanear(&gigante);

        assert!(salida.recortado);
        assert!(salida.html.len() <= MAX_HTML + 64, "{}", salida.html.len());
        // Cortar y ya dejaría un `<p>` sin cerrar; el saneador lo cierra al
        // serializar de nuevo.
        assert_eq!(
            salida.html.matches("<p").count(),
            salida.html.matches("</p>").count()
        );
    }

    #[test]
    fn un_html_normal_no_se_marca_como_recortado() {
        assert!(!sanear("<p>corto</p>").recortado);
    }

    /// El texto se escapa, no se pierde: un mensaje que habla de HTML se tiene
    /// que poder leer.
    #[test]
    fn el_texto_sobrevive_escapado() {
        let salida = sanear("<p>usá &lt;script&gt; con cuidado</p>").html;
        assert!(salida.contains("script"), "{salida}");
        assert!(!salida.contains("<script"), "{salida}");
    }

    /// Entrada vacía o basura no rompe nada.
    #[test]
    fn lo_que_no_es_html_no_rompe() {
        assert_eq!(sanear("").html, "");
        assert_eq!(sanear("<<<>>>").imagenes_bloqueadas, 0);
        assert!(!sanear("sólo texto").html.is_empty());
    }
}
