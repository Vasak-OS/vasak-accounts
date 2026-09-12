//! Los archivos pegados a un mensaje: cuáles hay y cómo se llaman.
//!
//! Hasta ahora se **detectaban** y no se podían abrir: la ventana recibía un
//! booleano —«este mensaje trae algo»— y nada más. Está escrito así a propósito,
//! porque alguien que lee un correo sin enterarse de que traía un archivo pierde
//! el archivo; pero enterarse y no poder abrirlo tampoco alcanza.
//!
//! Acá está lo que se puede resolver mirando el mensaje que ya se trajo: qué
//! partes son adjuntos, cómo se llaman, de qué tipo son y **qué número de parte
//! tienen** en el árbol MIME, que es lo que después hace falta para pedirle al
//! servidor esa parte sola.
//!
//! # El nombre del archivo lo eligió un desconocido
//!
//! Es la regla que ordena todo este módulo. El nombre viene dentro de un correo
//! que mandó cualquiera, así que se trata como hostil: se le saca todo separador
//! de ruta, se rechazan `..`, los vacíos, los de control y los nombres
//! reservados. Y **nunca** se usa para decidir dónde escribir: es una sugerencia
//! que se sanea, y el destino lo elige la persona.

use crate::mensaje::{
    a_texto, como_latin1, decodificar_palabras, es_adjunto, partir, tipo_de, Cabeceras,
    MAX_PROFUNDIDAD,
};

/// Un archivo pegado a un mensaje.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Adjunto {
    /// El número de parte en el árbol MIME —`2`, `1.3`—, como lo numera
    /// RFC 3501 §6.4.5. Es lo que se le manda al servidor para pedir esta parte
    /// sola en vez del mensaje entero.
    pub parte: String,
    /// Un nombre ya saneado, listo para proponer. Nunca vacío.
    pub nombre: String,
    /// El tipo declarado, en minúsculas. `application/octet-stream` si no dijo.
    pub tipo: String,
}

/// Un nombre que se puede proponer sin miedo.
///
/// Lo que entra es texto de un desconocido. Lo que sale se puede mostrar en un
/// diálogo y usar como nombre por omisión — **no** como ruta.
///
/// Devuelve `None` cuando no queda nada utilizable, y quien llama pone uno
/// genérico. Inventar acá un «adjunto.bin» escondería que el mensaje venía raro.
pub fn nombre_seguro(sugerido: &str) -> Option<String> {
    // Sólo la última parte: un `../../etc/passwd` o un `C:\algo\x.txt` se quedan
    // en `passwd` y `x.txt`. Se cortan las tres formas porque el nombre pudo
    // escribirlo cualquier sistema.
    let hoja = sugerido
        .rsplit(['/', '\\', ':'])
        .next()
        .unwrap_or(sugerido)
        .trim();

    // Los de control incluyen el salto de línea y el nulo. Un nombre con un
    // salto adentro parte cualquier cosa que después lo escriba en una línea.
    let limpio: String = hoja.chars().filter(|c| !c.is_control()).collect();
    let limpio = limpio.trim().trim_matches('.').trim();

    if limpio.is_empty() {
        return None;
    }

    // Los reservados de Windows. No es nuestro sistema, pero el archivo va a
    // terminar en un pendrive o en un adjunto de vuelta, y un `CON.txt` rompe
    // del otro lado.
    const RESERVADOS: [&str; 22] = [
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
        "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    let base = limpio
        .split('.')
        .next()
        .unwrap_or(limpio)
        .to_ascii_lowercase();
    if RESERVADOS.contains(&base.as_str()) {
        return None;
    }

    // Un nombre larguísimo no es un ataque, pero no entra en ningún sistema de
    // archivos. Se recorta por caracteres y no por bytes para no partir uno.
    const MAXIMO: usize = 200;
    if limpio.chars().count() > MAXIMO {
        return Some(limpio.chars().take(MAXIMO).collect());
    }
    Some(limpio.to_string())
}

/// Parte una lista de parámetros de cabecera respetando las comillas.
///
/// `filename="a;b.txt"` es **un** parámetro, no dos. Partir por `;` a secas
/// dejaría el nombre cortado a la mitad.
fn parametros(valor: &str) -> Vec<(String, String)> {
    let mut salida = Vec::new();
    let mut actual = String::new();
    let mut en_comillas = false;

    for c in valor.chars() {
        match c {
            '"' => {
                en_comillas = !en_comillas;
                actual.push(c);
            }
            ';' if !en_comillas => {
                salida.push(std::mem::take(&mut actual));
            }
            _ => actual.push(c),
        }
    }
    salida.push(actual);

    salida
        .into_iter()
        .skip(1) // El primero es el valor, no un parámetro.
        .filter_map(|trozo| {
            let (nombre, valor) = trozo.split_once('=')?;
            Some((
                nombre.trim().to_ascii_lowercase(),
                sin_comillas(valor.trim()).to_string(),
            ))
        })
        .collect()
}

fn sin_comillas(valor: &str) -> &str {
    valor
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(valor)
}

/// Deshace el `%XX` de un valor extendido y lo pasa a texto con su juego.
fn de_porcentajes(valor: &str, juego: &str) -> String {
    let bytes = valor.as_bytes();
    let mut crudo = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&valor[i + 1..i + 3], 16) {
                crudo.push(b);
                i += 3;
                continue;
            }
        }
        crudo.push(bytes[i]);
        i += 1;
    }
    a_texto(&crudo, juego)
}

/// `utf-8''%C3%A1rbol.pdf` → `árbol.pdf`.
///
/// El juego y el idioma van adelante, separados por comillas simples. Si no
/// están, el valor es texto tal cual: hay clientes que mandan el `*` sin la
/// parte del juego.
fn extendido(valor: &str) -> String {
    let mut trozos = valor.splitn(3, '\'');
    match (trozos.next(), trozos.next(), trozos.next()) {
        (Some(juego), Some(_idioma), Some(texto)) => {
            let juego = if juego.is_empty() { "utf-8" } else { juego };
            de_porcentajes(texto, juego)
        }
        _ => de_porcentajes(valor, "utf-8"),
    }
}

/// El valor de un parámetro, en cualquiera de las tres formas que existen.
///
/// - `filename="informe.pdf"` — el caso corriente.
/// - `filename*=utf-8''%C3%A1rbol.pdf` — RFC 2231, para lo que no es ASCII.
/// - `filename*0*=…; filename*1*=…` — RFC 2231 partido, para los largos.
///
/// Y el nombre puede venir además en RFC 2047 (`=?utf-8?B?…?=`), que es lo que
/// mandan los clientes viejos donde el estándar pedía la otra forma.
pub fn parametro(valor: &str, nombre: &str) -> Option<String> {
    let todos = parametros(valor);
    let busca = |clave: &str| {
        todos
            .iter()
            .find(|(n, _)| n == clave)
            .map(|(_, v)| v.clone())
    };

    // La forma extendida sin partir gana: si están las dos, la otra es la copia
    // en ASCII que dejan algunos clientes para los que no entienden ésta.
    if let Some(v) = busca(&format!("{nombre}*")) {
        return Some(extendido(&v));
    }

    // Partido en segmentos numerados. Se juntan en orden hasta el primer hueco:
    // seguir después de un segmento que falta pegaría trozos que no van juntos.
    let mut juntado = String::new();
    let mut juego = String::new();
    for i in 0.. {
        if let Some(v) = busca(&format!("{nombre}*{i}*")) {
            if i == 0 {
                let mut trozos = v.splitn(3, '\'');
                if let (Some(j), Some(_), Some(texto)) =
                    (trozos.next(), trozos.next(), trozos.next())
                {
                    juego = if j.is_empty() {
                        "utf-8".into()
                    } else {
                        j.to_string()
                    };
                    juntado.push_str(&de_porcentajes(texto, &juego));
                    continue;
                }
            }
            juntado.push_str(&de_porcentajes(
                &v,
                if juego.is_empty() { "utf-8" } else { &juego },
            ));
        } else if let Some(v) = busca(&format!("{nombre}*{i}")) {
            juntado.push_str(&v);
        } else {
            break;
        }
    }
    if !juntado.is_empty() {
        return Some(juntado);
    }

    busca(nombre).map(|v| decodificar_palabras(&v))
}

/// Los adjuntos de un mensaje, con su número de parte.
pub fn listar(crudo: &[u8]) -> Vec<Adjunto> {
    let vista = como_latin1(crudo);
    let (cabeceras, cuerpo) = partir(&vista);
    let mut encontrados = Vec::new();
    recorrer(&cabeceras, cuerpo, "", 0, &mut encontrados);
    encontrados
}

/// Baja por el árbol numerando las partes como RFC 3501 §6.4.5.
///
/// En un `multipart`, las partes son `1`, `2`, `3`…; una anidada dentro de la
/// primera es `1.1`. El mensaje entero —cuando no es `multipart`— es la parte
/// `1`, que es el caso de un correo que es un solo archivo.
fn recorrer(
    cabeceras: &Cabeceras,
    cuerpo: &str,
    prefijo: &str,
    profundidad: usize,
    salida: &mut Vec<Adjunto>,
) {
    if profundidad > MAX_PROFUNDIDAD {
        return;
    }

    let tipo = cabeceras
        .valor("content-type")
        .map(tipo_de)
        .unwrap_or_default();

    if let Some(frontera) = &tipo.frontera {
        for (i, parte) in crate::mensaje::partes_de(cuerpo, frontera)
            .into_iter()
            .enumerate()
        {
            let numero = if prefijo.is_empty() {
                (i + 1).to_string()
            } else {
                format!("{prefijo}.{}", i + 1)
            };
            let (suyas, su_cuerpo) = partir(parte);
            recorrer(&suyas, su_cuerpo, &numero, profundidad + 1, salida);
        }
        return;
    }

    if !es_adjunto(cabeceras) {
        return;
    }

    // El nombre está en el `Content-Disposition`; si no, en el `Content-Type`,
    // que es donde lo ponen los clientes viejos.
    let sugerido = cabeceras
        .valor("content-disposition")
        .and_then(|d| parametro(d, "filename"))
        .or_else(|| {
            cabeceras
                .valor("content-type")
                .and_then(|t| parametro(t, "name"))
        })
        .unwrap_or_default();

    salida.push(Adjunto {
        // Un mensaje que es un adjunto y nada más es la parte `1`.
        parte: if prefijo.is_empty() {
            "1".to_string()
        } else {
            prefijo.to_string()
        },
        // Sin nombre utilizable se pone uno genérico **con el número de parte**,
        // para que dos adjuntos sin nombre no se llamen igual.
        nombre: nombre_seguro(&sugerido).unwrap_or_else(|| {
            let cual = if prefijo.is_empty() { "1" } else { prefijo };
            format!("adjunto-{cual}.bin")
        }),
        tipo: if tipo.medio == "text/plain" && cabeceras.valor("content-type").is_none() {
            // El `text/plain` por omisión es una suposición del estándar para un
            // mensaje sin `Content-Type`; para un adjunto es casi seguro falsa.
            "application/octet-stream".to_string()
        } else {
            tipo.medio
        },
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La regla que ordena el módulo: el nombre lo eligió un desconocido.
    #[test]
    fn un_nombre_no_puede_llevar_a_otro_lado() {
        // Una ruta relativa se queda en su última parte.
        assert_eq!(nombre_seguro("../../etc/passwd").unwrap(), "passwd");
        assert_eq!(nombre_seguro("/etc/shadow").unwrap(), "shadow");
        // Las tres formas de separar, porque el nombre lo pudo escribir
        // cualquier sistema.
        assert_eq!(
            nombre_seguro(r"C:\Windows\system32\x.dll").unwrap(),
            "x.dll"
        );
        assert_eq!(nombre_seguro("carpeta/informe.pdf").unwrap(), "informe.pdf");
    }

    #[test]
    fn lo_que_no_deja_nada_utilizable_se_rechaza() {
        // Devolver `None` y no inventar un nombre: quien llama pone uno
        // genérico y queda claro que el mensaje venía raro.
        for malo in ["", "   ", "..", "../..", "/", "...", "\\", "./"] {
            assert!(nombre_seguro(malo).is_none(), "{malo:?}");
        }
    }

    #[test]
    fn los_caracteres_de_control_se_van() {
        // Un salto de línea adentro parte cualquier cosa que después lo escriba.
        assert_eq!(nombre_seguro("informe\n.pdf").unwrap(), "informe.pdf");
        assert_eq!(nombre_seguro("a\u{0}b.txt").unwrap(), "ab.txt");
        assert!(nombre_seguro("\u{7}").is_none());
    }

    /// No es nuestro sistema, pero el archivo termina en un pendrive o en un
    /// adjunto de vuelta, y un `CON.txt` rompe del otro lado.
    #[test]
    fn los_nombres_reservados_se_rechazan() {
        for reservado in ["CON", "con.txt", "PRN.pdf", "nul", "COM1.doc", "lpt9"] {
            assert!(nombre_seguro(reservado).is_none(), "{reservado}");
        }
        // Y uno que sólo empieza igual, no.
        assert_eq!(nombre_seguro("console.log").unwrap(), "console.log");
        assert_eq!(nombre_seguro("contrato.pdf").unwrap(), "contrato.pdf");
    }

    #[test]
    fn un_nombre_larguisimo_se_recorta_sin_partir_un_caracter() {
        let largo = "á".repeat(500) + ".pdf";
        let salida = nombre_seguro(&largo).unwrap();
        assert_eq!(salida.chars().count(), 200);
        // Y sigue siendo texto válido: recortar por bytes partiría una «á».
        assert!(salida.chars().all(|c| c == 'á'));
    }

    #[test]
    fn el_caso_corriente_pasa_entero() {
        assert_eq!(
            parametro(r#"attachment; filename="informe final.pdf""#, "filename").unwrap(),
            "informe final.pdf"
        );
        // Y el punto y coma dentro de las comillas no parte el nombre.
        assert_eq!(
            parametro(r#"attachment; filename="a;b.txt""#, "filename").unwrap(),
            "a;b.txt"
        );
    }

    /// RFC 2231. Es el que el issue marcaba como no implementado.
    #[test]
    fn un_nombre_con_acentos_llega_entero() {
        assert_eq!(
            parametro("attachment; filename*=utf-8''%C3%A1rbol.pdf", "filename").unwrap(),
            "árbol.pdf"
        );
        // Sin la parte del juego: hay clientes que mandan el `*` pelado.
        assert_eq!(
            parametro("attachment; filename*=%C3%A1rbol.pdf", "filename").unwrap(),
            "árbol.pdf"
        );
        // Y en otro juego que no sea UTF-8.
        assert_eq!(
            parametro("attachment; filename*=iso-8859-1''%E1rbol.pdf", "filename").unwrap(),
            "árbol.pdf"
        );
    }

    #[test]
    fn un_nombre_partido_en_segmentos_se_junta_en_orden() {
        let cabecera = "attachment; filename*0*=utf-8''informe%20; \
                        filename*1*=muy%20; filename*2*=largo.pdf";
        assert_eq!(
            parametro(cabecera, "filename").unwrap(),
            "informe muy largo.pdf"
        );

        // Un segmento que falta corta el juntado: seguir después de un hueco
        // pegaría trozos que no van juntos.
        let con_hueco = "attachment; filename*0*=utf-8''a; filename*2*=c";
        assert_eq!(parametro(con_hueco, "filename").unwrap(), "a");
    }

    /// RFC 2047, que es lo que mandan los clientes viejos donde el estándar
    /// pedía la otra forma.
    #[test]
    fn un_nombre_en_palabras_codificadas_se_decodifica() {
        let cabecera = "attachment; filename=\"=?utf-8?B?w6FyYm9sLnBkZg==?=\"";
        assert_eq!(parametro(cabecera, "filename").unwrap(), "árbol.pdf");
    }

    /// Si están las dos formas, gana la extendida: la otra es la copia en ASCII
    /// que dejan algunos clientes para los que no la entienden.
    #[test]
    fn la_forma_extendida_le_gana_a_la_simple() {
        let cabecera = "attachment; filename=\"arbol.pdf\"; filename*=utf-8''%C3%A1rbol.pdf";
        assert_eq!(parametro(cabecera, "filename").unwrap(), "árbol.pdf");
    }

    #[test]
    fn un_parametro_que_no_esta_no_se_inventa() {
        assert!(parametro("attachment", "filename").is_none());
        assert!(parametro("", "filename").is_none());
        assert!(parametro("inline; size=42", "filename").is_none());
    }

    const CON_DOS: &str = "Content-Type: multipart/mixed; boundary=xyz\r\n\
\r\n\
--xyz\r\n\
Content-Type: text/plain\r\n\
\r\n\
Hola\r\n\
--xyz\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"informe.pdf\"\r\n\
\r\n\
datos\r\n\
--xyz\r\n\
Content-Type: image/png\r\n\
Content-Disposition: attachment; filename=\"foto.png\"\r\n\
\r\n\
datos\r\n\
--xyz--\r\n";

    #[test]
    fn las_partes_se_numeran_como_las_pide_el_servidor() {
        let lista = listar(CON_DOS.as_bytes());
        assert_eq!(lista.len(), 2);
        // La primera parte es el texto; los adjuntos son la 2 y la 3.
        assert_eq!(lista[0].parte, "2");
        assert_eq!(lista[0].nombre, "informe.pdf");
        assert_eq!(lista[0].tipo, "application/pdf");
        assert_eq!(lista[1].parte, "3");
        assert_eq!(lista[1].nombre, "foto.png");
    }

    #[test]
    fn una_parte_anidada_lleva_el_numero_de_su_padre() {
        let crudo = "Content-Type: multipart/mixed; boundary=a\r\n\r\n\
--a\r\n\
Content-Type: multipart/alternative; boundary=b\r\n\r\n\
--b\r\n\
Content-Type: text/plain\r\n\r\n\
Hola\r\n\
--b\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"x.pdf\"\r\n\r\n\
datos\r\n\
--b--\r\n\
--a--\r\n";
        let lista = listar(crudo.as_bytes());
        assert_eq!(lista.len(), 1);
        assert_eq!(lista[0].parte, "1.2");
    }

    #[test]
    fn un_mensaje_sin_adjuntos_no_devuelve_ninguno() {
        let crudo = "Content-Type: text/plain\r\n\r\nHola\r\n";
        assert!(listar(crudo.as_bytes()).is_empty());
        assert!(listar(b"").is_empty());
    }

    /// Dos adjuntos sin nombre no se pueden llamar igual: quien los guarde
    /// pisaría el primero con el segundo sin enterarse.
    #[test]
    fn dos_adjuntos_sin_nombre_no_chocan() {
        let crudo = "Content-Type: multipart/mixed; boundary=z\r\n\r\n\
--z\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment\r\n\r\n\
uno\r\n\
--z\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment\r\n\r\n\
dos\r\n\
--z--\r\n";
        let lista = listar(crudo.as_bytes());
        assert_eq!(lista.len(), 2);
        assert_ne!(lista[0].nombre, lista[1].nombre);
    }

    /// El nombre del adjunto pasa por el saneador igual que cualquier otro: es
    /// el camino por el que llegaría un `../`.
    #[test]
    fn un_adjunto_con_nombre_hostil_llega_saneado() {
        let crudo = "Content-Type: multipart/mixed; boundary=z\r\n\r\n\
--z\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"../../../etc/passwd\"\r\n\r\n\
datos\r\n\
--z--\r\n";
        let lista = listar(crudo.as_bytes());
        assert_eq!(lista[0].nombre, "passwd");
        assert!(!lista[0].nombre.contains('/'));
    }

    /// El nombre en el `Content-Type` es donde lo ponen los clientes viejos.
    #[test]
    fn si_no_hay_filename_se_mira_el_name() {
        let crudo = "Content-Type: multipart/mixed; boundary=z\r\n\r\n\
--z\r\n\
Content-Type: application/pdf; name=\"viejo.pdf\"\r\n\
Content-Disposition: attachment\r\n\r\n\
datos\r\n\
--z--\r\n";
        assert_eq!(listar(crudo.as_bytes())[0].nombre, "viejo.pdf");
    }
}
