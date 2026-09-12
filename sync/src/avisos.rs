//! Avisar que llegó correo cuando la ventana no está abierta.
//!
//! El aviso de correo nuevo llegaba **hasta la ventana y no más allá**: IDLE →
//! señal de D-Bus → la ventana recarga. Con la ventana cerrada —que es lo
//! normal— no pasaba nada, porque no hay nada corriendo que avise.
//!
//! Lo manda el servicio y no la ventana, porque el servicio es lo que sigue
//! corriendo. Y por el bus de sesión, al que ya está conectado: no suma ni una
//! dependencia.
//!
//! # Lo que decide si esto sirve o molesta
//!
//! **Nada al arrancar.** La primera lista después de conectarse trae todo lo
//! que hay sin leer; avisar de eso son veinte carteles de correo de la semana
//! pasada. La regla es que sólo hay novedad cuando ya había una lista con qué
//! comparar, y eso sale solo de cómo está guardado: la primera vez no hay lista
//! anterior, así que no hay nada nuevo.
//!
//! **Uno por cuenta, no uno por mensaje.** Veinte mensajes juntos son un cartel
//! que dice cuántos. El de antes se reemplaza en vez de apilarse.
//!
//! **Y se puede hacer algo con él.** Un aviso que no se puede atender es medio
//! aviso: el cartel lleva un botón «Abrir» que levanta la aplicación de correo.
//! Sólo cuando el servidor de notificaciones dice que soporta botones —hay
//! varios que no—, porque declarar uno que no se va a dibujar no rompe nada pero
//! tampoco sirve, y saberlo es una llamada.

use std::collections::HashMap;

use crate::mensaje::Resumen;
use crate::preferencias::Detalle;

/// El identificador del botón, con el que vuelve la señal.
///
/// No se ve: lo que se lee en pantalla es la etiqueta que va al lado.
const ACCION_ABRIR: &str = "abrir";

/// La entrada del menú de la aplicación de correo, sin el `.desktop`.
///
/// La declara el cartel para que el escritorio sepa de qué aplicación es.
const ENTRADA_DE_ESCRITORIO: &str = "vasak-mail";

/// El programa que abre el botón.
///
/// Que este servicio sepa el nombre del binario de la aplicación de correo es
/// una atadura, y es la más chica de las que había: la alternativa es que el
/// cartel le avise a la aplicación, y la aplicación es justamente la que no está
/// corriendo — de eso se trata el aviso.
///
/// Abrirla dos veces no deja dos ventanas: `vasak-mail` es de instancia única y
/// la segunda le pide a la primera que se muestre.
const PROGRAMA_DE_CORREO: &str = "vasak-mail";

/// El servicio de notificaciones del escritorio.
const SERVICIO: &str = "org.freedesktop.Notifications";
const RUTA: &str = "/org/freedesktop/Notifications";

/// Cuáles de los mensajes de `ahora` no estaban en `antes`.
///
/// `antes` en `None` es la primera lista de la cuenta: no hay con qué comparar,
/// así que no hay novedad. Es lo que evita el aluvión de carteles al arrancar.
///
/// Se comparan por UID y no por posición: un mensaje borrado desde el teléfono
/// corre la lista entera, y por posición todo parecería nuevo.
pub fn los_nuevos<'a>(antes: Option<&[Resumen]>, ahora: &'a [Resumen]) -> Vec<&'a Resumen> {
    let Some(antes) = antes else {
        return Vec::new();
    };

    let conocidos: std::collections::HashSet<u32> = antes.iter().map(|m| m.uid).collect();
    ahora
        .iter()
        .filter(|m| !conocidos.contains(&m.uid))
        .collect()
}

/// Lo que dice el cartel.
///
/// Cuánto muestra lo elige la persona; lo de omisión es lo que menos dice. Ver
/// `preferencias.rs`, y el comentario de [`Detalle::Cantidad`] sobre por qué ese
/// es el valor por omisión.
///
/// # Lo que llega acá lo escribió un desconocido
///
/// El nombre de quien manda y el asunto salen del mensaje. Dos cosas que hay que
/// hacerles antes de que terminen en un cartel del escritorio:
///
/// - **Escapar.** El cuerpo de una notificación admite un subconjunto de marcado
///   —así lo define la especificación, y el servidor puede anunciar la capacidad
///   `body-markup`—, así que un remitente que se llame `<b>Banco</b>` sale en
///   negrita, y uno más creativo puede meter un enlace.
/// - **Acortar.** Un asunto de cinco mil caracteres no lo corta nadie por
///   nosotros: el cartel se estira hasta tapar la pantalla.
pub fn texto(nuevos: &[&Resumen], cuenta: &str, detalle: Detalle) -> (String, String) {
    let titulo = if nuevos.len() == 1 {
        "Llegó 1 mensaje".to_string()
    } else {
        format!("Llegaron {} mensajes", nuevos.len())
    };

    let cuerpo = match detalle {
        Detalle::Cantidad => escapar(cuenta),
        Detalle::Remitente => con_la_cuenta(&lista(nuevos, quien), cuenta),
        Detalle::Asunto => con_la_cuenta(
            &lista(nuevos, |m| {
                let asunto = recortar(m.asunto.trim());
                if asunto.is_empty() {
                    quien(m)
                } else {
                    format!("{}: {}", quien(m), asunto)
                }
            }),
            cuenta,
        ),
    };

    (titulo, cuerpo)
}

/// Quién manda, con la dirección de respaldo si no se firmó con un nombre.
fn quien(mensaje: &Resumen) -> String {
    let nombre = mensaje.de.trim();
    recortar(if nombre.is_empty() {
        mensaje.direccion.trim()
    } else {
        nombre
    })
}

/// Los primeros, y cuántos quedaron afuera.
///
/// Tres y no todos: un cartel con veinte renglones tapa la pantalla, y a partir
/// del cuarto lo único que importa es que hay más.
fn lista(nuevos: &[&Resumen], como: impl Fn(&Resumen) -> String) -> String {
    const CUANTOS: usize = 3;

    let mut renglones: Vec<String> = nuevos.iter().take(CUANTOS).map(|m| como(m)).collect();
    if nuevos.len() > CUANTOS {
        renglones.push(format!("y {} más", nuevos.len() - CUANTOS));
    }
    renglones.join("\n")
}

/// Junta lo que se muestra con a qué cuenta llegó.
///
/// La cuenta va siempre: con varias conectadas, saber que llegó correo sin saber
/// a cuál obliga a abrirlas todas.
fn con_la_cuenta(detalle: &str, cuenta: &str) -> String {
    let cuenta = escapar(cuenta);
    if detalle.is_empty() {
        return cuenta;
    }
    format!("{detalle}\n{cuenta}")
}

/// Tope de lo que se muestra de un nombre o de un asunto.
const MAX_TEXTO: usize = 80;

/// Acorta y escapa, en ese orden.
///
/// Primero se acorta sobre el texto original y después se escapa: al revés, un
/// `&amp;` podía quedar cortado por la mitad y el cartel mostraría `&am`.
fn recortar(texto: &str) -> String {
    let mut corte = MAX_TEXTO.min(texto.len());
    while corte > 0 && !texto.is_char_boundary(corte) {
        corte -= 1;
    }

    if corte < texto.len() {
        format!("{}…", escapar(&texto[..corte]))
    } else {
        escapar(texto)
    }
}

/// Lo que el cuerpo de una notificación interpreta como marcado.
fn escapar(texto: &str) -> String {
    texto
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Los identificadores de los carteles que ya se mostraron, por cuenta.
///
/// Guardarlos es lo que permite reemplazar el anterior en vez de apilar: el
/// servidor de notificaciones devuelve un número al mostrar uno, y pasárselo
/// como `replaces_id` la próxima vez le dice cuál pisar.
#[derive(Default)]
pub struct Carteles(HashMap<String, u32>);

impl Carteles {
    /// El cartel que hay que reemplazar para esta cuenta. `0` es «ninguno», que
    /// es lo que el estándar define como «mostrá uno nuevo».
    pub fn anterior(&self, cuenta: &str) -> u32 {
        self.0.get(cuenta).copied().unwrap_or(0)
    }

    /// Si ese cartel es uno de los nuestros.
    ///
    /// Hace falta porque `ActionInvoked` es una señal del bus y llega **por cada
    /// botón que alguien apriete en cualquier cartel del escritorio**, no sólo
    /// en los propios. Sin comprobar el número, un botón llamado «abrir» en el
    /// aviso de otro programa abriría el correo.
    pub fn es_nuestro(&self, id: u32) -> bool {
        self.0.values().any(|guardado| *guardado == id)
    }

    pub fn recordar(&mut self, cuenta: &str, id: u32) {
        // El servidor devuelve `0` cuando no quiere que lo reemplacen. Guardarlo
        // no rompe nada —`anterior` devolvería `0` igual— pero llenaría el mapa
        // de entradas que no sirven.
        if id != 0 {
            self.0.insert(cuenta.to_string(), id);
        }
    }
}

/// Si el servidor de notificaciones sabe dibujar botones.
///
/// Se pregunta y no se supone: hay servidores que no los soportan —y la
/// especificación lo contempla— y ahí declarar uno es pedir algo que nadie va a
/// ver. Ante la duda, `false`: un cartel sin botón sirve igual; uno con un botón
/// que no se dibuja no le suma nada a nadie.
pub async fn soporta_botones(conexion: &zbus::Connection) -> bool {
    let respuesta = conexion
        .call_method(Some(SERVICIO), RUTA, Some(SERVICIO), "GetCapabilities", &())
        .await;

    let Ok(respuesta) = respuesta else {
        return false;
    };
    respuesta
        .body()
        .deserialize::<Vec<String>>()
        .map(|capacidades| capacidades.iter().any(|c| c == "actions"))
        .unwrap_or(false)
}

/// Abre la aplicación de correo.
///
/// **Se espera al hijo en una tarea aparte.** Un proceso que termina y que nadie
/// recoge queda de zombi hasta que muera su padre, y el padre acá es un servicio
/// que vive toda la sesión: un zombi por cada vez que alguien apretara el botón.
pub fn abrir_el_correo() {
    match tokio::process::Command::new(PROGRAMA_DE_CORREO).spawn() {
        Ok(mut hijo) => {
            tokio::spawn(async move {
                let _ = hijo.wait().await;
            });
        }
        // Que no esté instalado, o que no se pueda ejecutar. No hay a quién
        // decírselo —el cartel ya se fue— así que queda en el diario.
        Err(error) => {
            eprintln!("[avisos] no se pudo abrir {PROGRAMA_DE_CORREO}: {error}");
        }
    }
}

/// Muestra el cartel por el bus de sesión.
///
/// `org.freedesktop.Notifications.Notify` directo y no un cliente aparte: el
/// servicio ya tiene la conexión al bus, así que esto no suma ninguna
/// dependencia al paquete.
///
/// Devuelve el identificador que dio el servidor, para poder reemplazar este
/// cartel la próxima vez. Si algo falla devuelve `None` y no pasa nada más: no
/// poder avisar no puede tumbar la sincronización del correo, que es lo que la
/// persona sí necesita.
pub async fn mostrar(
    conexion: &zbus::Connection,
    reemplaza: u32,
    titulo: &str,
    cuerpo: &str,
    con_boton: bool,
) -> Option<u32> {
    // Los botones van de a pares: primero el identificador con el que vuelve la
    // señal, después lo que se lee en pantalla.
    let acciones: Vec<&str> = if con_boton {
        vec![ACCION_ABRIR, "Abrir"]
    } else {
        Vec::new()
    };

    let mut pistas: HashMap<&str, zbus::zvariant::Value> = HashMap::new();
    // Con qué aplicación es este cartel. Sirve para que el escritorio lo agrupe
    // con la ventana de correo, y para que la configuración de notificaciones
    // por aplicación lo encuentre.
    pistas.insert(
        "desktop-entry",
        zbus::zvariant::Value::from(ENTRADA_DE_ESCRITORIO),
    );

    let respuesta = conexion
        .call_method(
            Some(SERVICIO),
            RUTA,
            Some(SERVICIO),
            "Notify",
            &(
                "VasakOS Correo",
                reemplaza,
                // El icono por nombre y no por ruta: lo resuelve el tema, así
                // que sigue al escritorio en vez de quedar fijo.
                "internet-mail",
                titulo,
                cuerpo,
                acciones,
                pistas,
                // Que lo decida el servidor de notificaciones, que es quien
                // sabe si hay un «no molestar» puesto.
                -1i32,
            ),
        )
        .await
        .ok()?;

    respuesta.body().deserialize::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resumen(uid: u32) -> Resumen {
        Resumen {
            uid,
            ..Default::default()
        }
    }

    /// La regla que evita el aluvión: la primera lista de una cuenta no es
    /// novedad, es lo que ya estaba.
    #[test]
    fn la_primera_lista_no_avisa_nada() {
        let ahora = vec![resumen(1), resumen(2), resumen(3)];
        assert_eq!(los_nuevos(None, &ahora).len(), 0);
    }

    #[test]
    fn lo_que_no_estaba_antes_es_nuevo() {
        let antes = vec![resumen(1), resumen(2)];
        let ahora = vec![resumen(3), resumen(1), resumen(2)];
        assert_eq!(los_nuevos(Some(&antes), &ahora).len(), 1);
    }

    /// Se compara por UID y no por posición. Un mensaje borrado desde el
    /// teléfono corre la lista entera: por posición, todo parecería nuevo.
    #[test]
    fn borrar_uno_no_hace_parecer_nuevos_a_los_demas() {
        let antes = vec![resumen(1), resumen(2), resumen(3)];
        let ahora = vec![resumen(2), resumen(3)];
        assert_eq!(los_nuevos(Some(&antes), &ahora).len(), 0);
    }

    #[test]
    fn sin_cambios_no_hay_novedad() {
        let lista = vec![resumen(1), resumen(2)];
        assert_eq!(los_nuevos(Some(&lista), &lista).len(), 0);
        assert_eq!(los_nuevos(Some(&[]), &[]).len(), 0);
    }

    #[test]
    fn varios_juntos_se_cuentan_juntos() {
        let antes = vec![resumen(1)];
        let ahora: Vec<Resumen> = (1..=21).map(resumen).collect();
        assert_eq!(los_nuevos(Some(&antes), &ahora).len(), 20);
    }

    fn de(uid: u32, quien: &str, asunto: &str) -> Resumen {
        Resumen {
            uid,
            de: quien.to_string(),
            asunto: asunto.to_string(),
            ..Default::default()
        }
    }

    /// **Lo de omisión no nombra a nadie**, que es lo que pasaba antes de que
    /// esto se pudiera configurar.
    #[test]
    fn por_omision_el_texto_no_nombra_a_nadie() {
        let nuevos = [de(1, "Ana", "Factura"), de(2, "Juan", "Hola")];
        let lista: Vec<&Resumen> = nuevos.iter().collect();

        let (titulo, cuerpo) = texto(&lista, "ana@ejemplo.com", Detalle::Cantidad);
        assert!(titulo.contains('2'));
        // La cuenta sí, porque es la de quien está mirando: dice a cuál de sus
        // casillas llegó. Quién escribió y qué escribió, no.
        assert_eq!(cuerpo, "ana@ejemplo.com");
        assert!(!cuerpo.contains("Ana"));
        assert!(!cuerpo.contains("Factura"));

        let uno = [de(1, "Ana", "x")];
        let uno: Vec<&Resumen> = uno.iter().collect();
        assert_eq!(texto(&uno, "x", Detalle::Cantidad).0, "Llegó 1 mensaje");
    }

    #[test]
    fn con_remitente_dice_de_quien_y_no_de_que() {
        let nuevos = [de(1, "Ana", "Factura secreta")];
        let lista: Vec<&Resumen> = nuevos.iter().collect();

        let (_, cuerpo) = texto(&lista, "ana@ejemplo.com", Detalle::Remitente);
        assert!(cuerpo.contains("Ana"), "{cuerpo}");
        assert!(!cuerpo.contains("Factura"), "{cuerpo}");
        // La cuenta va siempre: con varias conectadas, saber que llegó correo
        // sin saber a cuál obliga a abrirlas todas.
        assert!(cuerpo.contains("ana@ejemplo.com"), "{cuerpo}");
    }

    #[test]
    fn con_asunto_dice_las_dos_cosas() {
        let nuevos = [de(1, "Ana", "Factura")];
        let lista: Vec<&Resumen> = nuevos.iter().collect();

        let (_, cuerpo) = texto(&lista, "x", Detalle::Asunto);
        assert!(cuerpo.contains("Ana"), "{cuerpo}");
        assert!(cuerpo.contains("Factura"), "{cuerpo}");
    }

    /// Tres y el resto contado: un cartel con veinte renglones tapa la pantalla.
    #[test]
    fn con_muchos_se_nombran_los_primeros_y_se_cuenta_el_resto() {
        let nuevos: Vec<Resumen> = (1..=10).map(|i| de(i, &format!("P{i}"), "x")).collect();
        let lista: Vec<&Resumen> = nuevos.iter().collect();

        let (_, cuerpo) = texto(&lista, "x", Detalle::Remitente);
        assert!(cuerpo.contains("P1") && cuerpo.contains("P3"), "{cuerpo}");
        assert!(!cuerpo.contains("P4"), "{cuerpo}");
        assert!(cuerpo.contains("y 7 más"), "{cuerpo}");
    }

    /// **El nombre y el asunto los escribió un desconocido.** El cuerpo de una
    /// notificación admite un subconjunto de marcado, así que un remitente que
    /// se llame `<b>Banco</b>` sale en negrita si no se escapa.
    #[test]
    fn lo_que_escribio_un_desconocido_no_se_interpreta() {
        let nuevos = [de(1, "<b>Banco</b>", "<a href='x'>clic</a> & más")];
        let lista: Vec<&Resumen> = nuevos.iter().collect();

        let (_, cuerpo) = texto(&lista, "x", Detalle::Asunto);
        assert!(!cuerpo.contains("<b>"), "{cuerpo}");
        assert!(!cuerpo.contains("<a "), "{cuerpo}");
        assert!(cuerpo.contains("&lt;b&gt;"), "{cuerpo}");
        assert!(cuerpo.contains("&amp;"), "{cuerpo}");
    }

    /// Y la cuenta también se escapa: sale del servidor de cuentas, pero el
    /// nombre para mostrar lo puso alguien.
    #[test]
    fn la_cuenta_tambien_se_escapa() {
        let nuevos = [de(1, "Ana", "x")];
        let lista: Vec<&Resumen> = nuevos.iter().collect();

        let (_, cuerpo) = texto(&lista, "<i>casa</i>", Detalle::Cantidad);
        assert!(!cuerpo.contains("<i>"), "{cuerpo}");
    }

    /// Un asunto de cinco mil caracteres estira el cartel hasta tapar la
    /// pantalla: nadie lo corta por nosotros.
    #[test]
    fn un_asunto_enorme_se_corta() {
        let largo = "a".repeat(5000);
        let nuevos = [de(1, "Ana", &largo)];
        let lista: Vec<&Resumen> = nuevos.iter().collect();

        let (_, cuerpo) = texto(&lista, "x", Detalle::Asunto);
        assert!(cuerpo.len() < 200, "quedó de {}", cuerpo.len());
        assert!(cuerpo.contains('…'), "{cuerpo}");
    }

    /// Quien no se firmó con un nombre se muestra por su dirección: «llegó un
    /// mensaje de nadie» no le sirve a nadie.
    #[test]
    fn sin_nombre_se_muestra_la_direccion() {
        let mut sin_nombre = de(1, "", "x");
        sin_nombre.direccion = "quien@ejemplo.com".to_string();
        let nuevos = [sin_nombre];
        let lista: Vec<&Resumen> = nuevos.iter().collect();

        let (_, cuerpo) = texto(&lista, "x", Detalle::Remitente);
        assert!(cuerpo.contains("quien@ejemplo.com"), "{cuerpo}");
    }

    /// El botón vuelve por el bus con el número del cartel, y hay que saber si
    /// ese cartel es nuestro.
    ///
    /// `ActionInvoked` llega por cada botón que alguien apriete en **cualquier**
    /// cartel del escritorio. Sin esta comprobación, un botón llamado «abrir» en
    /// el aviso de otro programa abriría el correo.
    #[test]
    fn solo_se_atienden_los_carteles_propios() {
        let mut carteles = Carteles::default();
        assert!(
            !carteles.es_nuestro(42),
            "sin nada mostrado, ninguno es nuestro"
        );

        carteles.recordar("una", 42);
        assert!(carteles.es_nuestro(42));
        assert!(!carteles.es_nuestro(43));

        // Con dos cuentas, los dos.
        carteles.recordar("otra", 43);
        assert!(carteles.es_nuestro(42));
        assert!(carteles.es_nuestro(43));
    }

    /// Un cartel reemplazado deja de ser el vigente de esa cuenta.
    #[test]
    fn el_cartel_viejo_de_una_cuenta_deja_de_ser_nuestro() {
        let mut carteles = Carteles::default();
        carteles.recordar("una", 42);
        carteles.recordar("una", 55);

        assert!(carteles.es_nuestro(55));
        // El 42 ya no existe: lo pisó el 55 al reemplazarlo.
        assert!(!carteles.es_nuestro(42));
    }

    /// El cero no cuenta.
    ///
    /// Es lo que devuelve un servidor que no quiere que le reemplacen el cartel,
    /// y además es el número con el que se pide uno nuevo. Si contara como
    /// nuestro, cualquier señal con id cero abriría el correo.
    #[test]
    fn el_cero_no_es_el_cartel_de_nadie() {
        let mut carteles = Carteles::default();
        carteles.recordar("una", 0);
        assert!(!carteles.es_nuestro(0));
    }

    #[test]
    fn el_cartel_anterior_se_reemplaza() {
        let mut carteles = Carteles::default();
        // Sin nada guardado, `0`: el estándar lo define como «mostrá uno nuevo».
        assert_eq!(carteles.anterior("uno"), 0);

        carteles.recordar("uno", 42);
        assert_eq!(carteles.anterior("uno"), 42);
        // Y cada cuenta tiene el suyo: dos cuentas no se pisan el cartel.
        assert_eq!(carteles.anterior("otra"), 0);

        // Un `0` del servidor quiere decir «no me lo reemplaces»; guardarlo
        // llenaría el mapa de entradas que no sirven.
        carteles.recordar("dos", 0);
        assert_eq!(carteles.anterior("dos"), 0);
    }
}
