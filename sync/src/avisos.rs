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

/// Cuántos mensajes hay en `ahora` que no estaban en `antes`.
///
/// `antes` en `None` es la primera lista de la cuenta: no hay con qué comparar,
/// así que no hay novedad. Es lo que evita el aluvión de carteles al arrancar.
///
/// Se comparan por UID y no por posición: un mensaje borrado desde el teléfono
/// corre la lista entera, y por posición todo parecería nuevo.
pub fn cuantos_nuevos(antes: Option<&[Resumen]>, ahora: &[Resumen]) -> usize {
    let Some(antes) = antes else {
        return 0;
    };

    let conocidos: std::collections::HashSet<u32> = antes.iter().map(|m| m.uid).collect();
    ahora.iter().filter(|m| !conocidos.contains(&m.uid)).count()
}

/// Lo que dice el cartel.
///
/// **Sólo el número.** Ni remitente ni asunto: la pantalla puede estar
/// bloqueada, compartida o proyectada, y quién te escribe es un dato tan
/// personal como lo que te escribió. El issue pide que esto se pueda
/// configurar; mientras no haya dónde guardar esa preferencia, el valor por
/// omisión es el que no muestra nada de nadie.
pub fn texto(cuantos: usize, cuenta: &str) -> (String, String) {
    let titulo = if cuantos == 1 {
        "Llegó 1 mensaje".to_string()
    } else {
        format!("Llegaron {cuantos} mensajes")
    };
    (titulo, cuenta.to_string())
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
        assert_eq!(cuantos_nuevos(None, &ahora), 0);
    }

    #[test]
    fn lo_que_no_estaba_antes_es_nuevo() {
        let antes = vec![resumen(1), resumen(2)];
        let ahora = vec![resumen(3), resumen(1), resumen(2)];
        assert_eq!(cuantos_nuevos(Some(&antes), &ahora), 1);
    }

    /// Se compara por UID y no por posición. Un mensaje borrado desde el
    /// teléfono corre la lista entera: por posición, todo parecería nuevo.
    #[test]
    fn borrar_uno_no_hace_parecer_nuevos_a_los_demas() {
        let antes = vec![resumen(1), resumen(2), resumen(3)];
        let ahora = vec![resumen(2), resumen(3)];
        assert_eq!(cuantos_nuevos(Some(&antes), &ahora), 0);
    }

    #[test]
    fn sin_cambios_no_hay_novedad() {
        let lista = vec![resumen(1), resumen(2)];
        assert_eq!(cuantos_nuevos(Some(&lista), &lista), 0);
        assert_eq!(cuantos_nuevos(Some(&[]), &[]), 0);
    }

    #[test]
    fn varios_juntos_se_cuentan_juntos() {
        let antes = vec![resumen(1)];
        let ahora: Vec<Resumen> = (1..=21).map(resumen).collect();
        assert_eq!(cuantos_nuevos(Some(&antes), &ahora), 20);
    }

    #[test]
    fn el_texto_no_nombra_a_nadie() {
        let (titulo, cuerpo) = texto(3, "ana@ejemplo.com");
        assert!(titulo.contains('3'));
        // La cuenta sí, porque es la de quien está mirando: dice a cuál de sus
        // casillas llegó. Quién escribió y qué escribió, no.
        assert_eq!(cuerpo, "ana@ejemplo.com");
        assert_eq!(texto(1, "x").0, "Llegó 1 mensaje");
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
