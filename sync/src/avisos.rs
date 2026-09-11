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

use std::collections::HashMap;

use crate::mensaje::Resumen;

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

    pub fn recordar(&mut self, cuenta: &str, id: u32) {
        // El servidor devuelve `0` cuando no quiere que lo reemplacen. Guardarlo
        // no rompe nada —`anterior` devolvería `0` igual— pero llenaría el mapa
        // de entradas que no sirven.
        if id != 0 {
            self.0.insert(cuenta.to_string(), id);
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
) -> Option<u32> {
    let sin_acciones: Vec<&str> = Vec::new();
    let pistas: HashMap<&str, zbus::zvariant::Value> = HashMap::new();

    let respuesta = conexion
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "VasakOS Correo",
                reemplaza,
                // El icono por nombre y no por ruta: lo resuelve el tema, así
                // que sigue al escritorio en vez de quedar fijo.
                "internet-mail",
                titulo,
                cuerpo,
                sin_acciones,
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
