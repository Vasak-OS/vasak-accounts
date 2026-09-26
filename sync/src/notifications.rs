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

use crate::message::MessageSummary;
use crate::preferences::NotificationDetail;

/// El identificador del botón, con el que vuelve la señal.
///
/// No se ve: lo que se lee en pantalla es la etiqueta que va al lado.
const OPEN_ACTION: &str = "abrir";

/// La entrada del menú de la aplicación de correo, sin el `.desktop`.
///
/// La declara el cartel para que el escritorio sepa de qué aplicación es.
const DESKTOP_ENTRY: &str = "vasak-mail";

/// El programa que abre el botón.
///
/// Que este servicio sepa el nombre del binario de la aplicación de correo es
/// una atadura, y es la más chica de las que había: la alternativa es que el
/// cartel le avise a la aplicación, y la aplicación es justamente la que no está
/// corriendo — de eso se trata el aviso.
///
/// Abrirla dos veces no deja dos ventanas: `vasak-mail` es de instancia única y
/// la segunda le pide a la primera que se muestre.
const MAIL_PROGRAM: &str = "vasak-mail";

/// El servicio de notificaciones del escritorio.
const SERVICE: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";

/// Cuántos mensajes hay en `now` que no estaban en `before`.
///
/// `before` en `None` es la primera lista de la cuenta: no hay con qué comparar,
/// así que no hay novedad. Es lo que evita el aluvión de carteles al arrancar.
///
/// Se comparan por UID y no por posición: un mensaje borrado desde el teléfono
/// corre la lista entera, y por posición todo parecería nuevo.
pub fn just_arrived(
    before: Option<&[MessageSummary]>,
    now: &[MessageSummary],
) -> Vec<MessageSummary> {
    let Some(before) = before else {
        return Vec::new();
    };

    let known: std::collections::HashSet<u32> = before.iter().map(|m| m.uid).collect();
    now.iter()
        .filter(|m| !known.contains(&m.uid))
        .cloned()
        .collect()
}

/// Cuántos son nuevos. Lo mismo de arriba cuando sólo hace falta el número.
#[cfg(test)]
pub fn count_new(before: Option<&[MessageSummary]>, now: &[MessageSummary]) -> usize {
    just_arrived(before, now).len()
}

/// Lo que dice el cartel.
///
/// **Sólo el número.** Ni remitente ni asunto: la pantalla puede estar
/// bloqueada, compartida o proyectada, y quién te escribe es un dato tan
/// personal como lo que te escribió. El issue pide que esto se pueda
/// configurar; mientras no haya dónde guardar esa preferencia, el valor por
/// omisión es el que no muestra nada de nadie.
pub fn notification_text(
    new_messages: &[MessageSummary],
    account: &str,
    detail: NotificationDetail,
) -> (String, String) {
    let count = new_messages.len();
    let title = if count == 1 {
        "Llegó 1 mensaje".to_string()
    } else {
        format!("Llegaron {count} mensajes")
    };

    // Con uno solo se puede decir de quién y de qué. Con varios no: el cartel
    // diría el de uno y callaría los otros, que es peor que no decir ninguno.
    let single = (count == 1).then(|| new_messages.first()).flatten();

    let body = match (detail, single) {
        (NotificationDetail::Sender, Some(m)) => {
            with_account(&for_notification(&sender_name(m)), account)
        }
        (NotificationDetail::SenderAndSubject, Some(m)) => {
            let subject = m.subject.trim();
            if subject.is_empty() {
                with_account(&for_notification(&sender_name(m)), account)
            } else {
                // Cada uno por su lado y no el texto ya junto: así el tope de
                // largo vale para cada cosa, y un asunto enorme no se come el
                // nombre de quien lo mandó.
                with_account(
                    &format!(
                        "{}: {}",
                        for_notification(&sender_name(m)),
                        for_notification(subject)
                    ),
                    account,
                )
            }
        }
        // Lo callado: cuántos y a qué casilla llegaron, nada de quién ni de qué.
        _ => escape_markup(account),
    };

    (title, body)
}

/// Cómo se nombra a quien lo mandó.
///
/// El nombre con el que se firma si lo hay, y la dirección si no. **No los dos**:
/// en la lista van juntos porque ahí el engaño de firmarse «soporte@banco.com»
/// desde otra dirección se ve, y en un cartel de dos renglones no entra el
/// contraste que lo hace visible.
fn sender_name(message: &MessageSummary) -> String {
    let name = message.from.trim();
    if name.is_empty() {
        message.address.trim().to_string()
    } else {
        name.to_string()
    }
}

/// Tope de lo que se muestra de un nombre o de un asunto.
///
/// Ochenta caracteres entran en dos renglones de cartel. Un asunto de cinco mil
/// —que no es raro en una lista de correo, y que en uno hostil es deliberado—
/// estira el cartel hasta tapar la pantalla: nadie lo corta por nosotros.
const MAX_TEXT: usize = 80;

/// Deja un texto del mensaje en condiciones de ir a un cartel.
///
/// # Lo que llega acá lo escribió un desconocido
///
/// El nombre con el que alguien se firma y el asunto que le puso salen del
/// mensaje, y el mensaje lo manda cualquiera que sepa la dirección de la
/// persona.
///
/// **Se escapa** porque el cuerpo de una notificación admite un subconjunto de
/// marcado: la especificación lo define y el servidor lo anuncia como
/// `body-markup`. Sin esto, un remitente que se llame `<b>Banco</b>` sale en
/// negrita —y uno más creativo mete un enlace— en un cartel que el escritorio
/// presenta como propio.
///
/// **Se acorta primero y se escapa después.** Al revés, el corte puede caer en
/// medio de un `&amp;` y el cartel muestra `&am`.
fn for_notification(text: &str) -> String {
    let mut cut = MAX_TEXT.min(text.len());
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }

    if cut < text.len() {
        format!("{}…", escape_markup(&text[..cut]))
    } else {
        escape_markup(text)
    }
}

/// Lo que el cuerpo de una notificación interpreta como marcado.
fn escape_markup(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// La cuenta va siempre, porque dice a cuál de las casillas de alguien llegó.
fn with_account(what: &str, account: &str) -> String {
    // La cuenta también se escapa: la da el servicio de cuentas, pero el nombre
    // para mostrar lo puso alguien al conectarla.
    format!("{what} — {}", escape_markup(account))
}

/// Los identificadores de los carteles que ya se mostraron, por cuenta.
///
/// Guardarlos es lo que permite reemplazar el anterior en vez de apilar: el
/// servidor de notificaciones devuelve un número al mostrar uno, y pasárselo
/// como `replaces_id` la próxima vez le dice cuál pisar.
#[derive(Default)]
pub struct ShownNotifications(HashMap<String, u32>);

impl ShownNotifications {
    /// El cartel que hay que reemplazar para esta cuenta. `0` es «ninguno», que
    /// es lo que el estándar define como «mostrá uno nuevo».
    pub fn previous(&self, account: &str) -> u32 {
        self.0.get(account).copied().unwrap_or(0)
    }

    /// Si ese cartel es uno de los nuestros.
    ///
    /// Hace falta porque `ActionInvoked` es una señal del bus y llega **por cada
    /// botón que alguien apriete en cualquier cartel del escritorio**, no sólo
    /// en los propios. Sin comprobar el número, un botón llamado «abrir» en el
    /// aviso de otro programa abriría el correo.
    pub fn is_ours(&self, id: u32) -> bool {
        self.0.values().any(|stored| *stored == id)
    }

    pub fn remember(&mut self, account: &str, id: u32) {
        // El servidor devuelve `0` cuando no quiere que lo reemplacen. Guardarlo
        // no rompe nada —`previous` devolvería `0` igual— pero llenaría el mapa
        // de entradas que no sirven.
        if id != 0 {
            self.0.insert(account.to_string(), id);
        }
    }
}

/// Si el servidor de notificaciones sabe dibujar botones.
///
/// Se pregunta y no se supone: hay servidores que no los soportan —y la
/// especificación lo contempla— y ahí declarar uno es pedir algo que nadie va a
/// ver. Ante la duda, `false`: un cartel sin botón sirve igual; uno con un botón
/// que no se dibuja no le suma nada a nadie.
pub async fn supports_actions(connection: &zbus::Connection) -> bool {
    let reply = connection
        .call_method(Some(SERVICE), PATH, Some(SERVICE), "GetCapabilities", &())
        .await;

    let Ok(reply) = reply else {
        return false;
    };
    reply
        .body()
        .deserialize::<Vec<String>>()
        .map(|capabilities| capabilities.iter().any(|c| c == "actions"))
        .unwrap_or(false)
}

/// Abre la aplicación de correo.
///
/// **Se espera al hijo en una tarea aparte.** Un proceso que termina y que nadie
/// recoge queda de zombi hasta que muera su padre, y el padre acá es un servicio
/// que vive toda la sesión: un zombi por cada vez que alguien apretara el botón.
pub fn open_mail_app() {
    match tokio::process::Command::new(MAIL_PROGRAM).spawn() {
        Ok(mut child) => {
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
        }
        // Que no esté instalado, o que no se pueda ejecutar. No hay a quién
        // decírselo —el cartel ya se fue— así que queda en el diario.
        Err(error) => {
            eprintln!("[avisos] no se pudo abrir {MAIL_PROGRAM}: {error}");
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
pub async fn show(
    connection: &zbus::Connection,
    replaces: u32,
    title: &str,
    body: &str,
    with_action: bool,
) -> Option<u32> {
    // Los botones van de a pares: primero el identificador con el que vuelve la
    // señal, después lo que se lee en pantalla.
    let actions: Vec<&str> = if with_action {
        vec![OPEN_ACTION, "Abrir"]
    } else {
        Vec::new()
    };

    let mut hints: HashMap<&str, zbus::zvariant::Value> = HashMap::new();
    // Con qué aplicación es este cartel. Sirve para que el escritorio lo agrupe
    // con la ventana de correo, y para que la configuración de notificaciones
    // por aplicación lo encuentre.
    hints.insert("desktop-entry", zbus::zvariant::Value::from(DESKTOP_ENTRY));

    let reply = connection
        .call_method(
            Some(SERVICE),
            PATH,
            Some(SERVICE),
            "Notify",
            &(
                "VasakOS Correo",
                replaces,
                // El icono por nombre y no por ruta: lo resuelve el tema, así
                // que sigue al escritorio en vez de quedar fijo.
                "internet-mail",
                title,
                body,
                actions,
                hints,
                // Que lo decida el servidor de notificaciones, que es quien
                // sabe si hay un «no molestar» puesto.
                -1i32,
            ),
        )
        .await
        .ok()?;

    reply.body().deserialize::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(uid: u32) -> MessageSummary {
        MessageSummary {
            uid,
            ..Default::default()
        }
    }

    /// La regla que evita el aluvión: la primera lista de una cuenta no es
    /// novedad, es lo que ya estaba.
    #[test]
    fn la_primera_lista_no_avisa_nada() {
        let now = vec![summary(1), summary(2), summary(3)];
        assert_eq!(count_new(None, &now), 0);
    }

    #[test]
    fn lo_que_no_estaba_antes_es_nuevo() {
        let before = vec![summary(1), summary(2)];
        let now = vec![summary(3), summary(1), summary(2)];
        assert_eq!(count_new(Some(&before), &now), 1);
    }

    /// Se compara por UID y no por posición. Un mensaje borrado desde el
    /// teléfono corre la lista entera: por posición, todo parecería nuevo.
    #[test]
    fn borrar_uno_no_hace_parecer_nuevos_a_los_demas() {
        let before = vec![summary(1), summary(2), summary(3)];
        let now = vec![summary(2), summary(3)];
        assert_eq!(count_new(Some(&before), &now), 0);
    }

    #[test]
    fn sin_cambios_no_hay_novedad() {
        let list = vec![summary(1), summary(2)];
        assert_eq!(count_new(Some(&list), &list), 0);
        assert_eq!(count_new(Some(&[]), &[]), 0);
    }

    #[test]
    fn varios_juntos_se_cuentan_juntos() {
        let before = vec![summary(1)];
        let now: Vec<MessageSummary> = (1..=21).map(summary).collect();
        assert_eq!(count_new(Some(&before), &now), 20);
    }

    fn from(who: &str, address: &str, subject: &str) -> MessageSummary {
        MessageSummary {
            uid: 1,
            from: who.into(),
            address: address.into(),
            subject: subject.into(),
            ..Default::default()
        }
    }

    /// El valor por omisión. La pantalla puede estar bloqueada, compartida o
    /// proyectada, y quién te escribe es tan personal como lo que te escribió.
    #[test]
    fn por_omision_el_texto_no_nombra_a_nadie() {
        let three = vec![from("Ana", "ana@x.com", "Hola"); 3];
        let (title, body) =
            notification_text(&three, "mia@ejemplo.com", NotificationDetail::Account);

        assert!(title.contains('3'));
        assert_eq!(body, "mia@ejemplo.com");
        assert!(!body.contains("Ana"));
        assert!(!body.contains("Hola"));
    }

    #[test]
    fn con_uno_solo_se_puede_decir_de_quien() {
        let single = vec![from("Ana", "ana@x.com", "La factura")];
        let (_, body) = notification_text(&single, "mia@ejemplo.com", NotificationDetail::Sender);
        assert!(body.contains("Ana"));
        // El asunto no, que es el escalón siguiente.
        assert!(!body.contains("factura"));

        let (_, body) = notification_text(
            &single,
            "mia@ejemplo.com",
            NotificationDetail::SenderAndSubject,
        );
        assert!(body.contains("Ana") && body.contains("La factura"));
    }

    /// Con varios, el cartel diría el de uno y callaría los otros, que es peor
    /// que no decir ninguno.
    #[test]
    fn con_varios_no_se_nombra_a_ninguno() {
        let two = vec![
            from("Ana", "ana@x.com", "Uno"),
            from("Juan", "juan@y.com", "Dos"),
        ];
        for detail in [
            NotificationDetail::Sender,
            NotificationDetail::SenderAndSubject,
        ] {
            let (_, body) = notification_text(&two, "mia@ejemplo.com", detail);
            assert!(!body.contains("Ana"), "{body}");
            assert!(!body.contains("Juan"), "{body}");
        }
    }

    #[test]
    fn sin_nombre_se_usa_la_direccion() {
        let single = vec![from("", "ana@x.com", "Hola")];
        let (_, body) = notification_text(&single, "mia@ejemplo.com", NotificationDetail::Sender);
        assert!(body.contains("ana@x.com"));
    }

    /// Un asunto vacío no deja un cartel que termina en dos puntos y nada.
    #[test]
    fn sin_asunto_se_dice_sólo_quien() {
        let single = vec![from("Ana", "ana@x.com", "   ")];
        let (_, body) = notification_text(
            &single,
            "mia@ejemplo.com",
            NotificationDetail::SenderAndSubject,
        );
        assert!(body.contains("Ana"));
        assert!(!body.contains(':'), "{body}");
    }

    /// La cuenta va siempre: dice a cuál de las casillas de alguien llegó.
    #[test]
    fn la_cuenta_va_en_los_tres_escalones() {
        let single = vec![from("Ana", "ana@x.com", "Hola")];
        for detail in [
            NotificationDetail::Account,
            NotificationDetail::Sender,
            NotificationDetail::SenderAndSubject,
        ] {
            let (_, body) = notification_text(&single, "mia@ejemplo.com", detail);
            assert!(body.contains("mia@ejemplo.com"), "{body}");
        }
    }

    /// El botón vuelve por el bus con el número del cartel, y hay que saber si
    /// ese cartel es nuestro.
    ///
    /// `ActionInvoked` llega por cada botón que alguien apriete en **cualquier**
    /// cartel del escritorio. Sin esta comprobación, un botón llamado «abrir» en
    /// el aviso de otro programa abriría el correo.
    #[test]
    fn solo_se_atienden_los_carteles_propios() {
        let mut shown_notifications = ShownNotifications::default();
        assert!(
            !shown_notifications.is_ours(42),
            "sin nada mostrado, ninguno es nuestro"
        );

        shown_notifications.remember("una", 42);
        assert!(shown_notifications.is_ours(42));
        assert!(!shown_notifications.is_ours(43));

        // Con dos cuentas, los dos.
        shown_notifications.remember("otra", 43);
        assert!(shown_notifications.is_ours(42));
        assert!(shown_notifications.is_ours(43));
    }

    /// Un cartel reemplazado deja de ser el vigente de esa cuenta.
    #[test]
    fn el_cartel_viejo_de_una_cuenta_deja_de_ser_nuestro() {
        let mut shown_notifications = ShownNotifications::default();
        shown_notifications.remember("una", 42);
        shown_notifications.remember("una", 55);

        assert!(shown_notifications.is_ours(55));
        // El 42 ya no existe: lo pisó el 55 al reemplazarlo.
        assert!(!shown_notifications.is_ours(42));
    }

    /// El cero no cuenta.
    ///
    /// Es lo que devuelve un servidor que no quiere que le reemplacen el cartel,
    /// y además es el número con el que se pide uno nuevo. Si contara como
    /// nuestro, cualquier señal con id cero abriría el correo.
    #[test]
    fn el_cero_no_es_el_cartel_de_nadie() {
        let mut shown_notifications = ShownNotifications::default();
        shown_notifications.remember("una", 0);
        assert!(!shown_notifications.is_ours(0));
    }

    #[test]
    fn el_cartel_anterior_se_reemplaza() {
        let mut shown_notifications = ShownNotifications::default();
        // Sin nada guardado, `0`: el estándar lo define como «mostrá uno nuevo».
        assert_eq!(shown_notifications.previous("uno"), 0);

        shown_notifications.remember("uno", 42);
        assert_eq!(shown_notifications.previous("uno"), 42);
        // Y cada cuenta tiene el suyo: dos cuentas no se pisan el cartel.
        assert_eq!(shown_notifications.previous("otra"), 0);

        // Un `0` del servidor quiere decir «no me lo reemplaces»; guardarlo
        // llenaría el mapa de entradas que no sirven.
        shown_notifications.remember("dos", 0);
        assert_eq!(shown_notifications.previous("dos"), 0);
    }

    /// **Lo que llega al cartel lo escribió un desconocido.**
    ///
    /// El cuerpo de una notificación admite un subconjunto de marcado —la
    /// especificación lo define y el servidor lo anuncia como `body-markup`—, así
    /// que un remitente que se llame `<b>Banco</b>` sale en negrita en un cartel
    /// que el escritorio presenta como propio.
    #[test]
    fn el_marcado_de_un_desconocido_no_se_interpreta() {
        let m = MessageSummary {
            from: "<b>Banco</b>".to_string(),
            subject: "<a href='x'>clic</a> & más".to_string(),
            ..Default::default()
        };

        let (_, body) = notification_text(&[m], "casa", NotificationDetail::SenderAndSubject);
        assert!(!body.contains("<b>"), "{body}");
        assert!(!body.contains("<a "), "{body}");
        assert!(body.contains("&lt;b&gt;"), "{body}");
        assert!(body.contains("&amp;"), "{body}");
    }

    /// La cuenta también: la da el servicio de cuentas, pero el nombre para
    /// mostrar lo puso alguien al conectarla.
    #[test]
    fn la_cuenta_tambien_se_escapa() {
        let m = MessageSummary::default();
        let (_, body) = notification_text(&[m], "<i>casa</i>", NotificationDetail::Account);
        assert!(!body.contains("<i>"), "{body}");
        assert!(body.contains("&lt;i&gt;"), "{body}");
    }

    /// Un asunto enorme estira el cartel hasta tapar la pantalla: nadie lo corta
    /// por nosotros.
    #[test]
    fn un_asunto_enorme_se_corta() {
        let m = MessageSummary {
            from: "Ana".to_string(),
            subject: "a".repeat(5000),
            ..Default::default()
        };

        let (_, body) = notification_text(&[m], "casa", NotificationDetail::SenderAndSubject);
        assert!(body.len() < 200, "quedó de {}", body.len());
        assert!(body.contains('…'), "{body}");
        // Y el nombre sigue estando: cada cosa se acorta por su lado, así que un
        // asunto enorme no se come a quien lo mandó.
        assert!(body.contains("Ana"), "{body}");
    }

    /// Cortar no puede partir un carácter por la mitad.
    #[test]
    fn el_corte_respeta_los_acentos() {
        // Dos bytes por carácter: el corte cae justo en el medio de uno.
        let m = MessageSummary {
            from: "Ana".to_string(),
            subject: "ñ".repeat(200),
            ..Default::default()
        };

        let (_, body) = notification_text(&[m], "casa", NotificationDetail::SenderAndSubject);
        assert!(body.contains('ñ'), "{body}");
    }

    /// Y lo normal no se toca: si esto escapara de más, un asunto con un «&»
    /// aparecería como «&amp;» en pantalla.
    #[test]
    fn un_asunto_normal_sale_tal_cual() {
        let m = MessageSummary {
            from: "Ana Pérez".to_string(),
            subject: "Factura de septiembre".to_string(),
            ..Default::default()
        };

        let (_, body) = notification_text(&[m], "casa", NotificationDetail::SenderAndSubject);
        assert!(body.contains("Ana Pérez: Factura de septiembre"), "{body}");
        assert!(!body.contains("&amp;"), "{body}");
    }
}
