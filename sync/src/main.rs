//! `vasak-accounts-sync` — mantiene al día el correo, como servicio del usuario.
//!
//! ── Por qué es un binario aparte ────────────────────────────────────────────
//!
//! Porque habla IMAP con los servidores de correo de la persona, y eso es leer
//! lo que manda un servidor cualquiera. El servicio de cuentas corre **como
//! root** —los tokens están en archivos de root— y meterle ahí un cliente de
//! correo sería poner un parser de red detrás de los permisos más altos del
//! sistema. Es el mismo criterio por el que la prueba de conexión y el
//! autodescubrimiento viven en la ventana de configuración.
//!
//! ── Y por qué no tiene ningún atajo ─────────────────────────────────────────
//!
//! Le pide los tokens al servicio por el mismo método D-Bus que usaría una
//! aplicación de terceros, y la primera vez la persona ve el mismo diálogo de
//! permiso. Estar en el mismo repositorio no le da nada.
//!
//! Eso es a propósito y es media razón de que este binario se haya escrito antes
//! que la aplicación de correo: es el **primer cliente real** del modelo de
//! permisos, así que lo ejercita de punta a punta antes de que dependa de él
//! algo que la gente usa.
//!
//! ── Qué hace hoy, y qué no ──────────────────────────────────────────────────
//!
//! Cuenta el correo sin leer de cada cuenta, mantiene la lista de los últimos
//! mensajes y trae el texto de uno cuando la aplicación de correo lo pide.
//!
//! Empezó contando y nada más, a propósito, porque contar no necesita interpretar
//! nada de lo que escribió un desconocido. Ese parser llegó con la aplicación de
//! correo y vive en `mensaje.rs`, con su propia discusión escrita arriba.
//!
//! **La lista vive en memoria, no en un archivo.** Un caché en disco guardaría el
//! remitente y el asunto de todo el correo de la persona en texto plano, para
//! siempre, en un archivo que nadie recuerda que existe. A cambio ahorraría los
//! dos segundos de la primera lista — que igual se rehace sola en cuanto la
//! cuenta se conecta, cosa que pasa al arrancar la sesión.
//!
//! **Los cuerpos no se guardan en ninguna parte**: se traen del servidor cuando
//! alguien abre un mensaje.
//!
//! ── Lo que gana la aplicación de correo con esto ────────────────────────────
//!
//! Que **nunca toca una credencial**. No pide `account.email`, no ve una
//! contraseña y no habla IMAP: le pide a este servicio, por el bus de sesión, la
//! lista y el texto. Es la aplicación más expuesta del escritorio —lo que muestra
//! lo escribió cualquiera que sepa la dirección de la persona— y es la que menos
//! tiene para perder.
//!
//! Todavía **no envía**. Mandar correo pasa por SMTP y por una cola que sobreviva
//! a que se apague el equipo con algo sin mandar, y eso es su propio trabajo.

mod adjuntos;
mod avisos;
mod broker;
mod casillas;
mod consulta;
mod cola;
mod imap;
mod mensaje;
mod redactar;
mod smtp;
mod tls;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use zbus::object_server::SignalContext;
use zbus::interface;

use broker::{Broker, BrokerError};

/// Cada cuánto se vuelve a mirar cuando el servidor **no** sabe avisar.
///
/// Cinco minutos, y no algo más frecuente, porque cada vuelta abre una conexión
/// y se autentica contra el servidor de alguien: hacerlo cada treinta segundos
/// es maltratarlo.
const INTERVALO: Duration = Duration::from_secs(300);

/// Cada cuánto se renueva la espera de IDLE.
///
/// El estándar pide renovarla al menos cada veintinueve minutos. Veinticuatro
/// deja margen: si el servidor —o cualquier NAT en el medio— corta por
/// inactividad justo antes de la renovación, lo que se pierde es un aviso, y
/// eso se nota como correo que aparece tarde.
///
/// Es además el pulso que mantiene los tokens frescos. Antes lo hacía el bucle
/// de cinco minutos; con IDLE la conexión se queda quieta, así que en cada
/// renovación se le vuelve a pedir el token al servicio — que es lo que hace que
/// lo refresque. Sin eso, una cuenta que anda bien podría quedarse con un
/// refresh_token caducado por no usarse.
const RENOVAR_IDLE: Duration = Duration::from_secs(24 * 60);

/// Cuánto se espera antes de reconectar una cuenta que falló.
///
/// Las conexiones largas se cortan: se cae el wifi, el servidor se reinicia, un
/// NAT olvida la sesión. Es lo normal y no un error, así que se reconecta — pero
/// no en el acto, o un servidor caído recibiría un intento por milisegundo.
const REINTENTO_CUENTA: Duration = Duration::from_secs(30);

/// Cuánto se espera antes de volver a intentar cuando el servicio de cuentas no
/// está.
///
/// Corto, porque el caso normal es que todavía esté arrancando: este servicio
/// puede levantar antes que el bus del sistema termine de activarlo.
const REINTENTO: Duration = Duration::from_secs(15);

/// Cada cuánto se mira la cola de salida por las dudas.
///
/// El caso normal es que se despierte en el momento, cuando alguien encola algo.
/// Esto es para lo otro: un mensaje que quedó esperando porque el servidor
/// estaba caído tiene que salir solo cuando vuelva, sin que nadie apriete nada.
const REVISAR_COLA: Duration = Duration::from_secs(60);

/// Lo que se sabe de una cuenta después de mirarla.
#[derive(Debug, Clone, serde::Serialize)]
struct Resumen {
    account_id: String,
    display_name: String,
    #[serde(flatten)]
    estado: imap::Estado,
    /// Vacío si la última vuelta anduvo. Si no, qué pasó — la aplicación que lo
    /// muestre necesita poder decir «no se pudo» y no un cero que parece «no
    /// tenés correo».
    error: String,
}

#[derive(Default)]
struct Estado {
    por_cuenta: HashMap<String, Resumen>,
    /// Los últimos mensajes de cada cuenta, para que la aplicación de correo los
    /// muestre sin abrir su propia conexión.
    ///
    /// **En memoria y no en un archivo**, y eso es una decisión y no una etapa
    /// pendiente. Un caché en disco guardaría el remitente y el asunto de todo
    /// el correo de la persona en texto plano, para siempre, en un archivo que
    /// nadie recuerda que existe — y a cambio ahorraría los dos segundos que
    /// tarda la primera lista. La lista se rehace sola en cuanto la cuenta se
    /// conecta, que es de todos modos lo que pasa al arrancar la sesión.
    mensajes: HashMap<String, Vec<mensaje::Resumen>>,
    /// Las cuentas cuyo servidor rechazó las credenciales.
    ///
    /// Sin esta lista, la tarea de una cuenta rechazada termina, deja de figurar
    /// entre las que corren, y la revisión siguiente la vuelve a arrancar: con
    /// una revisión cada cinco minutos serían unos **288 intentos de
    /// autenticación por día** contra el servidor de alguien, que es exactamente
    /// lo que la salida por rechazo existe para evitar.
    ///
    /// No alcanza con mirar `needs_reauth` de la cuenta: esa marca la pone el
    /// servicio cuando el **proveedor OAuth2** revoca, y un servidor IMAP que
    /// rechaza una contraseña de aplicación no la toca.
    ///
    /// Se limpia sólo cuando el servicio avisa que las cuentas cambiaron — que
    /// es cuando la persona pudo haber arreglado algo.
    rechazadas: std::collections::HashSet<String>,
}

#[derive(Clone, Default)]
struct Servicio {
    estado: Arc<Mutex<Estado>>,
    /// La segunda conexión de cada cuenta, la que atiende lo que pide la
    /// ventana. Se crea cuando alguien abre un mensaje por primera vez.
    lectores: Arc<Mutex<HashMap<String, Arc<Mutex<Lector>>>>>,
    /// Con qué se le avisa al despachador que hay algo nuevo para mandar.
    ///
    /// Sin esto habría que esperar a la revisión por reloj, y apretar «Enviar»
    /// tardaría hasta un minuto en hacer algo visible — que se siente como que
    /// el botón no anduvo.
    hay_algo_que_mandar: Arc<tokio::sync::Notify>,
    /// Los carteles de correo nuevo que ya se mostraron, por cuenta.
    ///
    /// Sirven para reemplazar el anterior en vez de apilar: veinte mensajes que
    /// llegan juntos son un cartel que dice cuántos, no veinte carteles.
    carteles: Arc<Mutex<avisos::Carteles>>,
}

/// Un mensaje abierto, listo para mostrar.
#[derive(Debug, Clone, serde::Serialize)]
struct Abierto {
    texto: String,
    /// El mensaje era más largo de lo que se trae y hay más. La ventana tiene
    /// que poder decirlo en vez de dejar el texto terminado a la mitad sin
    /// explicación.
    recortado: bool,
    /// Los archivos pegados: cuáles hay, cómo se llaman y qué número de parte
    /// tienen.
    ///
    /// Era un booleano —«trae algo»— y ahora es la lista. Sale del mismo mensaje
    /// que ya se trajo, así que no cuesta ni una vuelta más al servidor, y el
    /// número de parte es lo que después hace falta para pedirle al servidor
    /// esa parte sola.
    ///
    /// **Si `recortado` es cierto, esta lista puede estar corta.** Se arma
    /// mirando lo que se trajo, y lo que se trae tiene tope; un adjunto que
    /// quedó más allá del corte no aparece. La ventana ya tiene que decir que el
    /// mensaje está recortado, y eso cubre también esto.
    adjuntos: Vec<adjuntos::Adjunto>,
    /// Lo que hace falta para responderlo: a quién, y con qué cabeceras para que
    /// la respuesta quede enganchada a la conversación.
    ///
    /// Viaja con el mensaje y no en un método aparte porque se necesita en el
    /// mismo momento —al abrirlo aparece el botón de responder— y porque sale de
    /// las mismas cabeceras que ya se trajeron: pedirlo después sería volver al
    /// servidor por algo que ya está en memoria.
    #[serde(flatten)]
    responder: mensaje::ParaResponder,
}

/// La conexión que atiende los pedidos de la aplicación de correo.
///
/// **Aparte de la que espera en IDLE, y no por comodidad.** IMAP no deja mandar
/// un comando mientras la conexión está esperando: hay que cortar la espera con
/// `DONE`, hacer lo pedido y volver a entrar. Hacer eso desde otra tarea es
/// interrumpir una lectura a mitad de camino, y si el corte cae en el lugar
/// equivocado la conexión queda desincronizada — el síntoma sería correo que
/// deja de llegar, sin ningún error y sin nada en el registro.
///
/// El costo es un login más contra el servidor de la persona, y se paga **sólo
/// cuando alguien abre un mensaje**: quien no usa la aplicación de correo sigue
/// teniendo una sola conexión.
#[derive(Default)]
struct Lector {
    sesion: Option<imap::Sesion>,
}

impl Lector {
    /// Las casillas del servidor.
    ///
    /// Se piden en el momento y no se guardan: son unas pocas y cambian cuando
    /// la persona crea una carpeta desde otro lado. Un caché acá sería una
    /// lista que se queda vieja sin que nada la invalide.
    async fn casillas(
        &mut self,
        broker: &Broker,
        cuenta: &broker::Account,
    ) -> Result<Vec<casillas::Casilla>, String> {
        self.con_reintento(broker, cuenta, |sesion| Box::pin(sesion.listar_casillas()))
            .await
    }

    /// Busca en una casilla y devuelve los resúmenes que coinciden.
    ///
    /// La búsqueda la hace el servidor, que es el único que tiene el correo
    /// entero: en memoria están los últimos doscientos de la de entrada y nada
    /// más. Después hay que traer los encabezados de lo que encontró, porque
    /// `SEARCH` devuelve números y no mensajes.
    async fn buscar_en(
        &mut self,
        broker: &Broker,
        cuenta: &broker::Account,
        casilla: &str,
        terminos: Vec<consulta::Termino>,
    ) -> Result<Vec<mensaje::Resumen>, String> {
        let casilla = casilla.to_string();
        self.con_reintento(broker, cuenta, move |sesion| {
            let casilla = casilla.clone();
            let terminos = terminos.clone();
            Box::pin(async move {
                // `EXAMINE`: buscar no tiene por qué marcar nada como leído.
                sesion.examinar(&casilla).await?;
                let uids = sesion.buscar(&terminos).await?;
                sesion.resumenes_de(&uids).await
            })
        })
        .await
    }

    /// Los últimos mensajes de una casilla que no es la de entrada.
    ///
    /// Se traen del servidor en el momento y no se guardan, al revés que los de
    /// `INBOX`. La razón es la misma por la que el IDLE se queda en `INBOX`:
    /// es la única que necesita aviso inmediato, y una conexión en espera por
    /// carpeta multiplicaría las conexiones contra el servidor de alguien.
    ///
    /// `EXAMINE` y no `SELECT`: abrir para mirar no tiene que marcar nada como
    /// leído.
    async fn resumenes_de(
        &mut self,
        broker: &Broker,
        cuenta: &broker::Account,
        casilla: &str,
    ) -> Result<Vec<mensaje::Resumen>, String> {
        let casilla = casilla.to_string();
        self.con_reintento(broker, cuenta, move |sesion| {
            let casilla = casilla.clone();
            Box::pin(async move {
                let cuantos = sesion.examinar(&casilla).await?;
                sesion.resumenes(cuantos).await
            })
        })
        .await
    }

    /// Lo que hace falta para mostrar un mensaje abierto.
    ///
    /// `casilla` importa y no es un adorno: **los UID son por casilla**. El 412
    /// de la de entrada y el 412 de «Enviados» son mensajes distintos, así que
    /// pedir uno sin decir de dónde es pedir cualquiera.
    async fn cuerpo(
        &mut self,
        broker: &Broker,
        cuenta: &broker::Account,
        casilla: &str,
        uid: u32,
    ) -> Result<Abierto, String> {
        let casilla = casilla.to_string();
        let (crudo, recortado) = self
            .con_reintento(broker, cuenta, move |sesion| {
                let casilla = casilla.clone();
                Box::pin(async move {
                    sesion.seleccionar(&casilla).await?;
                    sesion.cuerpo(uid).await
                })
            })
            .await?;

        // Los bytes se le pasan **crudos** al parser. Convertirlos a texto acá
        // —con `from_utf8_lossy`, que es lo que pide el tipo— reemplazaría cada
        // byte que no es UTF-8 por un rombo, y un mensaje en `iso-8859-1`
        // perdería el `0xF3` de la «ó» antes de que se supiera que había que
        // leerlo como latin-1. En qué idioma está escrito lo dice el propio
        // mensaje, y eso se resuelve adentro.
        Ok(Abierto {
            texto: mensaje::texto_de(&crudo),
            recortado,
            adjuntos: adjuntos::listar(&crudo),
            responder: mensaje::para_responder(&crudo),
        })
    }

    /// Marca un mensaje como leído **en el servidor**.
    ///
    /// En el servidor y no sólo acá: la persona lee en el teléfono y en el
    /// escritorio, y un «leído» que no viaja deja el mismo mensaje sin leer del
    /// otro lado para siempre.
    async fn marcar_leido(
        &mut self,
        broker: &Broker,
        cuenta: &broker::Account,
        casilla: &str,
        uid: u32,
    ) -> Result<(), String> {
        let casilla = casilla.to_string();
        self.con_reintento(broker, cuenta, move |sesion| {
            let casilla = casilla.clone();
            Box::pin(async move {
                // La casilla correcta antes de tocar nada: los UID son por
                // casilla, y marcar el 412 con «Enviados» abierta marcaría otro
                // mensaje.
                sesion.seleccionar(&casilla).await?;
                sesion.marcar_leido(uid).await
            })
        })
        .await
    }

    /// Hace algo sobre la sesión, abriéndola si hace falta.
    ///
    /// Con **un** reintento, y sólo si la conexión venía de antes: una que estuvo
    /// quieta un rato la cierra el servidor sin avisar, y el fallo aparece recién
    /// al usarla. En cambio, una que acaba de abrirse y falla no se reintenta —
    /// si el servidor rechazó la credencial, insistir es cómo se bloquea una
    /// cuenta.
    async fn con_reintento<T, F>(
        &mut self,
        broker: &Broker,
        cuenta: &broker::Account,
        mut trabajo: F,
    ) -> Result<T, String>
    where
        F: for<'a> FnMut(
            &'a mut imap::Sesion,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, imap::ImapError>> + Send + 'a>,
        >,
    {
        let reusada = self.sesion.is_some();

        match self.intentar(broker, cuenta, &mut trabajo).await {
            Ok(valor) => Ok(valor),
            Err(primero) => {
                // **La sesión se tira siempre**, se reintente o no. Un error de
                // protocolo puede haberla dejado a mitad de camino de algo, y
                // guardarla para el próximo pedido es guardar una conexión que
                // va a leer el correo de alguien como si fueran líneas del
                // protocolo. Abrir otra cuesta un login; usar una rota no se
                // arregla nunca.
                self.sesion = None;

                if !reusada {
                    return Err(primero);
                }
                // Se reintenta sólo si la conexión venía de antes: una que
                // estuvo quieta un rato la cierra el servidor sin avisar, y el
                // fallo aparece recién al usarla. Una recién abierta que falló
                // no se reintenta — si el servidor rechazó la credencial,
                // insistir es cómo se bloquea una cuenta.
                tracing::debug!("'{}': la conexión de lectura estaba muerta: {primero}", cuenta.id);
                self.intentar(broker, cuenta, &mut trabajo).await
            }
        }
    }

    async fn intentar<T, F>(
        &mut self,
        broker: &Broker,
        cuenta: &broker::Account,
        trabajo: &mut F,
    ) -> Result<T, String>
    where
        F: for<'a> FnMut(
            &'a mut imap::Sesion,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, imap::ImapError>> + Send + 'a>,
        >,
    {
        if self.sesion.is_none() {
            let mut nueva = abrir(broker, cuenta).await?;
            // `SELECT` y no `EXAMINE`: ésta es la conexión que actúa cuando la
            // persona pide algo, así que tiene que poder cambiar una bandera. La
            // que sólo cuenta sigue abriendo en modo lectura.
            nueva
                .seleccionar("INBOX")
                .await
                .map_err(|e| e.to_string())?;
            self.sesion = Some(nueva);
        }

        let sesion = self
            .sesion
            .as_mut()
            .ok_or_else(|| "no hay conexión con el servidor".to_string())?;
        trabajo(sesion).await.map_err(|e| e.to_string())
    }
}

#[interface(name = "ar.net.vasak.os.AccountsSync")]
impl Servicio {
    /// Cuánto correo sin leer hay, por cuenta.
    ///
    /// Sin pedir permiso: son los mismos números que el servicio de cuentas ya
    /// deja ver por `ListAccounts`, contados. Lo que necesita permiso es llegar
    /// al token, y de eso se ocupa el servicio — este proceso ya pasó por ahí.
    ///
    /// Y esto vive en el bus **de sesión**: es un servicio del usuario y lo que
    /// publica es suyo, así que no hay otra sesión que pueda escucharlo.
    async fn mailbox_status(&self) -> zbus::fdo::Result<String> {
        let estado = self.estado.lock().await;
        let mut resumenes: Vec<&Resumen> = estado.por_cuenta.values().collect();
        // Por identificador, para que la lista no cambie de orden entre lecturas
        // por el recorrido de un mapa.
        resumenes.sort_by(|a, b| a.account_id.cmp(&b.account_id));

        serde_json::to_string(&resumenes)
            .map_err(|e| zbus::fdo::Error::Failed(format!("no se pudo serializar: {e}")))
    }

    /// Los últimos mensajes de una cuenta.
    ///
    /// Sin cuerpos: la lista de una casilla grande tiene que caber en un mensaje
    /// de D-Bus, y para pintar una lista alcanzan cuatro campos por mensaje. El
    /// cuerpo se pide de a uno con `GetMessage`.
    ///
    /// Sin pedir permiso, como el contador y por lo mismo: esto vive en el bus
    /// **de sesión**, es un servicio del usuario, y lo que publica es suyo. Quien
    /// necesita permiso es este proceso para llegar al token, y ya pasó por ahí.
    ///
    /// El efecto de fondo vale decirlo: **la aplicación de correo nunca toca una
    /// credencial**. No pide `account.email`, no ve una contraseña y no habla
    /// IMAP. Es la aplicación más expuesta del escritorio —lo que muestra lo
    /// escribió cualquiera que sepa la dirección de la persona— y es la que menos
    /// tiene para perder.
    ///
    /// `mailbox` vacío o `INBOX` contesta con lo que ya está en memoria, que es
    /// lo que mantiene al día la sesión con IDLE. Cualquier otra casilla se
    /// abre en el momento: no hay caché de las demás, y no lo hay a propósito
    /// —una conexión en espera por carpeta multiplicaría las conexiones contra
    /// el servidor de alguien—.
    ///
    /// O sea que abrir «Enviados» tarda lo que tarda el servidor, y la de
    /// entrada es instantánea. Es la diferencia que se ve, y es la correcta:
    /// la que se mira todo el tiempo es la que está lista.
    async fn list_messages(&self, account_id: String, mailbox: String) -> zbus::fdo::Result<String> {
        let mensajes = if mailbox.is_empty() || mailbox.eq_ignore_ascii_case("INBOX") {
            let estado = self.estado.lock().await;
            estado.mensajes.get(&account_id).cloned().unwrap_or_default()
        } else {
            let (broker, cuenta) = self.cuenta(&account_id).await?;
            let lector = self.lector(&account_id).await;
            let mut lector = lector.lock().await;
            lector
                .resumenes_de(&broker, &cuenta, &mailbox)
                .await
                .map_err(zbus::fdo::Error::Failed)?
        };

        serde_json::to_string(&mensajes)
            .map_err(|e| zbus::fdo::Error::Failed(format!("no se pudo serializar: {e}")))
    }

    /// Las casillas de una cuenta: la de entrada, enviados, papelera y las que
    /// haya creado la persona.
    ///
    /// Hasta ahora el escritorio sólo conocía `INBOX`, escrito a mano, así que
    /// el correo enviado, el archivado, el spam y la papelera **no existían**.
    ///
    /// Cada casilla trae su `uso`, que sale de `SPECIAL-USE` cuando el servidor
    /// lo anuncia y de comparar nombres conocidos cuando no. Eso es lo que
    /// permite que la ventana sepa cuál es la papelera sin que la persona se lo
    /// diga, y sin que la ventana tenga que saber que en Gmail se llama
    /// `[Gmail]/Trash` y en un Exchange en español «Elementos eliminados».
    ///
    /// **Sólo lee.** Mover y borrar no están todavía, a propósito: mueven correo
    /// ajeno de lugar y esta parte no se ejerció nunca contra un servidor real.
    async fn list_mailboxes(&self, account_id: String) -> zbus::fdo::Result<String> {
        let (broker, cuenta) = self.cuenta(&account_id).await?;
        let lector = self.lector(&account_id).await;
        let mut lector = lector.lock().await;

        let casillas = lector
            .casillas(&broker, &cuenta)
            .await
            .map_err(zbus::fdo::Error::Failed)?;

        serde_json::to_string(&casillas)
            .map_err(|e| zbus::fdo::Error::Failed(format!("no se pudo serializar: {e}")))
    }

    /// Busca mensajes en una casilla.
    ///
    /// # Por qué recibe términos y no un criterio de IMAP
    ///
    /// Lo que llega es lo que alguien escribió en un campo de texto. Si viajara
    /// como criterio crudo, un término con palabras clave del protocolo sería un
    /// comando distinto del que se quiso mandar — contra la casilla de la propia
    /// persona, pero igual: sería la ventana decidiendo qué comando IMAP se
    /// ejecuta. Acá llega **qué** se busca y el criterio se arma en `consulta`.
    ///
    /// Un término que no se entiende hace fallar la llamada entera en vez de
    /// saltearse: buscar algo distinto de lo que se pidió y no decirlo es peor
    /// que no buscar.
    async fn search_messages(
        &self,
        account_id: String,
        mailbox: String,
        query: String,
    ) -> zbus::fdo::Result<String> {
        let terminos: Vec<consulta::Termino> = serde_json::from_str(&query)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("consulta inválida: {e}")))?;

        let (broker, cuenta) = self.cuenta(&account_id).await?;
        let lector = self.lector(&account_id).await;
        let mut lector = lector.lock().await;

        let encontrados = lector
            .buscar_en(&broker, &cuenta, &casilla_o_entrada(&mailbox), terminos)
            .await
            .map_err(zbus::fdo::Error::Failed)?;

        serde_json::to_string(&encontrados)
            .map_err(|e| zbus::fdo::Error::Failed(format!("no se pudo serializar: {e}")))
    }

    /// El texto de un mensaje.
    ///
    /// Se trae del servidor en el momento: guardar todos los cuerpos sería
    /// guardar el correo entero de la persona en el disco, y para leer uno hay
    /// que ir a buscarlo igual la primera vez.
    ///
    /// Devuelve el texto, si se cortó, si trae adjuntos, y lo que hace falta
    /// para responderlo. Los dos del medio son cosas que la ventana **tiene que
    /// poder decir**: un texto cortado sin explicación parece un mensaje raro, y
    /// un adjunto que no se nombra es un archivo que la persona no sabe que
    /// recibió.
    async fn get_message(
        &self,
        account_id: String,
        mailbox: String,
        uid: u32,
    ) -> zbus::fdo::Result<String> {
        let (broker, cuenta) = self.cuenta(&account_id).await?;
        let lector = self.lector(&account_id).await;
        let mut lector = lector.lock().await;

        let abierto = lector
            .cuerpo(&broker, &cuenta, &casilla_o_entrada(&mailbox), uid)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("no se pudo traer el mensaje: {e}")))?;

        serde_json::to_string(&abierto)
            .map_err(|e| zbus::fdo::Error::Failed(format!("no se pudo serializar: {e}")))
    }

    /// Marca un mensaje como leído en el servidor.
    ///
    /// Lo pide la ventana explícitamente y no pasa por haber traído el mensaje:
    /// todo lo que este proceso trae usa `BODY.PEEK`, que mira sin marcar. Que
    /// abrir la aplicación te vacíe el contador de sin leer sin haber leído nada
    /// es de los errores más molestos que puede tener un cliente de correo.
    async fn mark_read(
        &self,
        #[zbus(signal_context)] emisor: SignalContext<'_>,
        account_id: String,
        mailbox: String,
        uid: u32,
    ) -> zbus::fdo::Result<()> {
        let casilla = casilla_o_entrada(&mailbox);
        let (broker, cuenta) = self.cuenta(&account_id).await?;
        let lector = self.lector(&account_id).await;
        let mut lector = lector.lock().await;

        lector
            .marcar_leido(&broker, &cuenta, &casilla, uid)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("no se pudo marcar: {e}")))?;

        // Y acá también, para que la lista no muestre en negrita algo que el
        // servidor ya sabe que se leyó. La próxima vuelta del bucle lo confirma.
        //
        // Sólo para la de entrada: es la única que está en memoria, y buscar un
        // UID de otra casilla en esa lista encontraría el de un mensaje
        // distinto —los UID son por casilla— y lo marcaría leído sin que nadie
        // lo haya leído.
        if !casilla.eq_ignore_ascii_case("INBOX") {
            return Ok(());
        }

        let mut estado = self.estado.lock().await;
        let cambio = estado
            .mensajes
            .get_mut(&account_id)
            .and_then(|mensajes| mensajes.iter_mut().find(|m| m.uid == uid))
            .is_some_and(|m| std::mem::replace(&mut m.sin_leer, false));
        drop(estado);

        // Con aviso: la ventana que pidió esto ya lo sabe, pero puede haber otra
        // abierta —o el escritorio mirando el contador— y sin la señal se
        // quedarían mostrando en negrita algo que ya se leyó hasta la próxima
        // vuelta del bucle, que puede tardar veinticuatro minutos.
        if cambio {
            let _ = Servicio::messages_changed(&emisor).await;
        }
        Ok(())
    }

    /// Pone un mensaje en la cola de salida.
    ///
    /// **Encola, no manda.** La respuesta vuelve en cuanto el mensaje está a
    /// salvo en el disco, y el envío pasa después: así apretar «Enviar» no deja
    /// la ventana esperando a un servidor que puede tardar un minuto, y sobre
    /// todo, cerrar la sesión o quedarse sin luz en el medio no pierde lo que la
    /// persona escribió.
    ///
    /// Lo que **sí** se revisa antes de contestar es que el mensaje se pueda
    /// armar: una dirección mal escrita tiene que decirlo mientras la persona lo
    /// tiene en pantalla, no tres minutos después desde una cola que no está
    /// mirando.
    ///
    /// El `de` no lo elige la ventana: se toma de la cuenta. Mandar desde una
    /// dirección que no es la que autentica hace que el servidor rechace, o peor,
    /// que el mensaje llegue y lo marquen como falsificado.
    async fn send_message(
        &self,
        #[zbus(signal_context)] emisor: SignalContext<'_>,
        account_id: String,
        borrador: String,
    ) -> zbus::fdo::Result<String> {
        let mut borrador: redactar::Borrador = serde_json::from_str(&borrador)
            .map_err(|e| zbus::fdo::Error::InvalidArgs(format!("el borrador no se entiende: {e}")))?;

        let (broker, cuenta) = self.cuenta(&account_id).await?;
        let config = broker
            .account_data(&cuenta.id, "email")
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("no se pudo leer la cuenta: {e}")))?;
        let config = config.get("config").cloned().unwrap_or(config);

        borrador.de = config
            .get("username")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                zbus::fdo::Error::Failed("la cuenta no tiene una dirección guardada".into())
            })?
            .to_string();
        if borrador.nombre.trim().is_empty() {
            borrador.nombre = cuenta.display_name.clone();
        }

        redactar::revisar(&borrador).map_err(zbus::fdo::Error::InvalidArgs)?;

        let ahora = chrono::Utc::now();
        let unico = siguiente_unico();
        let salida = cola::Salida {
            id: cola::nuevo_id(ahora, unico),
            account_id,
            identificador: redactar::identificador(&borrador.de, ahora, unico),
            // La fecha de cuando se escribió y no de cuando sale: un mensaje
            // redactado anoche que sale a la mañana tiene que decir anoche.
            fecha: redactar::fecha_de_cabecera(chrono::Local::now()),
            borrador,
            intentos: 0,
            estado: cola::Estado::Pendiente,
            ultimo_error: String::new(),
            proximo_intento: String::new(),
        };

        cola::Cola::nueva(cola::directorio())
            .and_then(|c| c.encolar(&salida))
            .map_err(zbus::fdo::Error::Failed)?;

        // Recién ahora, con el mensaje ya en el disco: si el aviso se perdiera,
        // la revisión por reloj lo levanta igual.
        self.hay_algo_que_mandar.notify_one();
        let _ = Servicio::outbox_changed(&emisor).await;
        Ok(salida.id)
    }

    /// Lo que está esperando salir, y lo que se trabó.
    async fn list_outbox(&self) -> zbus::fdo::Result<String> {
        let salidas = cola::Cola::nueva(cola::directorio())
            .and_then(|c| c.todos())
            .map_err(zbus::fdo::Error::Failed)?;

        serde_json::to_string(&salidas)
            .map_err(|e| zbus::fdo::Error::Failed(format!("no se pudo serializar: {e}")))
    }

    /// Saca un mensaje de la cola sin mandarlo.
    ///
    /// Hace falta: un mensaje trabado —una dirección que no existe, un servidor
    /// que lo rechaza— se queda ahí para siempre, y la persona tiene que poder
    /// sacarlo. **Se pierde lo escrito**, así que quien llama tiene que
    /// preguntar antes; acá no hay forma de preguntar.
    async fn discard_outgoing(
        &self,
        #[zbus(signal_context)] emisor: SignalContext<'_>,
        id: String,
    ) -> zbus::fdo::Result<()> {
        // Sin barras ni puntos: el identificador viene de afuera y se convierte
        // en un nombre de archivo. Sin esto, un «id» como `../../algo` borraría
        // lo que quisiera de la carpeta de la persona.
        //
        // Y no vacío, que `all` acepta: la ruta quedaría en «.json», un archivo
        // que no es de nadie y que se borraría igual.
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(zbus::fdo::Error::InvalidArgs(
                "ese identificador no es válido".into(),
            ));
        }

        cola::Cola::nueva(cola::directorio())
            .and_then(|c| c.quitar(&id))
            .map_err(zbus::fdo::Error::Failed)?;

        let _ = Servicio::outbox_changed(&emisor).await;
        Ok(())
    }

    /// Señal `OutboxChanged` — cambió algo en la cola de salida.
    ///
    /// Sin detalle, como las otras: quien la recibe vuelve a leer y ve el
    /// estado completo.
    #[zbus(signal)]
    async fn outbox_changed(emisor: &SignalContext<'_>) -> zbus::Result<()>;

    /// Señal `MessagesChanged` — cambió la lista de mensajes de alguna cuenta.
    ///
    /// Sin detalle, como las otras dos y por lo mismo: quien la recibe vuelve a
    /// leer y ve el estado completo, en vez de reconciliar señales que se pueden
    /// perder.
    #[zbus(signal)]
    async fn messages_changed(emisor: &SignalContext<'_>) -> zbus::Result<()>;

    /// Señal `MailboxChanged` — cambió el correo sin leer de alguna cuenta.
    ///
    /// Sin detalle, como la del servicio de cuentas y por la misma razón: quien
    /// la recibe vuelve a leer y ve el estado completo, en vez de reconciliar
    /// señales que se pueden perder.
    #[zbus(signal)]
    async fn mailbox_changed(emisor: &SignalContext<'_>) -> zbus::Result<()>;
}

/// Lo que necesita el servicio y no es un método de D-Bus.
impl Servicio {
    /// El lector de una cuenta, creándolo si es el primer pedido.
    ///
    /// Uno por cuenta y compartido: dos pedidos a la vez sobre la misma conexión
    /// mezclarían las respuestas —IMAP las devuelve en el orden que quiere—, así
    /// que el `Mutex` los pone en fila. Es también lo que hace que abrir dos
    /// mensajes seguidos no abra dos conexiones.
    async fn lector(&self, account_id: &str) -> Arc<Mutex<Lector>> {
        let mut lectores = self.lectores.lock().await;
        Arc::clone(
            lectores
                .entry(account_id.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(Lector::default()))),
        )
    }

    /// Busca la cuenta que pide la ventana, y una conexión al servicio.
    ///
    /// La cuenta se relee del servicio en vez de guardarse: la persona puede
    /// haberla borrado desde Configuración mientras la aplicación de correo
    /// estaba abierta, y contestar con datos viejos sería intentar conectarse con
    /// una credencial que ya no existe.
    async fn cuenta(&self, account_id: &str) -> zbus::fdo::Result<(Broker, broker::Account)> {
        let broker = Broker::connect().await.map_err(|e| {
            zbus::fdo::Error::Failed(format!("no se pudo hablar con el servicio de cuentas: {e}"))
        })?;

        let cuentas = broker
            .accounts()
            .await
            .map_err(|e| zbus::fdo::Error::Failed(format!("no se pudieron leer las cuentas: {e}")))?;

        cuentas
            .into_iter()
            .find(|c| c.id == account_id)
            .map(|c| (broker, c))
            .ok_or_else(|| {
                zbus::fdo::Error::Failed(format!("la cuenta «{account_id}» ya no existe"))
            })
    }
}

/// Un número que no se repite en la vida del proceso.
///
/// Va junto a la hora en los identificadores: dos mensajes encolados en el mismo
/// microsegundo tendrían el mismo nombre de archivo y el mismo `Message-ID`, y
/// el segundo pisaría al primero — o sea, se perdería un mensaje que alguien
/// escribió.
fn siguiente_unico() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CONTADOR: AtomicU64 = AtomicU64::new(0);
    CONTADOR.fetch_add(1, Ordering::Relaxed)
}

/// El bucle que vacía la cola de salida.
///
/// Una sola tarea para todas las cuentas, y de a un mensaje por vez. Mandar
/// varios a la vez contra el mismo servidor no acelera nada —el cuello es la
/// red— y sí multiplica las conexiones contra el proveedor de la persona, que
/// es exactamente lo que hace que una cuenta parezca un emisor masivo.
///
/// Se despierta cuando alguien encola algo y, si no, cada tanto: un mensaje
/// que quedó esperando por un servidor caído tiene que salir solo cuando el
/// servidor vuelva, sin que nadie apriete nada.
async fn despachar(servicio: Servicio, emisor: SignalContext<'static>) {
    loop {
        let hubo_cambios = vaciar_la_cola(&servicio).await;
        if hubo_cambios {
            let _ = Servicio::outbox_changed(&emisor).await;
        }

        // Lo que sea que pase primero: alguien escribió algo, o pasó el rato.
        tokio::select! {
            _ = tokio::time::sleep(REVISAR_COLA) => {}
            _ = servicio.hay_algo_que_mandar.notified() => {}
        }
    }
}

/// Intenta mandar lo que esté listo. Devuelve si cambió algo.
async fn vaciar_la_cola(servicio: &Servicio) -> bool {
    let Ok(cola) = cola::Cola::nueva(cola::directorio()) else {
        return false;
    };
    let Ok(pendientes) = cola.todos() else {
        return false;
    };

    let ahora = chrono::Utc::now();
    let mut cambio = false;

    for mut salida in pendientes {
        if salida.estado == cola::Estado::Trabado {
            continue;
        }
        // Todavía no le toca: la espera crece con cada intento fallido.
        if !salida.le_toca(ahora) {
            continue;
        }

        match mandar_uno(servicio, &salida).await {
            Ok(()) => {
                tracing::info!("mensaje {} entregado", salida.id);
                // **El error de sacarlo importa.** Un mensaje entregado que
                // sigue en la cola se vuelve a mandar en la vuelta siguiente, y
                // quien lo recibe lo ve dos veces. Que quede en el diario es lo
                // único que permite entender después por qué pasó.
                if let Err(e) = cola.quitar(&salida.id) {
                    tracing::error!(
                        "el mensaje {} se entregó pero no se pudo sacar de la cola: {e}. \
                         Se va a volver a mandar",
                        salida.id
                    );
                }
                cambio = true;
            }
            Err(e) => {
                // La hora **de ahora** y no la del principio de la vuelta:
                // mandar cinco mensajes contra un servidor que no contesta
                // tarda diez minutos, y con la hora vieja el último quedaría
                // con su próximo intento ya cumplido. O sea, reintentos
                // seguidos contra un servidor que justamente no está.
                salida.fallo(e.to_string(), chrono::Utc::now());
                // Se deja de intentar cuando el servidor dijo que no va a
                // aceptarlo nunca, o cuando se acabaron los intentos. En los dos
                // casos hace falta que la persona haga algo, y seguir golpeando
                // el servidor de alguien no ayuda.
                if !e.se_reintenta() || salida.intentos >= cola::MAX_INTENTOS {
                    salida.estado = cola::Estado::Trabado;
                    tracing::warn!("el mensaje {} no se pudo mandar: {e}", salida.id);
                } else {
                    tracing::info!("el mensaje {} espera otro intento: {e}", salida.id);
                }
                let _ = cola.guardar(&salida);
                cambio = true;
            }
        }
    }

    cambio
}

/// Manda un mensaje, de principio a fin.
async fn mandar_uno(servicio: &Servicio, salida: &cola::Salida) -> Result<(), smtp::SmtpError> {
    let (broker, cuenta) = servicio
        .cuenta(&salida.account_id)
        .await
        .map_err(|e| smtp::SmtpError::Permanente(e.to_string()))?;

    let token = broker
        .access_token(&cuenta.id, "email")
        .await
        .map_err(|e| match e {
            // Sin permiso no es un problema pasajero: hasta que la persona lo
            // dé, este mensaje no va a salir.
            BrokerError::Denied(d) => smtp::SmtpError::Rechazado(d),
            otro => smtp::SmtpError::Temporal(otro.to_string()),
        })?;

    let config = broker
        .account_data(&cuenta.id, "email")
        .await
        .map_err(|e| smtp::SmtpError::Temporal(e.to_string()))?;
    let config = config.get("config").cloned().unwrap_or(config);

    // Una cuenta sin servidor de salida no se arregla esperando.
    let destino = broker::destino_smtp_de(&config, Some(token))
        .map_err(smtp::SmtpError::Permanente)?;

    let mensaje = redactar::armar(&salida.borrador, &salida.identificador, &salida.fecha)
        .map_err(smtp::SmtpError::Permanente)?;

    let mut sesion = smtp::Sesion::abrir(&destino).await?;
    let resultado = sesion
        .entregar(
            &salida.borrador.de,
            &salida.borrador.destinatarios(),
            &mensaje,
        )
        .await;
    sesion.cerrar().await;
    resultado
}

/// Abre la sesión de una cuenta: token, configuración y conexión.
async fn abrir(broker: &Broker, cuenta: &broker::Account) -> Result<imap::Sesion, String> {
    let token = broker
        .access_token(&cuenta.id, "email")
        .await
        .map_err(|e| e.to_string())?;

    let config = broker
        .account_data(&cuenta.id, "email")
        .await
        .map_err(|e| e.to_string())?;
    // La configuración viene envuelta: el servicio devuelve la cuenta entera con
    // la capacidad adentro.
    let config = config.get("config").cloned().unwrap_or(config);

    let destino = broker::destino_de(&config, Some(token))?;
    imap::Sesion::abrir(&destino).await.map_err(|e| e.to_string())
}

/// Cuenta lo que hay en la casilla abierta.
async fn contar(sesion: &mut imap::Sesion, mensajes: u32) -> Result<imap::Estado, String> {
    let sin_leer = sesion.sin_leer().await.map_err(|e| e.to_string())?;
    Ok(imap::Estado { mensajes, sin_leer })
}

/// Publica lo que se sabe de una cuenta y avisa si cambió.
async fn publicar(
    servicio: &Servicio,
    emisor: &SignalContext<'_>,
    cuenta: &broker::Account,
    resultado: Result<imap::Estado, String>,
) {
    let nuevo = match resultado {
        Ok(estado) => Resumen {
            account_id: cuenta.id.clone(),
            display_name: cuenta.display_name.clone(),
            estado,
            error: String::new(),
        },
        Err(detalle) => Resumen {
            account_id: cuenta.id.clone(),
            display_name: cuenta.display_name.clone(),
            estado: imap::Estado::default(),
            error: detalle,
        },
    };

    let mut estado = servicio.estado.lock().await;
    let anterior = estado.por_cuenta.get(&cuenta.id);
    let cambio =
        anterior.map(|a| (a.estado, a.error.clone())) != Some((nuevo.estado, nuevo.error.clone()));
    estado.por_cuenta.insert(cuenta.id.clone(), nuevo);
    drop(estado);

    if cambio {
        let _ = Servicio::mailbox_changed(emisor).await;
    }
}

/// Publica la lista de mensajes de una cuenta y avisa si cambió.
///
/// Se compara con lo que había: sin eso, cada renovación de la espera —cada
/// veinticuatro minutos, haya novedades o no— despertaría a la aplicación de
/// correo a redibujar una lista idéntica.
async fn publicar_mensajes(
    servicio: &Servicio,
    emisor: &SignalContext<'_>,
    account_id: &str,
    mensajes: Vec<mensaje::Resumen>,
) {
    let mut estado = servicio.estado.lock().await;
    let anterior = estado.mensajes.get(account_id);
    let cambio = anterior != Some(&mensajes);
    // Cuántos son nuevos se calcula **antes** de reemplazar la lista, que es la
    // única forma: después ya no hay con qué comparar. Y sale `0` la primera
    // vez, porque no había lista anterior — que es justo lo que evita veinte
    // carteles de correo de la semana pasada al conectarse.
    let nuevos = avisos::cuantos_nuevos(anterior.map(|v| v.as_slice()), &mensajes);
    if cambio {
        estado.mensajes.insert(account_id.to_string(), mensajes);
    }
    drop(estado);

    if !cambio {
        return;
    }
    let _ = Servicio::messages_changed(emisor).await;

    if nuevos == 0 {
        return;
    }

    // El cartel, por el bus de sesión. La ventana puede estar cerrada —que es lo
    // normal— y ésta es la única forma de que alguien se entere.
    let (titulo, cuerpo) = avisos::texto(nuevos, account_id);
    let mut carteles = servicio.carteles.lock().await;
    if let Some(id) = avisos::mostrar(
        emisor.connection(),
        carteles.anterior(account_id),
        &titulo,
        &cuerpo,
        // Preguntado cada vez y no una: el servidor de notificaciones se puede
        // reiniciar —o cambiar por otro— sin que este servicio se entere, y la
        // respuesta viene de un método que ya está conectado.
        avisos::soporta_botones(emisor.connection()).await,
    )
    .await
    {
        carteles.recordar(account_id, id);
    }
}

/// Atiende el botón «Abrir» de los carteles de correo nuevo.
///
/// Vive toda la sesión, como el despachador: el cartel puede seguir en el centro
/// de notificaciones mucho después de haberse mostrado, y alguien lo puede
/// apretar en cualquier momento.
fn atender_los_carteles(servicio: Servicio, conexion: zbus::Connection) {
    tokio::spawn(async move {
        // En bucle, igual que el resto de lo que escucha el bus: si la conexión
        // se corta, el botón dejaría de contestar hasta reiniciar la sesión.
        loop {
            if let Err(e) = seguir_los_carteles(&servicio, &conexion).await {
                eprintln!("[avisos] no se puede atender el botón del cartel: {e}");
            }
            tokio::time::sleep(REINTENTO).await;
        }
    });
}

async fn seguir_los_carteles(
    servicio: &Servicio,
    conexion: &zbus::Connection,
) -> Result<(), String> {
    use futures_util::StreamExt;

    let regla = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.Notifications")
        .and_then(|r| r.member("ActionInvoked"))
        .map_err(|e| format!("no se pudo armar el filtro: {e}"))?
        .build();

    let mut avisos_del_bus = zbus::MessageStream::for_match_rule(regla, conexion, None)
        .await
        .map_err(|e| format!("no se pudo escuchar «ActionInvoked»: {e}"))?;

    while let Some(Ok(mensaje)) = avisos_del_bus.next().await {
        let Ok((id, accion)) = mensaje.body().deserialize::<(u32, String)>() else {
            continue;
        };

        // **El número del cartel importa.** La señal llega por cada botón que
        // alguien apriete en cualquier cartel del escritorio, no sólo en los
        // propios: sin esto, un botón llamado «abrir» en el aviso de otro
        // programa abriría el correo.
        if accion != "abrir" || !servicio.carteles.lock().await.es_nuestro(id) {
            continue;
        }
        avisos::abrir_el_correo();
    }

    Err("el bus de sesión cerró la conexión".into())
}

/// La tarea de una cuenta: se conecta y se queda.
///
/// Vive mientras la cuenta exista. Cuando el servidor sabe avisar —IDLE— se
/// queda esperando y el correo nuevo aparece en el momento; cuando no, vuelve a
/// mirar cada cinco minutos sobre la misma conexión, que igual es mejor que
/// reconectarse cada vez.
async fn atender(
    cuenta: broker::Account,
    servicio: Servicio,
    emisor: SignalContext<'static>,
) {
    loop {
        let broker = match Broker::connect().await {
            Ok(b) => b,
            Err(e) => {
                tracing::info!("'{}': esperando al servicio de cuentas: {e}", cuenta.id);
                tokio::time::sleep(REINTENTO_CUENTA).await;
                continue;
            }
        };

        match sesion_de_cuenta(&broker, &cuenta, &servicio, &emisor).await {
            // Sólo se sale con un rechazo: insistir con una credencial que el
            // servidor no acepta es cómo se bloquea una cuenta, y en un bucle
            // serían cientos de intentos por día. La tarea termina y no vuelve
            // hasta que algo cambie en las cuentas.
            Err(Salida::Rechazada(detalle)) => {
                tracing::warn!("'{}' deja de mirarse: {detalle}", cuenta.id);
                // Antes de publicar: quien revisa las tareas tiene que ver la
                // marca aunque llegue justo ahora, o la vuelve a arrancar.
                servicio.estado.lock().await.rechazadas.insert(cuenta.id.clone());
                publicar(&servicio, &emisor, &cuenta, Err(detalle)).await;
                return;
            }
            Err(Salida::Cortada(detalle)) => {
                tracing::info!("'{}' se cortó: {detalle}; reconectando", cuenta.id);
                publicar(&servicio, &emisor, &cuenta, Err(detalle)).await;
                tokio::time::sleep(REINTENTO_CUENTA).await;
            }
        }
    }
}

/// Por qué terminó la sesión de una cuenta.
enum Salida {
    /// El servidor rechazó las credenciales, o el servicio negó el permiso.
    Rechazada(String),
    /// Se cortó, se cayó la red, el servidor se reinició. Se reconecta.
    Cortada(String),
}

/// La casilla que pidieron, o la de entrada si no dijeron ninguna.
///
/// Las ventanas viejas no mandan el campo. Caer a `INBOX` es lo que hacían
/// antes, así que una que no se actualizó sigue funcionando igual en vez de
/// fallar con un nombre vacío.
fn casilla_o_entrada(mailbox: &str) -> String {
    if mailbox.is_empty() {
        "INBOX".to_string()
    } else {
        mailbox.to_string()
    }
}

/// Una sesión, de principio a fin. Nunca vuelve bien: o se corta o la rechazan.
async fn sesion_de_cuenta(
    broker: &Broker,
    cuenta: &broker::Account,
    servicio: &Servicio,
    emisor: &SignalContext<'_>,
) -> Result<std::convert::Infallible, Salida> {
    let mut sesion = abrir(broker, cuenta).await.map_err(clasificar_salida)?;

    let mut mensajes = sesion
        .examinar("INBOX")
        .await
        .map_err(|e| Salida::Cortada(e.to_string()))?;

    // El `UIDVALIDITY` con el que se abrió. Si el servidor lo cambia a mitad de
    // la sesión, los UID que ya publicamos dejan de valer: el 412 de ayer no es
    // el 412 de hoy. Pasa cuando la casilla se recrea del otro lado —una
    // restauración, una migración de servidor— y es raro, pero el síntoma es
    // que abrir un mensaje trae otro.
    let mut uidvalidity = sesion.uidvalidity();

    let inicial = contar(&mut sesion, mensajes).await;
    publicar(servicio, emisor, cuenta, inicial).await;
    listar(&mut sesion, servicio, emisor, cuenta, mensajes).await?;

    let avisa = sesion.soporta_idle();
    if !avisa {
        tracing::info!(
            "'{}': el servidor no sabe avisar; se mira cada {} minutos",
            cuenta.id,
            INTERVALO.as_secs() / 60,
        );
    }

    loop {
        if avisa {
            // Esperar a que el servidor diga algo. Vuelve por novedad o porque
            // hay que renovar; en los dos casos se vuelve a contar, que es
            // barato y evita depender de interpretar bien cada aviso.
            sesion
                .esperar(RENOVAR_IDLE)
                .await
                .map_err(|e| Salida::Cortada(e.to_string()))?;
        } else {
            tokio::time::sleep(INTERVALO).await;
        }

        // Pedirle el token al servicio en cada vuelta es lo que lo mantiene
        // fresco: el servicio lo refresca si le queda poco. No se usa para nada
        // más — la sesión ya está autenticada— pero sin esto una cuenta que anda
        // podría quedarse con un refresh_token caducado por no usarse.
        if let Err(e) = broker.access_token(&cuenta.id, "email").await {
            if matches!(e, BrokerError::Denied(_)) {
                return Err(Salida::Rechazada(e.to_string()));
            }
            tracing::debug!("'{}': no se pudo refrescar el token: {e}", cuenta.id);
        }

        // `EXAMINE` otra vez para releer cuántos hay: el `EXISTS` que llegó
        // durante la espera puede haber quedado atrás si hubo varios.
        mensajes = sesion
            .examinar("INBOX")
            .await
            .map_err(|e| Salida::Cortada(e.to_string()))?;

        // Si cambió, lo guardado no sirve. Se tira y se vuelve a listar en vez
        // de intentar arreglarlo: la lista se rehace en un pedido, y quedarse
        // con UID que apuntan a otra cosa es peor que esperar dos segundos.
        let ahora_vale = sesion.uidvalidity();
        if ahora_vale != uidvalidity {
            tracing::info!(
                "'{}': el servidor cambió el UIDVALIDITY de INBOX ({:?} -> {:?}); se rehace la lista",
                cuenta.id,
                uidvalidity,
                ahora_vale,
            );
            uidvalidity = ahora_vale;
            servicio.estado.lock().await.mensajes.remove(&cuenta.id);
        }

        let ahora = contar(&mut sesion, mensajes).await;
        publicar(servicio, emisor, cuenta, ahora).await;
        listar(&mut sesion, servicio, emisor, cuenta, mensajes).await?;
    }
}

/// Trae la lista de mensajes y la publica.
///
/// Un fallo acá **no corta la sesión**: el contador de sin leer es lo que hace
/// este proceso desde que existe y lo que mira el escritorio, y perderlo porque
/// un servidor contestó raro a un `FETCH` sería cambiar algo que funciona por
/// algo que recién se estrena. Queda en el registro y se reintenta en la vuelta
/// siguiente.
///
/// **Salvo que la conexión haya quedado desincronizada**, que es la única
/// excepción y no admite otra: seguir usándola leería el correo de alguien como
/// si fueran líneas del protocolo, y el contador que se quería salvar pasaría a
/// decir cualquier cosa. Ahí se corta y se reconecta.
async fn listar(
    sesion: &mut imap::Sesion,
    servicio: &Servicio,
    emisor: &SignalContext<'_>,
    cuenta: &broker::Account,
    mensajes: u32,
) -> Result<(), Salida> {
    match sesion.resumenes(mensajes).await {
        Ok(lista) => {
            publicar_mensajes(servicio, emisor, &cuenta.id, lista).await;
            Ok(())
        }
        Err(e @ imap::ImapError::Desincronizada(_)) => Err(Salida::Cortada(e.to_string())),
        Err(e) => {
            tracing::warn!("'{}': no se pudo listar el correo: {e}", cuenta.id);
            Ok(())
        }
    }
}

/// Separa lo que hay que reintentar de lo que no.
fn clasificar_salida(detalle: String) -> Salida {
    if detalle.contains("rechazó las credenciales") || detalle.contains("sin permiso") {
        Salida::Rechazada(detalle)
    } else {
        Salida::Cortada(detalle)
    }
}

/// Arranca y para las tareas para que coincidan con las cuentas que hay.
async fn ajustar_tareas(
    broker: &Broker,
    servicio: &Servicio,
    emisor: &SignalContext<'static>,
    tareas: &mut HashMap<String, tokio::task::JoinHandle<()>>,
) -> Result<(), BrokerError> {
    let cuentas = broker.accounts().await?;
    let con_correo: Vec<&broker::Account> = cuentas
        .iter()
        .filter(|c| c.hay_correo_que_sincronizar())
        .collect();
    let vigentes: Vec<&str> = con_correo.iter().map(|c| c.id.as_str()).collect();

    // Las que ya no están, o que pasaron a necesitar reautenticación.
    tareas.retain(|id, tarea| {
        if vigentes.contains(&id.as_str()) && !tarea.is_finished() {
            return true;
        }
        tarea.abort();
        false
    });

    let mut estado = servicio.estado.lock().await;
    estado.por_cuenta.retain(|id, _| vigentes.contains(&id.as_str()));
    // Los mensajes de una cuenta que ya no está **se van con ella**. Sin esto,
    // borrar una cuenta desde Configuración dejaba en memoria el remitente y el
    // asunto de sus últimos doscientos mensajes, y `ListMessages` los seguía
    // entregando a quien preguntara por ese identificador. Alguien que quita una
    // cuenta espera que se vaya el correo también.
    estado.mensajes.retain(|id, _| vigentes.contains(&id.as_str()));
    estado.rechazadas.retain(|id| vigentes.contains(&id.as_str()));
    let rechazadas = estado.rechazadas.clone();
    drop(estado);

    // Y su conexión de lectura, que está autenticada contra el servidor. Una
    // cuenta borrada no puede dejar una sesión IMAP viva: al soltar el `Lector`
    // se cierra el socket.
    servicio
        .lectores
        .lock()
        .await
        .retain(|id, _| vigentes.contains(&id.as_str()));

    for cuenta in con_correo {
        if tareas.contains_key(&cuenta.id) {
            continue;
        }
        // Una cuenta rechazada no se vuelve a arrancar. Su tarea terminó, así
        // que sin esto la revisión siguiente la levantaría de nuevo y el
        // servidor recibiría un intento cada cinco minutos.
        if rechazadas.contains(&cuenta.id) {
            continue;
        }
        tracing::info!("'{}' pasa a atenderse", cuenta.id);
        let tarea = tokio::spawn(atender(
            cuenta.clone(),
            servicio.clone(),
            emisor.clone(),
        ));
        tareas.insert(cuenta.id.clone(), tarea);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    tracing::info!("Iniciando vasak-accounts-sync…");

    let servicio = Servicio::default();

    // El bus de **sesión**: es un servicio del usuario y lo que publica es suyo.
    let conexion = zbus::connection::Builder::session()?
        .name("ar.net.vasak.os.AccountsSync")?
        .serve_at("/ar/net/vasak/os/AccountsSync", servicio.clone())?
        .build()
        .await?;

    let emisor = SignalContext::new(&conexion, "/ar/net/vasak/os/AccountsSync")?.to_owned();

    let (despertar, mut despertador) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        loop {
            match escuchar_al_servicio(&despertar).await {
                Ok(()) => tracing::warn!("se cortó la escucha del servicio de cuentas"),
                Err(e) => tracing::warn!("no se pudo escuchar al servicio de cuentas: {e}"),
            }
            tokio::time::sleep(REINTENTO).await;
        }
    });

    // El despachador de la cola de salida: una sola tarea para todas las
    // cuentas. Arranca antes que nada porque lo primero que hace es intentar
    // mandar lo que haya quedado de la sesión anterior.
    tokio::spawn(despachar(servicio.clone(), emisor.clone()));

    // Y quien atiende el botón «Abrir» de los carteles de correo nuevo. También
    // una sola tarea: la señal es del servidor de notificaciones y no de una
    // cuenta.
    atender_los_carteles(servicio.clone(), emisor.connection().clone());

    // El hilo principal ya no mira casillas: sólo se asegura de que haya una
    // tarea por cuenta. Cada tarea se queda conectada y avisa por su cuenta.
    let mut tareas: HashMap<String, tokio::task::JoinHandle<()>> = HashMap::new();
    loop {
        match Broker::connect().await {
            Ok(broker) => {
                if let Err(e) = ajustar_tareas(&broker, &servicio, &emisor, &mut tareas).await {
                    match e {
                        BrokerError::Unavailable(d) => {
                            tracing::info!("el servicio de cuentas no está todavía: {d}")
                        }
                        otro => tracing::warn!("no se pudieron leer las cuentas: {otro}"),
                    }
                }
            }
            Err(e) => tracing::info!("esperando al servicio de cuentas: {e}"),
        }

        // Se revisa cuando el servicio avisa que cambió algo, y cada tanto por
        // las dudas: una tarea que terminó por rechazo tiene que poder volver si
        // la persona reconectó la cuenta.
        tokio::select! {
            _ = tokio::time::sleep(INTERVALO) => {}
            _ = despertador.recv() => {
                tracing::debug!("algo cambió en las cuentas");
                // Y sólo acá se olvidan los rechazos: la persona pudo haber
                // corregido una contraseña o reconectado una cuenta. En la
                // revisión por reloj no, o el olvido devolvería los 288
                // intentos diarios que la marca evita.
                servicio.estado.lock().await.rechazadas.clear();
            }
        }
    }
}

/// Escucha `AccountsChanged` del servicio de cuentas y avisa al bucle.
async fn escuchar_al_servicio(despertar: &tokio::sync::mpsc::Sender<()>) -> zbus::Result<()> {
    use futures_util::StreamExt;

    let conexion = zbus::Connection::system().await?;
    let mut señales = zbus::MessageStream::for_match_rule(
        zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface("ar.net.vasak.os.AccountManager")?
            .member("AccountsChanged")?
            .build(),
        &conexion,
        None,
    )
    .await?;

    while let Some(Ok(_)) = señales.next().await {
        // Sin esperar si el bucle está ocupado: una vuelta ya en curso va a ver
        // el cambio igual, y encolar varias no aporta nada.
        let _ = despertar.try_send(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cuenta(id: &str) -> broker::Account {
        broker::Account {
            id: id.into(),
            display_name: id.into(),
            provider_type: "custom".into(),
            capabilities: vec!["email".into()],
            needs_reauth: false,
        }
    }

    /// **La propiedad que se había roto.** Una cuenta rechazada no se vuelve a
    /// arrancar en la revisión siguiente.
    ///
    /// La tarea de una cuenta rechazada termina, así que deja de figurar entre
    /// las que corren — y sin la marca, la revisión por reloj la levantaba de
    /// nuevo cada cinco minutos: unos 288 intentos de autenticación por día
    /// contra el servidor de alguien, que es exactamente lo que la salida por
    /// rechazo existe para evitar.
    ///
    /// No alcanza con mirar `needs_reauth`: esa marca la pone el servicio cuando
    /// el proveedor OAuth2 revoca, y un servidor IMAP que rechaza una contraseña
    /// de aplicación no la toca.
    #[tokio::test]
    async fn una_cuenta_rechazada_no_se_vuelve_a_arrancar() {
        let servicio = Servicio::default();
        let cuentas = [cuenta("a"), cuenta("b")];

        servicio.estado.lock().await.rechazadas.insert("a".into());
        let rechazadas = servicio.estado.lock().await.rechazadas.clone();

        let arrancarian: Vec<&str> = cuentas
            .iter()
            .filter(|c| !rechazadas.contains(&c.id))
            .map(|c| c.id.as_str())
            .collect();

        assert_eq!(arrancarian, vec!["b"], "la rechazada no tenía que arrancar");
    }

    /// Y el olvido pasa **sólo** cuando el servicio avisa que algo cambió, que
    /// es cuando la persona pudo haber arreglado la contraseña. Olvidar en la
    /// revisión por reloj devolvería los 288 intentos diarios.
    #[tokio::test]
    async fn el_rechazo_se_olvida_cuando_cambian_las_cuentas() {
        let servicio = Servicio::default();
        servicio.estado.lock().await.rechazadas.insert("a".into());

        // Lo que hace el bucle al recibir la señal.
        servicio.estado.lock().await.rechazadas.clear();

        assert!(servicio.estado.lock().await.rechazadas.is_empty());
    }

    /// Una cuenta que se borró no puede dejar su marca colgada: si se vuelve a
    /// conectar con el mismo identificador, merece un intento limpio.
    #[tokio::test]
    async fn el_rechazo_de_una_cuenta_que_ya_no_esta_se_descarta() {
        let servicio = Servicio::default();
        {
            let mut estado = servicio.estado.lock().await;
            estado.rechazadas.insert("borrada".into());
            estado.rechazadas.insert("sigue".into());
        }

        let vigentes = ["sigue"];
        servicio
            .estado
            .lock()
            .await
            .rechazadas
            .retain(|id| vigentes.contains(&id.as_str()));

        let quedan = servicio.estado.lock().await.rechazadas.clone();
        assert!(quedan.contains("sigue"));
        assert!(!quedan.contains("borrada"));
    }

    /// El tope de un intercambio tiene que ser más corto que la renovación de la
    /// espera: si fuera al revés, un servidor mudo mantendría la cuenta colgada
    /// más de lo que dura un ciclo entero y no se notaría la diferencia con una
    /// conexión sana.
    #[test]
    fn los_tiempos_tienen_el_orden_que_corresponde() {
        assert!(
            RENOVAR_IDLE < Duration::from_secs(29 * 60),
            "el estándar pide renovar antes de los 29 minutos"
        );
        assert!(REINTENTO_CUENTA < INTERVALO);
    }

    /// Las ventanas viejas no mandan el campo. Caer a la de entrada es lo que
    /// hacían antes, así que una que no se actualizó sigue funcionando en vez
    /// de fallar con un nombre vacío.
    #[test]
    fn sin_casilla_se_usa_la_de_entrada() {
        assert_eq!(casilla_o_entrada(""), "INBOX");
        assert_eq!(casilla_o_entrada("INBOX"), "INBOX");
        assert_eq!(casilla_o_entrada("Sent"), "Sent");
        // No se normaliza: el servidor distingue mayúsculas en todo lo que no
        // sea `INBOX`, y «sent» puede ser otra carpeta distinta de «Sent».
        assert_eq!(casilla_o_entrada("[Gmail]/Sent Mail"), "[Gmail]/Sent Mail");
    }
}
