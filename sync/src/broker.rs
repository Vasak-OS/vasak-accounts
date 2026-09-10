//! Hablar con el servicio de cuentas, como cualquier otra aplicación.
//!
//! Y eso último no es una manera de decir: este proceso **no tiene ningún
//! atajo** por vivir en el mismo repositorio que el servicio. Le pide los
//! tokens por el mismo método D-Bus que usaría una aplicación de terceros, y la
//! primera vez que lo hace la persona ve el mismo diálogo de permiso.
//!
//! Es a propósito, y es la razón de que este binario se haya escrito antes que
//! la aplicación de correo: es el primer cliente real del modelo de permisos, y
//! sirve para ejercitarlo de punta a punta.

use serde::Deserialize;

const SERVICE: &str = "ar.net.vasak.os.AccountManager";
const PATH: &str = "/ar/net/vasak/os/AccountManager";
const INTERFACE: &str = "ar.net.vasak.os.AccountManager";

/// El resumen de una cuenta, tal como lo devuelve `ListAccounts`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Account {
    pub id: String,
    pub display_name: String,
    pub provider_type: String,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub needs_reauth: bool,
}

impl Account {
    /// Si esta cuenta tiene correo que sincronizar.
    ///
    /// Una cuenta marcada para reautenticar se salta: pedirle el token daría
    /// error, y hacerlo en cada vuelta del bucle llenaría el diario con el mismo
    /// fallo mientras la persona no la reconecte.
    pub fn hay_correo_que_sincronizar(&self) -> bool {
        !self.needs_reauth && self.capabilities.iter().any(|c| c == "email")
    }
}

#[derive(Debug)]
pub enum BrokerError {
    /// El servicio no está, o no contesta.
    Unavailable(String),
    /// Contestó, y dijo que no. Es la respuesta normal cuando la persona no dio
    /// permiso: no es un fallo que haya que reintentar.
    Denied(String),
    Failed(String),
}

impl std::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerError::Unavailable(d) => write!(f, "el servicio de cuentas no responde: {d}"),
            BrokerError::Denied(d) => write!(f, "sin permiso para usar la cuenta: {d}"),
            BrokerError::Failed(d) => write!(f, "{d}"),
        }
    }
}

impl std::error::Error for BrokerError {}

pub struct Broker {
    connection: zbus::Connection,
}

impl Broker {
    /// El bus del **sistema**: ahí vive el servicio de cuentas, porque los
    /// tokens están en archivos de root.
    pub async fn connect() -> Result<Self, BrokerError> {
        let connection = zbus::Connection::system()
            .await
            .map_err(|e| BrokerError::Unavailable(e.to_string()))?;
        Ok(Self { connection })
    }

    async fn llamar<A>(&self, metodo: &str, argumentos: &A) -> Result<String, BrokerError>
    where
        A: serde::ser::Serialize + zbus::zvariant::DynamicType,
    {
        let respuesta = self
            .connection
            .call_method(Some(SERVICE), PATH, Some(INTERFACE), metodo, argumentos)
            .await
            .map_err(|e| clasificar(metodo, e))?;

        respuesta
            .body()
            .deserialize()
            .map_err(|e| BrokerError::Failed(format!("respuesta inválida de {metodo}: {e}")))
    }

    /// Las cuentas de esta persona. No pide permiso: son metadatos.
    pub async fn accounts(&self) -> Result<Vec<Account>, BrokerError> {
        let json = self.llamar("ListAccounts", &()).await?;
        serde_json::from_str(&json)
            .map_err(|e| BrokerError::Failed(format!("no se pudo leer la lista de cuentas: {e}")))
    }

    /// Un token válido para una capacidad de una cuenta.
    ///
    /// Acá **sí** se pregunta, y la primera vez la persona ve un diálogo. El
    /// servicio refresca el token si hace falta, así que llamar a esto seguido
    /// es también lo que mantiene los tokens frescos sin una tarea aparte.
    pub async fn access_token(
        &self,
        account_id: &str,
        capability: &str,
    ) -> Result<String, BrokerError> {
        self.llamar("GetAccessToken", &(account_id, capability)).await
    }

    /// La configuración de una capacidad: el servidor, el usuario, los puertos.
    pub async fn account_data(
        &self,
        account_id: &str,
        capability: &str,
    ) -> Result<serde_json::Value, BrokerError> {
        let json = self.llamar("GetAccountData", &(account_id, capability)).await?;
        serde_json::from_str(&json)
            .map_err(|e| BrokerError::Failed(format!("no se pudo leer la configuración: {e}")))
    }
}

/// Separa «no está el servicio» de «dijo que no».
///
/// Importa para el bucle: lo primero se reintenta, porque el servicio puede
/// estar arrancando; lo segundo no, porque la respuesta va a ser la misma hasta
/// que la persona cambie de opinión, y reintentar sería insistir con un diálogo
/// que ya rechazó.
fn clasificar(metodo: &str, error: zbus::Error) -> BrokerError {
    if let zbus::Error::MethodError(nombre, detalle, _) = &error {
        let nombre = nombre.as_str();
        let detalle = detalle.clone().unwrap_or_default();

        if nombre.ends_with(".AccessDenied") {
            return BrokerError::Denied(detalle);
        }
        if nombre.ends_with(".ServiceUnknown") || nombre.ends_with(".NoReply") {
            return BrokerError::Unavailable(detalle);
        }
        return BrokerError::Failed(format!("{metodo}: {detalle}"));
    }
    BrokerError::Unavailable(format!("{metodo}: {error}"))
}

/// Cómo hay que autenticarse contra el servidor de esta cuenta.
///
/// Sale de la configuración que el servicio guardó al conectarla, y no de
/// adivinar por el proveedor: una cuenta de Google conectada con contraseña de
/// aplicación por IMAP y una conectada por OAuth2 se ven igual desde afuera y se
/// autentican distinto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credencial {
    /// Usuario y contraseña, con `LOGIN`.
    Contrasena { usuario: String, secreto: String },
    /// Token de OAuth2, con `AUTHENTICATE XOAUTH2`.
    Token { usuario: String, token: String },
}

/// Dónde y cómo conectarse al correo de una cuenta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destino {
    pub host: String,
    pub puerto: u16,
    pub credencial: Credencial,
}

/// Lee el servidor, el usuario y **cómo autenticarse** de la configuración.
///
/// La configuración la escribió quien conectó la cuenta, así que puede faltarle
/// cualquier cosa: se comprueba acá en vez de al intentar conectar, para que el
/// mensaje diga qué falta y no «no se pudo resolver el nombre ""».
///
/// La forma de autenticarse se decide por **lo que guardó el servicio** y no por
/// el proveedor. Una cuenta de Google conectada con contraseña de aplicación por
/// IMAP y una conectada por OAuth2 tienen el mismo `provider_type` y se
/// autentican distinto: la primera con `LOGIN` y la segunda con `XOAUTH2`.
/// Confundirlas manda una contraseña donde va un token, y el servidor contesta
/// un rechazo que parece de credenciales — que en cierto modo lo es, pero por el
/// motivo equivocado.
///
/// La marca es el `client_id`: sólo lo tienen las cuentas que pasaron por un
/// flujo OAuth2, porque lo escribe `CompleteAuth` junto con las URLs para
/// renovar el token.
pub fn destino_de(config: &serde_json::Value, secreto: Option<String>) -> Result<Destino, String> {
    let campo = |nombre: &str| config.get(nombre).and_then(|v| v.as_str());

    let usuario = campo("username")
        .ok_or("la cuenta no tiene usuario guardado")?
        .to_string();
    let host = campo("imap_server")
        .ok_or("la cuenta no tiene servidor IMAP guardado")?
        .to_string();

    // 993 por omisión: es el puerto de IMAP sobre TLS y el que pone el
    // formulario. Una cuenta guardada sin puerto es de una versión anterior, y
    // suponer el correcto es mejor que negarse a sincronizarla.
    let puerto = config
        .get("imap_port")
        .and_then(|v| v.as_u64())
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(993);

    let Some(secreto) = secreto else {
        return Err("no se obtuvo ninguna credencial para la cuenta".into());
    };

    let credencial = if campo("client_id").is_some() {
        Credencial::Token { usuario, token: secreto }
    } else {
        Credencial::Contrasena { usuario, secreto }
    };

    Ok(Destino { host, puerto, credencial })
}

/// Lo mismo, pero para el servidor por el que se manda.
///
/// Aparte de `destino_de` y no un parámetro suyo, porque lo que falta cuando
/// falta es distinto: una cuenta puede leer correo sin poder mandarlo —el
/// formulario deja el servidor de salida vacío, o la cuenta viene de una
/// versión anterior a que se guardara—, y el mensaje tiene que decir eso y no
/// «la cuenta no tiene servidor».
///
/// 587 por omisión: es el puerto de envío con `STARTTLS` y el que pone el
/// formulario. El otro que existe es el 465, que habla TLS desde el primer byte.
pub fn destino_smtp_de(
    config: &serde_json::Value,
    secreto: Option<String>,
) -> Result<Destino, String> {
    let campo = |nombre: &str| config.get(nombre).and_then(|v| v.as_str());

    let usuario = campo("username")
        .ok_or("la cuenta no tiene usuario guardado")?
        .to_string();
    let host = campo("smtp_server")
        .filter(|s| !s.trim().is_empty())
        .ok_or(
            "esta cuenta no tiene servidor de salida configurado,              así que no se puede mandar correo desde ella",
        )?
        .to_string();

    let puerto = config
        .get("smtp_port")
        .and_then(|v| v.as_u64())
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p != 0)
        .unwrap_or(587);

    let Some(secreto) = secreto else {
        return Err("no se obtuvo ninguna credencial para la cuenta".into());
    };

    // La misma regla que para leer: la marca es el `client_id`, que sólo lo
    // tienen las cuentas que pasaron por un flujo OAuth2. Confundirlas manda una
    // contraseña donde va un token.
    let credencial = if campo("client_id").is_some() {
        Credencial::Token { usuario, token: secreto }
    } else {
        Credencial::Contrasena { usuario, secreto }
    };

    Ok(Destino { host, puerto, credencial })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Una cuenta puede leer correo sin poder mandarlo: el formulario deja el
    /// servidor de salida vacío, o la cuenta viene de una versión anterior a
    /// que se guardara. El mensaje tiene que decir **eso** y no «la cuenta no
    /// tiene servidor», que manda a mirar el lugar equivocado.
    #[test]
    fn una_cuenta_sin_servidor_de_salida_lo_dice() {
        let config = serde_json::json!({
            "username": "ana@ejemplo.com",
            "imap_server": "imap.ejemplo.com",
        });
        let error = destino_smtp_de(&config, Some("c".into())).unwrap_err();
        assert!(error.contains("servidor de salida"), "{error}");

        // Y uno en blanco es lo mismo que no tenerlo: conectarse a "" da un
        // error de resolución de nombres que no explica nada.
        let vacio = serde_json::json!({ "username": "ana", "smtp_server": "  " });
        assert!(destino_smtp_de(&vacio, Some("c".into())).is_err());
    }

    /// 587 es el puerto de envío con `STARTTLS`, y es el que pone el formulario.
    /// Una cuenta guardada sin puerto es de una versión anterior.
    #[test]
    fn sin_puerto_de_salida_se_usa_el_de_siempre() {
        let config = serde_json::json!({
            "username": "ana@ejemplo.com",
            "smtp_server": "smtp.ejemplo.com",
        });
        let destino = destino_smtp_de(&config, Some("c".into())).unwrap();
        assert_eq!(destino.puerto, 587);
        assert_eq!(destino.host, "smtp.ejemplo.com");
    }

    /// El puerto guardado manda, incluido el 465, que habla TLS desde el primer
    /// byte y se trata distinto.
    #[test]
    fn el_puerto_guardado_se_respeta() {
        let config = serde_json::json!({
            "username": "ana", "smtp_server": "smtp.x.com", "smtp_port": 465,
        });
        assert_eq!(destino_smtp_de(&config, Some("c".into())).unwrap().puerto, 465);
    }

    /// La misma regla que para leer: el `client_id` es lo que distingue una
    /// cuenta con token de una con contraseña. Confundirlas manda una
    /// contraseña donde va un token, y el rechazo que vuelve parece de
    /// credenciales sin serlo.
    #[test]
    fn el_client_id_decide_como_autenticarse_tambien_al_mandar() {
        let con_token = serde_json::json!({
            "username": "ana", "smtp_server": "smtp.x.com", "client_id": "abc",
        });
        assert!(matches!(
            destino_smtp_de(&con_token, Some("t".into())).unwrap().credencial,
            Credencial::Token { .. }
        ));

        let con_clave = serde_json::json!({ "username": "ana", "smtp_server": "smtp.x.com" });
        assert!(matches!(
            destino_smtp_de(&con_clave, Some("c".into())).unwrap().credencial,
            Credencial::Contrasena { .. }
        ));
    }
    use serde_json::json;

    #[test]
    fn una_cuenta_con_correo_se_sincroniza() {
        let cuenta = Account {
            id: "a".into(),
            display_name: "Ana".into(),
            provider_type: "custom".into(),
            capabilities: vec!["email".into(), "calendar".into()],
            needs_reauth: false,
        };
        assert!(cuenta.hay_correo_que_sincronizar());
    }

    /// Una cuenta sin correo no es un error: es una de Nextcloud con archivos y
    /// calendario, por ejemplo. Se saltea en silencio.
    #[test]
    fn una_cuenta_sin_correo_se_saltea() {
        let cuenta = Account {
            id: "a".into(),
            display_name: "Nube".into(),
            provider_type: "nextcloud".into(),
            capabilities: vec!["drive".into(), "calendar".into()],
            needs_reauth: false,
        };
        assert!(!cuenta.hay_correo_que_sincronizar());
    }

    /// Y una que hay que reconectar tampoco: pedirle el token daría error, y
    /// hacerlo en cada vuelta llenaría el diario con el mismo fallo mientras la
    /// persona no la reconecte.
    #[test]
    fn una_cuenta_que_pide_reautenticacion_se_saltea() {
        let cuenta = Account {
            id: "a".into(),
            display_name: "Vieja".into(),
            provider_type: "google".into(),
            capabilities: vec!["email".into()],
            needs_reauth: true,
        };
        assert!(!cuenta.hay_correo_que_sincronizar());
    }

    /// El resumen que devuelve el servicio se lee tal como viene, incluida una
    /// cuenta guardada antes de que existiera la marca de reautenticación.
    #[test]
    fn se_lee_el_resumen_del_servicio() {
        let json = r#"[{"id":"a","display_name":"Ana","provider_type":"custom",
                        "capabilities":["email"],"needs_reauth":false},
                       {"id":"b","display_name":"Vieja","provider_type":"custom",
                        "capabilities":[]}]"#;
        let cuentas: Vec<Account> = serde_json::from_str(json).unwrap();

        assert_eq!(cuentas.len(), 2);
        assert!(cuentas[0].hay_correo_que_sincronizar());
        assert!(!cuentas[1].needs_reauth, "sin la marca es una cuenta que anda");
    }

    #[test]
    fn el_destino_sale_de_la_configuracion() {
        let config = json!({
            "username": "ana@ejemplo.com",
            "imap_server": "imap.ejemplo.com",
            "imap_port": 993,
        });

        let destino = destino_de(&config, Some("el-secreto".into())).unwrap();
        assert_eq!(destino.host, "imap.ejemplo.com");
        assert_eq!(destino.puerto, 993);
    }

    /// **El caso que se rompe callado si se elige mal.** Una cuenta conectada
    /// con contraseña de aplicación se autentica con `LOGIN`; una conectada por
    /// OAuth2, con `XOAUTH2`. Las dos pueden ser de Google y tener el mismo
    /// `provider_type`, así que la diferencia sale de lo que guardó el servicio:
    /// el `client_id` lo escribe `CompleteAuth` y sólo lo tienen las de OAuth2.
    ///
    /// Elegir mal manda una contraseña donde va un token, y el servidor contesta
    /// un rechazo que parece de credenciales.
    #[test]
    fn una_cuenta_con_contrasena_no_se_autentica_con_token() {
        let con_contrasena = json!({
            "username": "ana@gmail.com",
            "imap_server": "imap.gmail.com",
            "imap_port": 993,
        });
        assert_eq!(
            destino_de(&con_contrasena, Some("la-contrasena".into())).unwrap().credencial,
            Credencial::Contrasena {
                usuario: "ana@gmail.com".into(),
                secreto: "la-contrasena".into(),
            }
        );

        let con_oauth = json!({
            "username": "ana@gmail.com",
            "imap_server": "imap.gmail.com",
            "client_id": "el-mio.apps.googleusercontent.com",
            "token_url": "https://oauth2.googleapis.com/token",
        });
        assert_eq!(
            destino_de(&con_oauth, Some("el-token".into())).unwrap().credencial,
            Credencial::Token { usuario: "ana@gmail.com".into(), token: "el-token".into() }
        );
    }

    /// Sin credencial no hay nada que intentar, y el mensaje lo tiene que decir:
    /// llegar hasta la conexión para fallar ahí escondería el motivo.
    #[test]
    fn sin_credencial_no_se_arma_un_destino() {
        let config = json!({ "username": "ana", "imap_server": "imap.ejemplo.com" });
        assert!(destino_de(&config, None).is_err());
    }

    /// Una cuenta guardada antes de que el formulario pidiera el puerto no tiene
    /// ninguno. Suponer 993 —el de IMAP sobre TLS, y el que el formulario
    /// propone— es mejor que negarse a sincronizarla.
    #[test]
    fn sin_puerto_se_supone_el_de_imap_sobre_tls() {
        let config = json!({ "username": "ana", "imap_server": "imap.ejemplo.com" });
        assert_eq!(destino_de(&config, Some("t".into())).unwrap().puerto, 993);
    }

    /// El mensaje tiene que decir qué falta. Sin esto, una cuenta a la que le
    /// falta el servidor fallaría más tarde con «no se pudo resolver el nombre
    /// ""», que no señala a ninguna parte.
    #[test]
    fn una_configuracion_incompleta_dice_que_le_falta() {
        let sin_servidor = json!({ "username": "ana" });
        let error = destino_de(&sin_servidor, Some("t".into())).unwrap_err();
        assert!(error.contains("servidor"), "{error}");

        let sin_usuario = json!({ "imap_server": "imap.ejemplo.com" });
        let error = destino_de(&sin_usuario, Some("t".into())).unwrap_err();
        assert!(error.contains("usuario"), "{error}");
    }

    /// Un puerto que no entra en 16 bits es un archivo corrupto, no un puerto:
    /// se cae al de siempre en vez de recortarlo a algo que no se pidió.
    #[test]
    fn un_puerto_imposible_no_se_recorta() {
        let config = json!({
            "username": "ana",
            "imap_server": "imap.ejemplo.com",
            "imap_port": 999_999,
        });
        assert_eq!(destino_de(&config, Some("t".into())).unwrap().puerto, 993);
    }
}
