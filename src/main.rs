mod auth;
mod pending;
mod permissions;
mod protocols;
mod providers;
mod storage;
use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use pending::{PendingAuth, PendingAuths};
use storage::{AccountDatabase, CapabilityType};

use zbus::fdo::DBusProxy;
use zbus::fdo::Error as FdoError;
use zbus::message::Header;
use zbus::names::BusName;
use zbus::object_server::SignalContext;
use zbus::interface;

/// Decides whether `caller` may use `capability` on `account_id`.
///
/// The answer comes from `vasak-permissions`, a system service, and no longer
/// from a list inside `accounts.json`. That list lived in the user's own
/// configuration directory: any program running as them could rewrite it and
/// grant itself anything, so it protected nothing.
async fn authorize(
    caller: &auth::PinnedCaller,
    db: &AccountDatabase,
    account_id: &str,
    capability: &str,
) -> zbus::fdo::Result<CapabilityType> {
    // `InvalidArgs` y no `Failed`: un nombre de capacidad mal escrito es un
    // argumento malo, y el cliente que lo mandó puede distinguirlo de un fallo
    // del servicio y arreglarlo.
    let cap: CapabilityType = capability
        .parse()
        .map_err(|e: storage::UnknownCapability| FdoError::InvalidArgs(e.to_string()))?;

    let account = db
        .get(account_id)
        .ok_or_else(|| FdoError::Failed(format!("Cuenta '{account_id}' no encontrada")))?;

    // Named so the dialog can say which account is being asked for.
    let granted = permissions::check(caller.pid, &cap, &account.display_name).await?;

    if !granted {
        tracing::warn!(
            "ACCESS DENIED — PID {} no autorizado para '{}' en cuenta {}",
            caller.pid,
            capability,
            account_id,
        );
        return Err(FdoError::AccessDenied(format!(
            "El programa no tiene permiso para '{capability}' en esta cuenta. \
             Podés cambiarlo en Configuración → Privacidad y seguridad."
        )));
    }

    Ok(cap)
}

/// Estructura principal del servicio AccountManager.
/// Los métodos definidos en el bloque `#[interface]` se exponen como
/// métodos D-Bus en la interfaz `ar.net.vasak.os.AccountManager`.
#[derive(Default)]
struct AccountManager {
    /// Los flujos de autorización a medio terminar. Sólo en memoria: ver
    /// [`pending`].
    pendientes: Arc<Mutex<PendingAuths>>,
}

/// Abre la base del usuario y la carga, que es el arranque de casi todo método.
fn open_db(uid: u32) -> zbus::fdo::Result<AccountDatabase> {
    let mut db = AccountDatabase::for_user(uid)
        .map_err(|e| FdoError::Failed(format!("Error al abrir base de datos: {e}")))?;
    db.load()
        .map_err(|e| FdoError::Failed(format!("Error al cargar cuentas: {e}")))?;
    Ok(db)
}

/// Los nombres de secreto que sólo puede escribir el flujo de autorización.
///
/// `RegisterAccount` es para credenciales que la persona escribe —la contraseña
/// de aplicación de IMAP, por ejemplo—. Un refresh_token o un client_secret no
/// se escriben a mano: salen de `CompleteAuth`, que es el único que sabe con qué
/// proveedor se corresponden y guarda junto a ellos las URLs para renovarlos.
/// Aceptarlos por acá dejaría cuentas OAuth a medio armar, sin la configuración
/// que el motor de refresco necesita, que es exactamente el estado que hacía que
/// una cuenta se muriera en una hora.
const SECRETOS_DE_OAUTH: [&str; 2] = ["refresh", "client_secret"];

// ---------------------------------------------------------------------------
// Helper: extrae el PID del llamante desde la cabecera D-Bus
// ---------------------------------------------------------------------------

async fn caller_pid_and_uid(
    connection: &zbus::Connection,
    header: &Header<'_>,
) -> zbus::fdo::Result<(u32, u32)> {
    let sender = header
        .sender()
        .ok_or_else(|| FdoError::Failed("Sender no presente en la cabecera".into()))?;

    tracing::debug!("Nombre único del emisor: {}", sender);

    let dbus_proxy = DBusProxy::new(connection)
        .await
        .map_err(|e| FdoError::Failed(format!("Error al crear proxy D-Bus: {}", e)))?;

    let name = BusName::from(sender.clone());
    let pid = dbus_proxy
        .get_connection_unix_process_id(name.clone())
        .await
        .map_err(|e| {
            FdoError::Failed(format!("Error al obtener PID para '{}': {}", sender, e))
        })?;

    // The daemon serves every session on the machine, so the caller's user is
    // what keeps one person's accounts out of another person's requests.
    let uid = dbus_proxy
        .get_connection_unix_user(name)
        .await
        .map_err(|e| {
            FdoError::Failed(format!("Error al obtener usuario para '{}': {}", sender, e))
        })?;

    Ok((pid, uid))
}

/// Obtiene el PID del llamante y lo **fija con un pidfd** de inmediato, para que
/// el binario resuelto no pueda ser suplantado por reciclado de PID mientras se
/// realiza la verificación (cierra la ventana TOCTOU).
async fn caller_identity(
    connection: &zbus::Connection,
    header: &Header<'_>,
) -> zbus::fdo::Result<(auth::PinnedCaller, u32)> {
    let (pid, uid) = caller_pid_and_uid(connection, header).await?;
    let caller = auth::PinnedCaller::capture(pid).map_err(FdoError::Failed)?;
    Ok((caller, uid))
}

#[interface(name = "ar.net.vasak.os.AccountManager")]
impl AccountManager {
    /// Método `Ping` — identifica al cliente llamante (PID + binario).
    async fn ping(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        let (caller, _uid) = caller_identity(connection, &header).await?;

        tracing::info!(
            "Ping recibido del PID: {} (Ruta: {})",
            caller.pid,
            caller.exe.display(),
        );

        Ok(format!(
            "OK: PID {} identificado correctamente (Ruta: {})",
            caller.pid,
            caller.exe.display(),
        ))
    }

    /// Método `GetAccountData` — retorna datos de una cuenta solo si el
    /// proceso llamante tiene permiso en la ACL para la capability solicitada.
    async fn get_account_data(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        account_id: String,
        capability: String,
    ) -> zbus::fdo::Result<String> {
        let (caller, uid) = caller_identity(connection, &header).await?;

        let mut db = AccountDatabase::for_user(uid)
            .map_err(|e| FdoError::Failed(format!("Error al abrir base de datos: {}", e)))?;
        db.load()
            .map_err(|e| FdoError::Failed(format!("Error al cargar cuentas: {}", e)))?;

        let cap = authorize(&caller, &db, &account_id, &capability).await?;

        let account = db
            .get(&account_id)
            .ok_or_else(|| FdoError::Failed(format!("Cuenta '{}' no encontrada", account_id)))?;

        let data = account.capabilities.get(&cap).ok_or_else(|| {
            FdoError::Failed(format!("Capability '{}' no configurada en la cuenta", capability))
        })?;

        let response = serde_json::json!({
            "account_id": account_id,
            "display_name": account.display_name,
            "provider_type": account.provider_type,
            "capability": capability,
            "config": data,
        });

        serde_json::to_string_pretty(&response)
            .map_err(|e| FdoError::Failed(format!("Error de serialización: {}", e)))
    }

    /// Método `ListAccounts` — las cuentas del usuario que llama.
    ///
    /// Un resumen, no la cuenta entera, y **sin pedir permiso**. Que la
    /// pantalla de cuentas o la app de calendario puedan dibujar una lista no
    /// puede costar un diálogo por cuenta: preguntar por algo tan seguido es lo
    /// que enseña a apretar «permitir» sin leer, y ahí se pierde el valor de
    /// preguntar cuando importa.
    ///
    /// Lo que se paga por eso es que la lista la ve cualquier programa del
    /// usuario. Por eso sale un resumen —nombre, proveedor, qué capacidades
    /// tiene y si hay que reconectarla— y no la configuración completa, que
    /// sigue detrás de `GetAccountData`. Un token nunca sale por acá.
    async fn list_accounts(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        let (_caller, uid) = caller_identity(connection, &header).await?;
        let db = open_db(uid)?;

        let resumenes: Vec<storage::AccountSummary> =
            db.all().iter().map(storage::Account::summary).collect();

        serde_json::to_string(&resumenes)
            .map_err(|e| FdoError::Failed(format!("Error de serialización: {e}")))
    }

    /// Método `ListProviders` — qué proveedores se pueden conectar.
    ///
    /// Incluye los que **no** están listos, con `configured: false`, para que la
    /// pantalla pueda mostrarlos apagados y decir por qué en vez de esconderlos.
    /// Un proveedor que desaparece de la lista parece un proveedor que no existe.
    async fn list_providers(&self) -> zbus::fdo::Result<String> {
        let catalogo = providers::load()
            .map_err(|e| FdoError::Failed(format!("Error al leer el catálogo: {e}")))?;

        let mut lista: Vec<serde_json::Value> = catalogo
            .values()
            .map(|proveedor| {
                serde_json::json!({
                    "id": proveedor.id,
                    "display_name": proveedor.display_name,
                    "capabilities": proveedor.capabilities()
                        .iter()
                        .map(|c| c.as_id())
                        .collect::<Vec<_>>(),
                    // Sin el client_id no se puede empezar ningún flujo, y eso
                    // es lo único que la pantalla necesita saber para decidir si
                    // el botón va encendido.
                    "configured": proveedor
                        .client_id
                        .as_deref()
                        .is_some_and(|id| !id.is_empty()),
                })
            })
            .collect();
        lista.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));

        serde_json::to_string(&lista)
            .map_err(|e| FdoError::Failed(format!("Error de serialización: {e}")))
    }

    /// Método `BeginAuth` — empieza a conectar una cuenta OAuth2.
    ///
    /// Devuelve la URL a la que hay que mandar el navegador, un `request_id` y
    /// el `state` que va a volver en el callback.
    ///
    /// El `code_verifier` de PKCE se genera acá y **se queda acá**. Eso es todo
    /// el motivo de que este método exista: antes el intercambio ocurría en la
    /// ventana de configuración, así que el refresh_token pasaba por un proceso
    /// del usuario — justo lo que se había evitado al mover los tokens a
    /// archivos de root. Un código de autorización sin su verifier no sirve
    /// para nada, así que lo que la ventana maneja ahora no es un secreto.
    ///
    /// Conectar una cuenta *tuya* no pide permiso: es tuya. Lo que lo pide es
    /// que un programa llegue después al token.
    async fn begin_auth(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        provider_id: String,
        capabilities: String,
        redirect_uri: String,
    ) -> zbus::fdo::Result<String> {
        let (_caller, uid) = caller_identity(connection, &header).await?;

        let capacidades = parse_capabilities(&capabilities)?;
        if capacidades.is_empty() {
            return Err(FdoError::InvalidArgs(
                "hay que pedir al menos una capacidad".into(),
            ));
        }

        // Antes de armar nada: adónde vuelve el código de autorización lo elige
        // quien llama, y sin esto podría pedir que termine en un servidor ajeno
        // y quedarse con la cuenta.
        if !pending::is_loopback_redirect(&redirect_uri) {
            return Err(FdoError::InvalidArgs(format!(
                "redirect_uri tiene que apuntar a este equipo por http \
                 (127.0.0.1, localhost o [::1]); llegó '{redirect_uri}'"
            )));
        }

        let proveedor = providers::resolve(&provider_id, &capacidades)
            .map_err(|e| FdoError::Failed(e.to_string()))?;

        let (auth_url, verifier, state) =
            protocols::oauth2::authorization_url(&proveedor, &capacidades, &redirect_uri)
                .map_err(|e| FdoError::Failed(e.to_string()))?;

        let request_id = self
            .pendientes
            .lock()
            .await
            .insert(PendingAuth::new(
                uid,
                proveedor.id.clone(),
                capacidades,
                redirect_uri,
                verifier,
                state.clone(),
            ))
            .map_err(FdoError::Failed)?;

        tracing::info!("autorización '{request_id}' iniciada para '{provider_id}' (uid {uid})");

        serde_json::to_string(&serde_json::json!({
            "request_id": request_id,
            "auth_url": auth_url,
            "state": state,
        }))
        .map_err(|e| FdoError::Failed(format!("Error de serialización: {e}")))
    }

    /// Método `CompleteAuth` — canjea el código y crea la cuenta.
    ///
    /// El canje lo hace este servicio, contra el proveedor, con el verifier que
    /// nunca salió de acá. Los tokens van derecho al almacén de root: el
    /// programa que armó la cuenta no los puede leer después sin permiso, igual
    /// que cualquier otro.
    // Tres de estos argumentos no son argumentos: `connection`, `header` y el
    // emisor de señales los inyecta zbus. Los que la persona manda son los
    // otros, y son los que la interfaz D-Bus necesita.
    #[allow(clippy::too_many_arguments)]
    async fn complete_auth(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_context)] emisor: SignalContext<'_>,
        request_id: String,
        code: String,
        state: String,
        display_name: String,
    ) -> zbus::fdo::Result<String> {
        let (_caller, uid) = caller_identity(connection, &header).await?;

        let pendiente = self
            .pendientes
            .lock()
            .await
            .take(&request_id, uid, &state)
            .map_err(|e| FdoError::AccessDenied(e.to_string()))?;

        // Del catálogo otra vez, y no de lo guardado en el pendiente: si el
        // client_secret cambió entre que se abrió el navegador y volvió, el
        // canje tiene que usar el de ahora.
        let proveedor = providers::resolve(&pendiente.provider_id, &pendiente.capabilities)
            .map_err(|e| FdoError::Failed(e.to_string()))?;

        let frescos = protocols::oauth2::exchange_code(
            &proveedor,
            &code,
            &pendiente.verifier,
            &pendiente.redirect_uri,
        )
        .await
        .map_err(|e| FdoError::Failed(e.to_string()))?;

        // El nombre que puso la persona, o el del proveedor si dejó el campo
        // vacío. Sin esto la lista mostraría cuentas sin nombre.
        let nombre = if display_name.trim().is_empty() {
            proveedor.display_name.clone()
        } else {
            display_name
        };

        let capabilities: HashMap<CapabilityType, serde_json::Value> = pendiente
            .capabilities
            .iter()
            .map(|capacidad| {
                (
                    *capacidad,
                    protocols::oauth2::capability_config(&proveedor, capacidad, &frescos),
                )
            })
            .collect();

        let mut db = open_db(uid)?;
        let cuenta = storage::Account::new(&nombre, &proveedor.id, capabilities);
        let account_id = db
            .add(cuenta)
            .map_err(|e| FdoError::Failed(format!("Error al guardar la cuenta: {e}")))?;

        // Los secretos después de la cuenta: si esto falla, queda una cuenta sin
        // token que la persona puede borrar y rehacer. Al revés quedarían tokens
        // huérfanos que nada limpia.
        guardar_secretos_de_oauth(uid, &account_id, &proveedor, &frescos)?;

        tracing::info!("cuenta '{account_id}' conectada a '{}' (uid {uid})", proveedor.id);
        Self::accounts_changed(&emisor, uid).await?;
        Ok(account_id)
    }

    /// Método `CancelAuth` — descarta un flujo que la persona abandonó.
    ///
    /// Sin esto habría que esperar cinco minutos a que venza, y mientras tanto
    /// ocupa lugar contra el tope de flujos simultáneos.
    async fn cancel_auth(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        request_id: String,
    ) -> zbus::fdo::Result<bool> {
        let (_caller, uid) = caller_identity(connection, &header).await?;
        Ok(self.pendientes.lock().await.cancel(&request_id, uid))
    }

    /// Método `RegisterAccount` — agrega una cuenta con credenciales de
    /// contraseña.
    ///
    /// Es el camino de IMAP/SMTP, CalDAV y compañía: la persona escribe un
    /// servidor y una contraseña de aplicación, y eso va derecho al almacén de
    /// root. El programa que armó la cuenta no la puede leer después sin
    /// permiso, igual que cualquier otro.
    ///
    /// **No** acepta secretos de OAuth2. Ésos salen de `CompleteAuth`, que es el
    /// único que sabe con qué proveedor se corresponden y guarda junto a ellos
    /// las URLs para renovarlos; aceptarlos por acá dejaría cuentas OAuth sin la
    /// configuración que el motor de refresco necesita, que es exactamente el
    /// estado en que una cuenta se moría en una hora.
    ///
    /// Agregar una cuenta a tu *propio* usuario no pide permiso: es tuya. Lo que
    /// lo pide es que un programa llegue al token.
    // Tres de estos argumentos no son argumentos: `connection`, `header` y el
    // emisor de señales los inyecta zbus. Los que la persona manda son los
    // otros, y son los que la interfaz D-Bus necesita.
    #[allow(clippy::too_many_arguments)]
    async fn register_account(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_context)] emisor: SignalContext<'_>,
        display_name: String,
        provider_type: String,
        capabilities_json: String,
        secrets_json: String,
    ) -> zbus::fdo::Result<String> {
        let (_caller, uid) = caller_identity(connection, &header).await?;

        let capabilities: HashMap<CapabilityType, serde_json::Value> =
            serde_json::from_str(&capabilities_json)
                .map_err(|e| FdoError::InvalidArgs(format!("capabilities inválidas: {e}")))?;
        let secrets: HashMap<String, String> = serde_json::from_str(&secrets_json)
            .map_err(|e| FdoError::InvalidArgs(format!("secretos inválidos: {e}")))?;

        for nombre in &SECRETOS_DE_OAUTH {
            if secrets.contains_key(*nombre) {
                return Err(FdoError::InvalidArgs(format!(
                    "'{nombre}' no se puede registrar por acá: las cuentas OAuth2 \
                     se conectan con BeginAuth y CompleteAuth, que guardan además \
                     las URLs necesarias para renovar el token"
                )));
            }
        }

        let mut db = open_db(uid)?;
        let cuenta = storage::Account::new(&display_name, &provider_type, capabilities);
        let account_id = db
            .add(cuenta)
            .map_err(|e| FdoError::Failed(format!("Error al guardar la cuenta: {e}")))?;

        for (clave, valor) in secrets {
            storage::SecretStore::store_secret(uid, &account_id, &clave, &valor)
                .map_err(|e| FdoError::Failed(format!("Error al guardar el secreto: {e}")))?;
        }

        tracing::info!("Cuenta '{account_id}' registrada para el usuario {uid}");
        Self::accounts_changed(&emisor, uid).await?;
        Ok(account_id)
    }

    /// Método `RemoveAccount` — borra la cuenta y todos sus secretos.
    async fn remove_account(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_context)] emisor: SignalContext<'_>,
        account_id: String,
    ) -> zbus::fdo::Result<bool> {
        let (_caller, uid) = caller_identity(connection, &header).await?;

        let mut db = open_db(uid)?;
        let borrada = db
            .remove(&account_id)
            .map_err(|e| FdoError::Failed(format!("Error al eliminar la cuenta: {e}")))?;

        // Los secretos se limpian siempre, incluso si los metadatos ya no
        // estaban: si no, queda una credencial viva en disco para una cuenta que
        // la persona cree que no existe.
        storage::SecretStore::forget_account(uid, &account_id)
            .map_err(|e| FdoError::Failed(format!("Error al borrar los secretos: {e}")))?;

        if borrada {
            Self::accounts_changed(&emisor, uid).await?;
        }
        Ok(borrada)
    }

    /// Señal `AccountsChanged` — algo cambió en las cuentas de este usuario.
    ///
    /// Una sola señal sin detalle, y no cuatro con el id de la cuenta adentro.
    /// Dos razones.
    ///
    /// La primera es que este servicio atiende a todo el equipo desde el bus del
    /// sistema, así que una señal la reciben todas las sesiones. Con el id
    /// adentro, quien esté escuchando se enteraría de que a la persona de al
    /// lado le cambió tal cuenta. Un `uid` y nada más no dice nada que no se
    /// pueda ver con `who`.
    ///
    /// La segunda es que funciona mejor. Quien la recibe vuelve a llamar
    /// `ListAccounts` —que ya está acotado a su usuario— y ve el estado
    /// completo, incluida la marca de reautenticación. Con señales que llevan el
    /// cambio adentro, una que se pierde deja al cliente creyendo algo que no
    /// es, y hay que reconciliar igual.
    #[zbus(signal)]
    async fn accounts_changed(emisor: &SignalContext<'_>, uid: u32) -> zbus::Result<()>;

    /// Método `GetAccessToken` — un access_token **válido** para la cuenta y
    /// capacidad indicadas, refrescándolo si hace falta.
    async fn get_access_token(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_context)] emisor: SignalContext<'_>,
        account_id: String,
        capability: String,
    ) -> zbus::fdo::Result<String> {
        let (caller, uid) = caller_identity(connection, &header).await?;

        let db = open_db(uid)?;
        let cap = authorize(&caller, &db, &account_id, &capability).await?;

        match protocols::oauth2::get_valid_access_token(uid, &account_id, &cap).await {
            Ok(token) => {
                // Una cuenta que vuelve a andar deja de pedir reautenticación.
                // Pasa cuando la persona la reconecta, y sin esto la pantalla
                // seguiría diciendo que hay algo que arreglar.
                if marcar_reauth(uid, &account_id, false)? {
                    Self::accounts_changed(&emisor, uid).await?;
                }
                Ok(token)
            }
            // El proveedor dice que la autorización ya no vale. Se anota en la
            // cuenta y se avisa: es la diferencia entre «reconectá esta cuenta»
            // y un error de red que se repite para siempre sin decir qué hacer.
            Err(protocols::oauth2::TokenError::Revoked(detalle)) => {
                tracing::warn!("'{account_id}' necesita reautenticación: {detalle}");
                if marcar_reauth(uid, &account_id, true)? {
                    Self::accounts_changed(&emisor, uid).await?;
                }
                Err(FdoError::Failed(format!(
                    "hay que volver a conectar la cuenta: {detalle}"
                )))
            }
            Err(otro) => Err(FdoError::Failed(format!("Error al obtener token: {otro}"))),
        }
    }
}

/// Interpreta la lista de capacidades que llegó como JSON.
///
/// Acepta `["email","calendar"]`. Un nombre desconocido se rechaza nombrando los
/// válidos, en vez de conectar una cuenta a la que después le falte la mitad de
/// lo que la persona creía haber pedido.
fn parse_capabilities(json: &str) -> zbus::fdo::Result<Vec<CapabilityType>> {
    let nombres: Vec<String> = serde_json::from_str(json).map_err(|e| {
        FdoError::InvalidArgs(format!(
            "capabilities tiene que ser una lista JSON de nombres, como \
             [\"email\",\"calendar\"]: {e}"
        ))
    })?;

    let mut capacidades = Vec::new();
    for nombre in nombres {
        let capacidad: CapabilityType = nombre
            .parse()
            .map_err(|e: storage::UnknownCapability| FdoError::InvalidArgs(e.to_string()))?;
        // Sin repetir: pedir dos veces lo mismo duplicaría los alcances y hay
        // proveedores que responden error por eso.
        if !capacidades.contains(&capacidad) {
            capacidades.push(capacidad);
        }
    }
    Ok(capacidades)
}

/// Guarda los tokens de una cuenta recién conectada.
///
/// El `client_secret` se guarda con la cuenta y no se lee del catálogo cada vez:
/// si mañana cambia el archivo de `/etc`, las cuentas ya conectadas siguen
/// renovándose con el secreto con el que se autorizaron.
fn guardar_secretos_de_oauth(
    uid: u32,
    account_id: &str,
    proveedor: &providers::Provider,
    frescos: &protocols::oauth2::FreshTokens,
) -> zbus::fdo::Result<()> {
    let guardar = |clave: &str, valor: &str| -> zbus::fdo::Result<()> {
        storage::SecretStore::store_secret(uid, account_id, clave, valor)
            .map_err(|e| FdoError::Failed(format!("Error al guardar '{clave}': {e}")))
    };

    guardar("access", &frescos.access)?;
    if let Some(refresh) = &frescos.refresh {
        guardar("refresh", refresh)?;
    }
    if let Some(secreto) = proveedor.client_secret.as_deref().filter(|s| !s.is_empty()) {
        guardar("client_secret", secreto)?;
    }
    Ok(())
}

/// Escribe la marca de reautenticación. Devuelve si cambió algo.
fn marcar_reauth(uid: u32, account_id: &str, necesita: bool) -> zbus::fdo::Result<bool> {
    let mut db = open_db(uid)?;
    db.set_needs_reauth(account_id, necesita)
        .map_err(|e| FdoError::Failed(format!("Error al marcar la cuenta: {e}")))
}


/// The system bus, always, in a released build.
///
/// Debug builds can be pointed at a session bus to exercise the whole chain
/// without root. Compiled out of release entirely rather than guarded at
/// runtime: a token broker that could be moved onto a bus the user controls
/// would be handing its requests to whatever claimed the name there.
#[cfg(debug_assertions)]
fn service_bus() -> zbus::Result<zbus::connection::Builder<'static>> {
    if std::env::var_os("VASAK_ACCOUNTS_TEST_ROOT").is_some() {
        tracing::warn!("MODO DE DESARROLLO: usando el bus de sesión");
        return zbus::connection::Builder::session();
    }
    zbus::connection::Builder::system()
}

#[cfg(not(debug_assertions))]
fn service_bus() -> zbus::Result<zbus::connection::Builder<'static>> {
    zbus::connection::Builder::system()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Inicializamos el logging con tracing.
    // La variable de entorno RUST_LOG permite filtrar niveles:
    //   RUST_LOG=info   → mensajes info y superiores (por defecto)
    //   RUST_LOG=debug  → mensajes debug e info
    //   RUST_LOG=trace  → todos los mensajes (más verboso)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    tracing::info!("Iniciando AccountManager…");

    // Construimos la conexión D-Bus en el bus de sesión:
    // 1. Solicitamos el nombre well-known 'ar.net.vasak.os.AccountManager'.
    // 2. Registramos nuestro objeto en la ruta '/ar/net/vasak/os/AccountManager'.
    // The system bus, as root. The tokens live in root-owned files now, so the
    // daemon has to be somewhere a program running as the user cannot be: a
    // service in the session could be replaced by anything that got there
    // first, and would be able to read the files it serves.
    let _connection = service_bus()
        .map_err(|e| format!("Error al conectar al bus del sistema: {}", e))?
        .name("ar.net.vasak.os.AccountManager")
        .map_err(|e| format!("Error al solicitar nombre D-Bus: {}", e))?
        .serve_at("/ar/net/vasak/os/AccountManager", AccountManager::default())
        .map_err(|e| format!("Error al registrar el servicio: {}", e))?
        .build()
        .await?;

    tracing::info!(
        "AccountManager corriendo en 'ar.net.vasak.os.AccountManager' \
         (objeto en '/ar/net/vasak/os/AccountManager')"
    );

    tracing::info!("Esperando peticiones… (Ctrl+C para detener)");

    // Mantenemos el proceso vivo hasta recibir Ctrl+C
    tokio::signal::ctrl_c().await?;

    tracing::info!("AccountManager detenido");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn una_lista_de_capacidades_se_interpreta() {
        assert_eq!(
            parse_capabilities(r#"["email","calendar"]"#).unwrap(),
            vec![CapabilityType::Email, CapabilityType::Calendar],
        );
        assert_eq!(parse_capabilities("[]").unwrap(), vec![]);
    }

    /// Un nombre desconocido se rechaza en vez de ignorarse. Ignorarlo dejaría
    /// una cuenta conectada a la que le falta la mitad de lo que la persona
    /// creyó pedir, y el fallo aparecería recién cuando la app de calendario no
    /// encontrara nada.
    #[test]
    fn un_nombre_desconocido_frena_todo() {
        let error = parse_capabilities(r#"["email","calendario"]"#).unwrap_err();
        assert!(error.to_string().contains("calendario"), "{error}");
        assert!(error.to_string().contains("calendar"), "tiene que decir los válidos: {error}");
    }

    /// Pedir dos veces lo mismo duplicaría los alcances en la URL, y hay
    /// proveedores que responden error por eso.
    #[test]
    fn las_capacidades_repetidas_se_piden_una_sola_vez() {
        assert_eq!(
            parse_capabilities(r#"["email","email","calendar"]"#).unwrap(),
            vec![CapabilityType::Email, CapabilityType::Calendar],
        );
    }

    #[test]
    fn lo_que_no_es_una_lista_de_nombres_se_rechaza() {
        for malo in ["", "email", "{}", r#"{"email":true}"#, "[1,2]", "[null]", "[[\"email\"]]"] {
            assert!(
                parse_capabilities(malo).is_err(),
                "{malo:?} tenía que rechazarse"
            );
        }
    }

    /// El error de un JSON mal armado tiene que mostrar la forma esperada: es un
    /// error que ve quien programa una aplicación cliente.
    #[test]
    fn el_error_de_formato_muestra_un_ejemplo() {
        let error = parse_capabilities("no es json").unwrap_err().to_string();
        assert!(error.contains("[\"email\",\"calendar\"]"), "{error}");
    }

    /// `RegisterAccount` es para contraseñas escritas a mano. Los secretos de
    /// OAuth salen de `CompleteAuth`, que además guarda las URLs para renovar:
    /// aceptarlos por el otro camino dejaría cuentas que no se pueden refrescar.
    #[test]
    fn los_secretos_de_oauth_estan_nombrados() {
        assert!(SECRETOS_DE_OAUTH.contains(&"refresh"));
        assert!(SECRETOS_DE_OAUTH.contains(&"client_secret"));
        // `access` no está: una contraseña de aplicación de IMAP se guarda ahí y
        // sí se registra por RegisterAccount.
        assert!(!SECRETOS_DE_OAUTH.contains(&"access"));
    }
}
