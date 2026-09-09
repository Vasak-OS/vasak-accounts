use crate::providers::Provider;
use crate::storage::{Account, AccountDatabase, CapabilityType, SecretStore};
use chrono::{DateTime, Utc};
use oauth2::basic::{BasicClient, BasicErrorResponseType};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RefreshToken, RequestTokenError, Scope, TokenUrl,
};
use oauth2::TokenResponse;

/// Cuánta vida le tiene que quedar a un token para darlo sin refrescarlo.
///
/// Si se entregara un token que expira en diez segundos, la aplicación armaría
/// su pedido, lo mandaría, y se lo rechazarían — con un error que parece del
/// servidor y es de acá.
const MARGEN: chrono::TimeDelta = chrono::TimeDelta::minutes(5);

/// Lo que el proveedor devolvió al canjear un código o refrescar un token.
pub struct FreshTokens {
    pub access: String,
    pub refresh: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Por qué falló hablar con el proveedor.
#[derive(Debug)]
pub enum TokenError {
    /// El proveedor dice que la autorización ya no vale: la persona la revocó,
    /// cambió la contraseña, o el refresh_token caducó por no usarse.
    ///
    /// Se distingue del resto porque es el único caso en que la cuenta hay que
    /// marcarla para volver a autorizar. Un corte de red no significa eso, y
    /// tratarlos igual mandaría a reconectar cuentas que están perfectas cada
    /// vez que se cae el wifi.
    Revoked(String),
    Failed(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Revoked(detalle) => write!(
                f,
                "el proveedor ya no acepta esta autorización ({detalle}); \
                 hay que volver a conectar la cuenta"
            ),
            TokenError::Failed(detalle) => write!(f, "{detalle}"),
        }
    }
}

impl std::error::Error for TokenError {}

/// El cliente HTTP con el que se habla con el proveedor.
///
/// Sin redirecciones: un endpoint de token que responde con un redirect es un
/// endpoint que quiere mandar el `client_secret` y el código a otra parte.
fn http_client() -> Result<reqwest::Client, TokenError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| TokenError::Failed(format!("no se pudo crear el cliente HTTP: {e}")))
}

fn oauth_client(
    provider: &Provider,
    redirect_uri: Option<&str>,
) -> Result<BasicClient<oauth2::EndpointSet, oauth2::EndpointNotSet, oauth2::EndpointNotSet, oauth2::EndpointNotSet, oauth2::EndpointSet>, TokenError> {
    let client_id = provider
        .client_id
        .clone()
        .ok_or_else(|| TokenError::Failed("el proveedor no tiene client_id".into()))?;

    // Obligatorias para OAuth2. Un proveedor sin ellas es de otro tipo de flujo
    // —el catálogo los distingue— y no tendría que haber llegado hasta acá.
    let falta = |campo: &str| {
        TokenError::Failed(format!("el proveedor '{}' no tiene {campo}", provider.id))
    };

    let mut cliente = BasicClient::new(ClientId::new(client_id))
        .set_auth_uri(
            AuthUrl::new(provider.auth_url.clone().ok_or_else(|| falta("auth_url"))?)
                .map_err(|e| TokenError::Failed(format!("auth_url inválida: {e}")))?,
        )
        .set_token_uri(
            TokenUrl::new(provider.token_url.clone().ok_or_else(|| falta("token_url"))?)
                .map_err(|e| TokenError::Failed(format!("token_url inválida: {e}")))?,
        );

    if let Some(secreto) = provider.client_secret.clone().filter(|s| !s.is_empty()) {
        cliente = cliente.set_client_secret(ClientSecret::new(secreto));
    }

    if let Some(uri) = redirect_uri {
        cliente = cliente.set_redirect_uri(
            RedirectUrl::new(uri.to_string())
                .map_err(|e| TokenError::Failed(format!("redirect_uri inválida: {e}")))?,
        );
    }

    Ok(cliente)
}

/// Arma la URL a la que hay que mandar el navegador, y el verifier que hay que
/// guardar para el canje.
///
/// El verifier se queda del lado del servicio: es lo único que impide que un
/// código de autorización robado sirva para algo, y por eso este paso dejó de
/// vivir en la ventana de configuración.
pub fn authorization_url(
    provider: &Provider,
    capabilities: &[CapabilityType],
    redirect_uri: &str,
) -> Result<(String, String, String), TokenError> {
    let cliente = oauth_client(provider, Some(redirect_uri))?;
    let (desafio, verifier) = PkceCodeChallenge::new_random_sha256();
    let state = CsrfToken::new_random();

    let mut pedido = cliente
        .authorize_url(|| state.clone())
        .set_pkce_challenge(desafio);

    // Los alcances de todas las capacidades pedidas, juntos: así la persona ve
    // una sola pantalla de consentimiento en vez de una por capacidad.
    //
    // Sin repetir. Google devuelve error si el mismo alcance viene dos veces, y
    // dos capacidades del mismo proveedor comparten alcances a menudo.
    let mut vistos = std::collections::BTreeSet::new();
    for capacidad in capabilities {
        for alcance in provider.scopes.get(capacidad).into_iter().flatten() {
            if vistos.insert(alcance.clone()) {
                pedido = pedido.add_scope(Scope::new(alcance.clone()));
            }
        }
    }

    for (nombre, valor) in &provider.extra_auth_params {
        pedido = pedido.add_extra_param(nombre.clone(), valor.clone());
    }

    let (url, state) = pedido.url();
    Ok((url.to_string(), verifier.into_secret(), state.into_secret()))
}

/// Canjea el código de autorización por los tokens.
pub async fn exchange_code(
    provider: &Provider,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<FreshTokens, TokenError> {
    let cliente = oauth_client(provider, Some(redirect_uri))?;

    let respuesta = cliente
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()))
        .request_async(&http_client()?)
        .await
        .map_err(clasificar_error)?;

    let refresh = respuesta.refresh_token().map(|t| t.secret().to_string());
    if refresh.is_none() {
        // No es un error, pero es el que después se ve como «la cuenta dejó de
        // andar en una hora y nadie sabe por qué».
        tracing::warn!(
            "el proveedor '{}' no devolvió refresh_token; la cuenta va a pedir \
             reautenticación cuando expire el access_token",
            provider.id,
        );
    }

    Ok(FreshTokens {
        access: respuesta.access_token().secret().to_string(),
        refresh,
        expires_at: vencimiento(respuesta.expires_in()),
    })
}

/// Traduce el error del proveedor a algo con lo que se pueda decidir.
///
/// Lo único que importa distinguir es `invalid_grant`: es la respuesta con la
/// que el proveedor dice «esta autorización ya no vale». Todo lo demás —red
/// caída, endpoint mal escrito, respuesta ilegible— es un fallo pasajero o de
/// configuración, y marcar la cuenta para reconectar por un corte de wifi
/// mandaría a rehacer el flujo de cuentas que están perfectas.
fn clasificar_error<RE, TE>(error: RequestTokenError<RE, TE>) -> TokenError
where
    RE: std::error::Error,
    TE: oauth2::ErrorResponse,
{
    if let RequestTokenError::ServerResponse(respuesta) = &error {
        let cuerpo = format!("{respuesta}");
        if cuerpo.contains(BasicErrorResponseType::InvalidGrant.as_ref()) {
            return TokenError::Revoked(cuerpo);
        }
        return TokenError::Failed(format!("el proveedor rechazó el pedido: {cuerpo}"));
    }
    TokenError::Failed(format!("no se pudo hablar con el proveedor: {error}"))
}

fn vencimiento(expires_in: Option<std::time::Duration>) -> Option<DateTime<Utc>> {
    let duracion = expires_in?;
    Some(Utc::now() + chrono::Duration::from_std(duracion).ok()?)
}

/// Un access_token **válido** para la cuenta y capacidad indicadas.
///
/// Si el guardado tiene más de cinco minutos de vida, se devuelve tal cual. Si
/// no, se lo cambia por uno nuevo con el refresh_token y se persiste el
/// resultado.
///
/// Un `TokenError::Revoked` acá significa que la cuenta hay que reconectarla, y
/// quien llama la marca. Lo que **no** hace esta función es marcarla: el
/// almacén lo escribe el que atiende la petición, que es el que también tiene
/// que avisar por la señal.
pub async fn get_valid_access_token(
    uid: u32,
    account_id: &str,
    capability: &CapabilityType,
) -> Result<String, TokenError> {
    let mut db = AccountDatabase::for_user(uid)
        .map_err(|e| TokenError::Failed(format!("no se pudo abrir la base: {e}")))?;
    db.load()
        .map_err(|e| TokenError::Failed(format!("no se pudieron cargar las cuentas: {e}")))?;

    let cuenta = db
        .get(account_id)
        .ok_or_else(|| TokenError::Failed(format!("la cuenta '{account_id}' no existe")))?
        .clone();

    let config = cuenta
        .capabilities
        .get(capability)
        .ok_or_else(|| {
            TokenError::Failed(format!(
                "la cuenta no tiene configurado '{}'",
                capability.as_id()
            ))
        })?
        .clone();

    let access = SecretStore::get_token(uid, account_id)
        .map_err(|e| TokenError::Failed(format!("no se pudo leer el access_token: {e}")))?;

    let expires_at = config
        .get("expires_at")
        .and_then(|v| v.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let Some(expira) = expires_at else {
        // Sin vencimiento no hay nada que refrescar: es el caso de una
        // contraseña de aplicación de IMAP, que vale hasta que se revoque.
        tracing::debug!("'{account_id}' no tiene vencimiento; se entrega tal cual");
        return Ok(access);
    };

    if Utc::now() + MARGEN < expira {
        tracing::debug!("'{account_id}' sigue válido hasta {expira}");
        return Ok(access);
    }

    tracing::info!("'{account_id}' expira {expira}; refrescando");
    let frescos = refresh(uid, &cuenta, &config).await?;

    persistir(uid, &cuenta, capability, &config, &frescos)?;
    Ok(frescos.access)
}

/// Cambia el refresh_token por tokens nuevos.
///
/// El proveedor se reconstruye desde la configuración guardada en la cuenta y
/// no desde el catálogo. Es a propósito: si mañana alguien cambia el archivo de
/// `/etc`, las cuentas que ya están conectadas siguen hablando con el servidor
/// al que autorizaron, y no con el que dice el archivo nuevo.
async fn refresh(
    uid: u32,
    cuenta: &Account,
    config: &serde_json::Value,
) -> Result<FreshTokens, TokenError> {
    let refresh_token = SecretStore::get_secret(uid, &cuenta.id, "refresh").map_err(|e| {
        // No tener refresh_token guardado no es un fallo pasajero: la cuenta no
        // se puede renovar nunca más, así que es exactamente el caso en que hay
        // que volver a autorizar.
        TokenError::Revoked(format!("no hay refresh_token guardado: {e}"))
    })?;

    let provider = provider_desde_config(uid, cuenta, config)?;
    let cliente = oauth_client(&provider, None)?;

    let respuesta = cliente
        .exchange_refresh_token(&RefreshToken::new(refresh_token))
        .request_async(&http_client()?)
        .await
        .map_err(clasificar_error)?;

    Ok(FreshTokens {
        access: respuesta.access_token().secret().to_string(),
        // Algunos proveedores rotan el refresh_token en cada uso y otros no
        // devuelven ninguno. Si no vino, el que ya estaba sigue sirviendo.
        refresh: respuesta.refresh_token().map(|t| t.secret().to_string()),
        expires_at: vencimiento(respuesta.expires_in()),
    })
}

/// Reconstruye el proveedor desde lo que quedó guardado al conectar la cuenta.
fn provider_desde_config(
    uid: u32,
    cuenta: &Account,
    config: &serde_json::Value,
) -> Result<Provider, TokenError> {
    let campo = |nombre: &str| -> Result<String, TokenError> {
        config
            .get(nombre)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| {
                TokenError::Failed(format!(
                    "la cuenta '{}' no tiene '{nombre}' guardado; \
                     se conectó con una versión anterior y hay que reconectarla",
                    cuenta.id,
                ))
            })
    };

    Ok(Provider {
        id: cuenta.provider_type.clone(),
        display_name: cuenta.provider_type.clone(),
        kind: crate::providers::ProviderKind::Oauth2,
        auth_url: Some(campo("auth_url")?),
        token_url: Some(campo("token_url")?),
        client_id: Some(campo("client_id")?),
        // Si el proveedor no usa secreto no hay ninguno guardado, y eso es
        // normal: no puede ser un error.
        client_secret: SecretStore::get_secret(uid, &cuenta.id, "client_secret").ok(),
        scopes: Default::default(),
        extra_auth_params: Default::default(),
        capabilities: Default::default(),
    })
}

/// Guarda los tokens nuevos y su vencimiento.
///
/// El access_token primero. Si se guardara el vencimiento antes y algo fallara
/// en el medio, quedaría una fecha nueva describiendo un token viejo, y nadie
/// volvería a refrescarlo hasta que esa fecha llegara.
pub fn persistir(
    uid: u32,
    cuenta: &Account,
    capability: &CapabilityType,
    config: &serde_json::Value,
    frescos: &FreshTokens,
) -> Result<(), TokenError> {
    SecretStore::store_token(uid, &cuenta.id, &frescos.access)
        .map_err(|e| TokenError::Failed(format!("no se pudo guardar el access_token: {e}")))?;

    if let Some(refresh) = &frescos.refresh {
        SecretStore::store_secret(uid, &cuenta.id, "refresh", refresh)
            .map_err(|e| TokenError::Failed(format!("no se pudo guardar el refresh_token: {e}")))?;
    }

    let Some(expira) = frescos.expires_at else {
        tracing::warn!("el proveedor no dijo cuándo expira el token de '{}'", cuenta.id);
        return Ok(());
    };

    let mut nueva_config = config.clone();
    if let Some(objeto) = nueva_config.as_object_mut() {
        objeto.insert("expires_at".into(), serde_json::Value::String(expira.to_rfc3339()));
    }

    let mut db = AccountDatabase::for_user(uid)
        .map_err(|e| TokenError::Failed(format!("no se pudo reabrir la base: {e}")))?;
    db.load()
        .map_err(|e| TokenError::Failed(format!("no se pudieron recargar las cuentas: {e}")))?;

    let mut actualizada = match db.get(&cuenta.id) {
        Some(actual) => actual.clone(),
        // Si la borraron mientras hablábamos con el proveedor, no hay que
        // resucitarla: el token que acabamos de guardar lo limpia el borrado.
        None => return Ok(()),
    };
    actualizada.capabilities.insert(*capability, nueva_config);
    db.update_account(actualizada)
        .map_err(|e| TokenError::Failed(format!("no se pudo actualizar la cuenta: {e}")))?;

    tracing::info!("token de '{}' refrescado, expira {expira}", cuenta.id);
    Ok(())
}

/// La configuración que se guarda en la capacidad al conectar una cuenta.
///
/// Es lo que hace que el refresco pueda funcionar más adelante: sin `client_id`,
/// `token_url` y `expires_at` guardados, el motor de refresco no tiene con qué
/// hablarle al proveedor ni cómo saber que hace falta. Antes se guardaba sólo el
/// access_token, y la cuenta se moría en una hora sin decir por qué.
pub fn capability_config(
    provider: &Provider,
    capability: &CapabilityType,
    frescos: &FreshTokens,
) -> serde_json::Value {
    serde_json::json!({
        "client_id": provider.client_id,
        "auth_url": provider.auth_url,
        "token_url": provider.token_url,
        "scopes": provider.scopes.get(capability).cloned().unwrap_or_default(),
        "expires_at": frescos.expires_at.map(|e| e.to_rfc3339()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn proveedor() -> Provider {
        let mut scopes = HashMap::new();
        scopes.insert(
            CapabilityType::Calendar,
            vec!["https://www.googleapis.com/auth/calendar".to_string()],
        );
        // Comparte un alcance con calendario a propósito: es el caso que hace
        // que Google devuelva error si se manda repetido.
        scopes.insert(
            CapabilityType::Contacts,
            vec![
                "https://www.googleapis.com/auth/calendar".to_string(),
                "https://www.googleapis.com/auth/contacts".to_string(),
            ],
        );

        let mut extra = HashMap::new();
        extra.insert("access_type".to_string(), "offline".to_string());

        Provider {
            id: "google".into(),
            display_name: "Google".into(),
            kind: crate::providers::ProviderKind::Oauth2,
            auth_url: Some("https://accounts.google.com/o/oauth2/v2/auth".into()),
            token_url: Some("https://oauth2.googleapis.com/token".into()),
            client_id: Some("el-client-id".into()),
            client_secret: None,
            scopes,
            extra_auth_params: extra,
            capabilities: Vec::new(),
        }
    }

    /// El desafío de PKCE en la URL y el verifier fuera de ella. Es toda la
    /// propiedad que hace que el `code` que maneja la ventana no sea un secreto.
    #[test]
    fn la_url_lleva_el_desafio_de_pkce_y_no_el_verifier() {
        let (url, verifier, _state) = authorization_url(
            &proveedor(),
            &[CapabilityType::Calendar],
            "http://127.0.0.1:45321/callback",
        )
        .unwrap();

        assert!(url.contains("code_challenge="), "falta el desafío: {url}");
        assert!(url.contains("code_challenge_method=S256"), "{url}");
        assert!(!verifier.is_empty());
        assert!(
            !url.contains(&verifier),
            "el verifier no puede viajar en la URL que abre el navegador"
        );
    }

    /// Dos flujos no pueden compartir verifier ni state: si lo hicieran, un
    /// código robado de un flujo serviría para completar otro.
    #[test]
    fn cada_flujo_tiene_su_propio_verifier_y_state() {
        let destino = "http://127.0.0.1:45321/callback";
        let (_, verifier_a, state_a) =
            authorization_url(&proveedor(), &[CapabilityType::Calendar], destino).unwrap();
        let (_, verifier_b, state_b) =
            authorization_url(&proveedor(), &[CapabilityType::Calendar], destino).unwrap();

        assert_ne!(verifier_a, verifier_b);
        assert_ne!(state_a, state_b);
    }

    /// Un alcance repetido hace que Google rechace el pedido entero, y dos
    /// capacidades del mismo proveedor comparten alcances a menudo.
    #[test]
    fn un_alcance_compartido_no_se_manda_dos_veces() {
        let (url, _, _) = authorization_url(
            &proveedor(),
            &[CapabilityType::Calendar, CapabilityType::Contacts],
            "http://127.0.0.1:45321/callback",
        )
        .unwrap();

        let parseada = url::Url::parse(&url).unwrap();
        let scope = parseada
            .query_pairs()
            .find(|(k, _)| k == "scope")
            .map(|(_, v)| v.to_string())
            .expect("la URL tiene que llevar scope");

        let veces = scope.split(' ').filter(|s| s.ends_with("/calendar")).count();
        assert_eq!(veces, 1, "el alcance de calendario se mandó {veces} veces: {scope}");
        assert!(scope.contains("/contacts"), "falta el de contactos: {scope}");
    }

    /// Sin `access_type=offline` Google no devuelve refresh_token, y la cuenta
    /// se muere en una hora sin que nada lo explique. Por eso el catálogo puede
    /// poner parámetros extra, y por eso hay que comprobar que lleguen.
    #[test]
    fn los_parametros_extra_del_catalogo_llegan_a_la_url() {
        let (url, _, _) = authorization_url(
            &proveedor(),
            &[CapabilityType::Calendar],
            "http://127.0.0.1:45321/callback",
        )
        .unwrap();

        assert!(url.contains("access_type=offline"), "{url}");
        assert!(url.contains("redirect_uri="), "{url}");
        assert!(url.contains("client_id=el-client-id"), "{url}");
        assert!(url.contains("response_type=code"), "{url}");
    }

    #[test]
    fn sin_client_id_no_se_arma_ninguna_url() {
        let mut sin_id = proveedor();
        sin_id.client_id = None;

        assert!(authorization_url(
            &sin_id,
            &[CapabilityType::Calendar],
            "http://127.0.0.1:45321/callback"
        )
        .is_err());
    }

    /// La configuración que se guarda en la cuenta es lo que hace posible el
    /// refresco más adelante. Antes se guardaba sólo el access_token, y sin
    /// `client_id`/`token_url`/`expires_at` el motor no tenía con qué hablarle
    /// al proveedor ni cómo saber que hacía falta.
    #[test]
    fn la_configuracion_guardada_alcanza_para_refrescar() {
        let vence = Utc::now() + chrono::Duration::hours(1);
        let frescos = FreshTokens {
            access: "el-access".into(),
            refresh: Some("el-refresh".into()),
            expires_at: Some(vence),
        };

        let config = capability_config(&proveedor(), &CapabilityType::Calendar, &frescos);

        assert_eq!(config["client_id"], "el-client-id");
        assert_eq!(config["token_url"], "https://oauth2.googleapis.com/token");
        assert_eq!(config["auth_url"], "https://accounts.google.com/o/oauth2/v2/auth");
        assert_eq!(config["expires_at"], vence.to_rfc3339());
        assert_eq!(
            config["scopes"][0],
            "https://www.googleapis.com/auth/calendar"
        );

        // Y ningún token adentro: accounts.json no es donde viven los secretos.
        let texto = config.to_string();
        assert!(!texto.contains("el-access") && !texto.contains("el-refresh"), "{texto}");
    }

    /// Un proveedor que no dice cuándo expira deja `expires_at` en nulo, y eso
    /// significa «no refrescar», no «refrescar ya».
    #[test]
    fn sin_vencimiento_la_configuracion_lo_deja_nulo() {
        let frescos = FreshTokens {
            access: "el-access".into(),
            refresh: None,
            expires_at: None,
        };
        let config = capability_config(&proveedor(), &CapabilityType::Calendar, &frescos);
        assert!(config["expires_at"].is_null());
    }

    /// El margen es lo que impide entregar un token que expira mientras la
    /// aplicación arma su pedido.
    #[test]
    fn el_margen_es_de_cinco_minutos() {
        assert_eq!(MARGEN, chrono::TimeDelta::minutes(5));
    }

    /// `Revoked` y `Failed` se tratan distinto: uno manda a reconectar la cuenta
    /// y el otro no, así que el mensaje tiene que dejar claro cuál es cuál.
    #[test]
    fn el_error_de_revocado_dice_que_hay_que_reconectar() {
        let revocado = TokenError::Revoked("invalid_grant".into()).to_string();
        assert!(revocado.contains("volver a conectar"), "{revocado}");

        let otro = TokenError::Failed("se cayó la red".into()).to_string();
        assert!(!otro.contains("volver a conectar"), "{otro}");
    }
}
