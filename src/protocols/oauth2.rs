use crate::storage::{AccountDatabase, CapabilityType, SecureKeyringManager};
use chrono::{DateTime, Utc};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RefreshToken, TokenUrl};
use oauth2::TokenResponse;

/// Recupera un access_token **válido** (no expirado) para la cuenta y
/// capability indicadas.
///
/// 1. Carga los metadatos de la cuenta desde `accounts.json`.
/// 2. Si el `access_token` almacenado en el llavero tiene más de 5 minutos
///    de vida restante, lo retorna inmediatamente.
/// 3. Si expiró, intercambia el `refresh_token` del llavero por uno nuevo
///    mediante una petición HTTP POST al servidor OAuth2, persiste el nuevo
///    token y su fecha de expiración, y lo retorna.
pub async fn get_valid_access_token(
    account_id: &str,
    capability: &CapabilityType,
) -> Result<String, String> {
    // 1. Cargar metadata de la cuenta
    let mut db =
        AccountDatabase::new().map_err(|e| format!("Error al abrir base de datos: {}", e))?;
    db.load()
        .map_err(|e| format!("Error al cargar cuentas: {}", e))?;

    let account = db
        .get(account_id)
        .ok_or_else(|| format!("Cuenta '{}' no encontrada", account_id))?
        .clone();

    let config = account
        .capabilities
        .get(capability)
        .ok_or_else(|| format!("Capability '{:?}' no configurada en la cuenta", capability))?
        .clone();

    // 2. Parsear expires_at
    let expires_at = config
        .get("expires_at")
        .and_then(|v| v.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    // 3. Obtener access_token actual del llavero
    let access_token = SecureKeyringManager::get_token(account_id)
        .map_err(|e| format!("Error al leer access_token del llavero: {}", e))?;

    // 4. Si sigue siendo válido (más de 5 min de vida), retornar
    if let Some(expires) = expires_at {
        let now = Utc::now();
        let grace = chrono::Duration::minutes(5);
        if now + grace < expires {
            tracing::info!(
                "Token OK — '{}' / '{:?}' expira {}, faltan >5 min",
                account_id,
                capability,
                expires,
            );
            return Ok(access_token);
        }
        tracing::info!(
            "Token expirado para '{}' / '{:?}' (era {}), refrescando…",
            account_id,
            capability,
            expires,
        );
    } else {
        tracing::info!(
            "Token sin expiración para '{}' / '{:?}' — se retorna tal cual",
            account_id,
            capability,
        );
        return Ok(access_token);
    }

    // 5. Recuperar refresh_token + client_secret del llavero
    let refresh_token_str = SecureKeyringManager::get_secret(account_id, "refresh")
        .map_err(|e| format!("Error al leer refresh_token del llavero: {}", e))?;

    let client_secret_str = SecureKeyringManager::get_secret(account_id, "client_secret")
        .map_err(|e| format!("Error al leer client_secret del llavero: {}", e))?;

    // 6. Leer URLs del provider desde la capability config
    let client_id = config
        .get("client_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "client_id requerido en la configuración de la capability".to_string())?;

    let token_url_str = config
        .get("token_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "token_url requerido en la configuración de la capability".to_string())?;

    let auth_url_str = config
        .get("auth_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "auth_url requerido en la configuración de la capability".to_string())?;

    // 7. Construir cliente OAuth2
    let client = BasicClient::new(ClientId::new(client_id.to_string()))
        .set_client_secret(ClientSecret::new(client_secret_str))
        .set_auth_uri(AuthUrl::new(auth_url_str.to_string())
            .map_err(|e| format!("auth_url inválida '{}': {}", auth_url_str, e))?)
        .set_token_uri(TokenUrl::new(token_url_str.to_string())
            .map_err(|e| format!("token_url inválida '{}': {}", token_url_str, e))?);

    // 8. Crear HTTP client (sin redirects por seguridad)
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("Error al crear HTTP client: {}", e))?;

    tracing::info!("Enviando petición de refresco OAuth2 a {}…", token_url_str);

    let token_response = client
        .exchange_refresh_token(&RefreshToken::new(refresh_token_str))
        .request_async(&http_client)
        .await
        .map_err(|e| format!("Error en refresco OAuth2: {}", e))?;

    let new_access_token = token_response.access_token().secret().to_string();
    let new_expires_in = token_response.expires_in();

    // 9. Guardar nuevo access_token en el llavero
    SecureKeyringManager::store_token(account_id, &new_access_token)
        .map_err(|e| format!("Error al guardar nuevo access_token: {}", e))?;

    // 10. Actualizar expires_at en accounts.json
    if let Some(duration) = new_expires_in {
        let new_expires_at = Utc::now()
            + chrono::Duration::from_std(duration)
                .map_err(|_| "Duración de expiración inválida".to_string())?;

        let mut updated_config = config.clone();
        if let Some(obj) = updated_config.as_object_mut() {
            obj.insert(
                "expires_at".to_string(),
                serde_json::Value::String(new_expires_at.to_rfc3339()),
            );
        }

        let mut updated_account = account.clone();
        updated_account
            .capabilities
            .insert(capability.clone(), updated_config);

        let mut db = AccountDatabase::new()
            .map_err(|e| format!("Error al reabrir base de datos: {}", e))?;
        db.load()
            .map_err(|e| format!("Error al recargar cuentas: {}", e))?;
        db.update_account(updated_account)
            .map_err(|e| format!("Error al actualizar cuenta: {}", e))?;

        tracing::info!("Token refrescado — nuevo expires_at: {}", new_expires_at);
    } else {
        tracing::warn!("El servidor OAuth2 no devolvió 'expires_in'");
    }

    Ok(new_access_token)
}
