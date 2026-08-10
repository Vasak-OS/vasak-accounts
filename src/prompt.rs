//! Asking the user whether a program may use one of their accounts.
//!
//! The daemon has no interface of its own — it is headless and runs before any
//! window exists. It asks an *authorization agent*, a process with a screen to
//! draw on (the desktop shell), and remembers the answer so the question is
//! asked once per program and capability rather than on every access.

use std::time::Duration;

use crate::storage::CapabilityType;

pub const AGENT_SERVICE: &str = "org.vasak.Accounts.AuthorizationAgent";
pub const AGENT_PATH: &str = "/org/vasak/Accounts/AuthorizationAgent";
pub const AGENT_INTERFACE: &str = "org.vasak.Accounts.AuthorizationAgent";

/// How long to wait for someone to answer.
///
/// Long enough to read a dialog and think, short enough that a wedged agent
/// eventually releases the program that is waiting instead of hanging it for
/// the rest of the session.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);

/// Asks the agent to put the question to the user.
///
/// Every failure — no agent running, a timeout, a malformed reply — denies.
/// The caller is asking for access to someone's mail and files; the only safe
/// answer to "we could not ask" is no.
pub async fn request_access(
    connection: &zbus::Connection,
    account_id: &str,
    account_name: &str,
    program: &str,
    capability: &CapabilityType,
) -> bool {
    let capability = serde_json::to_string(capability)
        .unwrap_or_default()
        .trim_matches('"')
        .to_string();

    let arguments = (account_id, account_name, program, capability.as_str());
    let call = connection.call_method(
        Some(AGENT_SERVICE),
        AGENT_PATH,
        Some(AGENT_INTERFACE),
        "RequestAccess",
        &arguments,
    );

    let reply = match tokio::time::timeout(ANSWER_TIMEOUT, call).await {
        Ok(Ok(reply)) => reply,
        Ok(Err(error)) => {
            tracing::warn!(
                "No se pudo consultar al agente de autorización ({error}); \
                 se deniega el acceso de '{program}' a '{capability}'"
            );
            return false;
        }
        Err(_) => {
            tracing::warn!(
                "El agente de autorización no respondió en {}s; \
                 se deniega el acceso de '{program}' a '{capability}'",
                ANSWER_TIMEOUT.as_secs()
            );
            return false;
        }
    };

    match reply.body().deserialize::<bool>() {
        Ok(granted) => granted,
        Err(error) => {
            tracing::warn!("Respuesta inválida del agente de autorización: {error}");
            false
        }
    }
}
