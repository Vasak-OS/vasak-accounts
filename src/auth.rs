use std::os::fd::{FromRawFd, OwnedFd};

use crate::storage::{AccessDecision, Account, CapabilityType};

// ---------------------------------------------------------------------------
// Verification pública
// ---------------------------------------------------------------------------

/// Resuelve la ruta del binario correspondiente a un PID vía `/proc/{pid}/exe`.
///
/// Usado solo por los tests; el camino de producción usa [`PinnedCaller`], que
/// fija el PID antes de leer el ejecutable.
#[cfg(test)]
pub fn resolve_binary_path(pid: u32) -> Result<String, std::io::Error> {
    let link = std::fs::read_link(format!("/proc/{}/exe", pid))?;
    Ok(link.to_string_lossy().into_owned())
}

/// Identidad de un proceso llamante fijada por un `pidfd`.
///
/// Mientras se mantenga abierto el `pidfd`, el kernel **no puede reciclar** ese
/// PID sobre otro proceso, por lo que leer `/proc/{pid}/exe` deja de ser una
/// condición de carrera (TOCTOU): el binario resuelto corresponde con certeza
/// al proceso que originó la llamada D-Bus.
pub struct PinnedCaller {
    pub pid: u32,
    // Se conserva abierto durante toda la verificación; su `Drop` libera el pin.
    _pidfd: OwnedFd,
    pub exe: std::path::PathBuf,
}

impl PinnedCaller {
    /// Fija `pid` con `pidfd_open` (bloqueando el reciclado del PID) y resuelve
    /// su ejecutable. Debe llamarse lo antes posible tras obtener el PID del bus,
    /// para minimizar la ventana previa al pin.
    pub fn capture(pid: u32) -> Result<Self, String> {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        if raw < 0 {
            return Err(format!(
                "pidfd_open({pid}) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: `raw` es un descriptor válido recién devuelto por pidfd_open.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as std::os::fd::RawFd) };

        // El PID ya está fijado: resolver el ejecutable es libre de carreras.
        let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map_err(|e| format!("Failed to resolve /proc/{pid}/exe: {e}"))?;

        Ok(Self { pid, _pidfd: pidfd, exe })
    }
}

/// Verifica si el proceso `caller` (ya fijado por pidfd) tiene permiso para
/// acceder a `requested_capability` en la cuenta `account` según la ACL.
pub fn verify_access(
    account: &Account,
    caller: &PinnedCaller,
    requested_capability: &CapabilityType,
) -> Result<AccessDecision, String> {
    let resolved = std::fs::canonicalize(&caller.exe).unwrap_or_else(|_| caller.exe.clone());
    Ok(decide_access(account, &resolved, requested_capability))
}

/// The decision itself, separated from how the caller was identified so it can
/// be tested without a live process.
fn decide_access(
    account: &Account,
    resolved: &std::path::Path,
    requested_capability: &CapabilityType,
) -> AccessDecision {
    let Some(entry) = account
        .acl
        .iter()
        .find(|e| matches_path(&e.binary_path, resolved))
    else {
        return AccessDecision::Unknown;
    };

    if entry.allowed_capabilities.contains(requested_capability) {
        AccessDecision::Allowed
    } else if entry.denied_capabilities.contains(requested_capability) {
        AccessDecision::Denied
    } else {
        // The program is known but this capability was never decided — a mail
        // client that has been granted email and now asks for the calendar.
        AccessDecision::Unknown
    }
}

/// The path an access decision is recorded against.
///
/// Resolved through the filesystem so a symlinked or relative `/proc/pid/exe`
/// cannot produce a second entry for the same program.
pub fn caller_binary_path(caller: &PinnedCaller) -> String {
    std::fs::canonicalize(&caller.exe)
        .unwrap_or_else(|_| caller.exe.clone())
        .to_string_lossy()
        .into_owned()
}

// ---------------------------------------------------------------------------
// Helpers internos
// ---------------------------------------------------------------------------

fn matches_path(acl_path: &str, actual: &std::path::Path) -> bool {
    let acl_resolved = std::fs::canonicalize(acl_path).unwrap_or_else(|_| std::path::PathBuf::from(acl_path));
    acl_resolved == actual
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::AccessControlEntry;
    use std::collections::HashMap;

    fn test_account() -> Account {
        let mut account = Account::new("Test", "local", HashMap::new());
        account.acl = vec![
            AccessControlEntry {
                binary_path: "/usr/bin/thunderbird".into(),
                allowed_capabilities: vec![CapabilityType::Email],
                denied_capabilities: vec![CapabilityType::Drive],
            },
            AccessControlEntry {
                binary_path: "/usr/bin/rclone".into(),
                allowed_capabilities: vec![CapabilityType::Drive],
                denied_capabilities: Vec::new(),
            },
        ];
        account
    }

    #[test]
    fn test_resolve_own_pid() {
        let path = resolve_binary_path(std::process::id()).unwrap();
        // Solo verificamos que se haya resuelto a algo (path absoluto)
        assert!(path.starts_with('/'), "expected absolute path, got: {}", path);
    }

    #[test]
    fn test_resolve_nonexistent_pid() {
        let result = resolve_binary_path(999_999_999);
        assert!(result.is_err());
    }

    #[test]
    fn test_matches_path_false() {
        assert!(!matches_path("/usr/bin/thunderbird", std::path::Path::new("/usr/bin/nonexistent")));
    }

    fn decide(program: &str, capability: CapabilityType) -> AccessDecision {
        decide_access(&test_account(), std::path::Path::new(program), &capability)
    }

    #[test]
    fn a_granted_capability_is_allowed() {
        assert_eq!(
            decide("/usr/bin/thunderbird", CapabilityType::Email),
            AccessDecision::Allowed
        );
    }

    #[test]
    fn a_refused_capability_stays_refused_without_asking_again() {
        assert_eq!(
            decide("/usr/bin/thunderbird", CapabilityType::Drive),
            AccessDecision::Denied
        );
    }

    /// A program nobody has decided on is not denied — it is unknown, which is
    /// what triggers the question. Treating it as a refusal is what made every
    /// account created from the interface unusable by every application.
    #[test]
    fn an_unseen_program_is_asked_about() {
        assert_eq!(
            decide("/usr/bin/some-new-app", CapabilityType::Email),
            AccessDecision::Unknown
        );
    }

    /// Granting one capability must not answer for the others.
    #[test]
    fn a_known_program_asking_for_something_new_is_asked_again() {
        assert_eq!(
            decide("/usr/bin/rclone", CapabilityType::Email),
            AccessDecision::Unknown
        );
        assert_eq!(
            decide("/usr/bin/rclone", CapabilityType::Drive),
            AccessDecision::Allowed
        );
    }
}
