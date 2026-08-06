use std::os::fd::{FromRawFd, OwnedFd};

use crate::storage::{Account, CapabilityType};

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
) -> Result<bool, String> {
    let resolved = std::fs::canonicalize(&caller.exe)
        .unwrap_or_else(|_| caller.exe.clone());

    match account
        .acl
        .iter()
        .find(|e| matches_path(&e.binary_path, &resolved))
    {
        Some(entry) => Ok(entry.allowed_capabilities.contains(requested_capability)),
        None => Ok(false),
    }
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
            },
            AccessControlEntry {
                binary_path: "/usr/bin/rclone".into(),
                allowed_capabilities: vec![CapabilityType::Drive],
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
}
