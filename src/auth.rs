use crate::storage::{Account, CapabilityType};

// ---------------------------------------------------------------------------
// Verification pública
// ---------------------------------------------------------------------------

/// Resuelve la ruta del binario correspondiente a un PID vía `/proc/{pid}/exe`.
pub fn resolve_binary_path(pid: u32) -> Result<String, std::io::Error> {
    let link = std::fs::read_link(format!("/proc/{}/exe", pid))?;
    Ok(link.to_string_lossy().into_owned())
}

/// Verifica si el proceso identificado por `client_pid` tiene permiso para
/// acceder a `requested_capability` en la cuenta `account` según la ACL.
pub fn verify_access(
    account: &Account,
    client_pid: u32,
    requested_capability: &CapabilityType,
) -> Result<bool, String> {
    let binary_path = resolve_binary_path(client_pid)
        .map_err(|e| format!("Failed to resolve PID {}: {}", client_pid, e))?;

    let resolved = std::fs::canonicalize(&binary_path)
        .unwrap_or_else(|_| std::path::PathBuf::from(&binary_path));

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
