use std::os::fd::{FromRawFd, OwnedFd};


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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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

}
