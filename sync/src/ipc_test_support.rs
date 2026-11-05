//! Ayudantes compartidos de las pruebas de IPC de identidad (`smime_ipc_tests`,
//! `pgp_ipc_tests`): los descriptores que manda la ventana (memfd sellado, sin
//! sellar, pipe, archivo común) y el nombre corto de un error D-Bus.

use crate::test_bus::error_of;

pub(crate) const NAME_PREFIX: &str = "ar.net.vasak.os.AccountsSync.";

/// Un memfd sellado con estos bytes, como lo manda el cliente: la clave y la
/// contraseña viajan por descriptor, no como `ay`. Sella contra escritura (y
/// contra crecer/encoger) para que el servicio lo acepte.
pub(crate) fn sealed_fd(bytes: &[u8]) -> zbus::zvariant::OwnedFd {
    use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};
    use std::io::Write;

    let fd = memfd_create(
        "ipc-prueba",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .unwrap();
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes).unwrap();
    fcntl_add_seals(
        &file,
        SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
    )
    .unwrap();
    std::os::fd::OwnedFd::from(file).into()
}

/// Un memfd con estos bytes pero **sin sellar**: el que manda un cliente que
/// podría seguir escribiendo después de que el servicio validó (TOCTOU).
pub(crate) fn unsealed_fd(bytes: &[u8]) -> zbus::zvariant::OwnedFd {
    use rustix::fs::{memfd_create, MemfdFlags};
    use std::io::Write;

    let fd = memfd_create(
        "ipc-prueba-sin-sello",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )
    .unwrap();
    let mut file = std::fs::File::from(fd);
    file.write_all(bytes).unwrap();
    std::os::fd::OwnedFd::from(file).into()
}

/// El extremo de lectura de un pipe con estos bytes ya escritos. El de escritura
/// se cierra: si el servicio llegara a leerlo, termina en EOF en vez de colgarse.
pub(crate) fn pipe_fd(bytes: &[u8]) -> zbus::zvariant::OwnedFd {
    use std::io::Write;

    let (reader, mut writer) = std::io::pipe().unwrap();
    writer.write_all(bytes).unwrap();
    drop(writer);
    std::os::fd::OwnedFd::from(reader).into()
}

/// Un archivo común en disco (no un memfd) con estos bytes: no admite sellos.
pub(crate) fn regular_file_fd(bytes: &[u8]) -> zbus::zvariant::OwnedFd {
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Sin crate de temporales: se crea, se abre y se borra el nombre al instante.
    // El contador evita choques entre pruebas que corren a la vez.
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "vasak-ipc-prueba-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = std::fs::File::create_new(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    file.write_all(bytes).unwrap();
    std::os::fd::OwnedFd::from(file).into()
}

/// El nombre corto del error (`WrongPassword`…), sin el prefijo del servicio.
pub(crate) fn short_name(result: zbus::Result<zbus::Message>) -> String {
    let (name, _) = error_of(result);
    name.strip_prefix(NAME_PREFIX)
        .unwrap_or_else(|| panic!("el nombre del error no es del servicio"))
        .to_string()
}
