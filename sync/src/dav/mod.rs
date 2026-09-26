//! Hablar con servidores DAV: lo genérico de WebDAV, lo de CardDAV y lo de
//! CalDAV.
//!
//! Traído de `vasak-contacts` y `vasak-calendar` al sincronizador para que los
//! contactos y el calendario se guarden en el almacén local
//! (`vasak-accounts#23`). Sólo lee: no hay ningún método de escritura en el
//! cliente (ver [`webdav::Method`]).

// Lo usa la sincronización del calendario, que llega unos commits después.
#[allow(dead_code)]
pub mod caldav;
pub mod carddav;
#[cfg(test)]
#[allow(dead_code)]
pub mod fake;
pub mod webdav;
