//! Hablar con servidores DAV: lo genérico de WebDAV, lo de CardDAV y lo de
//! CalDAV.
//!
//! Traído de `vasak-contacts` y `vasak-calendar` al sincronizador para que los
//! contactos y el calendario se guarden en el almacén local
//! (`vasak-accounts#23`). Escribe sólo con `PUT` y `DELETE`, y **siempre con una
//! precondición de ETag** para no pisar un cambio del servidor; no hay ningún
//! otro método de escritura en el cliente (ver [`webdav::Method`] y
//! [`webdav::Precondition`]).

pub mod caldav;
pub mod carddav;
#[cfg(test)]
pub mod fake;
pub mod webdav;
