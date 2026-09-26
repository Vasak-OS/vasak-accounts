//! Hablar con servidores DAV: lo genérico de WebDAV y lo de CardDAV.
//!
//! Traído de `vasak-contacts` al sincronizador para que los contactos se
//! guarden en el almacén local (`vasak-accounts#23`). Sólo lee: no hay ningún
//! método de escritura en el cliente (ver [`webdav::Method`]).

pub mod carddav;
pub mod webdav;
