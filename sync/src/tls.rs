//! El TLS que usan IMAP y SMTP.
//!
//! En un módulo propio porque son dos protocolos con el mismo requisito, y dos
//! copias de la carga de certificados es una copia de más: el día que haya que
//! cambiar algo —una raíz que se agrega, una versión mínima que se sube— hay que
//! poder hacerlo en un solo lugar y saber que quedó parejo.
//!
//! rustls y no las bibliotecas TLS del sistema: es Rust puro, así que el paquete
//! no suma bibliotecas compartidas. Los certificados de confianza **sí** salen
//! del sistema — los de la distribución, los que el administrador agregó—, que
//! es lo correcto: un almacén propio dejaría fuera un certificado interno que la
//! persona sí tiene instalado.

use std::sync::Arc;

use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// El conector, con los certificados de confianza del equipo.
///
/// Si no hay ninguno se falla en vez de seguir: un conector sin raíces rechaza
/// cualquier servidor, y el error que da —«certificado desconocido»— manda a
/// buscar el problema en el servidor de la persona cuando está en su equipo.
pub fn conector() -> Result<TlsConnector, String> {
    let mut raices = RootCertStore::empty();
    for certificado in rustls_native_certs::load_native_certs().certs {
        let _ = raices.add(certificado);
    }
    if raices.is_empty() {
        return Err("no hay certificados de confianza instalados en el equipo".into());
    }

    Ok(TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(raices)
            .with_no_client_auth(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// En un equipo con la distribución instalada hay certificados. Que esto
    /// falle quiere decir que ni IMAP ni SMTP van a poder conectarse con nadie,
    /// y es mejor enterarse acá que en el diario de alguien.
    #[test]
    fn el_equipo_tiene_certificados_de_confianza() {
        assert!(conector().is_ok());
    }
}
