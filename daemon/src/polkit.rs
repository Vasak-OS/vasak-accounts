//! Preguntarle a polkit si se autoriza borrar una cuenta.
//!
//! ── Por qué borrar sí y agregar no ──────────────────────────────────────────
//!
//! Agregar una cuenta es tuya y se deshace sola: si te arrepentís, la borrás.
//! Borrarla no se deshace. Se va la credencial —que puede ser una contraseña de
//! aplicación que tardaste en sacar— y desde que el servicio avisa al proveedor,
//! además se corta el acceso del otro lado.
//!
//! Sin esto, cualquier programa corriendo con tu cuenta podía llamar
//! `RemoveAccount` y dejarte sin cuentas en silencio. Ahora tiene que pasar por
//! una autenticación que hacés vos, en un diálogo sobre el que el programa que
//! llamó no tiene ningún control.
//!
//! ── Por qué `auth_self_keep` y no la contraseña de administrador ────────────
//!
//! Es tu cuenta, no una configuración del equipo: no hace falta ser
//! administrador para sacar tu propio correo. Y `keep` recuerda la respuesta un
//! rato, así que borrar tres cuentas seguidas pregunta una vez y no tres.

use std::collections::HashMap;

use zbus::fdo::Error as FdoError;
use zbus::zvariant::Value;

/// La acción que declara `ar.net.vasak.os.accounts.policy`.
pub const REMOVE_ACTION: &str = "ar.net.vasak.os.accounts.remove";

/// Comprueba al llamante contra la acción de borrado.
///
/// Al proceso se lo identifica por PID **y momento de arranque**, no por PID
/// solo: un número se recicla, y polkit tiene que estar seguro de que autentica
/// al proceso que de verdad pidió.
pub async fn authorize_removal(
    connection: &zbus::Connection,
    caller: &crate::auth::PinnedCaller,
) -> Result<(), FdoError> {
    let start_time = crate::permissions::process_start_time(caller.pid)?;

    let mut sujeto: HashMap<&str, Value<'_>> = HashMap::new();
    sujeto.insert("pid", Value::U32(caller.pid));
    sujeto.insert("start-time", Value::U64(start_time));

    let subject = ("unix-process", sujeto);
    let detalles: HashMap<&str, &str> = HashMap::new();
    // 1 = permitir el diálogo interactivo. Sin esto polkit contesta «no
    // autorizado» para cualquier cosa que pida contraseña, y la pantalla
    // fallaría sin darle a la persona forma de seguir.
    let banderas: u32 = 1;
    let id_de_cancelacion = "";

    let respuesta = connection
        .call_method(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            Some("org.freedesktop.PolicyKit1.Authority"),
            "CheckAuthorization",
            &(subject, REMOVE_ACTION, detalles, banderas, id_de_cancelacion),
        )
        .await
        .map_err(|e| FdoError::Failed(format!("no se pudo consultar a polkit: {e}")))?;

    let (autorizado, _desafio, _detalles): (bool, bool, HashMap<String, String>) = respuesta
        .body()
        .deserialize()
        .map_err(|e| FdoError::Failed(format!("respuesta inválida de polkit: {e}")))?;

    if autorizado {
        return Ok(());
    }

    // Cancelar el diálogo es lo más común y no es un fallo, así que el mensaje
    // no suena a error del sistema.
    Err(FdoError::AccessDenied(
        "No se autorizó borrar la cuenta".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El identificador tiene que ser **exactamente** el que declara el archivo
    /// de polkit.
    ///
    /// Si se separan, polkit no conoce la acción que se le consulta y la deniega
    /// por omisión: borrar una cuenta dejaría de andar con un «no autorizado»
    /// que parece que la persona canceló el diálogo, cuando el diálogo nunca
    /// llegó a aparecer. Falla del lado seguro, pero falla, y sin ninguna pista.
    #[test]
    fn la_accion_es_la_misma_que_declara_el_archivo_de_polkit() {
        let politica = include_str!("../packaging/ar.net.vasak.os.accounts.policy");

        assert!(
            politica.contains(&format!(r#"<action id="{REMOVE_ACTION}">"#)),
            "el archivo no declara «{REMOVE_ACTION}»"
        );
    }

    /// Y que la acción pida autenticarse, no que se permita sola.
    ///
    /// Un `<allow_active>yes</allow_active>` dejaría el archivo en su lugar, la
    /// consulta contestando que sí, y el servicio creyendo que preguntó — con
    /// todo el trabajo hecho y ninguna protección puesta.
    #[test]
    fn la_accion_pide_autenticarse() {
        let politica = include_str!("../packaging/ar.net.vasak.os.accounts.policy");

        assert!(
            politica.contains("<allow_active>auth_self_keep</allow_active>"),
            "la acción tendría que pedir autenticación de la propia persona"
        );
        // Y que no se conceda sin sesión activa ni a cualquiera.
        assert!(politica.contains("<allow_any>no</allow_any>"));
        assert!(politica.contains("<allow_inactive>no</allow_inactive>"));
    }

    /// El archivo tiene que ser XML que polkit pueda leer. Uno mal formado se
    /// ignora en silencio, y el síntoma vuelve a ser el mismo: la acción no
    /// existe y todo borrado se deniega.
    #[test]
    fn el_archivo_de_polkit_esta_bien_formado() {
        let politica = include_str!("../packaging/ar.net.vasak.os.accounts.policy");

        assert!(politica.starts_with("<?xml"), "falta la declaración XML");
        assert_eq!(
            politica.matches("<action").count(),
            politica.matches("</action>").count(),
            "las etiquetas de acción no cierran"
        );
        assert!(politica.trim_end().ends_with("</policyconfig>"));
    }
}
