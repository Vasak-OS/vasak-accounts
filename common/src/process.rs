//! Cómo se nombra a un proceso ante el servicio de permisos.
//!
//! Por su pid y por el campo 22 de `/proc/<pid>/stat`, el momento en que
//! arrancó: el servicio de permisos compara los dos para detectar un pid que se
//! recicló entre que lo vimos y lo comprobó. Polkit necesita lo mismo, por la
//! misma razón.
//!
//! Sin zbus a propósito: el error es propio, y quien necesite uno de D-Bus lo
//! convierte (hay un `From` para `zbus::fdo::Error`).

/// Por qué no se pudo leer el momento de arranque de un proceso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartTimeError {
    /// `/proc/<pid>/stat` no se pudo leer: el proceso ya no existe, o no es
    /// visible desde acá.
    Gone { pid: u32, detail: String },
    /// Se leyó, pero no tiene la forma que se espera.
    Unparsable { pid: u32 },
}

impl std::fmt::Display for StartTimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartTimeError::Gone { pid, detail } => {
                write!(f, "el proceso {pid} ya no existe: {detail}")
            }
            StartTimeError::Unparsable { pid } => {
                write!(f, "no se pudo interpretar /proc/{pid}/stat")
            }
        }
    }
}

impl std::error::Error for StartTimeError {}

impl From<StartTimeError> for zbus::fdo::Error {
    fn from(error: StartTimeError) -> Self {
        zbus::fdo::Error::Failed(error.to_string())
    }
}

/// El campo 22 de `/proc/<pid>/stat`: cuándo arrancó el proceso, en tics desde
/// que arrancó el equipo.
pub fn process_start_time(pid: u32) -> Result<u64, StartTimeError> {
    let stat =
        std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| StartTimeError::Gone {
            pid,
            detail: e.to_string(),
        })?;

    parse_start_time(&stat).ok_or(StartTimeError::Unparsable { pid })
}

/// Se lee desde el último `)`: el campo 2 es el nombre del ejecutable entre
/// paréntesis y puede tener espacios o paréntesis adentro, así que partir la
/// línea entera por los espacios corre todos los campos que siguen.
fn parse_start_time(stat: &str) -> Option<u64> {
    let after_name = stat.rsplit_once(')')?.1;
    after_name.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_start_time_is_read_from_the_right_field() {
        let mut stat = String::from("1234 (bash) S");
        for field in 4..=21 {
            stat.push_str(&format!(" {field}"));
        }
        stat.push_str(" 4242 rest");

        assert_eq!(parse_start_time(&stat), Some(4242));
    }

    /// Un programa se puede llamar `weird ) name`; partir la línea entera por
    /// los espacios leería otro campo y el servicio de permisos rechazaría un
    /// pedido que estaba bien.
    #[test]
    fn a_program_name_with_brackets_does_not_shift_the_fields() {
        let mut stat = String::from("1234 (weird ) name) S");
        for field in 4..=21 {
            stat.push_str(&format!(" {field}"));
        }
        stat.push_str(" 99 more");

        assert_eq!(parse_start_time(&stat), Some(99));
    }

    #[test]
    fn our_own_start_time_can_be_read() {
        assert!(process_start_time(std::process::id()).is_ok());
    }

    /// Un proceso que no está se dice, con su pid, y el error de D-Bus lleva
    /// el mismo texto que antes de mudarse acá.
    #[test]
    fn un_proceso_que_no_existe_da_un_error_con_su_pid() {
        // El pid máximo de Linux es 2^22; éste no puede existir.
        let error = process_start_time(u32::MAX).unwrap_err();
        assert!(matches!(error, StartTimeError::Gone { pid: u32::MAX, .. }));
        let fdo: zbus::fdo::Error = error.into();
        assert!(
            matches!(&fdo, zbus::fdo::Error::Failed(text) if text.starts_with("el proceso 4294967295 ya no existe"))
        );
    }

    #[test]
    fn una_linea_sin_parentesis_no_se_interpreta() {
        assert_eq!(parse_start_time("1234 bash S 1 2 3"), None);
        assert_eq!(parse_start_time("1234 (bash) S 1 2"), None);
    }
}
