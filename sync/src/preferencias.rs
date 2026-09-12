//! Las preferencias de la aplicación de correo, desde este lado.
//!
//! # Quién escribe y quién lee
//!
//! El archivo lo escribe **la ventana** —ver `preferencias.rs` de `vasak-mail`,
//! que es donde está la decisión— y este servicio sólo lo lee. Un solo escritor:
//! así no hay dos procesos pisándose el archivo y no hace falta ningún bloqueo.
//!
//! # Por qué el servicio necesita leer esto
//!
//! Porque muestra el cartel de correo nuevo **con la ventana cerrada**, que es de
//! lo que se trata el aviso. Cuánto dice ese cartel es una decisión de la
//! persona, y no hay forma de que le llegue desde adentro del navegador.
//!
//! # Se lee cada vez, no se guarda en memoria
//!
//! Un archivo de unos cientos de bytes, una vez por tanda de correo nuevo. A
//! cambio, cambiar la preferencia se nota en el aviso siguiente y no al
//! reiniciar la sesión — que es lo mínimo que se espera de algo que se llama
//! preferencia.

use std::path::PathBuf;

/// Cuánto dice el cartel de correo nuevo.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Detalle {
    /// «Llegaron 3 mensajes», y a qué cuenta. **Lo de omisión.**
    ///
    /// La pantalla puede estar bloqueada, compartida o proyectada, y quién te
    /// escribe es un dato tan personal como lo que te escribió.
    #[default]
    Cantidad,
    /// Y de quién.
    Remitente,
    /// Y de qué.
    Asunto,
}

impl Detalle {
    fn de_texto(valor: &str) -> Self {
        match valor {
            "remitente" => Detalle::Remitente,
            "asunto" => Detalle::Asunto,
            // Lo que no se entiende cae a lo conservador, igual que del lado de
            // la ventana: un archivo editado a mano no puede terminar en un
            // cartel que nombra a quien escribió.
            _ => Detalle::Cantidad,
        }
    }
}

/// Lo que este servicio necesita saber.
///
/// Sólo lo suyo. Lo que es de la ventana —cuánto dura el arrepentimiento, por
/// ejemplo— está en el mismo archivo y a este lado no le importa.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Preferencias {
    pub detalle: Detalle,
}

fn ruta() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|ruta| ruta.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|casa| PathBuf::from(casa).join(".config")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));

    base.join("vasak-mail").join("preferencias.json")
}

/// Lee las preferencias.
///
/// Todo lo que puede salir mal —que el archivo no esté, que no sea JSON, que le
/// falte el campo, que traiga cualquier cosa— da lo de omisión. Un cartel es lo
/// último que puede romper una sincronización de correo.
pub fn leer() -> Preferencias {
    let Ok(contenido) = std::fs::read_to_string(ruta()) else {
        return Preferencias::default();
    };
    interpretar(&contenido)
}

/// Lo que dice el archivo, con respaldo en cada paso.
///
/// Aparte de [`leer`] para poder probarlo sin tocar el disco.
pub fn interpretar(contenido: &str) -> Preferencias {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(contenido) else {
        return Preferencias::default();
    };

    Preferencias {
        detalle: json
            .get("detalleDelAviso")
            .and_then(|v| v.as_str())
            .map(Detalle::de_texto)
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn se_lee_lo_que_eligio_la_persona() {
        assert_eq!(
            interpretar(r#"{"detalleDelAviso":"remitente"}"#).detalle,
            Detalle::Remitente
        );
        assert_eq!(
            interpretar(r#"{"detalleDelAviso":"asunto"}"#).detalle,
            Detalle::Asunto
        );
        assert_eq!(
            interpretar(r#"{"detalleDelAviso":"cantidad"}"#).detalle,
            Detalle::Cantidad
        );
    }

    /// **Lo que no se entiende cae a lo conservador**, no a cualquier otra cosa.
    /// El archivo está en el disco de la persona y se puede editar a mano; un
    /// valor raro no puede terminar en un cartel que nombra a quien escribió.
    #[test]
    fn lo_que_no_se_entiende_no_muestra_de_mas() {
        for raro in [
            r#"{"detalleDelAviso":"todo"}"#,
            r#"{"detalleDelAviso":"REMITENTE"}"#,
            r#"{"detalleDelAviso":42}"#,
            r#"{"detalleDelAviso":null}"#,
            r#"{"otraCosa":true}"#,
            "{}",
            "[]",
            "no es json",
            "",
        ] {
            assert_eq!(interpretar(raro).detalle, Detalle::Cantidad, "{raro:?}");
        }
    }

    /// Lo que es de la ventana está en el mismo archivo y no molesta.
    #[test]
    fn lo_que_es_de_la_ventana_se_ignora() {
        let ambas = r#"{"detalleDelAviso":"asunto","segundosParaDeshacer":30}"#;
        assert_eq!(interpretar(ambas).detalle, Detalle::Asunto);
    }

    /// Un archivo que no está es el caso normal: nadie tocó nada todavía.
    #[test]
    fn sin_archivo_vale_lo_de_omision() {
        assert_eq!(Preferencias::default().detalle, Detalle::Cantidad);
    }
}
