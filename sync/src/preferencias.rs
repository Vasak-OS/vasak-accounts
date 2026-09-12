//! Las preferencias de la aplicación de correo, del lado que las lee.
//!
//! # Quién escribe y quién lee
//!
//! **Sólo la ventana escribe. Este servicio sólo lee.** Con un solo escritor no
//! hay carrera que resolver, y el cuidado de escribir un archivo del usuario
//! —temporal, `rename`, permisos— queda del lado que escribe.
//!
//! # Se relee cada vez
//!
//! No hay vigilante ni señal, y no hace falta: de todo lo que la ventana guarda,
//! este proceso sólo necesita una cosa —cuánto detalle lleva el cartel de correo
//! nuevo— y la mira una vez por cartel, o sea unas pocas veces por día. Leer cien
//! bytes en ese momento no se nota.
//!
//! Lo otro que esto evita es peor que el costo: una preferencia que necesita
//! reiniciar la sesión para valer no se siente como una preferencia.
//!
//! # Lo que no se entiende vale como lo de siempre
//!
//! Un archivo que no está, uno que no se puede leer y uno que no se entiende dan
//! los valores por omisión. Una preferencia ilegible no puede dejar a nadie sin
//! avisos, y el valor por omisión es además el que no muestra nada de nadie.

use std::path::PathBuf;

/// Cuánto cuenta el cartel de correo nuevo.
///
/// El orden es de menos a más: cada escalón agrega algo que antes no se decía.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Detalle {
    /// Cuántos llegaron y a qué cuenta. Nada de quién ni de qué.
    ///
    /// Por omisión porque la pantalla puede estar bloqueada, compartida o
    /// proyectada, y quién te escribe es un dato tan personal como lo que te
    /// escribió. Lo más callado es lo que se elige cuando nadie eligió.
    #[default]
    Cuenta,
    /// Y quién lo mandó.
    Remitente,
    /// Y de qué se trata.
    RemitenteYAsunto,
}

/// Lo que la ventana guarda y este servicio mira.
///
/// Los campos que no se conozcan se ignoran, que es lo que hace `serde` por
/// omisión. Eso es lo que permite que la ventana agregue preferencias suyas
/// —la vista por omisión, los atajos— en el mismo archivo sin que este lado
/// tenga que enterarse, y que mañana se pueda agregar una por cuenta sin migrar
/// nada.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct Preferencias {
    #[serde(default)]
    pub detalle_del_aviso: Detalle,
}

/// Dónde vive el archivo.
///
/// `XDG_CONFIG_HOME` y, si no está, `~/.config`, que es lo que dice el estándar
/// y lo que ya hace `cola.rs` con `XDG_DATA_HOME`.
pub fn archivo() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("vasak-mail").join("preferencias.json"))
}

/// Las preferencias de ahora mismo.
///
/// Se llama cada vez que hacen falta, no al arrancar: así un cambio vale en el
/// próximo cartel y no en la próxima sesión.
pub fn leer() -> Preferencias {
    let Some(ruta) = archivo() else {
        return Preferencias::default();
    };
    let Ok(crudo) = std::fs::read_to_string(&ruta) else {
        return Preferencias::default();
    };
    interpretar(&crudo)
}

/// Lo mismo, a partir del texto. Aparte para poder probarlo sin tocar el disco.
pub fn interpretar(crudo: &str) -> Preferencias {
    serde_json::from_str(crudo).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lo_que_guarda_la_ventana_se_entiende() {
        let p = interpretar(r#"{"detalle_del_aviso": "remitente_y_asunto"}"#);
        assert_eq!(p.detalle_del_aviso, Detalle::RemitenteYAsunto);

        let p = interpretar(r#"{"detalle_del_aviso": "remitente"}"#);
        assert_eq!(p.detalle_del_aviso, Detalle::Remitente);
    }

    /// Lo más callado es lo que se elige cuando nadie eligió: la pantalla puede
    /// estar bloqueada, compartida o proyectada.
    #[test]
    fn sin_archivo_y_sin_campo_vale_lo_mas_callado() {
        assert_eq!(interpretar("{}").detalle_del_aviso, Detalle::Cuenta);
        assert_eq!(Preferencias::default().detalle_del_aviso, Detalle::Cuenta);
    }

    /// Una preferencia ilegible no puede dejar a nadie sin avisos. Y el valor
    /// por omisión es además el que no muestra nada de nadie, así que caer ahí
    /// tampoco cuenta de más.
    #[test]
    fn lo_que_no_se_entiende_vale_como_lo_de_siempre() {
        for roto in [
            "",
            "no es json",
            "[]",
            r#"{"detalle_del_aviso": "lo_que_sea"}"#,
            r#"{"detalle_del_aviso": 7}"#,
            r#"{"detalle_del_aviso"#,
        ] {
            assert_eq!(
                interpretar(roto).detalle_del_aviso,
                Detalle::Cuenta,
                "{roto:?}"
            );
        }
    }

    /// La ventana guarda además preferencias que sólo le importan a ella. Este
    /// lado tiene que ignorarlas, no atragantarse con ellas.
    #[test]
    fn los_campos_de_la_ventana_no_molestan() {
        let p = interpretar(
            r#"{"detalle_del_aviso": "remitente", "vistaPorOmision": "formato",
                "atajos": "vim", "remitentesConImagenes": ["a@b.c"]}"#,
        );
        assert_eq!(p.detalle_del_aviso, Detalle::Remitente);
    }

    #[test]
    fn el_archivo_cuelga_de_la_configuracion_del_usuario() {
        let ruta = archivo().expect("hay HOME o XDG_CONFIG_HOME en cualquier sesión");
        assert!(ruta.ends_with("vasak-mail/preferencias.json"), "{ruta:?}");
    }
}
