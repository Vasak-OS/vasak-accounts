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
pub enum NotificationDetail {
    /// Cuántos llegaron y a qué cuenta. Nada de quién ni de qué.
    ///
    /// Por omisión porque la pantalla puede estar bloqueada, compartida o
    /// proyectada, y quién te escribe es un dato tan personal como lo que te
    /// escribió. Lo más callado es lo que se elige cuando nadie eligió.
    #[default]
    #[serde(rename = "cuenta")]
    Account,
    /// Y quién lo mandó.
    #[serde(rename = "remitente")]
    Sender,
    /// Y de qué se trata.
    #[serde(rename = "remitente_y_asunto")]
    SenderAndSubject,
}

/// Lo que la ventana guarda y este servicio mira.
///
/// Los campos que no se conozcan se ignoran, que es lo que hace `serde` por
/// omisión. Eso es lo que permite que la ventana agregue preferencias suyas
/// —la vista por omisión, los atajos— en el mismo archivo sin que este lado
/// tenga que enterarse, y que mañana se pueda agregar una por cuenta sin migrar
/// nada.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct Preferences {
    #[serde(default, rename = "detalle_del_aviso")]
    pub notification_detail: NotificationDetail,
}

/// Dónde vive el archivo.
///
/// `XDG_CONFIG_HOME` y, si no está, `~/.config`, que es lo que dice el estándar
/// y lo que ya hace `outbox.rs` con `XDG_DATA_HOME`.
pub fn file_path() -> Option<PathBuf> {
    // Por `dirs`, igual que `outbox.rs`. Acá no se escribe, pero una base relativa
    // igual duele: se leería un archivo de preferencias de donde no está —o de
    // donde haya uno que no es—, y quien llama no lo distingue de «no hay
    // preferencias guardadas», así que se cae a las de por omisión sin decirlo.
    file_path_under(dirs::config_dir())
}

/// La misma decisión sin leer el entorno, para poder probarla.
fn file_path_under(base: Option<PathBuf>) -> Option<PathBuf> {
    let base = base.filter(|base| base.is_absolute())?;
    Some(base.join("vasak-mail").join("preferencias.json"))
}

/// Las preferencias de ahora mismo.
///
/// Se llama cada vez que hacen falta, no al arrancar: así un cambio vale en el
/// próximo cartel y no en la próxima sesión.
pub fn read() -> Preferences {
    let Some(path) = file_path() else {
        return Preferences::default();
    };
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Preferences::default();
    };
    parse(&raw)
}

/// Lo mismo, a partir del texto. Aparte para poder probarlo sin tocar el disco.
pub fn parse(raw: &str) -> Preferences {
    serde_json::from_str(raw).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lo_que_guarda_la_ventana_se_entiende() {
        let p = parse(r#"{"detalle_del_aviso": "remitente_y_asunto"}"#);
        assert_eq!(p.notification_detail, NotificationDetail::SenderAndSubject);

        let p = parse(r#"{"detalle_del_aviso": "remitente"}"#);
        assert_eq!(p.notification_detail, NotificationDetail::Sender);
    }

    /// Lo más callado es lo que se elige cuando nadie eligió: la pantalla puede
    /// estar bloqueada, compartida o proyectada.
    #[test]
    fn sin_archivo_y_sin_campo_vale_lo_mas_callado() {
        assert_eq!(parse("{}").notification_detail, NotificationDetail::Account);
        assert_eq!(
            Preferences::default().notification_detail,
            NotificationDetail::Account
        );
    }

    /// Una preferencia ilegible no puede dejar a nadie sin avisos. Y el valor
    /// por omisión es además el que no muestra nada de nadie, así que caer ahí
    /// tampoco cuenta de más.
    #[test]
    fn lo_que_no_se_entiende_vale_como_lo_de_siempre() {
        for broken in [
            "",
            "no es json",
            "[]",
            r#"{"detalle_del_aviso": "lo_que_sea"}"#,
            r#"{"detalle_del_aviso": 7}"#,
            r#"{"detalle_del_aviso"#,
        ] {
            assert_eq!(
                parse(broken).notification_detail,
                NotificationDetail::Account,
                "{broken:?}"
            );
        }
    }

    /// La ventana guarda además preferencias que sólo le importan a ella. Este
    /// lado tiene que ignorarlas, no atragantarse con ellas.
    #[test]
    fn los_campos_de_la_ventana_no_molestan() {
        let p = parse(
            r#"{"detalle_del_aviso": "remitente", "vistaPorOmision": "formato",
                "atajos": "vim", "remitentesConImagenes": ["a@b.c"]}"#,
        );
        assert_eq!(p.notification_detail, NotificationDetail::Sender);
    }

    #[test]
    fn archivo_usa_el_directorio_de_configuracion_del_sistema() {
        // Antes esto hacía `file_path().expect(...)` dando por sentado que hay
        // `HOME` o `XDG_CONFIG_HOME`. No lo hay siempre —`dirs::config_dir()`
        // puede no resolver nada—, y ahí `None` es la respuesta correcta y no
        // un fallo de la prueba.
        //
        // Lo que se comprueba entonces es el **cableado**: que `file_path()` sea
        // exactamente `file_under` sobre el directorio del sistema. Vale igual
        // en una máquina sin `HOME`, donde las dos dan `None`, y falla si
        // alguien cambia de dónde sale la base. Envolverlo en un `if let` habría
        // sido peor: una prueba que puede pasar sin comprobar nada.
        assert_eq!(file_path(), file_path_under(dirs::config_dir()));
    }

    #[test]
    fn el_archivo_cuelga_del_directorio_de_configuracion() {
        assert_eq!(
            file_path_under(Some(PathBuf::from("/home/pato/.config"))),
            Some(PathBuf::from(
                "/home/pato/.config/vasak-mail/preferencias.json"
            ))
        );
    }

    #[test]
    fn una_base_relativa_no_da_archivo() {
        // Acá no se escribe, pero una base relativa igual duele: se leería de
        // donde no está —o de donde haya un archivo que no es— y quien llama no
        // lo distingue de «no hay preferencias guardadas», así que se cae a las
        // de por omisión sin decirlo.
        for relative in ["", "config", "./config", "../config"] {
            assert_eq!(
                file_path_under(Some(PathBuf::from(relative))),
                None,
                "una base de {relative:?} no tiene que dar archivo"
            );
        }
        assert_eq!(file_path_under(None), None);
    }

    /// Lo que escribe la ventana en `vasak-mail/preferencias.json`: la clave y
    /// los tres valores son los de siempre, y los nombres de Rust en inglés no
    /// se leen.
    #[test]
    fn las_preferencias_se_leen_con_los_nombres_de_la_ventana() {
        for (wire, detail) in [
            ("cuenta", NotificationDetail::Account),
            ("remitente", NotificationDetail::Sender),
            ("remitente_y_asunto", NotificationDetail::SenderAndSubject),
        ] {
            let raw = format!(r#"{{"detalle_del_aviso": "{wire}"}}"#);
            assert_eq!(parse(&raw).notification_detail, detail, "{wire}");
        }
        assert_eq!(
            parse(r#"{"notification_detail": "sender"}"#).notification_detail,
            NotificationDetail::Account
        );
    }
}
