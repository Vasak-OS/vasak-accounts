//! Las carpetas base del estándar, y la regla que las filtra.
//!
//! La cola de salida, las preferencias de la ventana y el almacén local cuelgan
//! de `$XDG_DATA_HOME` o de `$XDG_CONFIG_HOME`, y los tres las piden a `dirs`.
//! `dirs` ya ignora una `XDG_*_HOME` relativa o vacía, que es lo que pide el
//! estándar. Lo que **no** mira es `HOME`: una vacía la cambia por la de
//! `/etc/passwd`, pero una relativa la usa tal cual, y `data_dir()` devuelve
//! entonces `datos/.local/share` —relativa al directorio de trabajo del
//! proceso, que en una unidad de systemd no es el home de nadie—.
//!
//! Esa otra mitad se cierra acá, en un solo lugar: estaba escrita tres veces,
//! una en cada módulo que la usaba, y tres copias de una regla son tres que se
//! pueden separar.

use std::path::{Path, PathBuf};

/// La carpeta de este servicio, dentro de la de datos y de la de configuración.
pub const APP_DIR: &str = "vasak-accounts-sync";

/// La carpeta base, sólo si es absoluta.
///
/// `base` es lo que devolvió `dirs` —`data_dir()`, `config_dir()`—, y se recibe
/// en vez de leerse acá para poder probarlo: el entorno es global al proceso y
/// las pruebas corren en paralelo, así que una que escriba una variable decide
/// al azar el resultado de otra.
///
/// La cadena vacía no es absoluta, así que una variable vacía también queda
/// afuera.
pub fn absolute_base(base: Option<PathBuf>) -> Option<PathBuf> {
    base.filter(|base| base.is_absolute())
}

/// `relative` bajo la carpeta base, o nada si la base no es absoluta.
pub fn path_under(base: Option<PathBuf>, relative: impl AsRef<Path>) -> Option<PathBuf> {
    absolute_base(base).map(|base| base.join(relative))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn una_base_absoluta_se_usa() {
        assert_eq!(
            path_under(Some(PathBuf::from("/home/ana/.local/share")), "x/y.json"),
            Some(PathBuf::from("/home/ana/.local/share/x/y.json"))
        );
        assert_eq!(
            absolute_base(Some(PathBuf::from("/home/ana/.config"))),
            Some(PathBuf::from("/home/ana/.config"))
        );
    }

    /// Las cuatro formas de no ser absoluta: la del nombre suelto es la que se
    /// escapa cuando uno se acuerda sólo de la vacía.
    #[test]
    fn una_base_relativa_o_ausente_no_se_usa() {
        for relative in ["", "datos", "./datos", "../datos"] {
            assert_eq!(
                path_under(Some(PathBuf::from(relative)), "x"),
                None,
                "una base de {relative:?} no tiene que usarse"
            );
            assert_eq!(absolute_base(Some(PathBuf::from(relative))), None);
        }
        assert_eq!(path_under(None, "x"), None);
        assert_eq!(absolute_base(None), None);
    }

    /// Lo que corre en el proceso hijo de la prueba de abajo: imprime lo que
    /// `dirs` contesta con el entorno que le pusieron.
    #[test]
    #[ignore = "la corre como proceso hijo la prueba de abajo"]
    fn sonda_de_dirs() {
        println!("SONDA data={:?}", dirs::data_dir());
        println!("SONDA config={:?}", dirs::config_dir());
    }

    /// Por qué este filtro existe: `dirs` deja pasar un `HOME` relativo.
    ///
    /// En un proceso aparte —esta misma prueba, con otro entorno—, porque
    /// escribir `HOME` acá cambiaría el de las demás pruebas que corren a la
    /// vez. Si un día `dirs` empieza a filtrarlo, esta prueba cae y el filtro
    /// se puede sacar; mientras tanto, el filtro es lo que lo cubre.
    #[test]
    fn dirs_no_filtra_un_home_relativo() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "xdg::tests::sonda_de_dirs",
                "--ignored",
                "--nocapture",
            ])
            .args(["--test-threads", "1"])
            .env("HOME", "datos")
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{stdout}");

        let relative_data = format!("{:?}", Some(PathBuf::from("datos/.local/share")));
        let relative_config = format!("{:?}", Some(PathBuf::from("datos/.config")));
        assert!(
            stdout.contains(&format!("SONDA data={relative_data}")),
            "{stdout}"
        );
        assert!(
            stdout.contains(&format!("SONDA config={relative_config}")),
            "{stdout}"
        );

        // Y lo que sale de `dirs` así, acá no pasa.
        assert_eq!(
            absolute_base(Some(PathBuf::from("datos/.local/share"))),
            None
        );
    }
}
