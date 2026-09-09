//! De dónde salen las URLs y el `client_id` de cada proveedor.
//!
//! No están escritos en el código a propósito. Agregar un proveedor —o poner el
//! `client_id` de Google— tiene que ser dejar un archivo, no recompilar el
//! servicio, igual que los complementos del instalador.
//!
//! Y hay una razón que va más allá de la comodidad. VasakOS **no** tiene un
//! `client_id` propio para Google ni para Microsoft, y no lo va a tener pronto:
//! registrar la aplicación para llegar al correo de Gmail exige una auditoría de
//! seguridad paga y recurrente. Lo que sí puede hacer cualquiera hoy, gratis, es
//! registrar su *propia* aplicación en la consola del proveedor y pegar el
//! `client_id` acá. Eso convierte la falta de presupuesto en un archivo de
//! configuración en vez de en una función que no existe.
//!
//! Dos directorios, y el segundo pisa al primero:
//!
//! - `/usr/share/vasak-accounts/providers.d/` — lo que trae el paquete. Sin
//!   `client_id`, porque no tenemos ninguno que dar.
//! - `/etc/vasak-accounts/providers.d/` — lo que agrega quien administra el
//!   equipo. Acá va el `client_id` propio.
//!
//! Los dos son de root: un proveedor define a qué servidor se le mandan los
//! códigos de autorización, así que si el usuario pudiera escribirlos, un
//! programa corriendo con su cuenta podría apuntar «Google» a otro lado.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::storage::CapabilityType;

const SHIPPED: &str = "/usr/share/vasak-accounts/providers.d";
const LOCAL: &str = "/etc/vasak-accounts/providers.d";

/// Cómo se conecta una cuenta de este proveedor.
///
/// No todos hablan OAuth2, y forzarlos a la misma forma habría significado
/// inventarle a Nextcloud un `client_id` que no existe.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// El flujo de siempre: navegador, código de autorización y PKCE. Necesita
    /// que alguien haya registrado la aplicación con el proveedor.
    #[default]
    Oauth2,
    /// El Login Flow v2 de Nextcloud, donde **no hay nada que registrar**: la
    /// persona escribe la dirección de su servidor y ese servidor emite una
    /// contraseña de aplicación. Por eso es el único proveedor que funciona sin
    /// que nadie pague ni tramite nada.
    Nextcloud,
}

/// Un proveedor tal como se lee del archivo.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Provider {
    pub id: String,
    pub display_name: String,

    #[serde(default)]
    pub kind: ProviderKind,

    /// Sólo para OAuth2. Nextcloud no las tiene: las arma a partir de la
    /// dirección que escribe la persona, que no se sabe hasta ese momento.
    #[serde(default)]
    pub auth_url: Option<String>,
    #[serde(default)]
    pub token_url: Option<String>,

    /// Sin él no se puede empezar ningún flujo. Es opcional porque el archivo
    /// que trae el paquete no puede traerlo: hay que registrar la aplicación
    /// para tenerlo, y el error que devuelve el servicio dice dónde ponerlo.
    #[serde(default)]
    pub client_id: Option<String>,

    /// Los clientes de escritorio de Google lo exigen aunque no sea un secreto
    /// de verdad —viaja en el paquete de cualquier aplicación—. Otros
    /// proveedores no lo quieren y mandarlo es un error.
    #[serde(default)]
    pub client_secret: Option<String>,

    /// Qué pedirle al proveedor para cada capacidad. Se piden juntos los de
    /// todas las capacidades que la persona eligió, en una sola pantalla de
    /// consentimiento.
    #[serde(default)]
    pub scopes: HashMap<CapabilityType, Vec<String>>,

    /// Parámetros extra en la URL de autorización. Google necesita
    /// `access_type=offline` y `prompt=consent`, o no devuelve refresh_token y
    /// la cuenta se muere en una hora sin que nada avise.
    #[serde(default)]
    pub extra_auth_params: HashMap<String, String>,

    /// Qué capacidades da, para los proveedores que no las expresan como
    /// alcances. Nextcloud entrega una contraseña de aplicación que sirve para
    /// todo lo que la cuenta tenga, así que no hay nada que pedir por separado.
    #[serde(default)]
    pub capabilities: Vec<CapabilityType>,
}

impl Provider {
    /// Las capacidades que este proveedor sabe dar.
    ///
    /// De la lista explícita si la hay, y si no de los alcances configurados —
    /// que es como las expresa un proveedor OAuth2, donde cada capacidad es un
    /// permiso distinto que hay que pedir.
    pub fn capabilities(&self) -> Vec<CapabilityType> {
        let mut lista: Vec<CapabilityType> = if self.capabilities.is_empty() {
            CapabilityType::ALL
                .into_iter()
                .filter(|c| self.scopes.contains_key(c))
                .collect()
        } else {
            self.capabilities.clone()
        };
        lista.sort_by_key(|c| c.as_id());
        lista.dedup();
        lista
    }

    /// Si se puede empezar un flujo con este proveedor tal como está.
    ///
    /// Para OAuth2 hace falta que alguien haya dejado el `client_id`; para
    /// Nextcloud no hace falta nada, porque las credenciales las emite el
    /// servidor de la propia persona.
    pub fn is_configured(&self) -> bool {
        match self.kind {
            ProviderKind::Oauth2 => {
                self.client_id.as_deref().is_some_and(|id| !id.is_empty())
                    && self.auth_url.is_some()
                    && self.token_url.is_some()
            }
            ProviderKind::Nextcloud => true,
        }
    }
}

#[derive(Debug)]
pub enum CatalogError {
    /// El proveedor no está en ningún archivo.
    Unknown(String),
    /// Está, pero le falta el `client_id`: no hay con qué empezar el flujo.
    NoClientId(String),
    /// Se lo pidió por un camino que no es el suyo — un flujo OAuth2 sobre un
    /// proveedor de Nextcloud, o al revés.
    WrongKind { provider: String, esperado: &'static str },
    /// El proveedor no ofrece alguna de las capacidades pedidas.
    UnsupportedCapability { provider: String, capability: &'static str },
    Io(String),
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CatalogError::Unknown(id) => write!(
                f,
                "no hay ningún proveedor '{id}'. Los archivos se leen de \
                 {SHIPPED} y de {LOCAL}",
            ),
            CatalogError::NoClientId(id) => write!(
                f,
                "el proveedor '{id}' no tiene client_id configurado. VasakOS no \
                 distribuye uno propio: registrá una aplicación en la consola del \
                 proveedor y dejá el client_id en {LOCAL}/{id}.toml",
            ),
            CatalogError::UnsupportedCapability { provider, capability } => write!(
                f,
                "el proveedor '{provider}' no ofrece '{capability}'",
            ),
            CatalogError::WrongKind { provider, esperado } => write!(
                f,
                "el proveedor '{provider}' no se conecta así; su flujo es '{esperado}'",
            ),
            CatalogError::Io(mensaje) => write!(f, "no se pudo leer el catálogo: {mensaje}"),
        }
    }
}

impl std::error::Error for CatalogError {}

/// Todos los proveedores conocidos, con los de `/etc` pisando a los del paquete.
pub fn load() -> Result<HashMap<String, Provider>, CatalogError> {
    let mut catalogo = HashMap::new();
    for directorio in [SHIPPED, LOCAL] {
        merge_directory(Path::new(directorio), &mut catalogo)?;
    }
    Ok(catalogo)
}

/// Uno solo, listo para empezar un flujo del tipo pedido.
///
/// Todo se comprueba **antes** de abrir el navegador. Si no, la persona pasa por
/// toda la pantalla de consentimiento del proveedor para que el fallo aparezca
/// al volver.
pub fn resolve(
    id: &str,
    kind: ProviderKind,
    capabilities: &[CapabilityType],
) -> Result<Provider, CatalogError> {
    let proveedor = load()?
        .remove(id)
        .ok_or_else(|| CatalogError::Unknown(id.to_string()))?;

    if proveedor.kind != kind {
        return Err(CatalogError::WrongKind {
            provider: id.to_string(),
            esperado: match proveedor.kind {
                ProviderKind::Oauth2 => "oauth2",
                ProviderKind::Nextcloud => "nextcloud",
            },
        });
    }

    if !proveedor.is_configured() {
        return Err(CatalogError::NoClientId(id.to_string()));
    }

    let ofrece = proveedor.capabilities();
    for capacidad in capabilities {
        if !ofrece.contains(capacidad) {
            return Err(CatalogError::UnsupportedCapability {
                provider: id.to_string(),
                capability: capacidad.as_id(),
            });
        }
    }

    Ok(proveedor)
}

/// Lee un directorio de `*.toml` y los suma al catálogo.
///
/// Que el directorio no exista no es un error: `/etc/vasak-accounts` sólo está
/// si alguien agregó algo. Un archivo ilegible **sí** lo es, y detiene la carga:
/// seguir de largo dejaría al proveedor sin su `client_id` local y el servicio
/// diría «no hay client_id» cuando en realidad lo hay y está mal escrito.
fn merge_directory(
    directorio: &Path,
    catalogo: &mut HashMap<String, Provider>,
) -> Result<(), CatalogError> {
    let entradas = match std::fs::read_dir(directorio) {
        Ok(entradas) => entradas,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(CatalogError::Io(format!("{}: {e}", directorio.display()))),
    };

    let mut archivos: Vec<PathBuf> = entradas
        .filter_map(|entrada| entrada.ok())
        .map(|entrada| entrada.path())
        .filter(|ruta| ruta.extension().is_some_and(|e| e == "toml"))
        .collect();
    // Por nombre, para que dos archivos que definan lo mismo den siempre el
    // mismo resultado y no el que dependa del orden del sistema de archivos.
    archivos.sort();

    for ruta in archivos {
        let texto = std::fs::read_to_string(&ruta)
            .map_err(|e| CatalogError::Io(format!("{}: {e}", ruta.display())))?;
        let proveedor: Provider = toml::from_str(&texto)
            .map_err(|e| CatalogError::Io(format!("{}: {e}", ruta.display())))?;
        catalogo.insert(proveedor.id.clone(), proveedor);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOGLE: &str = r#"
        id = "google"
        display_name = "Google"
        auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
        token_url = "https://oauth2.googleapis.com/token"

        [scopes]
        calendar = ["https://www.googleapis.com/auth/calendar"]
        contacts = ["https://www.googleapis.com/auth/contacts"]

        [extra_auth_params]
        access_type = "offline"
    "#;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cargar(directorio: &Path) -> HashMap<String, Provider> {
        let mut catalogo = HashMap::new();
        merge_directory(directorio, &mut catalogo).unwrap();
        catalogo
    }

    #[test]
    fn un_proveedor_se_lee_del_archivo() {
        let dir = temp_dir();
        std::fs::write(dir.join("google.toml"), GOOGLE).unwrap();

        let catalogo = cargar(&dir);
        let google = &catalogo["google"];

        assert_eq!(google.display_name, "Google");
        assert_eq!(google.client_id, None);
        assert_eq!(
            google.capabilities(),
            vec![CapabilityType::Calendar, CapabilityType::Contacts]
        );
        assert_eq!(google.extra_auth_params["access_type"], "offline");

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// Es la razón de que haya dos directorios: el paquete trae el proveedor
    /// sin `client_id` y quien administra el equipo pone el suyo sin tocar un
    /// archivo del paquete.
    #[test]
    fn lo_de_etc_pisa_lo_del_paquete() {
        let paquete = temp_dir();
        let local = temp_dir();
        std::fs::write(paquete.join("google.toml"), GOOGLE).unwrap();
        // El `client_id` va **antes** de las tablas: en TOML, una clave escrita
        // después de un `[bloque]` pertenece a ese bloque, así que pegarlo al
        // final lo metería dentro de `[extra_auth_params]`. Lo descubrió este
        // mismo test fallando.
        std::fs::write(
            local.join("google.toml"),
            GOOGLE.replace(
                "display_name = \"Google\"",
                "display_name = \"Google\"\nclient_id = \"el-mio.apps.googleusercontent.com\"",
            ),
        )
        .unwrap();

        let mut catalogo = HashMap::new();
        merge_directory(&paquete, &mut catalogo).unwrap();
        merge_directory(&local, &mut catalogo).unwrap();

        assert_eq!(
            catalogo["google"].client_id.as_deref(),
            Some("el-mio.apps.googleusercontent.com"),
        );

        std::fs::remove_dir_all(paquete).unwrap_or_default();
        std::fs::remove_dir_all(local).unwrap_or_default();
    }

    /// `/etc/vasak-accounts` sólo existe si alguien agregó algo, así que su
    /// ausencia es lo normal y no puede impedir que el servicio arranque.
    #[test]
    fn un_directorio_que_no_existe_no_es_un_error() {
        let mut catalogo = HashMap::new();
        merge_directory(Path::new("/no/existe/en/ningun/lado"), &mut catalogo).unwrap();
        assert!(catalogo.is_empty());
    }

    /// Un TOML mal escrito tiene que detener la carga y decir en qué archivo.
    /// Si se ignorara, el `client_id` local no se aplicaría y el servicio diría
    /// «no hay client_id» sobre un archivo que lo tiene, mal escrito.
    #[test]
    fn un_toml_roto_dice_que_archivo_es() {
        let dir = temp_dir();
        std::fs::write(dir.join("roto.toml"), "esto no [ es toml").unwrap();

        let mut catalogo = HashMap::new();
        let error = merge_directory(&dir, &mut catalogo).unwrap_err();
        assert!(
            error.to_string().contains("roto.toml"),
            "el error no nombra el archivo: {error}"
        );

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    #[test]
    fn lo_que_no_es_toml_se_ignora() {
        let dir = temp_dir();
        std::fs::write(dir.join("google.toml"), GOOGLE).unwrap();
        std::fs::write(dir.join("notas.txt"), "esto no es un proveedor").unwrap();
        std::fs::write(dir.join("google.toml.bak"), "ni esto").unwrap();

        assert_eq!(cargar(&dir).len(), 1);

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// El mensaje va a parar al error de D-Bus que ve la persona, así que tiene
    /// que decirle exactamente dónde dejar el client_id.
    const NEXTCLOUD: &str = r#"
        id = "nextcloud"
        display_name = "Nextcloud"
        kind = "nextcloud"
        capabilities = ["drive", "calendar"]
    "#;

    /// Nextcloud se conecta **sin configurar nada**: las credenciales las emite
    /// el servidor de la propia persona. Si `is_configured` le exigiera un
    /// client_id, el único proveedor que funciona gratis quedaría apagado.
    #[test]
    fn nextcloud_esta_listo_sin_client_id() {
        let dir = temp_dir();
        std::fs::write(dir.join("nextcloud.toml"), NEXTCLOUD).unwrap();

        let nube = &cargar(&dir)["nextcloud"];
        assert_eq!(nube.kind, ProviderKind::Nextcloud);
        assert_eq!(nube.client_id, None);
        assert!(nube.is_configured());
        assert_eq!(nube.capabilities(), vec![CapabilityType::Calendar, CapabilityType::Drive]);

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// Un proveedor OAuth2 sin client_id no está listo, y ésa es la diferencia
    /// que hace que la pantalla muestre a Google apagado y a Nextcloud
    /// encendido.
    #[test]
    fn un_oauth2_sin_client_id_no_esta_listo() {
        let dir = temp_dir();
        std::fs::write(dir.join("google.toml"), GOOGLE).unwrap();

        let google = &cargar(&dir)["google"];
        assert_eq!(google.kind, ProviderKind::Oauth2, "oauth2 es el tipo por omisión");
        assert!(!google.is_configured());

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// Las capacidades explícitas ganan a los alcances, que es como se
    /// recortaría lo que declara una cuenta de Nextcloud sin recompilar.
    #[test]
    fn la_lista_explicita_de_capacidades_gana_a_los_alcances() {
        let dir = temp_dir();
        std::fs::write(
            dir.join("mixto.toml"),
            r#"
                id = "mixto"
                display_name = "Mixto"
                auth_url = "https://ejemplo.com/auth"
                token_url = "https://ejemplo.com/token"
                capabilities = ["email"]

                [scopes]
                calendar = ["algo"]
                contacts = ["otro"]
            "#,
        )
        .unwrap();

        assert_eq!(cargar(&dir)["mixto"].capabilities(), vec![CapabilityType::Email]);

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// Sin `kind`, un archivo viejo tiene que seguir leyéndose como OAuth2: es
    /// el tipo que tenían todos antes de que Nextcloud existiera.
    #[test]
    fn un_archivo_sin_kind_es_oauth2() {
        assert_eq!(ProviderKind::default(), ProviderKind::Oauth2);
    }

    /// El mensaje va a parar al error de D-Bus que ve quien programa el cliente.
    #[test]
    fn el_error_de_tipo_equivocado_dice_cual_es_el_flujo() {
        let mensaje = CatalogError::WrongKind {
            provider: "nextcloud".into(),
            esperado: "nextcloud",
        }
        .to_string();
        assert!(mensaje.contains("nextcloud"), "{mensaje}");
        assert!(mensaje.contains("no se conecta así"), "{mensaje}");
    }

    #[test]
    fn el_error_de_client_id_dice_donde_ponerlo() {
        let mensaje = CatalogError::NoClientId("google".into()).to_string();
        assert!(mensaje.contains("/etc/vasak-accounts/providers.d/google.toml"), "{mensaje}");
    }

    /// Los archivos que el paquete instala tienen que parsear.
    ///
    /// Un error de tipeo en uno de ellos no rompe la compilación ni ningún otro
    /// test: aparecería recién cuando alguien aprieta el botón de conectar y el
    /// servicio responde «no se pudo leer el catálogo».
    #[test]
    fn los_proveedores_que_trae_el_paquete_parsean() {
        let directorio = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/providers.d");
        let catalogo = cargar(&directorio);

        assert!(!catalogo.is_empty(), "el paquete no trae ningún proveedor");

        for (id, proveedor) in &catalogo {
            assert_eq!(id, &proveedor.id, "el nombre del archivo no coincide con el id");
            assert!(!proveedor.display_name.is_empty(), "{id} no tiene nombre visible");
            assert!(
                !proveedor.capabilities().is_empty(),
                "{id} no ofrece ninguna capacidad; nadie lo podría conectar"
            );

            // Sin client_id **a propósito**: el paquete no distribuye ninguno.
            // Si alguno apareciera acá, sería una credencial nuestra viajando
            // dentro de un paquete público.
            assert_eq!(
                proveedor.client_id, None,
                "{id} trae un client_id; eso va en /etc, no en el paquete"
            );
            assert_eq!(proveedor.client_secret, None, "{id} trae un client_secret");

            match proveedor.kind {
                ProviderKind::Oauth2 => {
                    // Un proveedor OAuth2 sin URLs no se puede conectar nunca, y
                    // por http entregaría el código de autorización en claro.
                    for (nombre, url) in
                        [("auth_url", &proveedor.auth_url), ("token_url", &proveedor.token_url)]
                    {
                        let url = url
                            .as_deref()
                            .unwrap_or_else(|| panic!("{id} no tiene {nombre}"));
                        assert!(url.starts_with("https://"), "{id}: {nombre}={url} no es https");
                    }
                }
                // Nextcloud no las tiene: la dirección la escribe la persona y
                // no se sabe hasta ese momento.
                ProviderKind::Nextcloud => {
                    assert_eq!(proveedor.auth_url, None, "{id} no debería tener auth_url");
                    assert_eq!(proveedor.token_url, None, "{id} no debería tener token_url");
                    assert!(
                        proveedor.is_configured(),
                        "{id} tiene que poder conectarse sin configurar nada"
                    );
                }
            }
        }
    }

    /// Google no devuelve refresh_token sin estos dos parámetros, y la cuenta se
    /// muere en una hora sin decir por qué. Es el fallo más caro de diagnosticar
    /// de todo el flujo, así que se comprueba en el archivo.
    /// El archivo que trae el paquete tiene que declarar las capacidades que la
    /// pantalla ofrece. Sin ellas la cuenta se conectaría y no serviría para
    /// nada — ninguna aplicación le podría pedir permiso a algo que no declara.
    #[test]
    fn el_archivo_de_nextcloud_declara_sus_capacidades() {
        let directorio = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/providers.d");
        let nube = &cargar(&directorio)["nextcloud"];

        assert_eq!(nube.kind, ProviderKind::Nextcloud);
        assert!(nube.is_configured(), "no tiene que necesitar configuración");
        for esperada in [CapabilityType::Drive, CapabilityType::Calendar, CapabilityType::Contacts] {
            assert!(
                nube.capabilities().contains(&esperada),
                "falta '{}': una cuenta sin ella no la puede ofrecer a ninguna app",
                esperada.as_id(),
            );
        }
    }

    #[test]
    fn el_archivo_de_google_pide_acceso_sin_conexion() {
        let directorio = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/providers.d");
        let google = &cargar(&directorio)["google"];

        assert_eq!(google.extra_auth_params.get("access_type").map(String::as_str), Some("offline"));
        assert_eq!(google.extra_auth_params.get("prompt").map(String::as_str), Some("consent"));
    }

    /// `offline_access` cumple para Microsoft el mismo papel que
    /// `access_type=offline` para Google, y se pide como un alcance más.
    #[test]
    fn el_archivo_de_microsoft_pide_acceso_sin_conexion() {
        let directorio = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/providers.d");
        let microsoft = &cargar(&directorio)["microsoft"];

        for (capacidad, alcances) in &microsoft.scopes {
            assert!(
                alcances.iter().any(|a| a == "offline_access"),
                "'{}' no pide offline_access: la cuenta no se va a poder renovar",
                capacidad.as_id(),
            );
        }
    }

    #[test]
    fn el_error_de_proveedor_desconocido_dice_donde_se_buscan() {
        let mensaje = CatalogError::Unknown("inventado".into()).to_string();
        assert!(mensaje.contains(SHIPPED) && mensaje.contains(LOCAL), "{mensaje}");
    }
}
