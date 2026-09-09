//! Los flujos de autorización a medio terminar.
//!
//! Entre que se abre el navegador y vuelve el código de autorización hay que
//! guardar tres cosas: el `code_verifier` de PKCE, el `state` contra el que se
//! compara la vuelta, y a qué proveedor y usuario corresponde todo eso.
//!
//! **Sólo en memoria, y a propósito.** El `code_verifier` es lo único que
//! impide que un código robado sirva para algo, así que escribirlo en disco
//! sería guardar la llave al lado de la cerradura. Que un reinicio del servicio
//! tire los flujos a medias es correcto: la persona vuelve a apretar el botón.
//!
//! Tampoco sale nunca de acá. La interfaz recibe un `request_id` que no sirve
//! para nada más que devolverlo, y el verifier viaja del servicio al proveedor
//! sin pasar por el proceso del usuario — que es toda la razón de que este
//! flujo se haya mudado desde la ventana de configuración.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::storage::CapabilityType;

/// Cuánto vive un flujo sin terminar.
///
/// Cinco minutos es lo que tarda alguien en elegir la cuenta, escribir la
/// contraseña y pasar el segundo factor sin apurarse. Más que eso, y lo que
/// queda en memoria es basura de una ventana que se cerró.
const TTL: Duration = Duration::from_secs(300);

/// Cuántos flujos sin terminar se le aceptan a un usuario a la vez.
///
/// Sin tope, un programa corriendo con su cuenta puede llamar `BeginAuth` en un
/// bucle y hacer crecer la memoria de un proceso de root sin límite. Diez es
/// más de lo que cualquier persona va a tener abiertos.
const MAX_POR_USUARIO: usize = 10;

#[derive(Debug, Clone)]
pub struct PendingAuth {
    pub uid: u32,
    pub provider_id: String,
    pub capabilities: Vec<CapabilityType>,
    pub redirect_uri: String,
    pub verifier: String,
    pub state: String,
    creado: Instant,
}

impl PendingAuth {
    /// El único modo de armar uno.
    ///
    /// La marca de tiempo la pone esta función y no quien llama: si el momento
    /// de creación fuera un campo público, un flujo podría nacer ya vencido —o
    /// no vencer nunca— por un descuido en el lugar que lo construye.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        uid: u32,
        provider_id: String,
        capabilities: Vec<CapabilityType>,
        redirect_uri: String,
        verifier: String,
        state: String,
    ) -> Self {
        Self {
            uid,
            provider_id,
            capabilities,
            redirect_uri,
            verifier,
            state,
            creado: Instant::now(),
        }
    }

    fn vencido(&self, ahora: Instant) -> bool {
        ahora.duration_since(self.creado) >= TTL
    }
}

#[derive(Debug, Default)]
pub struct PendingAuths {
    por_id: HashMap<String, PendingAuth>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TakeError {
    /// No existe, o venció, o ya se usó. Los tres se responden igual **a
    /// propósito**: distinguirlos le diría a quien prueba identificadores al
    /// azar cuáles existen.
    Unknown,
    /// El `state` que volvió del navegador no es el que se mandó. Es la defensa
    /// contra que alguien te haga completar el flujo de *su* cuenta.
    StateMismatch,
    /// El flujo lo empezó otro usuario. No debería pasar nunca —los
    /// identificadores no se publican— pero completarlo escribiría en las
    /// cuentas de otra persona.
    WrongUser,
}

impl std::fmt::Display for TakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TakeError::Unknown => write!(
                f,
                "no hay ninguna autorización en curso con ese identificador; \
                 puede haber vencido (cinco minutos) o haberse completado ya"
            ),
            TakeError::StateMismatch => write!(
                f,
                "la respuesta del navegador no corresponde a esta autorización"
            ),
            TakeError::WrongUser => write!(f, "esa autorización la empezó otro usuario"),
        }
    }
}

impl PendingAuths {
    /// Guarda un flujo y devuelve su identificador.
    ///
    /// Aprovecha para tirar los vencidos: no hay ninguna tarea de limpieza
    /// dando vueltas, y este es el único momento en que el mapa crece.
    pub fn insert(&mut self, pendiente: PendingAuth) -> Result<String, String> {
        self.purgar(Instant::now());

        let del_usuario = self
            .por_id
            .values()
            .filter(|p| p.uid == pendiente.uid)
            .count();
        if del_usuario >= MAX_POR_USUARIO {
            return Err(format!(
                "hay {del_usuario} autorizaciones sin terminar; \
                 esperá a que venzan o cancelalas antes de empezar otra"
            ));
        }

        let id = uuid::Uuid::new_v4().to_string();
        self.por_id.insert(id.clone(), pendiente);
        Ok(id)
    }

    /// Saca el flujo del mapa si todo cuadra.
    ///
    /// Se **consume**: un código de autorización se canjea una sola vez, y dejar
    /// el verifier disponible para un segundo intento no aportaría nada más que
    /// una ventana para reintentar con otro código.
    pub fn take(
        &mut self,
        request_id: &str,
        uid: u32,
        state: &str,
    ) -> Result<PendingAuth, TakeError> {
        self.purgar(Instant::now());

        let pendiente = self.por_id.get(request_id).ok_or(TakeError::Unknown)?;

        if pendiente.uid != uid {
            return Err(TakeError::WrongUser);
        }
        if !constant_time_eq(&pendiente.state, state) {
            return Err(TakeError::StateMismatch);
        }

        Ok(self.por_id.remove(request_id).expect("recién se encontró"))
    }

    /// Cancela un flujo que la persona abandonó, sin esperar a que venza.
    pub fn cancel(&mut self, request_id: &str, uid: u32) -> bool {
        match self.por_id.get(request_id) {
            Some(p) if p.uid == uid => self.por_id.remove(request_id).is_some(),
            _ => false,
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.por_id.len()
    }

    fn purgar(&mut self, ahora: Instant) {
        self.por_id.retain(|_, pendiente| !pendiente.vencido(ahora));
    }
}

/// Compara sin cortar en la primera diferencia.
///
/// El `state` es un secreto corto que se compara contra algo que manda el
/// cliente. Un `==` común corta apenas encuentra un byte distinto, y ese tiempo
/// se puede medir para adivinarlo de a un carácter.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Sólo se aceptan destinos de vuelta en el propio equipo.
///
/// El `redirect_uri` lo elige quien llama, y es adonde el proveedor manda el
/// código de autorización. Sin esta comprobación, un programa podría pedir que
/// el código termine en un servidor ajeno y quedarse con la cuenta.
///
/// Es la misma regla que los proveedores aplican para aplicaciones de
/// escritorio, y acá se aplica antes de armar la URL para no depender de que el
/// proveedor la aplique bien.
pub fn is_loopback_redirect(uri: &str) -> bool {
    let Ok(url) = url::Url::parse(uri) else {
        return false;
    };
    if url.scheme() != "http" {
        return false;
    }
    matches!(url.host_str(), Some("127.0.0.1") | Some("localhost") | Some("[::1]") | Some("::1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pendiente(uid: u32) -> PendingAuth {
        PendingAuth {
            uid,
            provider_id: "google".into(),
            capabilities: vec![CapabilityType::Calendar],
            redirect_uri: "http://127.0.0.1:45321/callback".into(),
            verifier: "el-verifier".into(),
            state: "el-state".into(),
            creado: Instant::now(),
        }
    }

    #[test]
    fn un_flujo_se_guarda_y_se_recupera_una_sola_vez() {
        let mut mapa = PendingAuths::default();
        let id = mapa.insert(pendiente(1000)).unwrap();

        let recuperado = mapa.take(&id, 1000, "el-state").unwrap();
        assert_eq!(recuperado.verifier, "el-verifier");

        // La segunda vez ya no está: un código se canjea una sola vez.
        assert_eq!(mapa.take(&id, 1000, "el-state").unwrap_err(), TakeError::Unknown);
        assert_eq!(mapa.len(), 0);
    }

    /// Sin esto, alguien puede hacerte completar el flujo de *su* cuenta y
    /// quedarse leyendo tu correo desde tu propio escritorio.
    #[test]
    fn un_state_distinto_no_completa_el_flujo() {
        let mut mapa = PendingAuths::default();
        let id = mapa.insert(pendiente(1000)).unwrap();

        assert_eq!(mapa.take(&id, 1000, "otro-state").unwrap_err(), TakeError::StateMismatch);
        // Y el flujo sigue vivo: un intento fallido no puede servir para
        // cancelarle la autorización a quien la estaba haciendo bien.
        assert!(mapa.take(&id, 1000, "el-state").is_ok());
    }

    #[test]
    fn un_flujo_de_otro_usuario_no_se_puede_completar() {
        let mut mapa = PendingAuths::default();
        let id = mapa.insert(pendiente(1000)).unwrap();

        assert_eq!(mapa.take(&id, 1001, "el-state").unwrap_err(), TakeError::WrongUser);
    }

    #[test]
    fn un_identificador_inventado_no_dice_nada() {
        let mut mapa = PendingAuths::default();
        mapa.insert(pendiente(1000)).unwrap();

        assert_eq!(mapa.take("inventado", 1000, "el-state").unwrap_err(), TakeError::Unknown);
    }

    #[test]
    fn un_flujo_vencido_desaparece() {
        let mut mapa = PendingAuths::default();
        let mut viejo = pendiente(1000);
        viejo.creado = Instant::now() - TTL - Duration::from_secs(1);
        let id = mapa.insert(viejo).unwrap();

        assert_eq!(mapa.take(&id, 1000, "el-state").unwrap_err(), TakeError::Unknown);
        assert_eq!(mapa.len(), 0, "tenía que purgarse, no sólo rechazarse");
    }

    /// Un flujo vencido no puede ocupar lugar contra el tope: si no, diez
    /// ventanas cerradas dejarían a la persona sin poder conectar nada durante
    /// cinco minutos.
    #[test]
    fn los_vencidos_no_cuentan_para_el_tope() {
        let mut mapa = PendingAuths::default();
        for _ in 0..MAX_POR_USUARIO {
            let mut viejo = pendiente(1000);
            viejo.creado = Instant::now() - TTL - Duration::from_secs(1);
            mapa.insert(viejo).unwrap();
        }

        assert!(mapa.insert(pendiente(1000)).is_ok());
        assert_eq!(mapa.len(), 1);
    }

    /// Sin tope, un programa con la cuenta del usuario hace crecer la memoria
    /// de un proceso de root llamando BeginAuth en un bucle.
    #[test]
    fn no_se_pueden_acumular_flujos_sin_limite() {
        let mut mapa = PendingAuths::default();
        for _ in 0..MAX_POR_USUARIO {
            mapa.insert(pendiente(1000)).unwrap();
        }

        assert!(mapa.insert(pendiente(1000)).is_err());
        // Y el tope es por usuario: el de al lado no queda bloqueado.
        assert!(mapa.insert(pendiente(1001)).is_ok());
    }

    #[test]
    fn cancelar_saca_el_flujo_y_solo_al_dueno() {
        let mut mapa = PendingAuths::default();
        let id = mapa.insert(pendiente(1000)).unwrap();

        assert!(!mapa.cancel(&id, 1001), "otro usuario no puede cancelarlo");
        assert!(mapa.cancel(&id, 1000));
        assert!(!mapa.cancel(&id, 1000), "cancelar dos veces no es cancelar");
    }

    #[test]
    fn solo_se_vuelve_al_propio_equipo() {
        for bueno in [
            "http://127.0.0.1:45321/callback",
            "http://localhost:8080/x",
            "http://[::1]:45321/callback",
        ] {
            assert!(is_loopback_redirect(bueno), "{bueno} tenía que aceptarse");
        }

        for malo in [
            "http://ejemplo.com/callback",
            "https://ejemplo.com/callback",
            // El que se lleva el código a otro lado disfrazado de local.
            "http://127.0.0.1.ejemplo.com/callback",
            "http://ejemplo.com#127.0.0.1",
            "file:///tmp/x",
            "vasak://callback",
            "no es una url",
            "",
        ] {
            assert!(!is_loopback_redirect(malo), "{malo} tenía que rechazarse");
        }
    }

    #[test]
    fn la_comparacion_en_tiempo_constante_sigue_comparando() {
        assert!(constant_time_eq("igual", "igual"));
        assert!(!constant_time_eq("igual", "iguaL"));
        assert!(!constant_time_eq("corto", "mucho mas largo"));
        assert!(constant_time_eq("", ""));
    }
}
