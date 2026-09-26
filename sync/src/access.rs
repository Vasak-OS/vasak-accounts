//! Quién puede leer el almacén: el permiso `store.<área>` de quien llama.
//!
//! ── El camino de una lectura ────────────────────────────────────────────────
//!
//! 1. El **nombre único** de quien llamó (`:1.42`), del encabezado del mensaje.
//!    Lo pone el bus, así que no se puede inventar.
//! 2. Su **pid**, con `GetConnectionUnixProcessID` del bus de sesión.
//! 3. Su **momento de arranque**, de `/proc/<pid>/stat`
//!    (`vasak_accounts_common::process`), para que un pid reciclado no herede
//!    lo que se le concedió al anterior.
//! 4. `CheckPermissionFor(pid, arranque, "store.contacts", cuenta)` en
//!    `vasak-permissions`, en el bus del sistema. El sincronizador es un
//!    delegado de ese servicio desde su 0.15.0: pregunta **por quien lo
//!    llamó**, y la decisión queda anotada contra esa aplicación, no contra el
//!    sincronizador.
//!
//! ── La caché ────────────────────────────────────────────────────────────────
//!
//! La respuesta se guarda **30 segundos por nombre único y recurso**. Un «no»
//! también: sin eso, una aplicación a la que le dijeron que no preguntaría otra
//! vez en cada página, y `vasak-permissions` abriría un diálogo por cada una si
//! la persona todavía no decidió. Un nombre único no se reusa nunca en el bus,
//! así que la respuesta no puede pasar a otro proceso; y cuando el nombre se va
//! (`NameOwnerChanged` sin dueño nuevo) se olvida lo suyo en el acto.
//!
//! **Un error no se guarda y cuenta como «no»**: falla cerrado. Si el servicio
//! de permisos no está, no contesta, o contesta algo que no se entiende, no se
//! devuelve ningún dato, y la próxima lectura vuelve a preguntar.
//!
//! **Dos pedidos a la vez del mismo nombre son una sola pregunta.** El primero
//! pregunta y los demás esperan esa misma respuesta: una aplicación que pide la
//! lista y la búsqueda juntas no ve dos diálogos.
//!
//! **La pregunta puede tardar lo que tarde la persona**: sin decisión guardada,
//! el servicio abre un diálogo y contesta recién al cerrarlo. Se espera hasta
//! [`CHECK_TIMEOUT`], más que los 25 s que usan por omisión los clientes de
//! D-Bus; y quien llama al almacén también tiene que esperar con un tiempo
//! largo, o su llamada vence antes de que la persona conteste.
//!
//! ── Lo que esto no protege ──────────────────────────────────────────────────
//!
//! **Es consentimiento y visibilidad, no una frontera.** La base es un archivo
//! de la persona, y su clave vive en el llavero de la sesión, que le entrega
//! sus secretos a cualquier proceso de ese mismo usuario. Un programa que no
//! quiera preguntar puede ir directo al archivo, o pedirle la clave al llavero.
//! El permiso decide qué contesta **este servicio**, y le muestra a la persona
//! quién pidió qué; no impide que un proceso suyo lea lo que es suyo.
//!
//! ── El límite por llamante ──────────────────────────────────────────────────
//!
//! Los comandos que cambian algo (`ClearStore`, `SetStoreEnabled`,
//! `RequestSync`) no leen nada, pero cuestan: vaciar son dos escrituras del
//! llavero y un `fsync`, con el almacén tomado. [`CallerLimits`] pone dos
//! topes, y el pedido que pasa cualquiera de los dos contesta
//! `LimitsExceeded`:
//!
//! - [`CONTROL_BURST`] por cuenta y por nombre único cada [`CONTROL_WINDOW`],
//!   para los tres. Frena a una aplicación con un bucle por error, **no a un
//!   proceso que quiera esquivarlo**: cada conexión nueva es un nombre único
//!   nuevo, y el bus no limita cuántas se abren por segundo —sólo cuántas hay
//!   abiertas a la vez—. Medido: más de 300 por segundo con `busctl`.
//! - Un **piso por cuenta, venga de quien venga**: un `ClearStore`, un
//!   `SetStoreEnabled(true)` y un `SetStoreEnabled(false)` por cuenta cada
//!   [`ACCOUNT_FLOOR`], cada uno por su lado. Vaciar dos veces en diez
//!   segundos nunca hace falta, y con esto el costo queda acotado aunque cada
//!   pedido llegue de una conexión distinta. `RequestSync` no lo tiene: no
//!   borra nada, y dos aplicaciones que se abren a la vez lo piden las dos.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::future::{BoxFuture, FutureExt, Shared};

/// Cuánto vale una respuesta del servicio de permisos.
pub const CACHE_TTL: Duration = Duration::from_secs(30);

/// Cuánto se espera al servicio de permisos, que puede estar esperando a que
/// la persona conteste un diálogo.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(120);

/// Leer los contactos guardados. El recurso de `vasak-permissions`.
pub const CONTACTS_RESOURCE: &str = "store.contacts";

/// Cuántos comandos de control deja pasar [`CallerLimits`] por cuenta y
/// nombre único en cada ventana.
pub const CONTROL_BURST: usize = 3;

/// La ventana de [`CONTROL_BURST`].
pub const CONTROL_WINDOW: Duration = Duration::from_secs(60);

/// El piso por cuenta de lo que borra o rehace una base: uno de cada
/// [`ControlAction`] con piso, por cuenta, en este tiempo, de cualquier
/// llamante.
pub const ACCOUNT_FLOOR: Duration = Duration::from_secs(10);

/// Qué comando de control es: el piso por cuenta va por cada uno.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlAction {
    /// `ClearStore`.
    Clear,
    /// `SetStoreEnabled(true)`.
    Enable,
    /// `SetStoreEnabled(false)`.
    Disable,
    /// `RequestSync`: sin piso por cuenta.
    Sync,
}

impl ControlAction {
    fn has_floor(self) -> bool {
        !matches!(self, ControlAction::Sync)
    }
}

/// Por qué no entró un comando de control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Quien llama pasó su cupo sobre la cuenta, o no dice quién es.
    Caller,
    /// La cuenta recibió ese mismo comando hace menos de [`ACCOUNT_FLOOR`].
    Account,
}

/// El reloj de la caché y del límite, para poder probarlos sin esperar.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> Instant;
}

/// El reloj de verdad.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Lo que hace falta para preguntar: el bus de sesión y el servicio de
/// permisos. Un rasgo para poder probar la caché y la fusión de pedidos con uno
/// que cuenta cuántas veces le preguntaron.
pub trait PermissionBackend: Send + Sync + 'static {
    /// El pid del dueño de un nombre único del bus de sesión.
    fn caller_pid(&self, unique_name: String) -> BoxFuture<'static, Result<u32, String>>;

    /// El momento de arranque de un proceso.
    fn start_time(&self, pid: u32) -> Result<u64, String>;

    /// `CheckPermissionFor`.
    fn check_permission_for(
        &self,
        pid: u32,
        start_time: u64,
        resource: String,
        detail: String,
    ) -> BoxFuture<'static, Result<bool, String>>;
}

/// Lo que contestó el servicio de permisos, o que no contestó.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    Denied,
    /// No se pudo preguntar, o la respuesta no se entendió. **Cuenta como
    /// negado** y no se guarda.
    Failed(String),
}

struct Cached {
    allowed: bool,
    at: Instant,
}

struct InFlight {
    id: u64,
    answer: Shared<BoxFuture<'static, Verdict>>,
}

#[derive(Default)]
struct State {
    cache: HashMap<(String, String), Cached>,
    in_flight: HashMap<(String, String), InFlight>,
    next_id: u64,
}

/// El permiso de lectura, con su caché.
pub struct Access {
    backend: Arc<dyn PermissionBackend>,
    clock: Arc<dyn Clock>,
    timeout: Duration,
    state: Mutex<State>,
    limits: CallerLimits,
}

impl Access {
    pub fn new(backend: Arc<dyn PermissionBackend>, clock: Arc<dyn Clock>) -> Self {
        Self {
            limits: CallerLimits::new(Arc::clone(&clock)),
            backend,
            clock,
            timeout: CHECK_TIMEOUT,
            state: Mutex::new(State::default()),
        }
    }

    /// Lo mismo, con otro tiempo máximo para la pregunta.
    #[cfg(test)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// El límite de los comandos de control, con el mismo reloj.
    pub fn limits(&self) -> &CallerLimits {
        &self.limits
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        // Nada de lo que se hace con la cerradura tomada puede entrar en
        // pánico a mitad; si pasara, lo que queda adentro sigue siendo
        // coherente —una entrada está o no está—.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Si `caller` puede usar `resource`. `detail` va al diálogo: de qué cuenta
    /// se trata.
    ///
    /// Sin remitente —una conexión punto a punto, que no tiene bus que lo
    /// ponga— es `Failed`: no hay a quién preguntarle por quién.
    pub async fn check(&self, caller: Option<&str>, resource: &str, detail: &str) -> Verdict {
        let Some(name) = caller else {
            return Verdict::Failed("el pedido no dice quién lo manda".into());
        };
        let key = (name.to_string(), resource.to_string());

        let (id, answer) = {
            let mut state = self.state();
            let now = self.clock.now();
            if let Some(cached) = state.cache.get(&key) {
                if now.saturating_duration_since(cached.at) < CACHE_TTL {
                    return if cached.allowed {
                        Verdict::Allowed
                    } else {
                        Verdict::Denied
                    };
                }
                state.cache.remove(&key);
            }
            match state.in_flight.get(&key) {
                Some(flight) => (flight.id, flight.answer.clone()),
                None => {
                    state.next_id += 1;
                    let id = state.next_id;
                    let answer = ask(
                        Arc::clone(&self.backend),
                        self.timeout,
                        name.to_string(),
                        resource.to_string(),
                        detail.to_string(),
                    )
                    .boxed()
                    .shared();
                    state.in_flight.insert(
                        key.clone(),
                        InFlight {
                            id,
                            answer: answer.clone(),
                        },
                    );
                    (id, answer)
                }
            }
        };

        let verdict = answer.await;

        // El primero que vuelve de esta pregunta la anota; los que esperaban la
        // misma ya no encuentran su vuelo y no tocan nada.
        let mut state = self.state();
        if state.in_flight.get(&key).is_some_and(|f| f.id == id) {
            state.in_flight.remove(&key);
            let allowed = match &verdict {
                Verdict::Allowed => Some(true),
                Verdict::Denied => Some(false),
                Verdict::Failed(_) => None,
            };
            if let Some(allowed) = allowed {
                let now = self.clock.now();
                state
                    .cache
                    .retain(|_, c| now.saturating_duration_since(c.at) < CACHE_TTL);
                state.cache.insert(key, Cached { allowed, at: now });
            }
        }
        verdict
    }

    /// Lo que se sabe sin preguntar: la respuesta guardada, si todavía vale.
    ///
    /// Es lo que usa `GetStatus`, que **nunca** abre un diálogo.
    pub fn cached(&self, caller: Option<&str>, resource: &str) -> Option<bool> {
        let name = caller?;
        let state = self.state();
        let cached = state.cache.get(&(name.to_string(), resource.to_string()))?;
        (self.clock.now().saturating_duration_since(cached.at) < CACHE_TTL)
            .then_some(cached.allowed)
    }

    /// Un nombre único se fue del bus: se olvida todo lo suyo.
    pub fn forget(&self, unique_name: &str) {
        self.state()
            .cache
            .retain(|(name, _), _| name != unique_name);
        self.limits.forget(unique_name);
    }
}

/// La pregunta entera, de nombre único a respuesta.
async fn ask(
    backend: Arc<dyn PermissionBackend>,
    timeout: Duration,
    name: String,
    resource: String,
    detail: String,
) -> Verdict {
    let pid = match backend.caller_pid(name).await {
        Ok(pid) => pid,
        Err(e) => return Verdict::Failed(format!("no se supo el pid de quien llama: {e}")),
    };
    let start_time = match backend.start_time(pid) {
        Ok(start_time) => start_time,
        Err(e) => return Verdict::Failed(e),
    };
    match tokio::time::timeout(
        timeout,
        backend.check_permission_for(pid, start_time, resource, detail),
    )
    .await
    {
        Ok(Ok(true)) => Verdict::Allowed,
        Ok(Ok(false)) => Verdict::Denied,
        Ok(Err(e)) => Verdict::Failed(format!("el servicio de permisos no contestó: {e}")),
        Err(_) => Verdict::Failed(format!(
            "el servicio de permisos no contestó en {} s",
            timeout.as_secs()
        )),
    }
}

/// El límite de los comandos de control: [`CONTROL_BURST`] por cuenta y
/// nombre único cada [`CONTROL_WINDOW`], y el piso por cuenta
/// ([`ACCOUNT_FLOOR`]) de lo que borra.
///
/// El cupo va por nombre único porque es lo que el bus garantiza sin
/// preguntarle a nadie. **No alcanza contra quien lo quiera esquivar**: abrir
/// una conexión nueva es un nombre nuevo, y el bus no limita cuántas se abren
/// por segundo. Por eso el piso: no mira quién llama, y un nombre que se va del
/// bus —o un aviso falso de que se fue— no lo reinicia.
pub struct CallerLimits {
    clock: Arc<dyn Clock>,
    state: Mutex<LimitsState>,
}

#[derive(Default)]
struct LimitsState {
    /// Por nombre único y cuenta, cuándo llegó cada comando de la ventana.
    calls: HashMap<(String, String), VecDeque<Instant>>,
    /// Por cuenta y comando, cuándo entró el último con piso.
    floors: HashMap<(String, ControlAction), Instant>,
}

impl CallerLimits {
    fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            state: Mutex::new(LimitsState::default()),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, LimitsState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Anota un comando de `caller` sobre `account_id` y dice si entra. Uno
    /// que no entra no se anota en ninguno de los dos topes: no alarga la
    /// espera.
    ///
    /// Sin remitente no hay a quién contarle, y no entra.
    pub fn admit(
        &self,
        caller: Option<&str>,
        account_id: &str,
        action: ControlAction,
    ) -> Result<(), Refusal> {
        let Some(name) = caller else {
            return Err(Refusal::Caller);
        };
        let now = self.clock.now();
        let mut state = self.state();
        // Lo vencido se va, de todos: así las tablas no crecen con los nombres
        // que ya no llaman ni con las cuentas que nadie toca.
        state.calls.retain(|_, times| {
            while times
                .front()
                .is_some_and(|t| now.saturating_duration_since(*t) >= CONTROL_WINDOW)
            {
                times.pop_front();
            }
            !times.is_empty()
        });
        state
            .floors
            .retain(|_, at| now.saturating_duration_since(*at) < ACCOUNT_FLOOR);

        let key = (name.to_string(), account_id.to_string());
        if state
            .calls
            .get(&key)
            .is_some_and(|t| t.len() >= CONTROL_BURST)
        {
            return Err(Refusal::Caller);
        }
        let floor = (account_id.to_string(), action);
        if action.has_floor() && state.floors.contains_key(&floor) {
            return Err(Refusal::Account);
        }
        state.calls.entry(key).or_default().push_back(now);
        if action.has_floor() {
            state.floors.insert(floor, now);
        }
        Ok(())
    }

    /// Lo de un nombre único que se fue: su cupo. El piso por cuenta no es de
    /// nadie y no se toca.
    fn forget(&self, unique_name: &str) {
        self.state()
            .calls
            .retain(|(name, _), _| name != unique_name);
    }
}

/// Quien manda las señales del bus.
const BUS_NAME: &str = "org.freedesktop.DBus";

/// Olvida lo de cada nombre único que se va del bus: `NameOwnerChanged` con un
/// nombre único y sin dueño nuevo.
///
/// **Sólo las del bus mismo** (`org.freedesktop.DBus`), y se mira en cada
/// señal además de pedirlo en la regla: zbus no compara el remitente de la
/// regla con un nombre conocido en su filtro local, así que un
/// `NameOwnerChanged` que otro proceso mande directo a este —unicast, que el
/// bus entrega sin mirar la regla— pasaría. Olvidar no concede ningún
/// permiso, pero reiniciaba el cupo de ese nombre y hacía volver a preguntar.
pub async fn watch_departures(
    connection: zbus::Connection,
    access: Arc<Access>,
) -> zbus::Result<()> {
    use futures_util::StreamExt;

    // En una conexión punto a punto —las pruebas— no hay bus ni remitentes.
    let expected_sender = connection.is_bus().then_some(BUS_NAME);
    let mut rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.DBus")?
        .member("NameOwnerChanged")?;
    if let Some(sender) = expected_sender {
        rule = rule.sender(sender)?;
    }
    let mut departures =
        zbus::MessageStream::for_match_rule(rule.build(), &connection, None).await?;
    while let Some(Ok(message)) = departures.next().await {
        if let Some(name) = departed_name(&message, expected_sender) {
            access.forget(&name);
        }
    }
    Ok(())
}

/// El nombre único que se fue, si el mensaje dice eso: `(nombre, dueño viejo,
/// dueño nuevo)` con un nombre que empieza con `:` y el dueño nuevo vacío, y
/// mandado por `expected_sender` si hay uno que esperar.
fn departed_name(message: &zbus::Message, expected_sender: Option<&str>) -> Option<String> {
    if let Some(expected) = expected_sender {
        let header = message.header();
        if header.sender().map(|s| s.as_str()) != Some(expected) {
            return None;
        }
    }
    let (name, _old, new): (String, String, String) = message.body().deserialize().ok()?;
    (name.starts_with(':') && new.is_empty()).then_some(name)
}

/// El camino de verdad: el bus de sesión para el pid, y el servicio de
/// permisos en el bus del sistema.
pub struct DbusPermissions {
    bus: zbus::Connection,
    permissions: Arc<tokio::sync::OnceCell<zbus::Connection>>,
}

impl DbusPermissions {
    /// Sobre la conexión de sesión que ya existe. La del sistema se abre la
    /// primera vez que hace falta, y si falla se vuelve a intentar en la
    /// próxima pregunta.
    pub fn new(bus: zbus::Connection) -> Self {
        Self {
            bus,
            permissions: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// Con las dos conexiones ya hechas: las pruebas, punto a punto.
    #[cfg(test)]
    pub fn withconnections(bus: zbus::Connection, permissions: zbus::Connection) -> Self {
        Self {
            bus,
            permissions: Arc::new(tokio::sync::OnceCell::new_with(Some(permissions))),
        }
    }
}

impl PermissionBackend for DbusPermissions {
    fn caller_pid(&self, unique_name: String) -> BoxFuture<'static, Result<u32, String>> {
        let bus = self.bus.clone();
        async move {
            let destination = bus.is_bus().then_some("org.freedesktop.DBus");
            let reply = bus
                .call_method(
                    destination,
                    "/org/freedesktop/DBus",
                    Some("org.freedesktop.DBus"),
                    "GetConnectionUnixProcessID",
                    &(unique_name.as_str(),),
                )
                .await
                .map_err(|e| e.to_string())?;
            reply.body().deserialize::<u32>().map_err(|e| e.to_string())
        }
        .boxed()
    }

    fn start_time(&self, pid: u32) -> Result<u64, String> {
        vasak_accounts_common::process::process_start_time(pid).map_err(|e| e.to_string())
    }

    fn check_permission_for(
        &self,
        pid: u32,
        start_time: u64,
        resource: String,
        detail: String,
    ) -> BoxFuture<'static, Result<bool, String>> {
        let cell = Arc::clone(&self.permissions);
        async move {
            let connection = cell
                .get_or_try_init(vasak_accounts_common::permissions::permission_bus)
                .await
                .map_err(|e| format!("no se pudo llegar al servicio de permisos: {e}"))?;
            vasak_accounts_common::permissions::check_permission_for(
                connection, pid, start_time, &resource, &detail,
            )
            .await
            .map_err(|e| e.to_string())
        }
        .boxed()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;

    use zbus::object_server::SignalContext;

    use super::*;

    /// Un reloj que avanza sólo cuando la prueba lo pide.
    pub(crate) struct FakeClock(Mutex<Instant>);

    impl FakeClock {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(Instant::now())))
        }

        pub(crate) fn advance(&self, by: Duration) {
            *self.0.lock().unwrap() += by;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Answer {
        Allow,
        Deny,
        Fail,
    }

    pub(crate) struct PermissionsState {
        pub answer: Answer,
        pub calls: usize,
        pub asked: Vec<(u32, u64, String, String)>,
        /// Si está, cada pregunta espera un permiso de acá antes de contestar:
        /// la persona mirando el diálogo.
        pub gate: Option<Arc<tokio::sync::Semaphore>>,
    }

    /// Un `vasak-permissions` falso: contesta lo que se le diga y cuenta.
    #[derive(Clone)]
    pub(crate) struct FakePermissions(pub Arc<Mutex<PermissionsState>>);

    impl FakePermissions {
        pub(crate) fn new(answer: Answer) -> Self {
            Self(Arc::new(Mutex::new(PermissionsState {
                answer,
                calls: 0,
                asked: Vec::new(),
                gate: None,
            })))
        }

        pub(crate) fn calls(&self) -> usize {
            self.0.lock().unwrap().calls
        }

        pub(crate) fn set(&self, answer: Answer) {
            self.0.lock().unwrap().answer = answer;
        }
    }

    #[zbus::interface(name = "ar.net.vasak.os.Permissions")]
    impl FakePermissions {
        async fn check_permission_for(
            &self,
            subject_pid: u32,
            subject_start_time: u64,
            resource_id: String,
            detail: String,
        ) -> zbus::fdo::Result<bool> {
            let gate = {
                let mut state = self.0.lock().unwrap();
                state.calls += 1;
                state
                    .asked
                    .push((subject_pid, subject_start_time, resource_id, detail));
                state.gate.clone()
            };
            if let Some(gate) = gate {
                gate.acquire().await.unwrap().forget();
            }
            match self.0.lock().unwrap().answer {
                Answer::Allow => Ok(true),
                Answer::Deny => Ok(false),
                Answer::Fail => Err(zbus::fdo::Error::Failed("roto".into())),
            }
        }
    }

    /// El bus de sesión falso: de cada nombre único, su pid.
    #[derive(Clone, Default)]
    pub(crate) struct FakeBus(pub Arc<Mutex<HashMap<String, u32>>>);

    #[zbus::interface(name = "org.freedesktop.DBus")]
    impl FakeBus {
        #[zbus(name = "GetConnectionUnixProcessID")]
        async fn get_connection_unix_process_id(&self, name: String) -> zbus::fdo::Result<u32> {
            self.0
                .lock()
                .unwrap()
                .get(&name)
                .copied()
                .ok_or_else(|| zbus::fdo::Error::NameHasNoOwner(name))
        }
    }

    async fn pair(
        path: &str,
        iface: impl zbus::object_server::Interface,
    ) -> (zbus::Connection, zbus::Connection) {
        let (server_end, client_end) = tokio::net::UnixStream::pair().unwrap();
        let server = zbus::connection::Builder::unix_stream(server_end)
            .server(zbus::Guid::generate())
            .unwrap()
            .p2p()
            .serve_at(path, iface)
            .unwrap()
            .build();
        let client = zbus::connection::Builder::unix_stream(client_end)
            .p2p()
            .build();
        let (server, client) = tokio::join!(server, client);
        (server.unwrap(), client.unwrap())
    }

    /// Todo lo de una prueba del permiso: el bus y el servicio falsos, del otro
    /// lado de dos conexiones punto a punto, y el camino de verdad
    /// ([`DbusPermissions`]) hablando con ellos.
    pub(crate) struct AccessFixture {
        pub access: Arc<Access>,
        pub permissions: FakePermissions,
        pub bus: FakeBus,
        pub clock: Arc<FakeClock>,
        /// El lado del bus, para mandar `NameOwnerChanged`.
        pub bus_server: zbus::Connection,
        connections: Vec<zbus::Connection>,
    }

    impl AccessFixture {
        pub(crate) async fn new(answer: Answer) -> Self {
            let permissions = FakePermissions::new(answer);
            let bus = FakeBus::default();
            // Quien llama en las pruebas es este mismo proceso: su momento de
            // arranque se lee de verdad.
            bus.0
                .lock()
                .unwrap()
                .insert(":1.7".into(), std::process::id());
            bus.0
                .lock()
                .unwrap()
                .insert(":1.8".into(), std::process::id());
            let (bus_server, bus_client) = pair("/org/freedesktop/DBus", bus.clone()).await;
            let (permissions_server, permissions_client) = pair(
                vasak_accounts_common::permissions::SERVICE_PATH,
                permissions.clone(),
            )
            .await;
            let clock = FakeClock::new();
            let access = Arc::new(Access::new(
                Arc::new(DbusPermissions::withconnections(
                    bus_client.clone(),
                    permissions_client.clone(),
                )),
                Arc::clone(&clock) as Arc<dyn Clock>,
            ));
            Self {
                access,
                permissions,
                bus,
                clock,
                bus_server: bus_server.clone(),
                connections: vec![
                    bus_server,
                    bus_client,
                    permissions_server,
                    permissions_client,
                ],
            }
        }

        pub(crate) async fn check(&self, caller: &str) -> Verdict {
            self.access
                .check(Some(caller), CONTACTS_RESOURCE, "Trabajo")
                .await
        }
    }

    #[tokio::test]
    async fn se_pregunta_por_quien_llama_con_su_pid_y_su_arranque() {
        let f = AccessFixture::new(Answer::Allow).await;
        assert_eq!(f.check(":1.7").await, Verdict::Allowed);

        let asked = f.permissions.0.lock().unwrap().asked.clone();
        let start = vasak_accounts_common::process::process_start_time(std::process::id()).unwrap();
        assert_eq!(
            asked,
            vec![(
                std::process::id(),
                start,
                "store.contacts".to_string(),
                "Trabajo".to_string()
            )]
        );
    }

    /// Un «no» se guarda igual que un «sí»: si no, una aplicación negada abriría
    /// un diálogo por página.
    #[tokio::test]
    async fn un_no_tambien_se_guarda() {
        let f = AccessFixture::new(Answer::Deny).await;
        assert_eq!(f.check(":1.7").await, Verdict::Denied);
        assert_eq!(f.check(":1.7").await, Verdict::Denied);
        assert_eq!(f.permissions.calls(), 1);
        assert_eq!(
            f.access.cached(Some(":1.7"), CONTACTS_RESOURCE),
            Some(false)
        );
    }

    /// Un error del servicio de permisos **falla cerrado**: cuenta como negado,
    /// y no se guarda, así que la próxima vuelve a preguntar.
    #[tokio::test]
    async fn un_error_del_servicio_cuenta_como_negado_y_no_se_guarda() {
        let f = AccessFixture::new(Answer::Fail).await;
        let verdict = f.check(":1.7").await;
        assert!(matches!(verdict, Verdict::Failed(_)));
        assert_ne!(verdict, Verdict::Allowed);
        assert_eq!(f.access.cached(Some(":1.7"), CONTACTS_RESOURCE), None);

        f.permissions.set(Answer::Allow);
        assert_eq!(f.check(":1.7").await, Verdict::Allowed);
        assert_eq!(f.permissions.calls(), 2, "el error no se guardó");
    }

    /// Un nombre que el bus no conoce, o un proceso que ya no está: negado y
    /// sin preguntarle nada al servicio de permisos.
    #[tokio::test]
    async fn sin_pid_o_sin_proceso_no_hay_pregunta_ni_permiso() {
        let f = AccessFixture::new(Answer::Allow).await;
        assert!(matches!(f.check(":1.99").await, Verdict::Failed(_)));
        f.bus.0.lock().unwrap().insert(":1.9".into(), u32::MAX);
        assert!(matches!(f.check(":1.9").await, Verdict::Failed(_)));
        assert!(matches!(
            f.access.check(None, CONTACTS_RESOURCE, "x").await,
            Verdict::Failed(_)
        ));
        assert_eq!(f.permissions.calls(), 0);
    }

    #[tokio::test]
    async fn la_cache_vence_a_los_30_segundos() {
        let f = AccessFixture::new(Answer::Allow).await;
        assert_eq!(f.check(":1.7").await, Verdict::Allowed);
        f.clock.advance(CACHE_TTL - Duration::from_secs(1));
        assert_eq!(f.check(":1.7").await, Verdict::Allowed);
        assert_eq!(f.permissions.calls(), 1, "a los 29 s sigue valiendo");

        f.clock.advance(Duration::from_secs(1));
        assert_eq!(f.access.cached(Some(":1.7"), CONTACTS_RESOURCE), None);
        f.permissions.set(Answer::Deny);
        assert_eq!(f.check(":1.7").await, Verdict::Denied);
        assert_eq!(f.permissions.calls(), 2, "a los 30 s se vuelve a preguntar");
    }

    /// La caché es por nombre único: otro proceso del mismo programa pregunta
    /// por su cuenta, y otro recurso también.
    #[tokio::test]
    async fn la_cache_es_por_nombre_y_recurso() {
        let f = AccessFixture::new(Answer::Allow).await;
        assert_eq!(f.check(":1.7").await, Verdict::Allowed);
        assert_eq!(f.check(":1.8").await, Verdict::Allowed);
        assert_eq!(
            f.access.check(Some(":1.7"), "store.email", "x").await,
            Verdict::Allowed
        );
        assert_eq!(f.permissions.calls(), 3);
    }

    /// Cuando el nombre se va del bus, lo suyo se olvida en el acto; un nombre
    /// que gana dueño, o uno conocido que cambia, no tocan nada.
    #[tokio::test]
    async fn la_cache_se_olvida_cuando_el_nombre_se_va() {
        let f = AccessFixture::new(Answer::Allow).await;
        let bus_client = f.connections[1].clone();
        tokio::spawn(watch_departures(bus_client, Arc::clone(&f.access)));
        assert_eq!(f.check(":1.7").await, Verdict::Allowed);
        assert_eq!(f.check(":1.8").await, Verdict::Allowed);

        let emit = |name: &'static str, old: &'static str, new: &'static str| {
            let server = f.bus_server.clone();
            async move {
                let context = SignalContext::new(&server, "/org/freedesktop/DBus").unwrap();
                server
                    .emit_signal(
                        None::<&str>,
                        context.path(),
                        "org.freedesktop.DBus",
                        "NameOwnerChanged",
                        &(name, old, new),
                    )
                    .await
                    .unwrap();
            }
        };
        // Se repite hasta que llega: la escucha se suscribe en su propia
        // tarea, y lo que se mande antes no lo ve. Las dos que no son una
        // salida van antes, así que si la de `:1.7` llegó, llegaron ellas.
        let forgotten = async {
            while f.access.cached(Some(":1.7"), CONTACTS_RESOURCE).is_some() {
                emit(":1.8", "", ":1.8").await;
                emit("ar.net.vasak.os.Contacts", ":1.8", "").await;
                emit(":1.7", ":1.7", "").await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), forgotten)
            .await
            .expect("no se olvidó el nombre que se fue");
        assert_eq!(
            f.access.cached(Some(":1.8"), CONTACTS_RESOURCE),
            Some(true),
            "el otro sigue"
        );
        assert_eq!(f.check(":1.7").await, Verdict::Allowed);
        assert_eq!(f.permissions.calls(), 3, "el que se fue vuelve a preguntar");
    }

    /// Dos pedidos a la vez del mismo nombre son **una** pregunta: la persona
    /// ve un diálogo, no dos, y los dos reciben la misma respuesta.
    #[tokio::test]
    async fn dos_pedidos_a_la_vez_son_una_sola_pregunta() {
        let f = AccessFixture::new(Answer::Allow).await;
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        f.permissions.0.lock().unwrap().gate = Some(Arc::clone(&gate));

        let first = f.check(":1.7");
        let second = f.check(":1.7");
        let release = async {
            while f.permissions.calls() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            // Un rato con la pregunta abierta, para que el segundo llegue.
            tokio::time::sleep(Duration::from_millis(50)).await;
            gate.add_permits(10);
        };
        let (a, b, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(first, second, release)
        })
        .await
        .expect("la pregunta no terminó");
        assert_eq!((a, b), (Verdict::Allowed, Verdict::Allowed));
        assert_eq!(f.permissions.calls(), 1, "una sola pregunta");
    }

    /// Una pregunta que no vuelve —un diálogo que nadie cierra— vence y cuenta
    /// como negada, sin guardarse.
    #[tokio::test]
    async fn una_pregunta_que_no_vuelve_vence_y_cuenta_como_negada() {
        let mut f = AccessFixture::new(Answer::Allow).await;
        f.permissions.0.lock().unwrap().gate = Some(Arc::new(tokio::sync::Semaphore::new(0)));
        let access = Access::new(
            Arc::new(DbusPermissions::withconnections(
                f.connections[1].clone(),
                f.connections[3].clone(),
            )),
            Arc::clone(&f.clock) as Arc<dyn Clock>,
        )
        .with_timeout(Duration::from_millis(100));
        f.access = Arc::new(access);
        assert!(matches!(f.check(":1.7").await, Verdict::Failed(_)));
        assert_eq!(f.access.cached(Some(":1.7"), CONTACTS_RESOURCE), None);
    }

    #[test]
    fn el_limite_por_llamante_corta_la_llamada_siguiente() {
        use ControlAction::Sync;
        let clock = FakeClock::new();
        let limits = CallerLimits::new(Arc::clone(&clock) as Arc<dyn Clock>);
        for _ in 0..CONTROL_BURST {
            assert_eq!(limits.admit(Some(":1.7"), "cuenta", Sync), Ok(()));
        }
        assert_eq!(
            limits.admit(Some(":1.7"), "cuenta", Sync),
            Err(Refusal::Caller),
            "la siguiente no entra"
        );
        assert_eq!(
            limits.admit(Some(":1.7"), "cuenta", ControlAction::Clear),
            Err(Refusal::Caller),
            "ni otro comando"
        );
        // Por cuenta y por nombre.
        assert_eq!(limits.admit(Some(":1.7"), "otra", Sync), Ok(()));
        assert_eq!(limits.admit(Some(":1.8"), "cuenta", Sync), Ok(()));
        // Sin remitente, nunca.
        assert_eq!(limits.admit(None, "cuenta", Sync), Err(Refusal::Caller));

        // Pasada la ventana, vuelve a entrar.
        clock.advance(CONTROL_WINDOW);
        assert_eq!(limits.admit(Some(":1.7"), "cuenta", Sync), Ok(()));

        // Y un nombre que se va se olvida.
        for _ in 0..CONTROL_BURST {
            let _ = limits.admit(Some(":1.9"), "cuenta", Sync);
        }
        assert!(limits.admit(Some(":1.9"), "cuenta", Sync).is_err());
        limits.forget(":1.9");
        assert_eq!(limits.admit(Some(":1.9"), "cuenta", Sync), Ok(()));
    }

    /// El cupo por nombre se esquiva abriendo conexiones nuevas: cada una es un
    /// nombre nuevo. El piso por cuenta no mira quién llama, y un nombre que se
    /// va no lo reinicia.
    #[test]
    fn vaciar_desde_nombres_nuevos_no_pasa_el_piso_por_cuenta() {
        use ControlAction::{Clear, Disable, Enable, Sync};
        let clock = FakeClock::new();
        let limits = CallerLimits::new(Arc::clone(&clock) as Arc<dyn Clock>);
        assert_eq!(limits.admit(Some(":1.7"), "cuenta", Clear), Ok(()));
        for name in [":1.8", ":1.9"] {
            assert_eq!(
                limits.admit(Some(name), "cuenta", Clear),
                Err(Refusal::Account),
                "{name} vació la misma cuenta dentro de los 10 s"
            );
        }
        limits.forget(":1.7");
        assert_eq!(
            limits.admit(Some(":1.10"), "cuenta", Clear),
            Err(Refusal::Account),
            "que el nombre se vaya no reinicia el piso"
        );
        // Lo mismo para encender y apagar, cada uno por su lado.
        assert_eq!(limits.admit(Some(":1.7"), "cuenta", Disable), Ok(()));
        assert_eq!(limits.admit(Some(":1.8"), "cuenta", Enable), Ok(()));
        assert_eq!(
            limits.admit(Some(":1.9"), "cuenta", Disable),
            Err(Refusal::Account)
        );
        // Otra cuenta tiene el suyo, y pedir una vuelta no tiene piso.
        assert_eq!(limits.admit(Some(":1.8"), "otra", Clear), Ok(()));
        assert_eq!(limits.admit(Some(":1.9"), "cuenta", Sync), Ok(()));
        assert_eq!(limits.admit(Some(":1.10"), "cuenta", Sync), Ok(()));

        clock.advance(ACCOUNT_FLOOR);
        assert_eq!(limits.admit(Some(":1.11"), "cuenta", Clear), Ok(()));
    }

    /// Un `NameOwnerChanged` que no manda el bus no se cree: si no, cualquiera
    /// le reinicia el cupo a un nombre, o le borra la respuesta guardada.
    #[test]
    fn un_aviso_de_salida_que_no_manda_el_bus_no_se_cree() {
        let departure = |sender: &str| {
            zbus::Message::signal(
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "NameOwnerChanged",
            )
            .unwrap()
            .sender(sender)
            .unwrap()
            .build(&(":1.7", ":1.7", ""))
            .unwrap()
        };
        assert_eq!(
            departed_name(&departure(BUS_NAME), Some(BUS_NAME)),
            Some(":1.7".to_string())
        );
        assert_eq!(departed_name(&departure(":1.66"), Some(BUS_NAME)), None);
        // Sin remitente, tampoco.
        let anonymous = zbus::Message::signal(
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameOwnerChanged",
        )
        .unwrap()
        .build(&(":1.7", ":1.7", ""))
        .unwrap();
        assert_eq!(departed_name(&anonymous, Some(BUS_NAME)), None);
        // Punto a punto no hay bus que mande nada: se acepta.
        assert_eq!(
            departed_name(&departure(":1.66"), None),
            Some(":1.7".to_string())
        );
    }
}
