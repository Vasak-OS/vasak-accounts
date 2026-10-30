//! Devolver a su casilla los mensajes pospuestos cuando llega su hora, con la
//! ventana de correo cerrada.
//!
//! Es el gemelo de [`crate::reminders`] puesto en el correo: el servicio es lo
//! que sigue corriendo, así que es él quien, a la hora anotada, mueve el mensaje
//! de `VasakOS/Pospuestos` de vuelta a donde estaba. La fila que dice cuándo y a
//! dónde la escribió `SnoozeMessage` (ver `main.rs`) en el almacén cifrado
//! (`store::snooze`, migración V13).
//!
//! # En qué se parece a los recordatorios y en qué no
//!
//! Igual: duerme hasta la próxima vuelta con un techo ([`MAX_SLEEP`]) por si el
//! reloj salta —suspender, un ajuste de NTP—, y lo despierta además un `wake`
//! cuando alguien pospone algo que puede vencer antes del techo.
//!
//! Distinto: **no hay borde `since`**. El recordatorio no se borra y se acota con
//! `since` para no repetirlo; el pospuesto **se borra al atenderlo**, así que la
//! consulta de vencidos no tiene borde inferior y una fila atendida no vuelve a
//! aparecer. La anti-repetición es la baja de la fila, no la marca en el reloj.
//!
//! # Qué pasa cuando la vuelta falla
//!
//! La fila **sólo se borra si el mensaje salió de Pospuestos** —se movió, o ya no
//! estaba ahí porque otro dispositivo lo movió—. Si el servidor no contesta, la
//! fila se queda y la próxima vuelta lo reintenta: un pospuesto no se pierde
//! porque el wifi estuviera caído a su hora. Eso lo decide el `SnoozeReturner`,
//! que borra tras una vuelta buena y calla ante un error de red.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

use crate::calendar_sync::Clock;
use crate::store::snooze::SnoozedMessage;

/// Cuánto, como mucho, se vuelve a mirar aunque no venza ninguno ni llegue un
/// `wake`. La red para un reloj que saltó, como en los recordatorios.
const MAX_SLEEP: Duration = Duration::from_secs(15 * 60);

/// Cuántos vencidos se devuelven de una pasada. Una tanda de pospuestos a la
/// misma hora no abre decenas de conexiones de una; el resto espera la siguiente
/// vuelta.
const BATCH: usize = 50;

/// Con qué se despierta al bucle cuando aparece un pospuesto que puede vencer
/// antes del techo del sueño. Lo toca `nudge_snooze` desde `SnoozeMessage`.
static WAKE: std::sync::OnceLock<Arc<Notify>> = std::sync::OnceLock::new();

/// Despierta al bucle de vuelta sin esperar al techo del sueño: se acaba de
/// posponer algo y su hora puede ser más cercana que la que el bucle tenía
/// agendada. Sin el bucle en marcha no hace nada.
pub fn nudge_snooze() {
    if let Some(wake) = WAKE.get() {
        wake.notify_one();
    }
}

/// De dónde salen los pospuestos vencidos. Una implementación en producción
/// —el almacén de cada cuenta— y otra en las pruebas —una lista en memoria con
/// horas simuladas—, así la lógica del bucle se prueba sin bus ni base.
pub trait SnoozeSource: Send + Sync {
    /// Los vencidos (`return_at <= now`) de todas las cuentas, hasta `limit`,
    /// cada uno con su cuenta.
    fn due(
        &self,
        now: i64,
        limit: usize,
    ) -> impl std::future::Future<Output = Vec<(String, SnoozedMessage)>> + Send;

    /// La próxima hora de vuelta después de `now`, o nada si no queda ninguna.
    fn next_after(&self, now: i64) -> impl std::future::Future<Output = Option<i64>> + Send;
}

/// Qué hacer con un pospuesto vencido: moverlo de vuelta y, **sólo si salió de
/// Pospuestos**, borrar su fila. El productor calla ante un error de red para
/// que el bucle lo reintente; en las pruebas se cuenta qué se atendió.
pub trait SnoozeReturner: Send + Sync {
    fn return_due(
        &self,
        account_id: &str,
        row: &SnoozedMessage,
    ) -> impl std::future::Future<Output = ()> + Send;
}

/// El bucle: devuelve lo vencido, duerme hasta la próxima vuelta, y se despierta
/// también cuando `wake` lo toca (alguien pospuso algo más cercano).
pub async fn run<Src, Snk>(source: Src, returner: Snk, clock: Clock, wake: Arc<Notify>)
where
    Src: SnoozeSource,
    Snk: SnoozeReturner,
{
    // Para que `SnoozeMessage` pueda acortar el sueño al posponer algo cercano.
    let _ = WAKE.set(Arc::clone(&wake));
    loop {
        let now = clock().timestamp();
        let sleep = step(now, &source, &returner).await;
        tokio::select! {
            _ = tokio::time::sleep(sleep) => {}
            _ = wake.notified() => {}
        }
    }
}

/// Una pasada: devuelve los vencidos y calcula cuánto dormir hasta el próximo.
///
/// Separada del bucle para probarla con horas dadas a mano. Sin borde `since`:
/// la anti-repetición es que el `SnoozeReturner` borra la fila al atenderla.
async fn step<Src, Snk>(now: i64, source: &Src, returner: &Snk) -> Duration
where
    Src: SnoozeSource + ?Sized,
    Snk: SnoozeReturner + ?Sized,
{
    for (account_id, row) in source.due(now, BATCH).await {
        returner.return_due(&account_id, &row).await;
    }

    match source.next_after(now).await {
        Some(next) => {
            let seconds = (next - now).clamp(0, MAX_SLEEP.as_secs() as i64);
            Duration::from_secs(seconds as u64)
        }
        None => MAX_SLEEP,
    }
}

/// Los pospuestos del almacén de cada cuenta con correo, leídos por las
/// funciones libres de `store_api` (que ya saltan la base cerrada y la cuenta
/// apagada). Es el servicio mirando sus propias bases, como el de recordatorios.
pub struct StoreSnoozeSource;

impl SnoozeSource for StoreSnoozeSource {
    async fn due(&self, now: i64, limit: usize) -> Vec<(String, SnoozedMessage)> {
        crate::store_api::snooze_due_all(now, limit).await
    }

    async fn next_after(&self, now: i64) -> Option<i64> {
        crate::store_api::snooze_next_after(now).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Mutex;

    fn row(message_id: &str, return_at: i64) -> SnoozedMessage {
        SnoozedMessage {
            id: return_at, // basta con que sean distintos en las pruebas
            message_id: message_id.to_string(),
            origin_mailbox: "INBOX".to_string(),
            new_uid: Some(7),
            uidvalidity: Some(3),
            return_at,
            created_at: 1,
        }
    }

    /// El mundo de mentira del bucle: una cola de pospuestos que hace de almacén
    /// (con el mismo filtro de vencidos que el de verdad: `return_at <= now`,
    /// sin borde inferior, ordenados) y de servicio que los devuelve (borra la
    /// fila **sólo** si la vuelta no falló, como el productor de verdad).
    struct World {
        rows: Mutex<Vec<(String, SnoozedMessage)>>,
        /// Con el almacén cerrado o la cuenta apagada no se ve nada.
        open: Mutex<bool>,
        /// Los mensajes cuya vuelta falla (el servidor no contesta).
        failing: Mutex<HashSet<String>>,
        /// Qué se pidió devolver, en orden.
        returned: Mutex<Vec<(String, String)>>,
        /// Los `limit` con que se pidieron los vencidos.
        limits: Mutex<Vec<usize>>,
    }

    impl World {
        fn new(rows: Vec<SnoozedMessage>) -> Arc<World> {
            Arc::new(World {
                rows: Mutex::new(
                    rows.into_iter()
                        .map(|r| ("cuenta".to_string(), r))
                        .collect(),
                ),
                open: Mutex::new(true),
                failing: Mutex::new(HashSet::new()),
                returned: Mutex::new(Vec::new()),
                limits: Mutex::new(Vec::new()),
            })
        }

        fn returned_ids(&self) -> Vec<String> {
            self.returned
                .lock()
                .unwrap()
                .iter()
                .map(|(_, id)| id.clone())
                .collect()
        }

        fn pending_ids(&self) -> Vec<String> {
            self.rows
                .lock()
                .unwrap()
                .iter()
                .map(|(_, r)| r.message_id.clone())
                .collect()
        }
    }

    impl SnoozeSource for Arc<World> {
        async fn due(&self, now: i64, limit: usize) -> Vec<(String, SnoozedMessage)> {
            self.limits.lock().unwrap().push(limit);
            if !*self.open.lock().unwrap() {
                return Vec::new();
            }
            let mut found: Vec<_> = self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, r)| r.return_at <= now)
                .cloned()
                .collect();
            found.sort_by_key(|(_, r)| r.return_at);
            found.truncate(limit);
            found
        }

        async fn next_after(&self, now: i64) -> Option<i64> {
            if !*self.open.lock().unwrap() {
                return None;
            }
            self.rows
                .lock()
                .unwrap()
                .iter()
                .map(|(_, r)| r.return_at)
                .filter(|at| *at > now)
                .min()
        }
    }

    impl SnoozeReturner for Arc<World> {
        async fn return_due(&self, account_id: &str, row: &SnoozedMessage) {
            self.returned
                .lock()
                .unwrap()
                .push((account_id.to_string(), row.message_id.clone()));
            if self.failing.lock().unwrap().contains(&row.message_id) {
                return; // error de red: la fila se queda para la próxima vuelta
            }
            self.rows
                .lock()
                .unwrap()
                .retain(|(_, r)| r.message_id != row.message_id);
        }
    }

    /// Deja correr a las demás tareas unas cuantas veces: con el reloj pausado,
    /// una sola cesión no alcanza para que el bucle complete una pasada.
    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    /// Una pasada devuelve cada vencido, con su cuenta y en orden de hora, y no
    /// toca los que todavía no vencieron.
    #[tokio::test]
    async fn la_pasada_devuelve_los_vencidos_en_orden_y_deja_los_futuros() {
        let world = World::new(vec![
            row("<c@x>", 300),
            row("<a@x>", 100),
            row("<z@x>", 5_000),
        ]);

        step(1_000, &world, &world).await;

        assert_eq!(world.returned_ids(), vec!["<a@x>", "<c@x>"]);
        assert_eq!(world.returned.lock().unwrap()[0].0, "cuenta");
        assert_eq!(world.pending_ids(), vec!["<z@x>"]);
    }

    /// El borde es inclusivo: un pospuesto que vence justo ahora vuelve ahora.
    #[tokio::test]
    async fn el_que_vence_justo_ahora_vuelve_ahora() {
        let world = World::new(vec![row("<a@x>", 1_000)]);
        step(1_000, &world, &world).await;
        assert_eq!(world.returned_ids(), vec!["<a@x>"]);

        let world = World::new(vec![row("<b@x>", 1_001)]);
        step(1_000, &world, &world).await;
        assert!(world.returned_ids().is_empty());
    }

    /// Lo atendido no vuelve a aparecer: la anti-repetición es la baja de la
    /// fila, no una marca en el reloj. Una segunda pasada a la misma hora no lo
    /// devuelve de nuevo.
    #[tokio::test]
    async fn lo_atendido_no_se_devuelve_dos_veces() {
        let world = World::new(vec![row("<a@x>", 100)]);

        step(1_000, &world, &world).await;
        step(1_000, &world, &world).await;
        step(2_000, &world, &world).await;

        assert_eq!(world.returned_ids(), vec!["<a@x>"]);
        assert!(world.pending_ids().is_empty());
    }

    /// Un error de red no pierde el pospuesto: la fila se queda y la pasada
    /// siguiente lo reintenta, hasta que el servidor conteste.
    #[tokio::test]
    async fn si_la_vuelta_falla_se_reintenta_en_la_pasada_siguiente() {
        let world = World::new(vec![row("<a@x>", 100), row("<b@x>", 200)]);
        world.failing.lock().unwrap().insert("<a@x>".to_string());

        step(1_000, &world, &world).await;
        // <b> volvió; <a> falló y sigue anotado.
        assert_eq!(world.pending_ids(), vec!["<a@x>"]);

        step(1_100, &world, &world).await;
        // Volvió a intentarse <a>, y sólo <a>.
        assert_eq!(world.returned_ids(), vec!["<a@x>", "<b@x>", "<a@x>"]);

        world.failing.lock().unwrap().clear();
        step(1_200, &world, &world).await;
        assert!(world.pending_ids().is_empty());
    }

    /// Una tanda grande no se atiende de una: la pasada devuelve a lo sumo
    /// `BATCH` y el resto espera la vuelta siguiente (no se abren decenas de
    /// conexiones juntas).
    #[tokio::test]
    async fn una_tanda_grande_se_reparte_en_pasadas_de_cincuenta() {
        let rows: Vec<_> = (0..60)
            .map(|i| row(&format!("<m{i}@x>"), 100 + i))
            .collect();
        let world = World::new(rows);

        step(1_000, &world, &world).await;
        assert_eq!(world.returned_ids().len(), 50);
        assert_eq!(world.limits.lock().unwrap()[0], 50);
        assert_eq!(world.pending_ids().len(), 10);
        // Los 50 primeros por hora, no 50 cualquiera.
        assert_eq!(world.returned_ids()[0], "<m0@x>");
        assert_eq!(world.returned_ids()[49], "<m49@x>");

        step(1_000, &world, &world).await;
        assert_eq!(world.returned_ids().len(), 60);
        assert!(world.pending_ids().is_empty());
    }

    /// El sueño va hasta la próxima hora de vuelta, con el techo de `MAX_SLEEP`.
    #[tokio::test]
    async fn el_sueno_llega_a_la_proxima_vuelta() {
        let world = World::new(vec![row("<a@x>", 1_050)]);
        assert_eq!(step(1_000, &world, &world).await, Duration::from_secs(50));
    }

    /// Los bordes del techo, exactos: a `MAX_SLEEP` justos se duerme `MAX_SLEEP`,
    /// un segundo menos se duerme un segundo menos, y de ahí para arriba manda el
    /// techo.
    #[tokio::test]
    async fn el_techo_del_sueno_es_de_quince_minutos_exactos() {
        assert_eq!(MAX_SLEEP, Duration::from_secs(900));

        let sleep_for = |next: i64| async move {
            let world = World::new(vec![row("<a@x>", next)]);
            step(1_000, &world, &world).await
        };
        assert_eq!(sleep_for(1_000 + 899).await, Duration::from_secs(899));
        assert_eq!(sleep_for(1_000 + 900).await, MAX_SLEEP);
        assert_eq!(sleep_for(1_000 + 901).await, MAX_SLEEP);
        assert_eq!(sleep_for(1_000 + 1_000_000).await, MAX_SLEEP);
    }

    /// Sin nada por delante se duerme el techo, y no se despierta por gusto.
    #[tokio::test]
    async fn sin_pospuestos_duerme_el_techo() {
        let world = World::new(vec![]);
        assert_eq!(step(1_000, &world, &world).await, MAX_SLEEP);
    }

    /// Una fuente que contesta una hora ya pasada (el reloj saltó entre dos
    /// lecturas) no da un sueño negativo —que como `u64` sería eterno—: vuelve a
    /// mirar enseguida.
    #[tokio::test]
    async fn una_hora_ya_pasada_no_da_un_sueno_negativo() {
        struct Stale;
        impl SnoozeSource for Stale {
            async fn due(&self, _: i64, _: usize) -> Vec<(String, SnoozedMessage)> {
                Vec::new()
            }
            async fn next_after(&self, now: i64) -> Option<i64> {
                Some(now - 5)
            }
        }
        struct Never;
        impl SnoozeReturner for Never {
            async fn return_due(&self, _: &str, _: &SnoozedMessage) {
                unreachable!("no había nada vencido");
            }
        }
        assert_eq!(step(1_000, &Stale, &Never).await, Duration::ZERO);
    }

    /// Con el almacén cerrado o la cuenta apagada la pasada no ve nada: no
    /// devuelve, no falla y duerme el techo; cuando se abre, atiende lo que
    /// quedó esperando.
    #[tokio::test]
    async fn con_el_almacen_cerrado_salta_y_reintenta_cuando_abre() {
        let world = World::new(vec![row("<a@x>", 100)]);
        *world.open.lock().unwrap() = false;

        assert_eq!(step(1_000, &world, &world).await, MAX_SLEEP);
        assert!(world.returned_ids().is_empty());

        *world.open.lock().unwrap() = true;
        step(1_100, &world, &world).await;
        assert_eq!(world.returned_ids(), vec!["<a@x>"]);
    }

    /// El adaptador del almacén de verdad, sin almacén (antes de que arranque el
    /// servicio de almacén, o sin ninguna cuenta con correo): no hay vencidos ni
    /// próxima hora, y la pasada no explota.
    #[tokio::test]
    async fn la_fuente_del_almacen_sin_almacen_no_ve_nada() {
        let source = StoreSnoozeSource;
        assert!(source.due(1_000, BATCH).await.is_empty());
        assert_eq!(source.next_after(1_000).await, None);

        struct Never;
        impl SnoozeReturner for Never {
            async fn return_due(&self, _: &str, _: &SnoozedMessage) {
                unreachable!("sin almacén no hay nada que devolver");
            }
        }
        assert_eq!(step(1_000, &source, &Never).await, MAX_SLEEP);
    }

    /// El bucle entero, con el reloj pausado. **Una sola prueba** corre `run`:
    /// éste fija el `WAKE` de todo el proceso (`OnceLock`), así que `nudge_snooze`
    /// sólo se puede probar con el bucle propio. Recorre: nada vence → el sueño
    /// vence y atiende → el almacén cerrado no rompe nada y el techo lo reabre →
    /// `Notify` despierta sin esperar → `nudge_snooze` despierta igual.
    #[tokio::test(start_paused = true)]
    async fn el_bucle_devuelve_al_vencer_el_sueno_y_al_despertarlo() {
        // Antes de que el bucle exista, avisar no hace nada ni falla.
        nudge_snooze();

        let now = Arc::new(AtomicI64::new(1_000));
        let reading = Arc::clone(&now);
        let clock: Clock = Arc::new(move || {
            chrono::DateTime::from_timestamp(reading.load(Ordering::SeqCst), 0).unwrap()
        });
        let world = World::new(vec![row("<a@x>", 1_100)]);
        let wake = Arc::new(Notify::new());

        let handle = tokio::spawn(run(
            Arc::clone(&world),
            Arc::clone(&world),
            Arc::clone(&clock),
            Arc::clone(&wake),
        ));

        // Primera pasada: nada vence todavía.
        settle().await;
        assert!(world.returned_ids().is_empty(), "devolvió antes de tiempo");

        // El sueño (100 s, hasta <a>) vence con el reloj ya pasado de la hora.
        now.store(1_200, Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(100)).await;
        settle().await;
        assert_eq!(world.returned_ids(), vec!["<a@x>"]);

        // Almacén cerrado: se agrega uno vencido que no se ve. El bucle sigue
        // vivo y, pasado el techo, lo atiende apenas el almacén abre.
        *world.open.lock().unwrap() = false;
        world
            .rows
            .lock()
            .unwrap()
            .push(("cuenta".into(), row("<b@x>", 1_300)));
        now.store(1_400, Ordering::SeqCst);
        wake.notify_one();
        settle().await;
        assert_eq!(
            world.returned_ids(),
            vec!["<a@x>"],
            "atendió con el almacén cerrado"
        );
        *world.open.lock().unwrap() = true;
        tokio::time::advance(MAX_SLEEP).await;
        settle().await;
        assert_eq!(world.returned_ids(), vec!["<a@x>", "<b@x>"]);

        // Un `Notify` despierta al bucle sin esperar al sueño.
        world
            .rows
            .lock()
            .unwrap()
            .push(("cuenta".into(), row("<c@x>", 1_450)));
        now.store(1_500, Ordering::SeqCst);
        wake.notify_one();
        settle().await;
        assert_eq!(world.returned_ids().last().unwrap(), "<c@x>");

        // Y `nudge_snooze` —lo que toca `SnoozeMessage` al posponer— hace lo mismo.
        world
            .rows
            .lock()
            .unwrap()
            .push(("cuenta".into(), row("<d@x>", 1_550)));
        now.store(1_600, Ordering::SeqCst);
        nudge_snooze();
        settle().await;
        assert_eq!(world.returned_ids().last().unwrap(), "<d@x>");

        handle.abort();
    }
}
