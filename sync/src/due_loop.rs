//! El reloj compartido de las dos colas del correo: posponer
//! ([`crate::snooze_return`]) y seguimiento ([`crate::followup_notify`]).
//!
//! Las dos hacen lo mismo con el tiempo: duermen hasta la próxima hora anotada
//! —con un techo ([`MAX_SLEEP`]) por si el reloj salta: suspender, un ajuste de
//! NTP— y, además, despiertan cuando alguien las toca por un `Notify`. A su
//! hora atienden lo vencido, en tandas de a lo sumo [`BATCH`] para no abrir
//! decenas de conexiones de una, y vuelven a dormir. Lo único que cambia entre
//! una cola y la otra es **de dónde** salen los vencidos y **qué** se hace con
//! cada uno; eso es lo que ponen el [`DueSource`] y el [`DueAction`] de cada una.
//!
//! El bucle vive acá una sola vez a propósito: antes estaba copiado en
//! `snooze_return` (y sigue, distinto, en `reminders`, que lleva borde `since`);
//! una tercera copia para el seguimiento sería la misma lógica escrita tres
//! veces. Cada cola conserva sus propios traits —con sus nombres y sus fakes— y
//! los adapta a éstos con un envoltorio fino, así sus pruebas no cambian.
//!
//! **Sin borde `since`**: la anti-repetición es que el `DueAction` borra la fila
//! al atenderla, así que `due` consulta `*_at <= now` sin borde inferior y una
//! fila atendida no vuelve a aparecer. (Los recordatorios del calendario, que no
//! se borran, sí se acotan con `since`; por eso no comparten este bucle.)

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

use crate::calendar_sync::Clock;

/// Cuánto, como mucho, se vuelve a mirar aunque no venza ninguno ni llegue un
/// toque. La red para un reloj que saltó.
pub const MAX_SLEEP: Duration = Duration::from_secs(15 * 60);

/// Cuántos vencidos se atienden de una pasada. El resto espera la siguiente
/// vuelta, para no abrir decenas de conexiones juntas.
pub const BATCH: usize = 50;

/// De dónde salen los vencidos de una cola, con su cuenta. Una implementación en
/// producción —el almacén de cada cuenta— y otra en las pruebas —una lista en
/// memoria con horas simuladas—, así el bucle se prueba sin bus ni base.
pub trait DueSource {
    /// La fila que esta cola atiende (un pospuesto, un seguimiento).
    type Row;

    /// Los vencidos (`*_at <= now`) de todas las cuentas, hasta `limit`, cada uno
    /// con su cuenta.
    fn due(
        &self,
        now: i64,
        limit: usize,
    ) -> impl std::future::Future<Output = Vec<(String, Self::Row)>> + Send;

    /// La próxima hora después de `now`, o nada si no queda ninguna.
    fn next_after(&self, now: i64) -> impl std::future::Future<Output = Option<i64>> + Send;
}

/// Qué hacer con cada vencido de una cola. Lo que distingue a las dos: posponer
/// lo devuelve a su casilla, seguimiento mira si hubo respuesta y, si no, avisa.
pub trait DueAction {
    /// La fila que esta cola atiende; igual que la de su [`DueSource`].
    type Row;

    fn act(
        &self,
        account_id: &str,
        row: &Self::Row,
    ) -> impl std::future::Future<Output = ()> + Send;
}

/// Una pasada: atiende los vencidos y calcula cuánto dormir hasta el próximo.
///
/// Separada del bucle para probarla con horas dadas a mano.
pub async fn step<Src, Act>(now: i64, source: &Src, action: &Act) -> Duration
where
    Src: DueSource + ?Sized,
    Act: DueAction<Row = Src::Row> + ?Sized,
{
    for (account_id, row) in source.due(now, BATCH).await {
        action.act(&account_id, &row).await;
    }

    match source.next_after(now).await {
        Some(next) => {
            let seconds = (next - now).clamp(0, MAX_SLEEP.as_secs() as i64);
            Duration::from_secs(seconds as u64)
        }
        None => MAX_SLEEP,
    }
}

/// El bucle: atiende lo vencido, duerme hasta la próxima hora, y se despierta
/// también cuando `wake` lo toca (alguien agregó algo más cercano que el techo).
pub async fn run<Src, Act>(source: Src, action: Act, clock: Clock, wake: Arc<Notify>)
where
    Src: DueSource,
    Act: DueAction<Row = Src::Row>,
{
    loop {
        let now = clock().timestamp();
        let sleep = step(now, &source, &action).await;
        tokio::select! {
            _ = tokio::time::sleep(sleep) => {}
            _ = wake.notified() => {}
        }
    }
}
