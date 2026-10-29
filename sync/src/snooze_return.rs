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
