//! Avisar un seguimiento cuando llega su hora y el mensaje sigue sin respuesta.
//!
//! Es el gemelo de [`crate::snooze_return`] sobre la otra cola del correo (la
//! tabla `followups` de `store::snooze`, migración V13): mismo reloj compartido
//! ([`crate::due_loop`]), otra acción. La fila la escribe `send_message` cuando
//! el borrador pidió recordar un seguimiento (`Draft::followup_at`); a su hora,
//! el servicio —que es lo que sigue corriendo— mira si llegó una respuesta y, si
//! no, avisa.
//!
//! # Qué hace a la hora de cada seguimiento
//!
//! Busca en INBOX una respuesta que enhebre el mensaje por su `Message-ID`
//! (`References` o `In-Reply-To`, decisión 4 de `vasak-accounts#22`):
//!
//! - **Hubo respuesta** → ya contestaron: no se avisa, y se borra la fila.
//! - **No hubo respuesta** (la búsqueda anduvo y volvió vacía) → se avisa con un
//!   cartel con botón «Ver», y se borra la fila (el recordatorio es de un solo
//!   disparo).
//! - **La búsqueda falló** (el servidor no contesta, no hay INBOX) → **no** es lo
//!   mismo que «no hubo respuesta»: la fila se deja y la próxima vuelta lo
//!   reintenta, para no avisar «sin respuesta» sólo porque el wifi estaba caído.
//!
//! Esa distinción —búsqueda OK y vacía vs. búsqueda fallida— la lleva un
//! `Result<bool, _>` de punta a punta, igual que el posponer lleva el resultado
//! del movimiento. La decide [`crate::apply_followup_in`], el core testeable.
//!
//! # Sin `nudge`
//!
//! A diferencia del posponer, esta cola no se despierta al anotar una fila: un
//! seguimiento vence dentro de horas o días, nunca antes del techo del sueño (15
//! min), así que el reloj lo alcanza solo. El `Notify` que recibe el bucle está
//! por la firma del reloj compartido y nadie lo toca.

use std::sync::Arc;

use tokio::sync::Notify;

use crate::calendar_sync::Clock;
use crate::due_loop;
use crate::store::snooze::Followup;

/// De dónde salen los seguimientos vencidos. Una implementación en producción
/// —el almacén de cada cuenta— y las que escriba `qa` en las pruebas, así la
/// lógica se prueba sin bus ni base.
pub trait FollowupSource: Send + Sync {
    /// Los vencidos (`remind_at <= now`) de todas las cuentas, hasta `limit`.
    fn due(
        &self,
        now: i64,
        limit: usize,
    ) -> impl std::future::Future<Output = Vec<(String, Followup)>> + Send;

    /// La próxima hora de aviso después de `now`, o nada si no queda ninguna.
    fn next_after(&self, now: i64) -> impl std::future::Future<Output = Option<i64>> + Send;
}

/// Qué hacer con un seguimiento vencido: comprobar si hubo respuesta y, según
/// eso, avisar y/o borrar la fila. El productor de producción está en `main.rs`
/// (necesita el IMAP del `Service` y el bus de sesión); las pruebas ponen un
/// fake que cuenta qué se atendió.
pub trait FollowupNotifier: Send + Sync {
    fn notify_due(
        &self,
        account_id: &str,
        row: &Followup,
    ) -> impl std::future::Future<Output = ()> + Send;
}

/// Adaptan los traits de esta cola al reloj compartido ([`crate::due_loop`]), que
/// tiene el bucle. Finos a propósito: reenvían y nada más, para que las fuentes y
/// los fakes sigan implementando `FollowupSource`/`FollowupNotifier`.
struct AsSource<'a, S: ?Sized>(&'a S);
struct AsAction<'a, A: ?Sized>(&'a A);

impl<S: FollowupSource + ?Sized> due_loop::DueSource for AsSource<'_, S> {
    type Row = Followup;

    fn due(
        &self,
        now: i64,
        limit: usize,
    ) -> impl std::future::Future<Output = Vec<(String, Followup)>> + Send {
        self.0.due(now, limit)
    }

    fn next_after(&self, now: i64) -> impl std::future::Future<Output = Option<i64>> + Send {
        self.0.next_after(now)
    }
}

impl<A: FollowupNotifier + ?Sized> due_loop::DueAction for AsAction<'_, A> {
    type Row = Followup;

    fn act(
        &self,
        account_id: &str,
        row: &Followup,
    ) -> impl std::future::Future<Output = ()> + Send {
        self.0.notify_due(account_id, row)
    }
}

/// El bucle: avisa lo vencido y duerme hasta el próximo, con el reloj compartido.
/// `wake` está por la firma del reloj y no se usa (ver el módulo: sin `nudge`).
pub async fn run<Src, Snk>(source: Src, notifier: Snk, clock: Clock, wake: Arc<Notify>)
where
    Src: FollowupSource,
    Snk: FollowupNotifier,
{
    due_loop::run(AsSource(&source), AsAction(&notifier), clock, wake).await;
}

/// Los seguimientos del almacén de cada cuenta con correo, leídos por las
/// funciones libres de `store_api` (que ya saltan la base cerrada y la cuenta
/// apagada). Es el servicio mirando sus propias bases, como el de pospuestos.
pub struct StoreFollowupSource;

impl FollowupSource for StoreFollowupSource {
    async fn due(&self, now: i64, limit: usize) -> Vec<(String, Followup)> {
        crate::store_api::followup_due_all(now, limit).await
    }

    async fn next_after(&self, now: i64) -> Option<i64> {
        crate::store_api::followup_next_after(now).await
    }
}
