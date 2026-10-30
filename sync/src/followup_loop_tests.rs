//! El bucle de seguimiento (`followup_notify`) sobre el reloj compartido
//! (`due_loop`), con un mundo de mentira: una cola de seguimientos en memoria con
//! el mismo filtro que el almacén de verdad (`remind_at <= now`, sin borde
//! inferior, por hora) y un notificador que cuenta qué se atendió.
//!
//! El reloj compartido ya lo ejercen a fondo las pruebas de `snooze_return`
//! (`step`, el techo, la tanda, el reloj pausado); acá se prueba lo que es de
//! esta cola: que los adaptadores le pasan al reloj la fuente y la acción
//! correctas, que no hay `nudge`, y la fuente del almacén sin almacén.

use std::collections::HashSet;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use crate::calendar_sync::Clock;
use crate::due_loop::{BATCH, MAX_SLEEP};
use crate::followup_notify::{run, FollowupNotifier, FollowupSource, StoreFollowupSource};
use crate::store::snooze::Followup;

fn row(message_id: &str, remind_at: i64) -> Followup {
    Followup {
        id: remind_at,
        message_id: message_id.to_string(),
        recipients: "ana@x.com".to_string(),
        remind_at,
        created_at: 1,
    }
}

struct World {
    rows: Mutex<Vec<(String, Followup)>>,
    /// Los mensajes cuya comprobación falla: la fila se queda para reintentar.
    failing: Mutex<HashSet<String>>,
    /// Qué se atendió, en orden, con su cuenta.
    attended: Mutex<Vec<(String, String)>>,
    limits: Mutex<Vec<usize>>,
}

impl World {
    fn new(rows: Vec<Followup>) -> Arc<World> {
        Arc::new(World {
            rows: Mutex::new(
                rows.into_iter()
                    .map(|r| ("cuenta".to_string(), r))
                    .collect(),
            ),
            failing: Mutex::new(HashSet::new()),
            attended: Mutex::new(Vec::new()),
            limits: Mutex::new(Vec::new()),
        })
    }

    fn attended_ids(&self) -> Vec<String> {
        self.attended
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

impl FollowupSource for Arc<World> {
    async fn due(&self, now: i64, limit: usize) -> Vec<(String, Followup)> {
        self.limits.lock().unwrap().push(limit);
        let mut found: Vec<_> = self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, r)| r.remind_at <= now)
            .cloned()
            .collect();
        found.sort_by_key(|(_, r)| r.remind_at);
        found.truncate(limit);
        found
    }

    async fn next_after(&self, now: i64) -> Option<i64> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .map(|(_, r)| r.remind_at)
            .filter(|at| *at > now)
            .min()
    }
}

impl FollowupNotifier for Arc<World> {
    async fn notify_due(&self, account_id: &str, row: &Followup) {
        self.attended
            .lock()
            .unwrap()
            .push((account_id.to_string(), row.message_id.clone()));
        if self.failing.lock().unwrap().contains(&row.message_id) {
            return; // la comprobación falló: la fila queda
        }
        self.rows
            .lock()
            .unwrap()
            .retain(|(_, r)| r.message_id != row.message_id);
    }
}

/// Deja correr a las demás tareas unas cuantas veces: con el reloj pausado, una
/// sola cesión no alcanza para que el bucle complete una pasada.
async fn settle() {
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

/// Una pasada del reloj compartido con los adaptadores de esta cola: avisa cada
/// vencido con su cuenta y en orden de hora, deja los futuros, y duerme hasta el
/// próximo. Se prueba por `run`, que es lo que los arma.
#[tokio::test(start_paused = true)]
async fn el_bucle_atiende_los_vencidos_en_orden_y_duerme_hasta_el_proximo() {
    let now = Arc::new(AtomicI64::new(1_000));
    let reading = Arc::clone(&now);
    let clock: Clock = Arc::new(move || {
        chrono::DateTime::from_timestamp(reading.load(Ordering::SeqCst), 0).unwrap()
    });
    let world = World::new(vec![
        row("<c@x>", 300),
        row("<a@x>", 100),
        row("<futuro@x>", 1_100),
    ]);
    let wake = Arc::new(Notify::new());

    let handle = tokio::spawn(run(
        Arc::clone(&world),
        Arc::clone(&world),
        Arc::clone(&clock),
        Arc::clone(&wake),
    ));

    // Primera pasada: los dos vencidos, por hora, con su cuenta y pidiendo la tanda.
    settle().await;
    assert_eq!(world.attended_ids(), ["<a@x>", "<c@x>"]);
    assert_eq!(world.attended.lock().unwrap()[0].0, "cuenta");
    assert_eq!(world.limits.lock().unwrap()[0], BATCH);
    assert_eq!(world.pending_ids(), ["<futuro@x>"]);

    // El sueño llega hasta el que falta (100 s) y entonces lo atiende.
    now.store(1_150, Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(100)).await;
    settle().await;
    assert_eq!(world.attended_ids(), ["<a@x>", "<c@x>", "<futuro@x>"]);
    assert!(world.pending_ids().is_empty());

    // Un aviso nuevo se atiende sin esperar al techo cuando algo despierta al
    // bucle (el `Notify` está por la firma del reloj; acá se toca igual).
    world
        .rows
        .lock()
        .unwrap()
        .push(("cuenta".into(), row("<d@x>", 1_200)));
    now.store(1_300, Ordering::SeqCst);
    wake.notify_one();
    settle().await;
    assert_eq!(world.attended_ids().last().unwrap(), "<d@x>");

    handle.abort();
}

/// La comprobación fallida deja la fila, y el bucle la reintenta al volver a
/// mirar, hasta que anda; lo atendido no se repite.
#[tokio::test(start_paused = true)]
async fn si_la_comprobacion_falla_el_bucle_reintenta_y_lo_atendido_no_se_repite() {
    let now = Arc::new(AtomicI64::new(1_000));
    let reading = Arc::clone(&now);
    let clock: Clock = Arc::new(move || {
        chrono::DateTime::from_timestamp(reading.load(Ordering::SeqCst), 0).unwrap()
    });
    let world = World::new(vec![row("<a@x>", 100), row("<b@x>", 200)]);
    world.failing.lock().unwrap().insert("<a@x>".to_string());
    let wake = Arc::new(Notify::new());

    let handle = tokio::spawn(run(
        Arc::clone(&world),
        Arc::clone(&world),
        Arc::clone(&clock),
        Arc::clone(&wake),
    ));

    settle().await;
    assert_eq!(world.attended_ids(), ["<a@x>", "<b@x>"]);
    assert_eq!(world.pending_ids(), ["<a@x>"], "<b> se atendió, <a> falló");

    // Sin hora futura el bucle duerme el techo y, al vencer, reintenta sólo <a>.
    now.store(1_900, Ordering::SeqCst);
    tokio::time::advance(MAX_SLEEP).await;
    settle().await;
    assert_eq!(world.attended_ids(), ["<a@x>", "<b@x>", "<a@x>"]);

    world.failing.lock().unwrap().clear();
    now.store(2_800, Ordering::SeqCst);
    tokio::time::advance(MAX_SLEEP).await;
    settle().await;
    assert!(world.pending_ids().is_empty());
    let attended = world.attended_ids();
    assert_eq!(attended.iter().filter(|id| *id == "<b@x>").count(), 1);

    handle.abort();
}

/// La fuente del almacén sin almacén (antes de que arranque el servicio de
/// almacén, o sin cuenta con correo): no hay vencidos ni próxima hora.
#[tokio::test]
async fn la_fuente_del_almacen_sin_almacen_no_ve_nada() {
    let source = StoreFollowupSource;
    assert!(source.due(1_000, BATCH).await.is_empty());
    assert_eq!(source.next_after(1_000).await, None);
}
