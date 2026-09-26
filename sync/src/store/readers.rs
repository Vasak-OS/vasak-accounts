//! Las conexiones de sólo lectura de una base.
//!
//! **Un solo escritor, y dos lectores.** La conexión de escritura es de
//! [`super::Store`] y la usa sólo `StoreManager::with_store`, de a un lote por
//! vez. Las lecturas que piden las aplicaciones van por estas dos, que abren el
//! mismo archivo con la misma clave y **no pueden escribir**:
//! `SQLITE_OPEN_READONLY` y además `PRAGMA query_only`. En WAL, un lector ve lo
//! último que se confirmó y no espera a un lote que se está escribiendo; y como
//! no pasan por la cerradura del administrador, tampoco esperan a que el
//! escritor la suelte.
//!
//! Nacen con la base y se cierran con ella: soltar la [`super::Store`] cierra
//! el grupo ([`ReadPool::close`]), también cuando el llavero se bloquea. Una
//! conexión que está en medio de una lectura en ese momento se cierra al
//! terminarla, y ninguna lectura nueva empieza. SQLCipher borra su copia de la
//! clave al cerrar cada conexión.
//!
//! **Una lectura larga no tiene tomada una conexión mientras hace CPU.** Lo
//! que el calendario expande en el momento se lee de a partes ([`Reader`]): la
//! conexión se toma para leer una tanda, se suelta, y la expansión corre sin
//! ella. Y hay un turno por base para eso ([`ExpansionGate`]): una sola
//! expansión en el momento a la vez, así que dos aplicaciones que piden años
//! lejanos no se llevan la CPU entre las dos ni dejan sin lector a las demás.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, TryLockError};
use std::time::Instant;

use rusqlite::{Connection, OpenFlags};

use super::key::StoreKey;
use super::{classify, StoreError};

/// Cuántas conexiones de lectura tiene cada base.
pub const READERS: usize = 2;

/// Por dónde lee una consulta que se hace de a partes: una conexión que se
/// toma para cada parte y se suelta entre una y otra.
pub trait Reader {
    /// Una parte: con una conexión, dentro de una transacción de lectura.
    fn read<T>(
        &self,
        work: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError>;

    /// El turno de la base para expandir en el momento, si tiene.
    fn expansion_gate(&self) -> Option<&ExpansionGate> {
        None
    }
}

/// Una conexión sola —la de las pruebas, o una ya tomada— es un lector de a
/// partes sin turno: cada parte usa la misma.
impl Reader for Connection {
    fn read<T>(
        &self,
        work: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        work(self)
    }
}

/// Un turno: de a uno por vez. El que llega mientras está ocupado espera, pero
/// no más que su plazo.
#[derive(Debug, Default)]
pub struct ExpansionGate {
    busy: Mutex<bool>,
    freed: Condvar,
}

/// Tener el turno; se devuelve al soltarse.
#[derive(Debug)]
pub struct Turn<'a> {
    gate: &'a ExpansionGate,
}

impl ExpansionGate {
    /// Toma el turno, esperando hasta `deadline` si está ocupado. `None` si no
    /// se liberó a tiempo.
    pub fn enter_until(&self, deadline: Instant) -> Option<Turn<'_>> {
        let mut busy = self.busy.lock().unwrap_or_else(|p| p.into_inner());
        while *busy {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            busy = self
                .freed
                .wait_timeout(busy, deadline - now)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
        *busy = true;
        Some(Turn { gate: self })
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        *self.gate.busy.lock().unwrap_or_else(|p| p.into_inner()) = false;
        self.gate.freed.notify_one();
    }
}

/// Las conexiones de lectura de una base abierta.
pub struct ReadPool {
    slots: [Mutex<Option<Connection>>; READERS],
    closed: AtomicBool,
    next: AtomicUsize,
    /// El turno para expandir en el momento.
    expansion: ExpansionGate,
}

impl ReadPool {
    /// Abre las [`READERS`] conexiones. La base ya tiene que existir, en WAL y
    /// con el esquema al día: las abre [`super::Store`] después de migrar.
    pub(super) fn open(db: &Path, key: &StoreKey) -> Result<Self, StoreError> {
        let first = open_reader(db, key)?;
        let second = open_reader(db, key)?;
        Ok(Self {
            slots: [Mutex::new(Some(first)), Mutex::new(Some(second))],
            closed: AtomicBool::new(false),
            next: AtomicUsize::new(0),
            expansion: ExpansionGate::default(),
        })
    }

    /// Si ya se cerró: no empieza ninguna lectura más.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Cierra el grupo. Las conexiones libres se cierran ya; la que esté en
    /// medio de una lectura, al terminarla. No espera a nadie.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        for slot in &self.slots {
            match slot.try_lock() {
                Ok(mut connection) => *connection = None,
                Err(TryLockError::Poisoned(p)) => *p.into_inner() = None,
                Err(TryLockError::WouldBlock) => {}
            }
        }
    }

    /// Cuántas conexiones siguen abiertas. Sólo para las pruebas.
    #[cfg(test)]
    pub fn open_connections(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.lock().unwrap_or_else(|p| p.into_inner()).is_some())
            .count()
    }

    /// Hace una lectura, dentro de una transacción —todo lo que lee ve la base
    /// en el mismo momento—, con una de las conexiones libres; si están las
    /// dos ocupadas, espera a una. **Bloquea**: se llama fuera del bucle de
    /// eventos.
    pub fn read<T>(
        &self,
        work: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        if self.is_closed() {
            return Err(StoreError::Missing);
        }
        let mut slot = self.acquire();
        let result = match slot.as_ref() {
            // Cerrado mientras se esperaba la conexión.
            _ if self.is_closed() => Err(StoreError::Missing),
            // Al soltarse se deshace, que en una transacción de lectura no
            // deshace nada.
            Some(connection) => connection
                .unchecked_transaction()
                .map_err(classify)
                .and_then(|transaction| work(&transaction)),
            None => Err(StoreError::Missing),
        };
        if self.is_closed() {
            *slot = None;
        }
        result
    }

    fn acquire(&self) -> MutexGuard<'_, Option<Connection>> {
        for slot in &self.slots {
            match slot.try_lock() {
                Ok(guard) => return guard,
                Err(TryLockError::Poisoned(p)) => return p.into_inner(),
                Err(TryLockError::WouldBlock) => {}
            }
        }
        let index = self.next.fetch_add(1, Ordering::Relaxed) % READERS;
        self.slots[index].lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Reader for ReadPool {
    fn read<T>(
        &self,
        work: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        ReadPool::read(self, work)
    }

    fn expansion_gate(&self) -> Option<&ExpansionGate> {
        Some(&self.expansion)
    }
}

/// Una conexión de sólo lectura, con la clave y la misma comprobación que la
/// de escritura.
pub(super) fn open_reader(db: &Path, key: &StoreKey) -> Result<Connection, StoreError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(db, flags).map_err(classify)?;
    super::apply_key(&connection, key)?;
    connection
        .execute_batch("PRAGMA cipher_compatibility = 4;")
        .map_err(classify)?;
    let cipher: String = connection
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .map_err(classify)?;
    if cipher.is_empty() {
        return Err(StoreError::NotEncrypted);
    }
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(classify)?;
    // Sólo lectura dos veces: la apertura, y esto, que además rechaza
    // cualquier orden que escriba antes de intentarla.
    connection
        .execute_batch("PRAGMA query_only = 1; PRAGMA busy_timeout = 5000;")
        .map_err(classify)?;
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    /// **Una sola expansión a la vez.** El segundo que pide el turno espera a
    /// que el primero lo suelte; y si no lo suelta dentro de su plazo, se va
    /// sin él.
    #[test]
    fn el_turno_es_de_a_uno() {
        let gate = Arc::new(ExpansionGate::default());
        let first = gate.enter_until(Instant::now()).expect("libre");
        assert!(
            gate.enter_until(Instant::now() + Duration::from_millis(50))
                .is_none(),
            "ocupado: no hay turno"
        );
        let waiting = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                let started = Instant::now();
                let turn = gate.enter_until(Instant::now() + Duration::from_secs(10));
                (turn.is_some(), started.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(200));
        drop(first);
        let (got, waited) = waiting.join().unwrap();
        assert!(got, "al soltarlo, el que esperaba lo toma");
        assert!(waited >= Duration::from_millis(150), "esperó {waited:?}");
        // Y se devolvió al terminar el hilo.
        assert!(gate.enter_until(Instant::now()).is_some());
    }
}
