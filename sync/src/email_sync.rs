//! Mantener al día el correo de cada cuenta en el almacén local.
//!
//! Es lo que hace que las aplicaciones lean el correo **de lo que ya está en el
//! sistema** y no esperen a la red: la lista aparece al abrir la ventana, y el
//! sincronizador la mantiene al día en segundo plano.
//!
//! ── Cuándo ──────────────────────────────────────────────────────────────────
//!
//! Como contactos y calendario: el área se enciende la primera vez que una
//! aplicación con permiso la lee o pide `RequestSync`, y desde ahí sigue sola.
//! Cada cuenta encendida se sincroniza cada [`EMAIL_INTERVAL`], con cada
//! `RequestSync` —el botón «Actualizar» de la aplicación— y cuando la sesión
//! en vivo de la bandeja de entrada recibe un aviso de IDLE (ver
//! [`crate::store_api::nudge_email`]).
//!
//! ── Cómo, y por qué es barato ───────────────────────────────────────────────
//!
//! Una conexión por vuelta, y por casilla lo mínimo que alcanza para saber qué
//! cambió:
//!
//! 1. `EXAMINE` —nunca `SELECT`: mirar no cambia nada del servidor de nadie—,
//!    con `(CONDSTORE)` cuando el servidor lo sabe. Si `UIDVALIDITY` y
//!    `HIGHESTMODSEQ` son los de la vuelta anterior, **nada** de la casilla
//!    cambió y no se pide nada más. Sin CONDSTORE, `UIDNEXT` y la cantidad de
//!    mensajes dicen si llegó o se fue algo; las banderas de las casillas que
//!    no son la de entrada se refrescan en la vuelta en que cambie otra cosa.
//! 2. `FETCH <ventana> (UID FLAGS)` sobre los últimos [`window_for`] mensajes:
//!    unas decenas de bytes por mensaje.
//! 3. Por diferencia con lo guardado: encabezados **sólo de los UID nuevos**,
//!    de a [`HEADER_CHUNK`]; banderas sólo de los que cambiaron; y se borran
//!    los que ya no están —o quedaron fuera de la ventana, que es lo que pone
//!    techo al tamaño de la base—.
//! 4. `UIDVALIDITY` distinto: los UID guardados ya no apuntan a nada; la
//!    casilla se vacía y se rehace. Quedarse con UID que apuntan a otro
//!    mensaje es peor que esperar a que vuelva a bajar.
//! 5. Los cuerpos de los [`BODY_PREFETCH`] mensajes más nuevos de la bandeja
//!    de entrada que todavía no lo tienen, para que abrirlos sea instantáneo.
//!
//! Lo que se escribe va de a lotes y sube la generación del área una vez por
//! lote: una vuelta sin novedades no escribe nada ni despierta a nadie.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::broker::{self, Broker, BrokerError};
use crate::dav_sync::{self, AreaSync};
use crate::imap::{self, HeaderRecord, ImapError, Session, UidFlags};
use crate::mailboxes::{self, Mailbox};
use crate::store::email::{
    MailboxListing, MailboxRole, MessageAttachmentRow, MessageBodyRow, MessageOp, MessageRow,
    StoredFlags, StoredMailbox, WRITE_BATCH_ROWS,
};
use crate::store::key::KeySource;
use crate::store::lifecycle::{AreaState, StoreManager, EMAIL_AREA};
use crate::store::StoreError;

/// Cada cuánto se sincroniza el correo de una cuenta encendida sin que nadie
/// lo pida. Más seguido que los contactos (una hora): el correo es lo que
/// cambia durante el día. Lo urgente —lo que llega a la bandeja de entrada—
/// no espera a esto: lo trae el aviso de IDLE.
pub const EMAIL_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Cada cuánto se mira qué cuentas toca sincronizar.
pub const EMAIL_TICK: Duration = crate::POLL_INTERVAL;

/// Cuántos mensajes se guardan de la bandeja de entrada: los más nuevos.
pub const INBOX_WINDOW: u32 = 2000;

/// Y de cada una de las otras casillas.
pub const OTHER_WINDOW: u32 = 500;

/// Cuántas casillas se sincronizan como mucho. Una cuenta corporativa puede
/// tener cientos; las que quedan afuera son las últimas en el orden de
/// [`priority`], nunca la de entrada ni las especiales.
pub const MAX_MAILBOXES: usize = 100;

/// De a cuántos UID se piden los encabezados.
pub const HEADER_CHUNK: usize = 200;

/// Cuántos cuerpos de la bandeja de entrada se traen por vuelta.
pub const BODY_PREFETCH: usize = 25;

/// Cuánto puede durar una vuelta de una cuenta, como mucho. Lo que quedó sin
/// hacer lo retoma la siguiente: cada casilla guarda su token al terminar.
pub const ROUND_DEADLINE: Duration = Duration::from_secs(10 * 60);

/// Lo que se ve en el estado cuando el servicio de cuentas dice que no.
const DENIED_DETAIL: &str = "el servicio de cuentas no le da al sincronizador permiso para el \
     correo de esta cuenta: hay que permitirlo en Configuración → Privacidad y seguridad";

/// Lo que se ve cuando la base no está abierta.
const CLOSED_DETAIL: &str =
    "la base no está abierta: se sincroniza cuando se desbloquee el llavero";

/// Cómo terminó una vuelta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailOutcome {
    StoreClosed,
    Denied,
    Synced(EmailReport),
    Failed(String),
}

/// Lo que hizo una vuelta, para el diario y las pruebas.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmailReport {
    pub mailboxes: usize,
    /// Casillas que no se tocaron porque nada cambió.
    pub unchanged: usize,
    pub fetched: usize,
    pub flag_updates: usize,
    pub removed: usize,
    /// Casillas vaciadas porque el servidor cambió el `UIDVALIDITY`.
    pub resets: usize,
    pub bodies: usize,
}

// ---------------------------------------------------------------------------
// Lo que se puede probar sin red
// ---------------------------------------------------------------------------

/// El rol que guarda el almacén para el de una casilla del servidor.
pub fn store_role(role: mailboxes::MailboxRole) -> MailboxRole {
    match role {
        mailboxes::MailboxRole::Inbox => MailboxRole::Inbox,
        mailboxes::MailboxRole::Sent => MailboxRole::Sent,
        mailboxes::MailboxRole::Drafts => MailboxRole::Drafts,
        mailboxes::MailboxRole::Trash => MailboxRole::Trash,
        mailboxes::MailboxRole::Spam => MailboxRole::Junk,
        mailboxes::MailboxRole::Archive => MailboxRole::Archive,
        mailboxes::MailboxRole::All | mailboxes::MailboxRole::Other => MailboxRole::Other,
    }
}

/// En qué orden se sincronizan las casillas: la de entrada primero, después
/// las especiales, y al final el resto. «Todo el correo» (Gmail) va última:
/// es una copia de todas las demás.
pub fn priority(role: mailboxes::MailboxRole) -> u8 {
    match role {
        mailboxes::MailboxRole::Inbox => 0,
        mailboxes::MailboxRole::Sent => 1,
        mailboxes::MailboxRole::Drafts => 2,
        mailboxes::MailboxRole::Archive => 3,
        mailboxes::MailboxRole::Trash => 4,
        mailboxes::MailboxRole::Spam => 5,
        mailboxes::MailboxRole::Other => 6,
        mailboxes::MailboxRole::All => 7,
    }
}

/// Las casillas que se sincronizan: sólo las que se pueden abrir, en orden
/// de [`priority`] y con tope.
pub fn selectable(mut listed: Vec<Mailbox>) -> Vec<Mailbox> {
    listed.retain(|m| m.selectable);
    listed.sort_by(|a, b| {
        priority(a.role)
            .cmp(&priority(b.role))
            .then_with(|| a.path.cmp(&b.path))
    });
    listed.dedup_by(|a, b| a.path == b.path);
    listed.truncate(MAX_MAILBOXES);
    listed
}

/// La ventana de una casilla.
pub fn window_for(role: MailboxRole) -> u32 {
    if role == MailboxRole::Inbox {
        INBOX_WINDOW
    } else {
        OTHER_WINDOW
    }
}

/// Dónde quedó una casilla: lo que hay que comparar en la vuelta siguiente.
///
/// Se guarda como texto en `mailboxes.modseq` —`v1 <uidvalidity>
/// <highestmodseq|-> <uidnext|-> <exists>`—: para el almacén es un token
/// opaco, como el `sync-token` de DAV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxToken {
    pub uidvalidity: u32,
    pub highest_modseq: Option<u64>,
    pub uid_next: Option<u32>,
    pub exists: u32,
}

impl MailboxToken {
    pub fn encode(&self) -> String {
        let opt = |v: Option<u64>| v.map_or_else(|| "-".to_string(), |v| v.to_string());
        format!(
            "v1 {} {} {} {}",
            self.uidvalidity,
            opt(self.highest_modseq),
            opt(self.uid_next.map(u64::from)),
            self.exists
        )
    }

    /// `None` para lo que no se entiende: una casilla sin token se sincroniza
    /// entera, que es lo seguro.
    pub fn decode(text: &str) -> Option<Self> {
        let mut parts = text.split(' ');
        if parts.next()? != "v1" {
            return None;
        }
        let uidvalidity = parts.next()?.parse().ok()?;
        let opt = |s: &str| -> Option<Option<u64>> {
            if s == "-" {
                Some(None)
            } else {
                s.parse().ok().map(Some)
            }
        };
        let highest_modseq = opt(parts.next()?)?;
        let uid_next = match opt(parts.next()?)? {
            Some(v) => Some(u32::try_from(v).ok()?),
            None => None,
        };
        let exists = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            uidvalidity,
            highest_modseq,
            uid_next,
            exists,
        })
    }
}

/// Qué hacer con una casilla, según lo que se guardó y lo que dice ahora el
/// servidor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxAction {
    /// Nada cambió.
    Skip,
    /// Comparar por diferencia.
    Diff,
    /// El `UIDVALIDITY` cambió: vaciar y rehacer.
    Reset,
}

/// Decide [`MailboxAction`].
///
/// Sin CONDSTORE, «nada cambió» sólo se puede afirmar de lo que llega o se
/// va —`UIDNEXT` y la cantidad—, no de las banderas: por eso la de entrada,
/// que es la que se mira, se compara igual.
pub fn decide(previous: Option<MailboxToken>, now: MailboxToken, inbox: bool) -> MailboxAction {
    let Some(previous) = previous else {
        return MailboxAction::Diff;
    };
    if previous.uidvalidity != now.uidvalidity {
        return MailboxAction::Reset;
    }
    match (previous.highest_modseq, now.highest_modseq) {
        (Some(a), Some(b)) => {
            if a == b {
                MailboxAction::Skip
            } else {
                MailboxAction::Diff
            }
        }
        _ => {
            let same = previous.uid_next.is_some()
                && previous.uid_next == now.uid_next
                && previous.exists == now.exists;
            if same && !inbox {
                MailboxAction::Skip
            } else {
                MailboxAction::Diff
            }
        }
    }
}

/// Las banderas de columna a partir de las del servidor.
pub fn stored_flags(flags: &[String]) -> StoredFlags {
    let has = |name: &str| flags.iter().any(|f| f.eq_ignore_ascii_case(name));
    StoredFlags {
        seen: has("\\Seen"),
        answered: has("\\Answered"),
        flagged: has("\\Flagged"),
        draft: has("\\Draft"),
        deleted: has("\\Deleted"),
    }
}

/// Lo que hay que hacer en una casilla, por diferencia.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MailboxPlan {
    /// UID que no están guardados: hay que traer sus encabezados. Del más
    /// nuevo al más viejo, para que lo de hoy llegue primero.
    pub new: Vec<u32>,
    /// Guardados cuyas banderas cambiaron.
    pub flags: Vec<(u64, StoredFlags)>,
    /// Guardados que ya no están en la ventana del servidor.
    pub gone: Vec<u64>,
}

/// Compara lo guardado con la ventana del servidor.
pub fn plan_mailbox(stored: &HashMap<u64, StoredFlags>, server: &[UidFlags]) -> MailboxPlan {
    let mut plan = MailboxPlan::default();
    let mut seen = HashSet::with_capacity(server.len());
    for item in server {
        let uid = u64::from(item.uid);
        if !seen.insert(uid) {
            continue;
        }
        let flags = stored_flags(&item.flags);
        match stored.get(&uid) {
            None => plan.new.push(item.uid),
            Some(before) if *before != flags => plan.flags.push((uid, flags)),
            Some(_) => {}
        }
    }
    plan.new.sort_unstable_by(|a, b| b.cmp(a));
    plan.flags.sort_unstable_by_key(|(uid, _)| *uid);
    plan.gone = stored
        .keys()
        .filter(|uid| !seen.contains(uid))
        .copied()
        .collect();
    plan.gone.sort_unstable();
    plan
}

/// La fila del almacén de unos encabezados.
pub fn message_row(mailbox_id: i64, record: &HeaderRecord) -> MessageRow {
    let headers = crate::message::Headers::parse(&record.headers);
    let flags = stored_flags(&record.flags);
    let from = headers.get("From").map(join_sender).unwrap_or_default();
    let date_ts = headers
        .get("Date")
        .map(crate::message::parse_date)
        .and_then(|iso| chrono::DateTime::parse_from_rfc3339(&iso).ok())
        .map(|d| d.timestamp())
        .unwrap_or(0);
    let has_attachments = headers
        .get("Content-Type")
        .is_some_and(|v| v.to_ascii_lowercase().contains("multipart/mixed"));
    MessageRow {
        mailbox_id,
        uid: u64::from(record.uid),
        message_id: headers
            .get("Message-ID")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty()),
        from_addr: from,
        to_addrs: headers.decoded("To"),
        cc_addrs: headers.decoded("Cc"),
        bcc_addrs: String::new(),
        reply_to: Some(headers.decoded("Reply-To")).filter(|v| !v.is_empty()),
        subject: headers.decoded("Subject"),
        date_ts,
        // La fecha del mensaje ordena; si no se entendió, el UID —que crece
        // con la llegada— lo deja al fondo y no arriba de todo.
        sort_key: if date_ts > 0 {
            date_ts
        } else {
            i64::from(record.uid)
        },
        flags_seen: flags.seen,
        flags_answered: flags.answered,
        flags_flagged: flags.flagged,
        flags_draft: flags.draft,
        flags_deleted: flags.deleted,
        has_attachments,
        size: i64::try_from(record.size).unwrap_or(i64::MAX),
    }
}

/// `Nombre <dirección>`, con nombre y dirección separados por el mismo
/// analizador que usa la lista en memoria.
fn join_sender(value: &str) -> String {
    let (name, address) = crate::message::parse_sender(value);
    match (name.is_empty(), address.is_empty()) {
        (true, _) => address,
        (false, true) => name,
        (false, false) if name == address => address,
        (false, false) => format!("{name} <{address}>"),
    }
}

/// Lo que se guarda de un mensaje abierto: el texto, el HTML **saneado** y los
/// adjuntos (sólo qué son, no su contenido).
pub fn opened_rows(
    message_id: i64,
    raw: &[u8],
    truncated: bool,
) -> (MessageBodyRow, Vec<MessageAttachmentRow>) {
    let text = crate::message::plain_text(raw);
    let html = crate::message::html_part(raw).map(|h| crate::html::sanitize(&h).html);
    let attachments = crate::attachments::list(raw)
        .into_iter()
        .map(|a| MessageAttachmentRow {
            message_id,
            part_number: a.part,
            name: Some(a.name),
            content_type: a.content_type,
            size: 0,
            inline: false,
            content_id: None,
        })
        .collect();
    (
        MessageBodyRow {
            message_id,
            text_body: Some(text),
            html_body: html,
            truncated,
        },
        attachments,
    )
}

// ---------------------------------------------------------------------------
// La vuelta
// ---------------------------------------------------------------------------

/// Por qué se cortó una vuelta.
#[derive(Debug)]
enum RoundError {
    /// La base se cerró o falló: no se escribe más.
    Store(StoreError),
    /// La conexión quedó inservible.
    Imap(ImapError),
}

impl From<StoreError> for RoundError {
    fn from(e: StoreError) -> Self {
        RoundError::Store(e)
    }
}

/// La sincronización de correo de todas las cuentas.
pub struct EmailSync<K: KeySource> {
    manager: Arc<StoreManager<K>>,
    notify: Arc<dyn Fn() + Send + Sync>,
}

impl<K: KeySource> EmailSync<K> {
    pub fn new(manager: Arc<StoreManager<K>>, notify: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self { manager, notify }
    }

    async fn set_status(&self, account_id: &str, state: AreaState, detail: &str) {
        if self
            .manager
            .set_area_status(EMAIL_AREA, account_id, state, detail)
            .await
        {
            (self.notify)();
        }
    }

    /// Una vuelta de una cuenta, de punta a punta, con su estado.
    pub async fn sync_account(&self, account_id: &str) -> EmailOutcome {
        if !self.manager.prepare_for_sync(EMAIL_AREA, account_id).await {
            self.set_status(account_id, AreaState::Pending, CLOSED_DETAIL)
                .await;
            return EmailOutcome::StoreClosed;
        }
        self.set_status(account_id, AreaState::Syncing, "").await;

        let mut session = match open(account_id).await {
            Ok(session) => session,
            Err(BrokerError::Denied(_)) => {
                tracing::info!("'{account_id}': sin permiso para el correo");
                self.set_status(account_id, AreaState::Unavailable, DENIED_DETAIL)
                    .await;
                return EmailOutcome::Denied;
            }
            Err(e) => {
                tracing::warn!("'{account_id}': no se pudo abrir el correo: {e}");
                let shown = "no se pudo conectar con el servidor de correo";
                self.set_status(account_id, AreaState::Failed, shown).await;
                return EmailOutcome::Failed(shown.into());
            }
        };

        // Con plazo: la vuelta de las cuentas es una por vez, y un servidor que
        // contesta lento no puede dejar sin correo al resto.
        let outcome = match tokio::time::timeout(
            ROUND_DEADLINE,
            sync_session(&self.manager, account_id, &mut session),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => Err(RoundError::Imap(ImapError::Failed(
                "la vuelta pasó su plazo".into(),
            ))),
        };
        let _ = session.logout().await;
        match outcome {
            Ok(report) => {
                tracing::debug!("'{account_id}': correo al día: {report:?}");
                self.set_status(account_id, AreaState::Synced, "").await;
                EmailOutcome::Synced(report)
            }
            Err(RoundError::Store(e)) => {
                tracing::warn!("'{account_id}': la base del correo: {e}");
                let shown = e.public_detail();
                self.set_status(account_id, AreaState::Failed, shown).await;
                EmailOutcome::Failed(shown.into())
            }
            Err(RoundError::Imap(e)) => {
                tracing::warn!("'{account_id}': el servidor de correo: {e}");
                let shown = "el servidor de correo no contestó como se esperaba";
                self.set_status(account_id, AreaState::Failed, shown).await;
                EmailOutcome::Failed(shown.into())
            }
        }
    }
}

/// Abre una sesión IMAP de una cuenta con la credencial del servicio de
/// cuentas, por la puerta de permisos como cualquier aplicación.
async fn open(account_id: &str) -> Result<Session, BrokerError> {
    let broker = Broker::connect().await?;
    let token = broker.access_token(account_id, "email").await?;
    let config = broker.account_data(account_id, "email").await?;
    let config = config.get("config").cloned().unwrap_or(config);
    let destination = broker::imap_endpoint(&config, Some(token)).map_err(BrokerError::Failed)?;
    Session::open(&destination)
        .await
        .map_err(|e| BrokerError::Failed(e.to_string()))
}

/// Todas las casillas de una sesión ya abierta.
async fn sync_session<K, F>(
    manager: &StoreManager<K>,
    account_id: &str,
    session: &mut Session<F>,
) -> Result<EmailReport, RoundError>
where
    K: KeySource,
    F: AsyncRead + AsyncWrite + Unpin + Send,
{
    let listed = selectable(session.list_mailboxes().await.map_err(RoundError::Imap)?);
    let listings: Vec<MailboxListing> = listed
        .iter()
        .map(|m| MailboxListing {
            name: m.path.clone(),
            display_name: m.name.clone(),
            role: store_role(m.role),
        })
        .collect();

    let mut report = EmailReport {
        mailboxes: listed.len(),
        ..Default::default()
    };

    // Las que se fueron del servidor, de a tandas.
    let names: HashSet<String> = listings.iter().map(|l| l.name.clone()).collect();
    let stored = manager.with_store(account_id, |s| s.mailboxes()).await?;
    for gone in stored.into_iter().filter(|m| !names.contains(&m.name)) {
        loop {
            let removed = manager
                .with_store(account_id, move |s| s.remove_mailbox_chunk(gone.id))
                .await?;
            report.removed += removed;
            if removed == 0 {
                break;
            }
        }
    }

    let boxes = manager
        .with_store(account_id, move |s| s.upsert_mailboxes(&listings))
        .await?;

    for (mailbox, listing) in boxes.iter().zip(listed.iter()) {
        let role = store_role(listing.role);
        match sync_mailbox(manager, account_id, session, mailbox, role, &mut report).await {
            Ok(()) => {}
            // Una casilla que no abre —se borró recién, permisos del
            // servidor— no corta la vuelta de las demás.
            Err(RoundError::Imap(ImapError::Failed(detail))) => {
                tracing::info!(
                    "'{account_id}': «{}» no se pudo mirar: {detail}",
                    mailbox.name
                );
            }
            Err(e) => return Err(e),
        }
    }

    Ok(report)
}

/// Una casilla.
async fn sync_mailbox<K, F>(
    manager: &StoreManager<K>,
    account_id: &str,
    session: &mut Session<F>,
    mailbox: &StoredMailbox,
    role: MailboxRole,
    report: &mut EmailReport,
) -> Result<(), RoundError>
where
    K: KeySource,
    F: AsyncRead + AsyncWrite + Unpin + Send,
{
    let exists = session
        .examine(&mailbox.name)
        .await
        .map_err(RoundError::Imap)?;
    let Some(uidvalidity) = session.uidvalidity() else {
        // Sin `UIDVALIDITY` no hay forma de saber si los UID guardados siguen
        // valiendo: no se guarda nada de esta casilla.
        return Ok(());
    };
    let now = MailboxToken {
        uidvalidity,
        highest_modseq: session.highest_modseq(),
        uid_next: session.uid_next(),
        exists,
    };
    let previous = mailbox.modseq.as_deref().and_then(MailboxToken::decode);
    let id = mailbox.id;
    let inbox = role == MailboxRole::Inbox;

    match decide(previous, now, inbox) {
        MailboxAction::Skip => {
            report.unchanged += 1;
            if inbox {
                prefetch_bodies(manager, account_id, session, id, report).await?;
            }
            return Ok(());
        }
        MailboxAction::Reset => {
            report.resets += 1;
            loop {
                let removed = manager
                    .with_store(account_id, move |s| s.clear_mailbox_chunk(id))
                    .await?;
                if removed == 0 {
                    break;
                }
            }
        }
        MailboxAction::Diff => {}
    }

    let server = match imap::last_range(exists, window_for(role)) {
        Some(range) => session.uid_flags(&range).await.map_err(RoundError::Imap)?,
        None => Vec::new(),
    };
    let stored = manager
        .with_store(account_id, move |s| s.stored_flags(id))
        .await?;
    let plan = plan_mailbox(&stored, &server);

    // Lo que se fue, primero: libera lugar antes de sumar.
    for chunk in plan.gone.chunks(WRITE_BATCH_ROWS) {
        let ops: Vec<MessageOp> = chunk
            .iter()
            .map(|uid| MessageOp::Delete(id, *uid))
            .collect();
        report.removed += ops.len();
        manager
            .with_store(account_id, move |s| s.apply_messages(ops, id))
            .await?;
    }

    if !plan.flags.is_empty() {
        let changes = plan.flags;
        report.flag_updates += manager
            .with_store(account_id, move |s| s.update_flags(id, &changes))
            .await?;
    }

    for chunk in plan.new.chunks(HEADER_CHUNK) {
        let records = session
            .header_records(chunk)
            .await
            .map_err(RoundError::Imap)?;
        let ops: Vec<MessageOp> = records
            .iter()
            .map(|r| MessageOp::Upsert(Box::new(message_row(id, r))))
            .collect();
        report.fetched += ops.len();
        manager
            .with_store(account_id, move |s| s.apply_messages(ops, id))
            .await?;
    }

    // Recién ahora: una vuelta cortada a la mitad no deja la casilla por al
    // día, y la siguiente vuelve a comparar.
    let name = mailbox.name.clone();
    let token = Some(now.encode());
    manager
        .with_store(account_id, move |s| s.set_mailbox_modseq(&name, token))
        .await?;

    if inbox {
        prefetch_bodies(manager, account_id, session, id, report).await?;
    }
    Ok(())
}

/// Trae los cuerpos de los mensajes más nuevos de la casilla abierta que
/// todavía no lo tienen, y los guarda en una sola transacción.
async fn prefetch_bodies<K, F>(
    manager: &StoreManager<K>,
    account_id: &str,
    session: &mut Session<F>,
    mailbox_id: i64,
    report: &mut EmailReport,
) -> Result<(), RoundError>
where
    K: KeySource,
    F: AsyncRead + AsyncWrite + Unpin + Send,
{
    let pending = manager
        .with_store(account_id, move |s| {
            s.messages_without_body(mailbox_id, BODY_PREFETCH)
        })
        .await?;
    if pending.is_empty() {
        return Ok(());
    }
    let mut opened = Vec::with_capacity(pending.len());
    for (message_id, uid) in pending {
        let Ok(uid) = u32::try_from(uid) else {
            continue;
        };
        match session.fetch_body(uid).await {
            Ok((raw, truncated)) => opened.push(opened_rows(message_id, &raw, truncated)),
            Err(e @ ImapError::Desynced(_)) => return Err(RoundError::Imap(e)),
            // Uno que no se pudo traer —se borró recién— no frena a los demás.
            Err(e) => tracing::debug!("'{account_id}': un cuerpo no se pudo traer: {e}"),
        }
    }
    report.bodies += opened.len();
    manager
        .with_store(account_id, move |s| s.store_opened(opened))
        .await?;
    Ok(())
}

impl<K: KeySource> AreaSync for EmailSync<K> {
    fn interval(&self) -> Duration {
        EMAIL_INTERVAL
    }

    async fn targets(&self) -> Vec<String> {
        self.manager.area_targets(EMAIL_AREA).await
    }

    async fn attempt(&self, account_id: &str) -> bool {
        self.sync_account(account_id).await != EmailOutcome::StoreClosed
    }
}

/// Decide cuándo le toca a cada cuenta.
pub type EmailScheduler<K> = dav_sync::DavScheduler<EmailSync<K>>;

#[cfg(test)]
mod tests;
