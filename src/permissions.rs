//! Asking the permission service whether a program may use an account.
//!
//! This daemon used to answer that question itself, from a list inside
//! `accounts.json`. That could never work: the file lives in the user's own
//! configuration directory, so any program running as them could rewrite it and
//! grant itself anything. The rules now belong to `vasak-permissions`, a system
//! service whose policy file the user cannot write.

use zbus::fdo::Error as FdoError;

use crate::storage::CapabilityType;

const SERVICE_NAME: &str = "ar.net.vasak.os.Permissions";
const SERVICE_PATH: &str = "/ar/net/vasak/os/Permissions";
const SERVICE_INTERFACE: &str = "ar.net.vasak.os.Permissions";

/// Asks on behalf of the program that called this daemon.
///
/// The permission service would otherwise see *this* daemon as the caller, and
/// one decision recorded against `/usr/bin/vasak-accounts` would be shared by
/// every application. It accepts a named subject only from a short list of
/// system-installed services, of which this is one.
pub async fn check(
    subject_pid: u32,
    capability: &CapabilityType,
    account_name: &str,
) -> Result<bool, FdoError> {
    let resource_id = format!("account.{}", capability_id(capability));
    let start_time = process_start_time(subject_pid)?;

    // The system bus, because that is where a service the user cannot tamper
    // with has to live.
    let connection = permission_bus().await.map_err(|e| {
        FdoError::Failed(format!(
            "no se pudo contactar al servicio de permisos: {e}. \
             Sin él no se puede autorizar el acceso a la cuenta."
        ))
    })?;

    let reply = connection
        .call_method(
            Some(SERVICE_NAME),
            SERVICE_PATH,
            Some(SERVICE_INTERFACE),
            "CheckPermissionFor",
            &(subject_pid, start_time, resource_id.as_str(), account_name),
        )
        .await
        .map_err(|e| {
            FdoError::Failed(format!("el servicio de permisos rechazó la consulta: {e}"))
        })?;

    reply
        .body()
        .deserialize::<bool>()
        .map_err(|e| FdoError::Failed(format!("respuesta inválida del servicio de permisos: {e}")))
}


/// Follows the permission service onto the development bus when one is in use.
/// Compiled out of release: see the note on the daemon's own bus selection.
#[cfg(debug_assertions)]
async fn permission_bus() -> zbus::Result<zbus::Connection> {
    if std::env::var_os("VASAK_ACCOUNTS_TEST_ROOT").is_some() {
        return zbus::Connection::session().await;
    }
    zbus::Connection::system().await
}

#[cfg(not(debug_assertions))]
async fn permission_bus() -> zbus::Result<zbus::Connection> {
    zbus::Connection::system().await
}

/// The text form the permission service uses for a capability.
fn capability_id(capability: &CapabilityType) -> &'static str {
    match capability {
        CapabilityType::Email => "email",
        CapabilityType::Calendar => "calendar",
        CapabilityType::Contacts => "contacts",
        CapabilityType::Chat => "chat",
        CapabilityType::Drive => "drive",
        CapabilityType::Tasks => "tasks",
    }
}

/// Field 22 of `/proc/<pid>/stat`, which the permission service compares to
/// detect a PID that was reused between us seeing it and it being checked.
fn process_start_time(pid: u32) -> Result<u64, FdoError> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|e| FdoError::Failed(format!("el proceso {pid} ya no existe: {e}")))?;

    parse_start_time(&stat)
        .ok_or_else(|| FdoError::Failed(format!("no se pudo interpretar /proc/{pid}/stat")))
}

/// Parsed from the last `)` onwards: field 2 is the executable name in
/// parentheses and can itself contain spaces or brackets, so splitting the
/// whole line on whitespace misplaces every field after it.
fn parse_start_time(stat: &str) -> Option<u64> {
    let after_name = stat.rsplit_once(')')?.1;
    after_name.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_ids_match_what_the_permission_service_expects() {
        assert_eq!(capability_id(&CapabilityType::Email), "email");
        assert_eq!(capability_id(&CapabilityType::Calendar), "calendar");
        assert_eq!(capability_id(&CapabilityType::Contacts), "contacts");
        assert_eq!(capability_id(&CapabilityType::Chat), "chat");
        assert_eq!(capability_id(&CapabilityType::Drive), "drive");
        assert_eq!(capability_id(&CapabilityType::Tasks), "tasks");
    }

    #[test]
    fn the_start_time_is_read_from_the_right_field() {
        let mut stat = String::from("1234 (bash) S");
        for field in 4..=21 {
            stat.push_str(&format!(" {field}"));
        }
        stat.push_str(" 4242 rest");

        assert_eq!(parse_start_time(&stat), Some(4242));
    }

    /// A program can be called `weird ) name`; splitting the whole line on
    /// spaces would read the wrong field and the service would reject a
    /// perfectly good request.
    #[test]
    fn a_program_name_with_brackets_does_not_shift_the_fields() {
        let mut stat = String::from("1234 (weird ) name) S");
        for field in 4..=21 {
            stat.push_str(&format!(" {field}"));
        }
        stat.push_str(" 99 more");

        assert_eq!(parse_start_time(&stat), Some(99));
    }

    #[test]
    fn our_own_start_time_can_be_read() {
        assert!(process_start_time(std::process::id()).is_ok());
    }
}
