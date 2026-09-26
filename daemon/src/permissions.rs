//! Asking the permission service whether a program may use an account.
//!
//! This daemon used to answer that question itself, from a list inside
//! `accounts.json`. That could never work: the file lives in the user's own
//! configuration directory, so any program running as them could rewrite it and
//! grant itself anything. The rules now belong to `vasak-permissions`, a system
//! service whose policy file the user cannot write.

use vasak_accounts_common::permissions::{check_permission_for, permission_bus};
use vasak_accounts_common::process::process_start_time;
use zbus::fdo::Error as FdoError;

use crate::storage::CapabilityType;

/// Asks on behalf of the program that called this daemon.
///
/// The permission service would otherwise see *this* daemon as the caller, and
/// one decision recorded against `/usr/bin/vasak-accounts` would be shared by
/// every application. It accepts a named subject only from a short list of
/// system-installed services, of which this is one.
///
/// El momento de arranque, el bus y la pregunta misma viven en
/// `vasak-accounts-common`, porque el sincronizador pregunta lo mismo por las
/// aplicaciones que leen el almacén.
pub async fn check(
    subject_pid: u32,
    capability: &CapabilityType,
    account_name: &str,
) -> Result<bool, FdoError> {
    let resource_id = format!("account.{}", capability.as_id());
    let start_time = process_start_time(subject_pid)?;

    // The system bus, because that is where a service the user cannot tamper
    // with has to live.
    let connection = permission_bus().await.map_err(|e| {
        FdoError::Failed(format!(
            "no se pudo contactar al servicio de permisos: {e}. \
             Sin él no se puede autorizar el acceso a la cuenta."
        ))
    })?;

    check_permission_for(
        &connection,
        subject_pid,
        start_time,
        &resource_id,
        account_name,
    )
    .await
    .map_err(|e| match e {
        zbus::Error::Variant(e) => {
            FdoError::Failed(format!("respuesta inválida del servicio de permisos: {e}"))
        }
        e => FdoError::Failed(format!("el servicio de permisos rechazó la consulta: {e}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Los identificadores que el servicio de permisos guarda en su política.
    /// Cambiar uno acá deja sin efecto los permisos ya concedidos: la decisión
    /// quedó grabada contra el nombre viejo y nadie la volvería a encontrar.
    #[test]
    fn capability_ids_match_what_the_permission_service_expects() {
        assert_eq!(CapabilityType::Email.as_id(), "email");
        assert_eq!(CapabilityType::Calendar.as_id(), "calendar");
        assert_eq!(CapabilityType::Contacts.as_id(), "contacts");
        assert_eq!(CapabilityType::Chat.as_id(), "chat");
        assert_eq!(CapabilityType::Drive.as_id(), "drive");
        assert_eq!(CapabilityType::Tasks.as_id(), "tasks");
    }

    /// El servicio de permisos reconoce `account.<capacidad>` y nada más, así
    /// que el prefijo es parte del contrato entre los dos servicios.
    #[test]
    fn every_capability_maps_to_an_account_resource_id() {
        for capability in CapabilityType::ALL {
            let resource = format!("account.{}", capability.as_id());
            assert!(
                resource.starts_with("account."),
                "{resource} no es un recurso de cuentas"
            );
            assert!(!capability.as_id().is_empty());
        }
    }
}
