//! La identidad OpenPGP propia en el llavero, por cuenta.
//!
//! La clave privada OpenPGP de una cuenta —y su contraseña (passphrase)— viven en
//! `vasak-keyring` bajo el esquema [`SCHEMA`] (`ar.net.vasak.os.PgpKey`), cifradas
//! en reposo como el resto. La idea es el mismo trato que la identidad S/MIME
//! ([`super::smime_key`]) —el esquema y las claves de búsqueda son lo único que
//! cambia—, así que esto reusa el cliente de Secret Service de [`super::key`]
//! (sesión `plain`, `CreateItem replace=true`, `SearchItems`/`GetSecret`).
//!
//! **Pendiente (Vasak-OS/vasak-keyring#64):** la aislación —que sólo este servicio
//! lo toque y a cualquier otro proceso el llavero le conteste `SearchItems` vacío—
//! la aplica `vasak-keyring` por su lista `PROTECTED_SCHEMAS`, y `PgpKey` **todavía
//! no está** en esa lista (sí lo está `SmimeKey`). Es **precondición dura del PR5**
//! (import de la identidad): ninguna clave privada OpenPGP real debe guardarse acá
//! antes de que esa puerta exista. Hoy este módulo está inerte (`dead_code`) hasta
//! que PR5 lo enganche.
//!
//! Por cuenta se guardan dos ítems **secretos**: la **clave privada** (el armor o
//! los bytes binarios de OpenPGP, como vinieron) y la **contraseña** que la abre.
//! Las dos son secreto y por eso van acá y nunca en el SQLCipher ni en texto; las
//! claves **públicas de terceros** (peerstate TOFU) no son secretas y van en el
//! almacén por cuenta ([`super::pgp_peer`]).
//!
//! Esta capa es sólo almacenamiento: guardar, leer y borrar. El **parseo y la
//! validación** de la clave (ligar la UID al `From`, rechazos honestos) es PR3, y
//! el import por D-Bus con memfd sellado es PR5; los dos consumen esto después.
// PR2 es sólo almacenamiento: lo consumen el parseo/import (PR3) y la firma/
// descifrado (PR4/PR5), que todavía no están. Hasta que lo llamen, el chequeo de
// código muerto lo marcaría entero; se saca al engancharlo. Mismo criterio que
// `smime_key` y el núcleo `pgp.rs` del PR1.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;

use zeroize::Zeroizing;

use super::key::{KeyError, SecretServiceKeys};

/// El esquema protegido de las identidades OpenPGP. Tiene que coincidir con el
/// que `vasak-keyring` restringe a este ejecutable, como el de S/MIME.
pub const SCHEMA: &str = "ar.net.vasak.os.PgpKey";

const SCHEMA_ATTRIBUTE: &str = "xdg:schema";
const ACCOUNT_ATTRIBUTE: &str = "account";
const TYPE_ATTRIBUTE: &str = "type";
const TYPE_SECRET_KEY: &str = "secret-key";
const TYPE_PASSPHRASE: &str = "passphrase";

fn pgp_attributes<'a>(account: &'a str, type_: &'a str) -> HashMap<&'a str, &'a str> {
    HashMap::from([
        (SCHEMA_ATTRIBUTE, SCHEMA),
        (ACCOUNT_ATTRIBUTE, account),
        (TYPE_ATTRIBUTE, type_),
    ])
}

impl SecretServiceKeys {
    /// Guarda la clave privada y la contraseña de la identidad de una cuenta,
    /// reemplazando lo que hubiera.
    pub(crate) async fn store_pgp_identity(
        &self,
        account: &str,
        secret_key: &[u8],
        passphrase: &[u8],
    ) -> Result<(), KeyError> {
        let label = format!("Clave OpenPGP de VasakOS ({account})");
        self.store_secret_item(
            pgp_attributes(account, TYPE_SECRET_KEY),
            label.clone(),
            secret_key,
            "application/pgp-keys",
        )
        .await?;
        self.store_secret_item(
            pgp_attributes(account, TYPE_PASSPHRASE),
            label,
            passphrase,
            "text/plain",
        )
        .await
    }

    /// La clave privada OpenPGP de una cuenta, si hay una.
    pub(crate) async fn find_pgp_secret_key(
        &self,
        account: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, KeyError> {
        Ok(self
            .find_secret_item(&pgp_attributes(account, TYPE_SECRET_KEY))
            .await?
            .map(Zeroizing::new))
    }

    /// La contraseña que abre la clave de una cuenta, si hay una.
    pub(crate) async fn find_pgp_passphrase(
        &self,
        account: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, KeyError> {
        Ok(self
            .find_secret_item(&pgp_attributes(account, TYPE_PASSPHRASE))
            .await?
            .map(Zeroizing::new))
    }

    /// Borra la clave y la contraseña de una cuenta. Que no hubiera no es un
    /// error; la colección bloqueada sí ([`KeyError::Locked`]).
    pub(crate) async fn delete_pgp_identity(&self, account: &str) -> Result<(), KeyError> {
        for type_ in [TYPE_SECRET_KEY, TYPE_PASSPHRASE] {
            self.delete_secret_items(&pgp_attributes(account, type_))
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::key::tests::{fake_keyring, lock_and_announce};
    use super::*;

    #[tokio::test]
    async fn guardar_y_leer_da_los_mismos_bytes_de_clave_y_de_contrasena() {
        let (keys, _server, _shared) = fake_keyring().await;
        let secret_key = [0u8, 1, 2, 0xff, 0xfe, 10, 13];
        keys.store_pgp_identity("ana@example.com", &secret_key, b"pa ss\xc3\xb1")
            .await
            .unwrap();

        let key = keys.find_pgp_secret_key("ana@example.com").await.unwrap();
        let pass = keys.find_pgp_passphrase("ana@example.com").await.unwrap();
        assert_eq!(key.expect("hay clave").as_slice(), &secret_key);
        assert_eq!(pass.expect("hay contraseña").as_slice(), b"pa ss\xc3\xb1");
    }

    #[tokio::test]
    async fn reimportar_reemplaza_y_no_deja_dos_items() {
        let (keys, _server, _shared) = fake_keyring().await;
        keys.store_pgp_identity("ana@example.com", b"clave-vieja", b"vieja")
            .await
            .unwrap();
        keys.store_pgp_identity("ana@example.com", b"clave-nueva", b"nueva")
            .await
            .unwrap();

        let key = keys.find_pgp_secret_key("ana@example.com").await.unwrap();
        let pass = keys.find_pgp_passphrase("ana@example.com").await.unwrap();
        assert_eq!(key.unwrap().as_slice(), b"clave-nueva");
        assert_eq!(pass.unwrap().as_slice(), b"nueva");
    }

    #[tokio::test]
    async fn borrar_quita_los_dos_items_y_deja_a_las_demas_cuentas() {
        let (keys, _server, _shared) = fake_keyring().await;
        keys.store_pgp_identity("ana@example.com", b"k-ana", b"p-ana")
            .await
            .unwrap();
        keys.store_pgp_identity("beto@example.com", b"k-beto", b"p-beto")
            .await
            .unwrap();

        keys.delete_pgp_identity("ana@example.com").await.unwrap();

        assert!(keys
            .find_pgp_secret_key("ana@example.com")
            .await
            .unwrap()
            .is_none());
        assert!(keys
            .find_pgp_passphrase("ana@example.com")
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            keys.find_pgp_secret_key("beto@example.com")
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"k-beto"
        );
    }

    #[tokio::test]
    async fn una_cuenta_sin_identidad_da_ausencia_y_borrarla_no_es_error() {
        let (keys, _server, _shared) = fake_keyring().await;
        assert!(keys
            .find_pgp_secret_key("nadie@example.com")
            .await
            .unwrap()
            .is_none());
        assert!(keys
            .find_pgp_passphrase("nadie@example.com")
            .await
            .unwrap()
            .is_none());
        keys.delete_pgp_identity("nadie@example.com").await.unwrap();
    }

    #[tokio::test]
    async fn la_identidad_de_una_cuenta_no_se_lee_con_otra() {
        let (keys, _server, _shared) = fake_keyring().await;
        keys.store_pgp_identity("ana@example.com", b"k-ana", b"p-ana")
            .await
            .unwrap();
        assert!(keys
            .find_pgp_secret_key("beto@example.com")
            .await
            .unwrap()
            .is_none());
        assert!(keys
            .find_pgp_passphrase("beto@example.com")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn clave_y_contrasena_no_se_confunden_entre_si() {
        let (keys, _server, _shared) = fake_keyring().await;
        keys.store_pgp_identity("ana@example.com", b"LA-CLAVE", b"LA-PASS")
            .await
            .unwrap();
        assert_ne!(
            keys.find_pgp_secret_key("ana@example.com")
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            keys.find_pgp_passphrase("ana@example.com")
                .await
                .unwrap()
                .unwrap()
                .as_slice()
        );
    }

    /// Con el llavero bloqueado `SearchItems` contesta vacío: no se puede tomar
    /// por «no hay clave», es un error.
    #[tokio::test]
    async fn con_el_llavero_bloqueado_todo_da_error_y_no_ausencia() {
        let (keys, server, shared) = fake_keyring().await;
        keys.store_pgp_identity("ana@example.com", b"k", b"p")
            .await
            .unwrap();
        lock_and_announce(&server, &shared).await.unwrap();

        assert!(matches!(
            keys.find_pgp_secret_key("ana@example.com").await,
            Err(KeyError::Locked)
        ));
        assert!(matches!(
            keys.find_pgp_passphrase("ana@example.com").await,
            Err(KeyError::Locked)
        ));
        assert!(matches!(
            keys.store_pgp_identity("ana@example.com", b"x", b"y").await,
            Err(KeyError::Locked)
        ));
        assert!(matches!(
            keys.delete_pgp_identity("ana@example.com").await,
            Err(KeyError::Locked)
        ));
    }
}
