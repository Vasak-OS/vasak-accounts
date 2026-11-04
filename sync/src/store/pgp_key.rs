//! La identidad OpenPGP propia en el llavero, por cuenta.
//!
//! La clave privada OpenPGP de una cuenta —y su contraseña (passphrase)— viven en
//! `vasak-keyring` bajo el esquema protegido [`SCHEMA`] (`ar.net.vasak.os.PgpKey`):
//! sólo la toca este servicio, cifrada en reposo como el resto, y a cualquier
//! otro proceso el llavero le contesta `SearchItems` vacío. Es el mismo trato que
//! la identidad S/MIME ([`super::smime_key`]) —el esquema y las claves de búsqueda
//! son lo único que cambia—, así que esto reusa el cliente de Secret Service de
//! [`super::key`] (sesión `plain`, `CreateItem replace=true`,
//! `SearchItems`/`GetSecret`).
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
#![allow(dead_code)]

use std::collections::HashMap;

use zbus::zvariant::{OwnedObjectPath, Value};
use zeroize::Zeroizing;

use super::key::{KeyError, Secret, SecretServiceKeys};

/// El esquema protegido de las identidades OpenPGP. Tiene que coincidir con el
/// que `vasak-keyring` restringe a este ejecutable, como el de S/MIME.
pub const SCHEMA: &str = "ar.net.vasak.os.PgpKey";

const SCHEMA_ATTRIBUTE: &str = "xdg:schema";
const ACCOUNT_ATTRIBUTE: &str = "account";
const TYPE_ATTRIBUTE: &str = "type";
const TYPE_SECRET_KEY: &str = "secret-key";
const TYPE_PASSPHRASE: &str = "passphrase";

const COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";

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
        self.store_pgp_item(account, TYPE_SECRET_KEY, secret_key, "application/pgp-keys")
            .await?;
        self.store_pgp_item(account, TYPE_PASSPHRASE, passphrase, "text/plain")
            .await
    }

    /// La clave privada OpenPGP de una cuenta, si hay una.
    pub(crate) async fn find_pgp_secret_key(
        &self,
        account: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, KeyError> {
        Ok(self
            .find_pgp_item(account, TYPE_SECRET_KEY)
            .await?
            .map(Zeroizing::new))
    }

    /// La contraseña que abre la clave de una cuenta, si hay una.
    pub(crate) async fn find_pgp_passphrase(
        &self,
        account: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, KeyError> {
        Ok(self
            .find_pgp_item(account, TYPE_PASSPHRASE)
            .await?
            .map(Zeroizing::new))
    }

    /// Borra la clave y la contraseña de una cuenta. Que no hubiera no es un
    /// error; la colección bloqueada sí ([`KeyError::Locked`]).
    pub(crate) async fn delete_pgp_identity(&self, account: &str) -> Result<(), KeyError> {
        for type_ in [TYPE_SECRET_KEY, TYPE_PASSPHRASE] {
            let attributes = pgp_attributes(account, type_);
            for item in self.search(&attributes).await? {
                let prompt: OwnedObjectPath =
                    self.call(item.as_str(), ITEM_IFACE, "Delete", &()).await?;
                if prompt.as_str() != "/" {
                    return Err(KeyError::PromptRequired);
                }
            }
        }
        Ok(())
    }

    async fn store_pgp_item(
        &self,
        account: &str,
        type_: &str,
        value: &[u8],
        content_type: &str,
    ) -> Result<(), KeyError> {
        let collection = self.default_collection().await?;
        let label = format!("Clave OpenPGP de VasakOS ({account})");
        let attributes = pgp_attributes(account, type_);
        let mut properties: HashMap<&str, Value<'_>> = HashMap::new();
        properties.insert("org.freedesktop.Secret.Item.Label", Value::from(label));
        properties.insert(
            "org.freedesktop.Secret.Item.Attributes",
            Value::from(attributes),
        );

        let session = self.open_session().await?;
        let secret = Secret {
            session: session.clone(),
            parameters: Vec::new(),
            value: value.to_vec(),
            content_type: content_type.into(),
        };
        // `replace = true`: reimportar una identidad reemplaza su clave en vez de
        // dejar dos que después no se sabe cuál es.
        let reply: Result<(OwnedObjectPath, OwnedObjectPath), KeyError> = self
            .call(
                collection.as_str(),
                COLLECTION_IFACE,
                "CreateItem",
                &(properties, &secret, true),
            )
            .await;
        drop(secret);
        self.close_session(&session).await;

        let (_item, prompt) = reply?;
        if prompt.as_str() != "/" {
            return Err(KeyError::PromptRequired);
        }
        Ok(())
    }

    async fn find_pgp_item(&self, account: &str, type_: &str) -> Result<Option<Vec<u8>>, KeyError> {
        let attributes = pgp_attributes(account, type_);
        let items = self.search(&attributes).await?;
        let Some(item) = items.first() else {
            return Ok(None);
        };
        let session = self.open_session().await?;
        let reply: Result<(Secret,), KeyError> = self
            .call(item.as_str(), ITEM_IFACE, "GetSecret", &(&session,))
            .await;
        self.close_session(&session).await;
        let (mut secret,) = reply?;
        Ok(Some(std::mem::take(&mut secret.value)))
    }
}
