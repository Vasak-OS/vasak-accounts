//! Preguntarle a `vasak-permissions` por otro proceso.
//!
//! `CheckPermissionFor(pid, momento de arranque, recurso, detalle)` sólo lo
//! aceptan los delegados que lista el servicio (`DELEGATE_BINARIES` en su
//! protocolo): el servicio de cuentas, que habla por cualquiera porque corre
//! como root, y el sincronizador, que sólo puede hablar por procesos de su
//! propio usuario. Los dos preguntan por **quien los llamó**, no por sí
//! mismos: si no, todas las aplicaciones compartirían una sola decisión anotada
//! contra el delegado, que no es ninguna decisión.
//!
//! El servicio vive en el bus del **sistema**, que es donde tiene que estar algo
//! que la persona no puede reemplazar.

use zbus::Connection;

pub const SERVICE_NAME: &str = "ar.net.vasak.os.Permissions";
pub const SERVICE_PATH: &str = "/ar/net/vasak/os/Permissions";
pub const SERVICE_INTERFACE: &str = "ar.net.vasak.os.Permissions";

/// El bus donde está el servicio de permisos.
///
/// En una compilación de depuración con `VASAK_ACCOUNTS_TEST_ROOT`, el de
/// sesión: ahí es donde corre el servicio de permisos de desarrollo. Fuera de
/// la compilación de producción por completo, y no detrás de un `if`.
#[cfg(debug_assertions)]
pub async fn permission_bus() -> zbus::Result<Connection> {
    if std::env::var_os("VASAK_ACCOUNTS_TEST_ROOT").is_some() {
        return Connection::session().await;
    }
    Connection::system().await
}

#[cfg(not(debug_assertions))]
pub async fn permission_bus() -> zbus::Result<Connection> {
    Connection::system().await
}

/// `CheckPermissionFor`, tal cual: si el proceso `subject_pid`, que arrancó en
/// `subject_start_time`, puede usar `resource_id`.
///
/// `detail` es el contexto del diálogo —de qué cuenta se trata— y no cambia la
/// decisión guardada: el servicio la anota por programa y recurso.
///
/// **Puede tardar lo que tarde la persona en contestar**: si no hay decisión
/// guardada, el servicio abre un diálogo y la respuesta llega recién cuando lo
/// cierran. Quien llama pone su propio tiempo máximo.
///
/// En una conexión punto a punto —las pruebas— no hay nombres de bus, y el
/// pedido va sin destino.
pub async fn check_permission_for(
    connection: &Connection,
    subject_pid: u32,
    subject_start_time: u64,
    resource_id: &str,
    detail: &str,
) -> zbus::Result<bool> {
    let destination = connection.is_bus().then_some(SERVICE_NAME);
    let reply = connection
        .call_method(
            destination,
            SERVICE_PATH,
            Some(SERVICE_INTERFACE),
            "CheckPermissionFor",
            &(subject_pid, subject_start_time, resource_id, detail),
        )
        .await?;
    reply.body().deserialize::<bool>()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Una pregunta tal como llegó: pid, arranque, recurso y detalle.
    type Question = (u32, u64, String, String);

    /// Un servicio de permisos falso que anota lo que le preguntaron.
    struct FakePermissions {
        asked: std::sync::Arc<std::sync::Mutex<Vec<Question>>>,
    }

    #[zbus::interface(name = "ar.net.vasak.os.Permissions")]
    impl FakePermissions {
        async fn check_permission_for(
            &self,
            subject_pid: u32,
            subject_start_time: u64,
            resource_id: String,
            detail: String,
        ) -> bool {
            self.asked.lock().unwrap().push((
                subject_pid,
                subject_start_time,
                resource_id.clone(),
                detail,
            ));
            resource_id == "store.contacts"
        }
    }

    /// La pregunta llega con los cuatro argumentos en el orden del servicio, y
    /// la respuesta vuelve tal cual.
    #[tokio::test]
    async fn la_pregunta_lleva_los_cuatro_argumentos_en_orden() {
        let asked = std::sync::Arc::default();
        let (server_end, client_end) = tokio::net::UnixStream::pair().unwrap();
        let server = zbus::connection::Builder::unix_stream(server_end)
            .server(zbus::Guid::generate())
            .unwrap()
            .p2p()
            .serve_at(
                SERVICE_PATH,
                FakePermissions {
                    asked: std::sync::Arc::clone(&asked),
                },
            )
            .unwrap()
            .build();
        let client = zbus::connection::Builder::unix_stream(client_end)
            .p2p()
            .build();
        let (server, client) = tokio::join!(server, client);
        let (_server, client) = (server.unwrap(), client.unwrap());

        assert!(
            check_permission_for(&client, 42, 4242, "store.contacts", "Trabajo")
                .await
                .unwrap()
        );
        assert!(
            !check_permission_for(&client, 42, 4242, "account.email", "Trabajo")
                .await
                .unwrap()
        );
        assert_eq!(
            asked.lock().unwrap()[0],
            (
                42,
                4242,
                "store.contacts".to_string(),
                "Trabajo".to_string()
            )
        );
    }
}
