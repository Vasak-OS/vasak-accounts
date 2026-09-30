//! La superficie de una interfaz de D-Bus, tal como la ve un cliente.
//!
//! Sólo para las pruebas: lo habilita la función `introspection`, que el
//! demonio y el sincronizador piden en sus `dev-dependencies`. Ningún binario
//! que se instala la trae.
//!
//! Lo que un cliente usa de una interfaz son los nombres, las firmas, el
//! sentido de cada argumento, las propiedades con su acceso y las anotaciones.
//! Los comentarios que zbus copia de la documentación, el orden en que lista las
//! interfaces y los espacios no cambian nada del otro lado del bus, así que
//! quedan afuera: una prueba que los mirara fallaría por corregir una tilde en
//! un comentario, y aprendería a regenerarse sin leer.
//!
//! El orden de los miembros tampoco: se ordenan por tipo y nombre. El de los
//! argumentos **sí** se conserva, porque es la firma.

/// La superficie de `interface` dentro del XML de `Introspect`, en texto: una
/// línea por miembro, estable entre versiones de zbus. `None` si el XML no
/// declara esa interfaz o no se puede leer.
pub fn interface_surface(xml: &str, interface: &str) -> Option<String> {
    // Con la DTD permitida: zbus encabeza el XML con el `DOCTYPE` del estándar,
    // y roxmltree lo rechaza por omisión. Nunca la descarga ni resuelve nada de
    // afuera, y lo que se lee es la respuesta de un objeto propio en una prueba.
    let options = roxmltree::ParsingOptions {
        allow_dtd: true,
        ..roxmltree::ParsingOptions::default()
    };
    let document = roxmltree::Document::parse_with_options(xml, options).ok()?;
    let node = document
        .descendants()
        .find(|node| node.has_tag_name("interface") && node.attribute("name") == Some(interface))?;

    let mut members: Vec<(u8, String, String)> = Vec::new();
    for member in node.children().filter(roxmltree::Node::is_element) {
        let name = member.attribute("name").unwrap_or_default().to_string();
        let (order, line) = match member.tag_name().name() {
            "method" => (1, format!("method {name}({})", arguments(member, true))),
            "signal" => (2, format!("signal {name}({})", arguments(member, false))),
            "property" => (
                3,
                format!(
                    "property {name}: {} {}",
                    member.attribute("type").unwrap_or_default(),
                    member.attribute("access").unwrap_or_default(),
                ),
            ),
            "annotation" => (0, annotation(member)),
            other => (4, format!("{other} {name}")),
        };
        let mut text = format!("  {line}\n");
        for nested in member
            .children()
            .filter(|child| child.has_tag_name("annotation"))
        {
            text.push_str(&format!("    {}\n", annotation(nested)));
        }
        members.push((order, name, text));
    }
    members.sort();

    let mut surface = format!("interface {interface}\n");
    for (_, _, text) in members {
        surface.push_str(&text);
    }
    Some(surface)
}

/// El XML de `Introspect` del objeto en `path`, preguntado por `connection`
/// como lo haría un cliente. Sin destino: sirve en una conexión punto a punto,
/// donde no hay nombres.
pub async fn introspect(connection: &zbus::Connection, path: &str) -> zbus::Result<String> {
    connection
        .call_method(
            None::<&str>,
            path,
            Some("org.freedesktop.DBus.Introspectable"),
            "Introspect",
            &(),
        )
        .await?
        .body()
        .deserialize()
}

/// Publica `interface` en `path` del otro lado de una conexión punto a punto y
/// devuelve las dos puntas: la del servicio, que hay que mantener viva, y la
/// del cliente. Sin `dbus-daemon`.
pub async fn serve_p2p<I>(
    path: &str,
    interface: I,
) -> zbus::Result<(zbus::Connection, zbus::Connection)>
where
    I: zbus::object_server::Interface,
{
    let (server_end, client_end) = tokio::net::UnixStream::pair()?;
    let server = zbus::connection::Builder::unix_stream(server_end)
        .server(zbus::Guid::generate())?
        .p2p()
        .serve_at(path, interface)?
        .build();
    let client = zbus::connection::Builder::unix_stream(client_end)
        .p2p()
        .build();
    let (server, client) = tokio::join!(server, client);
    Ok((server?, client?))
}

/// Los argumentos en orden, con su sentido cuando lo tienen. En un método el
/// sentido por omisión es `in`; en una señal no hay sentido.
fn arguments(member: roxmltree::Node<'_, '_>, method: bool) -> String {
    member
        .children()
        .filter(|child| child.has_tag_name("arg"))
        .map(|arg| {
            let signature = arg.attribute("type").unwrap_or_default();
            let name = arg
                .attribute("name")
                .map(|n| format!(" {n}"))
                .unwrap_or_default();
            if method {
                let direction = arg.attribute("direction").unwrap_or("in");
                format!("{direction} {signature}{name}")
            } else {
                format!("{signature}{name}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn annotation(node: roxmltree::Node<'_, '_>) -> String {
    format!(
        "annotation {} = {}",
        node.attribute("name").unwrap_or_default(),
        node.attribute("value").unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
  <interface name="org.freedesktop.DBus.Peer">
    <method name="Ping"/>
  </interface>
  <interface name="ar.net.vasak.os.Example">
    <!-- Un comentario que no es parte de la interfaz. -->
    <signal name="Changed">
      <arg name="generation" type="t"/>
    </signal>
    <method name="Get">
      <arg name="id" type="s" direction="in"/>
      <arg type="s" direction="out"/>
    </method>
    <property name="Version" type="u" access="read">
      <annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>
    </property>
    <method name="Add">
      <arg name="a" type="i"/>
      <arg name="b" type="i"/>
    </method>
  </interface>
</node>"#;

    #[test]
    fn la_superficie_lista_firmas_sentidos_propiedades_y_anotaciones() {
        assert_eq!(
            interface_surface(XML, "ar.net.vasak.os.Example").unwrap(),
            "interface ar.net.vasak.os.Example\n\
             \x20 method Add(in i a, in i b)\n\
             \x20 method Get(in s id, out s)\n\
             \x20 signal Changed(t generation)\n\
             \x20 property Version: u read\n\
             \x20   annotation org.freedesktop.DBus.Property.EmitsChangedSignal = const\n"
        );
    }

    /// Los comentarios, el orden de las interfaces y el de los miembros no
    /// cambian nada para un cliente, y la superficie tampoco.
    #[test]
    fn los_comentarios_y_el_orden_no_cambian_la_superficie() {
        let reordered = XML
            .replace("<!-- Un comentario que no es parte de la interfaz. -->", "")
            .replace(
                "  <interface name=\"org.freedesktop.DBus.Peer\">\n    <method name=\"Ping\"/>\n  </interface>\n",
                "",
            );
        assert_eq!(
            interface_surface(&reordered, "ar.net.vasak.os.Example"),
            interface_surface(XML, "ar.net.vasak.os.Example"),
        );
    }

    /// El orden de los argumentos sí es la firma: invertirlos es otra interfaz.
    #[test]
    fn el_orden_de_los_argumentos_si_cuenta() {
        let swapped = XML.replace(
            "<arg name=\"a\" type=\"i\"/>\n      <arg name=\"b\" type=\"i\"/>",
            "<arg name=\"b\" type=\"i\"/>\n      <arg name=\"a\" type=\"i\"/>",
        );
        assert_ne!(
            interface_surface(&swapped, "ar.net.vasak.os.Example"),
            interface_surface(XML, "ar.net.vasak.os.Example"),
        );
    }

    struct Example;

    #[zbus::interface(name = "ar.net.vasak.os.Example")]
    impl Example {
        async fn get(&self, id: &str) -> String {
            id.to_string()
        }
    }

    /// De punta a punta: lo que contesta un objeto publicado por zbus es lo
    /// que se lee, con el `DOCTYPE` incluido.
    #[tokio::test]
    async fn la_superficie_se_lee_de_un_objeto_publicado() {
        let (_server, client) = serve_p2p("/ar/net/vasak/os/Example", Example)
            .await
            .unwrap();
        let xml = introspect(&client, "/ar/net/vasak/os/Example")
            .await
            .unwrap();
        assert_eq!(
            interface_surface(&xml, "ar.net.vasak.os.Example").unwrap(),
            "interface ar.net.vasak.os.Example\n  method Get(in s id, out s)\n"
        );
    }

    #[test]
    fn una_interfaz_que_no_esta_da_nada() {
        assert_eq!(interface_surface(XML, "ar.net.vasak.os.Other"), None);
        assert_eq!(
            interface_surface("no es xml", "ar.net.vasak.os.Example"),
            None
        );
    }
}
