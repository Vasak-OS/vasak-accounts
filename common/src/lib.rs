//! Lo que comparten los dos binarios del espacio de trabajo.
//!
//! El servicio de cuentas (root, bus del sistema) y el sincronizador (la
//! persona, bus de sesión) preguntan lo mismo a `vasak-permissions`: «¿puede
//! este otro proceso usar esto?», con `CheckPermissionFor`. Para eso los dos
//! tienen que nombrar al proceso por su pid **y** su momento de arranque —un
//! pid solo se recicla—, y los dos hablan con el mismo servicio en el mismo
//! bus. Eso vive acá una sola vez: dos copias de la lectura de `/proc` son dos
//! copias que se separan.

pub mod permissions;
pub mod process;
