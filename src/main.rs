#[cfg(feature="client")]
mod client;
#[cfg(feature="server")]
mod server;
mod handshake;
pub(crate) mod db;
pub(crate) mod error;
pub(crate) mod dice;
pub(crate) mod shared;
pub(crate) mod base64;

fn main() {
    if cfg!(feature = "server") {
        init_server();
    } else if cfg!(feature = "client") {
        init_client();
    } else {
        panic!("No features enabled");
    }
}

fn init_server() {
    #[cfg(feature = "server")]
    {
        server::init_cred();
        server::init_server().unwrap();
    }
}
fn init_client() {
    #[cfg(feature = "client")]
    {
        client::init_client().unwrap();
    }
}