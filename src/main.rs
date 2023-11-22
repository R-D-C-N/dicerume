use std::sync::OnceLock;

use snow::params::NoiseParams;

const SECRET: &[u8] = b"THE ROLLER THE WATER DRYER THE CUDDLER THE STRING WORMS";
static PARAMS: OnceLock<NoiseParams> = OnceLock::new();
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


fn init_params() {
    PARAMS.set("Noise_XXpsk3_25519_ChaChaPoly_SHA256".parse().unwrap()).ok();
}

fn main() {
    init_params();
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