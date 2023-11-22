use serde::{Serialize, Deserialize};

pub type RumeResult<T> = Result<T, RumeError>;


// TODO maybe use thiserror
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RumeError {
    Serialization,
    Database,
    AlreadyExists,
    DoesNotExist,
    Unauthorized,
    CryptoError,
    InvalidOperation,
    InvalidParameters
}

#[derive(Debug)]
pub enum CommandError {
    RumeError(RumeError),
    IoError(std::io::Error),
    Sled(sled::Error),
    Serde(serde_cbor::Error),
    Noise(snow::Error),
    #[cfg(feature = "server")]
    Nothing
}

impl From<std::io::Error> for CommandError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}
impl From<RumeError> for CommandError {
    fn from(value: RumeError) -> Self {
        Self::RumeError(value)
    }
}
impl From<sled::Error> for CommandError {
    fn from(value: sled::Error) -> Self {
        Self::Sled(value)
    }
}
impl From<serde_cbor::Error> for CommandError {
    fn from(value: serde_cbor::Error) -> Self {
        Self::Serde(value)
    }
}

impl From<snow::Error> for CommandError {
    fn from(value: snow::Error) -> Self {
        Self::Noise(value)
    }
}

pub trait ResultUtil {
    type T;
    type E;
    fn trade_ok_with_err(&mut self, e: Self::E) -> Self::T;
    fn trade_ok_with_ok(&mut self, t: Self::T) -> Self::T;
}

impl<T, E: std::fmt::Debug> ResultUtil for Result<T, E> {
    type T = T;
    type E = E;
    fn trade_ok_with_err(&mut self, e: Self::E) -> Self::T {
        let mut f = Err(e);
        std::mem::swap(&mut f, self);
        f.unwrap()
    }
    fn trade_ok_with_ok(&mut self, t: Self::T) -> Self::T {
        let mut f = Ok(t);
        std::mem::swap(&mut f, self);
        f.unwrap()
    }
}