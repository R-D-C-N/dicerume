use serde::{Deserialize, Serialize};

pub trait SerialDb {
    fn ser_get<K: AsRef<[u8]>, T: for<'de> Deserialize<'de>>(
        &self,
        key: K,
    ) -> Result<Option<T>, sled::Error>;
    fn ser_insert<K: AsRef<[u8]>, T: Serialize>(&self, key: K, t: &T) -> Result<bool, sled::Error>;
}

impl SerialDb for sled::Tree {
    fn ser_insert<K: AsRef<[u8]>, T: Serialize>(&self, key: K, t: &T) -> Result<bool, sled::Error> {
        if let Ok(serialised_bytes) = serde_cbor::to_vec(t) {
            let _insert = self.insert(key, serialised_bytes)?;
            return Ok(true);
        } else {
            return Ok(false);
        }
    }

    fn ser_get<K: AsRef<[u8]>, T: for<'de> Deserialize<'de>>(
        &self,
        key: K,
    ) -> Result<Option<T>, sled::Error> {
        match self.get(key)? {
            Some(v) => Ok(serde_cbor::from_slice(&v).ok()),
            None => Ok(None),
        }
    }
}