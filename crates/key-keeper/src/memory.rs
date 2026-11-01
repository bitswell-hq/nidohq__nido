use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use ed25519_dalek::SigningKey;

use crate::{ed25519, KeyId, KeyKeeper, Payload, SignError, Signature};

/// An in-process [`KeyKeeper`] over Ed25519 keys, for unit tests of the
/// components that call a keeper.
///
/// It records every `sign` call it receives, including refused ones, so a
/// test can assert which requests reached the keeper (for example, that a
/// request the grant check denied never did).
#[derive(Default)]
pub struct MemoryKeyKeeper {
    keys: BTreeMap<KeyId, SigningKey>,
    requests: Mutex<Vec<(KeyId, Payload)>>,
}

impl MemoryKeyKeeper {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add (or replace) the key `id` with the Ed25519 secret `seed`, returning
    /// its public key.
    pub fn insert(&mut self, id: KeyId, seed: [u8; 32]) -> [u8; 32] {
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        self.keys.insert(id, key);
        public
    }

    /// The public key of `id`, if the keeper holds it.
    #[must_use]
    pub fn public_key(&self, id: &KeyId) -> Option<[u8; 32]> {
        self.keys.get(id).map(|k| k.verifying_key().to_bytes())
    }

    /// Every `(key, payload)` passed to [`KeyKeeper::sign`], in call order.
    ///
    /// # Panics
    ///
    /// If a thread panicked while recording a request.
    #[must_use]
    pub fn requests(&self) -> Vec<(KeyId, Payload)> {
        self.requests.lock().expect("request log poisoned").clone()
    }
}

impl KeyKeeper for MemoryKeyKeeper {
    fn sign(&self, key: &KeyId, payload: &Payload) -> Result<Signature, SignError> {
        self.requests
            .lock()
            .expect("request log poisoned")
            .push((key.clone(), payload.clone()));
        let signing_key = self
            .keys
            .get(key)
            .ok_or_else(|| SignError::UnknownKey(key.clone()))?;
        Ok(Signature(ed25519::sign(signing_key, payload)?.to_vec()))
    }
}

impl fmt::Debug for MemoryKeyKeeper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryKeyKeeper")
            .field("keys", &self.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}
