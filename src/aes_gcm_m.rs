use super::{LineValid, Line, Key};
use core::fmt;
use generic_array::{
    GenericArray,
    typenum::{U16, U32},
};

#[derive(Eq, PartialEq)]
pub struct AesGcmAeadKey(GenericArray<u8, U32>);

impl fmt::Display for AesGcmAeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for AesGcmAeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AesGcmAeadKey")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl LineValid for AesGcmAeadKey {
    type Length = U32;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        Ok(AesGcmAeadKey(a.clone()))
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        self.0.clone()
    }
}

impl Line for AesGcmAeadKey {
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self {
        AesGcmAeadKey(a.clone())
    }
}

impl Key for AesGcmAeadKey {
    type TagLength = U16;

    const NAME: &'static str = "AESGCM";

    fn encrypt(
        &self,
        nonce: u64,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> GenericArray<u8, Self::TagLength> {
        use byteorder::{ByteOrder, BigEndian};
        use aes_gcm::Aes256Gcm;
        use aes_gcm::aead::{Aead, NewAead};

        let mut nonce_bytes = GenericArray::default();
        BigEndian::write_u64(&mut nonce_bytes[4..], nonce);

        let aead = Aes256Gcm::new(self.0);
        aead.encrypt_in_place_detached(&nonce_bytes, associated_data, buffer)
            .unwrap()
    }

    fn decrypt(
        &self,
        nonce: u64,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagLength>,
    ) -> Result<(), ()> {
        use byteorder::{ByteOrder, BigEndian};
        use aes_gcm::Aes256Gcm;
        use aes_gcm::aead::{Aead, NewAead};

        let mut nonce_bytes = GenericArray::default();
        BigEndian::write_u64(&mut nonce_bytes[4..], nonce);

        let aead = Aes256Gcm::new(self.0);
        aead.decrypt_in_place_detached(&nonce_bytes, associated_data, buffer, &tag)
            .map_err(|_| ())
    }
}
