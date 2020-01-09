use super::{LineValid, Line, Key};
use core::fmt;
use generic_array::{
    GenericArray,
    typenum::{U16, U32},
};

#[derive(Eq, PartialEq)]
pub struct Chacha20Poly1305AeadKey(GenericArray<u8, U32>);

impl fmt::Display for Chacha20Poly1305AeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Chacha20Poly1305AeadKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Chacha20Poly1305AeadKey")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl LineValid for Chacha20Poly1305AeadKey {
    type Length = U32;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        Ok(Chacha20Poly1305AeadKey(a.clone()))
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        self.0.clone()
    }
}

impl Line for Chacha20Poly1305AeadKey {
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self {
        Chacha20Poly1305AeadKey(a.clone())
    }
}

impl Key for Chacha20Poly1305AeadKey {
    type TagLength = U16;

    const NAME: &'static str = "ChaChaPoly";

    fn encrypt(
        &self,
        nonce: u64,
        associated_data: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> GenericArray<u8, Self::TagLength> {
        use byteorder::{ByteOrder, LittleEndian};
        use chacha20poly1305::ChaCha20Poly1305;
        use chacha20poly1305::aead::{Aead, NewAead};

        let mut nonce_bytes = GenericArray::default();
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);

        let aead = ChaCha20Poly1305::new(self.0);
        output.clone_from_slice(input);
        aead.encrypt_in_place_detached(
            &nonce_bytes,
            associated_data,
            output.as_mut(),
        ).unwrap()
    }

    fn decrypt(
        &self,
        nonce: u64,
        associated_data: &[u8],
        input: &[u8],
        output: &mut [u8],
        tag: &GenericArray<u8, Self::TagLength>,
    ) -> Result<(), ()> {
        use byteorder::{ByteOrder, LittleEndian};
        use chacha20poly1305::ChaCha20Poly1305;
        use chacha20poly1305::aead::{Aead, NewAead};

        let mut nonce_bytes = GenericArray::default();
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);

        let aead = ChaCha20Poly1305::new(self.0);
        output.clone_from_slice(input);
        aead.decrypt_in_place_detached(
            &nonce_bytes,
            associated_data,
            output.as_mut(),
            &tag,
        ).map_err(|_| ())
    }
}
