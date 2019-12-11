use super::{LineValid, Line, Tag, Key};
use core::fmt;
use generic_array::{
    GenericArray,
    typenum::{U16, U32},
};

#[derive(Eq, PartialEq)]
pub struct Chacha20Poly1305AeadTag(GenericArray<u8, U16>);

impl fmt::Display for Chacha20Poly1305AeadTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Chacha20Poly1305AeadTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Chacha20Poly1305AeadTag")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl LineValid for Chacha20Poly1305AeadTag {
    type Length = U16;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        Ok(Chacha20Poly1305AeadTag(a.clone()))
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        self.0.clone()
    }
}

impl Line for Chacha20Poly1305AeadTag {
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self {
        Chacha20Poly1305AeadTag(a.clone())
    }
}

impl Tag for Chacha20Poly1305AeadTag {}

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
    type Tag = Chacha20Poly1305AeadTag;

    const NAME: &'static str = "ChaChaPoly";

    fn encrypt(
        &self,
        nonce: u64,
        associated_data: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Self::Tag {
        use std::io::Cursor;
        use byteorder::{ByteOrder, LittleEndian};
        use chacha20_poly1305_aead::encrypt;

        let mut nonce_bytes = [0; 12];
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);

        let mut output = Cursor::new(output.as_mut());
        // safe to unwrap, because write to slice never fails
        let array = encrypt(
            self.0.as_slice(),
            nonce_bytes.as_ref(),
            associated_data,
            input,
            &mut output,
        )
        .unwrap();

        Chacha20Poly1305AeadTag::clone_array(GenericArray::from_slice(array.as_ref()))
    }

    fn decrypt(
        &self,
        nonce: u64,
        associated_data: &[u8],
        input: &[u8],
        output: &mut [u8],
        tag: Self::Tag,
    ) -> Result<(), ()> {
        use std::io::Cursor;
        use byteorder::{ByteOrder, LittleEndian};
        use chacha20_poly1305_aead::{decrypt, DecryptError};

        let mut nonce_bytes = [0; 12];
        LittleEndian::write_u64(&mut nonce_bytes[4..], nonce);

        let mut output = Cursor::new(output.as_mut());
        decrypt(
            self.0.as_slice(),
            nonce_bytes.as_ref(),
            associated_data,
            input,
            tag.0.as_ref(),
            &mut output,
        )
        .map_err(|e| match e {
            DecryptError::TagMismatch => (),
            DecryptError::IoError(_e) => unreachable!(),
        })
    }
}
