#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "use_std"), no_std)]

use core::ops::Add;
use generic_array::{GenericArray, ArrayLength, arr::AddLength};

pub trait LineValid
where
    Self: Sized,
{
    type Length: ArrayLength<u8>;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()>;
    fn clone_line(&self) -> GenericArray<u8, Self::Length>;
}

pub trait Line
where
    Self: LineValid,
{
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self;
}

impl<L> LineValid for GenericArray<u8, L>
where
    L: ArrayLength<u8>,
{
    type Length = L;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        Ok(a.clone())
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        self.clone()
    }
}

impl<L> Line for GenericArray<u8, L>
where
    L: ArrayLength<u8>,
{
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self {
        a.clone()
    }
}

pub struct Concat<U, V>(pub U, pub V)
where
    U: LineValid,
    V: LineValid;

impl<U, V> LineValid for Concat<U, V>
where
    U: LineValid,
    V: LineValid,
    U::Length: Add<V::Length>,
    <U::Length as Add<V::Length>>::Output: ArrayLength<u8>,
{
    type Length = <U::Length as AddLength<u8, V::Length>>::Output;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        use generic_array::typenum::marker_traits::Unsigned;

        let u_length = U::Length::to_usize();
        let v_length = V::Length::to_usize();

        let u_slice = &a[0..u_length];
        let v_slice = &a[u_length..(v_length + u_length)];

        let u = U::try_clone_array(GenericArray::from_slice(u_slice))?;
        let v = V::try_clone_array(GenericArray::from_slice(v_slice))?;

        Ok(Concat(u, v))
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        use generic_array::typenum::marker_traits::Unsigned;

        let u_length = U::Length::to_usize();
        let v_length = V::Length::to_usize();

        let u_array = self.0.clone_line();
        let v_array = self.1.clone_line();

        let mut r = GenericArray::default();
        r.as_mut()[0..u_length].clone_from_slice(u_array.as_ref());
        r.as_mut()[u_length..(v_length + u_length)].clone_from_slice(v_array.as_ref());

        r
    }
}

impl<U, V> Line for Concat<U, V>
where
    U: Line,
    V: Line,
    U::Length: Add<V::Length>,
    <U::Length as Add<V::Length>>::Output: ArrayLength<u8>,
{
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self {
        use generic_array::typenum::marker_traits::Unsigned;

        let u_length = U::Length::to_usize();
        let v_length = V::Length::to_usize();

        let u_slice = &a[0..u_length];
        let v_slice = &a[u_length..(v_length + u_length)];

        let u = U::clone_array(GenericArray::from_slice(u_slice));
        let v = V::clone_array(GenericArray::from_slice(v_slice));

        Concat(u, v)
    }
}

pub trait Scalar
where
    Self: Line,
{
    const NAME: &'static str;

    fn add_ff(&self, rhs: &Self) -> Self;
    fn mul_ff(&self, rhs: &Self) -> Self;
    fn inv_ff(&self) -> Self;
}

pub trait Curve
where
    Self: LineValid,
{
    type Scalar: Scalar;

    fn base() -> Self;
    fn mul_ec(&self, rhs: &Self) -> Self;
    fn exp_ec(&self, rhs: &Self::Scalar) -> Self;
    fn compress(&self) -> (bool, Self::Scalar);
}

pub trait Signature
where
    Self: LineValid,
{
    type Scalar: Scalar;
    type Curve: Curve<Scalar = Self::Scalar>;

    fn sign(secret_key: &Self::Scalar, message: &Self::Scalar) -> Self;
    fn verify(&self, public_key: &Self::Curve, message: &Self::Scalar) -> Result<(), ()>;
}

pub trait Tag
where
    Self: Line,
{
}

pub trait Key
where
    Self: Line,
{
    type Tag: Tag;

    const NAME: &'static str;

    fn encrypt(
        &self,
        nonce: u64,
        associated_data: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Self::Tag;

    fn decrypt(
        &self,
        nonce: u64,
        associated_data: &[u8],
        input: &[u8],
        output: &mut [u8],
        tag: Self::Tag,
    ) -> Result<(), ()>;
}

#[cfg(feature = "secp256k1")]
mod secp256k1_m {
    use super::{LineValid, Line, Scalar, Curve, Signature};
    use generic_array::{
        GenericArray,
        typenum::{U32, U64},
    };
    use secp256k1::{SecretKey, PublicKey, Signature as Secp256k1Signature};

    impl LineValid for SecretKey {
        type Length = U32;

        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            SecretKey::from_slice(a.as_slice()).map_err(|_| ())
        }

        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            GenericArray::from_slice(&self[..]).clone()
        }
    }

    impl Line for SecretKey {
        fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self {
            Self::try_clone_array(a).unwrap()
        }
    }

    impl Scalar for SecretKey {
        const NAME: &'static str = "secp256k1";

        fn add_ff(&self, rhs: &Self) -> Self {
            let mut c = self.clone();
            c.add_assign(rhs.clone_line().as_slice()).unwrap();
            c
        }

        fn mul_ff(&self, rhs: &Self) -> Self {
            let mut c = self.clone();
            c.mul_assign(rhs.clone_line().as_slice()).unwrap();
            c
        }

        fn inv_ff(&self) -> Self {
            unimplemented!()
        }
    }

    impl LineValid for PublicKey {
        type Length = U64;

        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            let mut buffer = [0; 65];
            buffer[0] = 4;
            buffer[1..].clone_from_slice(a.as_slice());
            PublicKey::from_slice(buffer.as_ref()).map_err(|_| ())
        }

        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            let mut a = GenericArray::default();
            a.clone_from_slice(&self.serialize_uncompressed()[1..]);
            a
        }
    }

    impl Curve for PublicKey {
        type Scalar = SecretKey;

        fn base() -> Self {
            let buffer = [
                0x04,
                0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
                0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
                0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
                0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
                0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
                0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
                0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
                0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
            ];
            PublicKey::from_slice(buffer.as_ref()).unwrap()
        }

        fn mul_ec(&self, rhs: &Self) -> Self {
            let _ = rhs;
            unimplemented!()
        }

        fn exp_ec(&self, rhs: &Self::Scalar) -> Self {
            use secp256k1::Secp256k1;

            let context = Secp256k1::verification_only();
            let mut c = self.clone();
            c.mul_assign(&context, rhs.clone_line().as_slice()).unwrap();
            c
        }

        fn compress(&self) -> (bool, Self::Scalar) {
            let buffer = self.serialize();
            let mut a = GenericArray::default();
            a.clone_from_slice(&buffer[1..]);
            (buffer[0] & 1 == 1, Self::Scalar::clone_array(&a))
        }
    }

    impl LineValid for Secp256k1Signature {
        type Length = U64;

        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            Secp256k1Signature::from_compact(a.as_slice()).map_err(|_| ())
        }

        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            let mut a = GenericArray::default();
            a.clone_from_slice(self.serialize_compact().as_ref());
            a
        }
    }

    impl Signature for Secp256k1Signature {
        type Scalar = SecretKey;
        type Curve = PublicKey;

        fn sign(secret_key: &Self::Scalar, message: &Self::Scalar) -> Self {
            use secp256k1::{Secp256k1, Message};

            let context = Secp256k1::signing_only();
            let m = Message::from_slice(message.clone_line().as_slice()).unwrap();
            context.sign(&m, &secret_key)
        }

        fn verify(&self, public_key: &Self::Curve, message: &Self::Scalar) -> Result<(), ()> {
            use secp256k1::{Secp256k1, Message};

            let context = Secp256k1::verification_only();
            let m = Message::from_slice(message.clone_line().as_slice()).unwrap();
            context.verify(&m, self, public_key).map_err(|_| ())
        }
    }
}

#[cfg(all(feature = "chacha20-poly1305-aead", feature = "use_std"))]
mod chacha20_poly1305_aead_m {
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
}
