#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "use_std"), no_std)]

mod line;
pub use self::line::{LineValid, Line};

mod concat;
pub use self::concat::Concat;

mod elliptic;
pub use self::elliptic::{Scalar, Curve, Signature};

mod symmetric;
pub use self::symmetric::Key;

#[cfg(feature = "secp256k1")]
mod secp256k1_m;

#[cfg(feature = "curve25519-dalek")]
mod curve25519_dalek_m;

#[cfg(feature = "chacha20poly1305")]
mod chacha20poly1305_m;
#[cfg(feature = "chacha20poly1305")]
pub use self::chacha20poly1305_m::Chacha20Poly1305AeadKey;

#[cfg(feature = "aes-gcm")]
mod aes_gcm_m;
#[cfg(feature = "aes-gcm")]
pub use self::aes_gcm_m::AesGcmAeadKey;
