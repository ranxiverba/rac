#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "use_std"), no_std)]

mod line;
pub use self::line::{LineValid, Line};

mod concat;
pub use self::concat::Concat;

mod elliptic;
pub use self::elliptic::{Scalar, Curve, Signature};

mod symmetric;
pub use self::symmetric::{Tag, Key};

#[cfg(feature = "secp256k1")]
mod secp256k1_m;

#[cfg(all(feature = "chacha20-poly1305-aead", feature = "use_std"))]
mod chacha20_poly1305_aead_m;
#[cfg(all(feature = "chacha20-poly1305-aead", feature = "use_std"))]
pub use self::chacha20_poly1305_aead_m::{Chacha20Poly1305AeadTag, Chacha20Poly1305AeadKey};
