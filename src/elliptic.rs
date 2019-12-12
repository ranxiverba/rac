use crate::line::{LineValid, Line};

use generic_array::{GenericArray, ArrayLength};

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
    type CompressedLength: ArrayLength<u8>;

    fn base() -> Self;
    fn mul_ec(&self, rhs: &Self) -> Self;
    fn exp_ec(&self, rhs: &Self::Scalar) -> Self;
    fn decompress(packed: &GenericArray<u8, Self::CompressedLength>) -> Self;
    fn compress(&self) -> GenericArray<u8, Self::CompressedLength>;
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
