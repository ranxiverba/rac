use crate::{
    line::{LineValid, Line},
    concat::Concat,
};

use generic_array::{GenericArray, typenum::U1};

pub trait Scalar
where
    Self: Line,
{
    const NAME: &'static str;

    fn add_ff(&self, rhs: &Self) -> Self;
    fn mul_ff(&self, rhs: &Self) -> Self;
    fn inv_ff(&self) -> Self;
}

pub type CurveSign = GenericArray<u8, U1>;
pub type CompressedCurve<S> = GenericArray<u8, <Concat<CurveSign, S> as LineValid>::Length>;

pub trait Curve
where
    Self: LineValid,
    Concat<CurveSign, Self::Scalar>: LineValid,
{
    type Scalar: Scalar;

    fn base() -> Self;
    fn mul_ec(&self, rhs: &Self) -> Self;
    fn exp_ec(&self, rhs: &Self::Scalar) -> Self;
    fn decompress(packed: &CompressedCurve<Self::Scalar>) -> Self;
    fn compress(&self) -> CompressedCurve<Self::Scalar>;
}

pub trait Signature
where
    Self: LineValid,
    Concat<CurveSign, Self::Scalar>: LineValid,
{
    type Scalar: Scalar;
    type Curve: Curve<Scalar = Self::Scalar>;

    fn sign(secret_key: &Self::Scalar, message: &Self::Scalar) -> Self;
    fn verify(&self, public_key: &Self::Curve, message: &Self::Scalar) -> Result<(), ()>;
}
