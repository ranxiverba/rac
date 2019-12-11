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

pub struct PackedCurve<S>
where
    S: Scalar,
{
    sign: bool,
    x: S,
}

impl<S> LineValid for PackedCurve<S>
where
    S: Scalar,
    Concat<GenericArray<u8, U1>, S>: Line,
{
    type Length = <Concat<GenericArray<u8, U1>, S> as LineValid>::Length;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        let Concat(header, x): Concat<GenericArray<u8, U1>, S> = Concat::clone_array(a);
        Ok(PackedCurve {
            sign: header[0] & 1 == 1,
            x: x,
        })
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        let sign = self.sign.clone();
        let x = S::clone_array(&self.x.clone_line());

        let header = GenericArray::clone_from_slice(&[if sign { 0x03 } else { 0x02 }]);
        let concat = Concat::<GenericArray<u8, U1>, S>(header, x);
        concat.clone_line()
    }
}

impl<S> Line for PackedCurve<S>
where
    S: Scalar,
    Concat<GenericArray<u8, U1>, S>: Line,
{
    fn clone_array(a: &GenericArray<u8, Self::Length>) -> Self {
        let Concat(header, x): Concat<GenericArray<u8, U1>, S> = Concat::clone_array(a);
        PackedCurve {
            sign: header[0] & 1 == 1,
            x: x,
        }
    }
}

pub trait Curve
where
    Self: LineValid,
{
    type Scalar: Scalar;

    fn base() -> Self;
    fn mul_ec(&self, rhs: &Self) -> Self;
    fn exp_ec(&self, rhs: &Self::Scalar) -> Self;
    fn decompress(packed: &PackedCurve<Self::Scalar>) -> Self;
    fn compress(&self) -> PackedCurve<Self::Scalar>;
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
