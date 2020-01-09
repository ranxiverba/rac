use crate::line::Line;

use generic_array::{GenericArray, ArrayLength};

pub trait Key
where
    Self: Line,
{
    type TagLength: ArrayLength<u8>;

    const NAME: &'static str;

    fn encrypt(
        &self,
        nonce: u64,
        associated_data: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> GenericArray<u8, Self::TagLength>;

    fn decrypt(
        &self,
        nonce: u64,
        associated_data: &[u8],
        input: &[u8],
        output: &mut [u8],
        tag: &GenericArray<u8, Self::TagLength>,
    ) -> Result<(), ()>;
}
