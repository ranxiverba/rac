use crate::line::Line;

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
