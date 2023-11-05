use std::ops::Index;

pub trait BlockCipher {
    type BlockType:
        for<'a> TryFrom<&'a [u8]> +  // BlockType must be created from u8 slices
        for<'a> TryFrom<&'a mut [u8]> +  // idem but mutable
        Index<usize>;  // BlockType must be index-able (useful to copy ciphertext blocks into global ciphertext)
    type KeyType;
    fn block_size() -> usize;
    fn key_size() -> usize;
    fn cipher(&self, plaintext: &Self::BlockType, ciphertext: &mut Self::BlockType, key: &Self::KeyType) -> Result<(), &'static str>;
    fn decipher(&self, plaintext: &mut Self::BlockType, ciphertext: &Self::BlockType, key: &Self::KeyType) -> Result<(), &'static str>;

}