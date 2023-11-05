use crate::symetric::block_ciphers::common::BlockCipher;
use std::ops::Index;

pub trait BlockChaining<T>
where
    T: BlockCipher,  // chaining only applies to block ciphers
    <T as BlockCipher>::BlockType: Copy,  // blocks must be copyable (useful in many situations)
    <<T as BlockCipher>::BlockType as Index<usize>>::Output: Into<u8>,  // values get from index must be convertible to u8 because we use u8 slices
    <<T as BlockCipher>::BlockType as Index<usize>>::Output: Copy  // values get from index must be copy-able to be able to use into()
{
    fn cipher(&self, cipher: &T, plaintext: &[u8], ciphertext: &mut [u8], key: &T::KeyType) -> Result<(), &'static str>;
    fn decipher(&self, cipher: &T, plaintext: &mut [u8], ciphertext: &[u8], key: &T::KeyType) -> Result<(), &'static str>;
}
