use crate::symetric::block_ciphers::common::BlockCipher;

pub trait BlockChaining<T>
where
    T: BlockCipher,  // chaining only applies to block ciphers
{
    fn cipher(plaintext: &[u8], ciphertext: &mut [u8], key: &[u8; T::KEY_SIZE]) -> Result<(), &'static str>;
    fn decipher(plaintext: &mut [u8], ciphertext: &[u8], key: &[u8; T::KEY_SIZE]) -> Result<(), &'static str>;
}

pub trait BlockChainingWithIV<T>
where
    T: BlockCipher,
{
    fn cipher(plaintext: &[u8], ciphertext: &mut [u8], key: &[u8; T::KEY_SIZE], iv: &[u8; T::BLOCK_SIZE]) -> Result<(), &'static str>;
    fn decipher(plaintext: &mut [u8], ciphertext: &[u8], key: &[u8; T::KEY_SIZE], iv: &[u8; T::BLOCK_SIZE]) -> Result<(), &'static str>;
}
