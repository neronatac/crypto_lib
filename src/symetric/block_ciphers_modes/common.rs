//! Shared code between chaining modes

use crate::symetric::block_ciphers::common::BlockCipher;

/// Trait implemented by chaining modes that do not need an IV or anything else.
pub trait BlockChaining<T>
where
    T: BlockCipher,  // chaining only applies to block ciphers
{
    fn cipher(plaintext: &[u8], ciphertext: &mut [u8], key: &[u8; T::KEY_SIZE]) -> Result<(), &'static str>;
    fn decipher(plaintext: &mut [u8], ciphertext: &[u8], key: &[u8; T::KEY_SIZE]) -> Result<(), &'static str>;
}

/// Trait implemented by chaining modes that need an IV.
pub trait BlockChainingWithIV<T>
where
    T: BlockCipher,
{
    fn cipher(plaintext: &[u8], ciphertext: &mut [u8], key: &[u8; T::KEY_SIZE], iv: &[u8; T::BLOCK_SIZE]) -> Result<(), &'static str>;
    fn decipher(plaintext: &mut [u8], ciphertext: &[u8], key: &[u8; T::KEY_SIZE], iv: &[u8; T::BLOCK_SIZE]) -> Result<(), &'static str>;
}
