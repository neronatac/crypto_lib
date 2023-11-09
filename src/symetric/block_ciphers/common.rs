//! Shared code between block ciphers

/// Trait implemented by all block ciphers.
///
/// Each block cipher has a `KEY_SIZE` and a `BLOCK_SIZE`. Sizes are expressed as bytes.
/// 2 static methods are available:
/// - `cipher`: encrypts the `plaintext` and put the result in `ciphertext`
/// - `decipher`: decrypts the `ciphertext` and put the result in `plaintext`
///
/// These methods can only treat a single block.
///
pub trait BlockCipher {
    const KEY_SIZE: usize;
    const BLOCK_SIZE: usize;
    fn cipher(plaintext: &[u8; Self::BLOCK_SIZE], ciphertext: &mut [u8;Self::BLOCK_SIZE], key: &[u8; Self::KEY_SIZE]) -> Result<(), &'static str>;
    fn decipher(plaintext: &mut [u8;Self::BLOCK_SIZE], ciphertext: &[u8;Self::BLOCK_SIZE], key: &[u8; Self::KEY_SIZE]) -> Result<(), &'static str>;
}