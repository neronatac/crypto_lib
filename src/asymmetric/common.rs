//! Shared code between asymmetric ciphers

/// Trait implemented by all asymmetric ciphers.
///
/// 2 static methods are available:
/// - `sign`: encrypts the `plaintext` and puts the result in `signature`
/// - `verify`: decrypts the `signature` and compares the result to `reference`

pub trait AsymmetricCipher {
    type PrivateKeyType;
    type PublicKeyType;
    
    fn sign(plaintext: &[u8], priv_key: &Self::PrivateKeyType) -> Result<Vec<u8>, &'static str>;
    fn verify(signature: &[u8], reference: &[u8], pub_key: &Self::PublicKeyType) -> Result<bool, &'static str>;
}