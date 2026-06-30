use crate::asymmetric::common::AsymmetricCipher;
use num_bigint::BigUint;

pub struct RSA {}

pub struct RSAPublicKey {
    e: BigUint,
    n: BigUint,
}

pub struct RSAPrivateKey {
    d: BigUint,
    n: BigUint,
}

impl AsymmetricCipher for RSA {
    type PrivateKeyType = RSAPrivateKey;
    type PublicKeyType = RSAPublicKey;

    fn sign(plaintext: &[u8], priv_key: &Self::PrivateKeyType) -> Result<Vec<u8>, &'static str> {
        let p = BigUint::from_bytes_be(plaintext);

        let s = p.modpow(&priv_key.d, &priv_key.n);

        Ok(s.to_bytes_be())
    }

    fn verify(signature: &[u8], reference: &[u8], pub_key: &Self::PublicKeyType) -> Result<bool, &'static str> {
        let s = BigUint::from_bytes_be(signature);
        let r = BigUint::from_bytes_be(reference);

        let res = s.modpow(&pub_key.e, &pub_key.n);

        Ok(res == r)
    }
}


#[cfg(test)]
mod tests_rsa {
    use super::*;
    use num_bigint::{ToBigUint};

    #[test]
    fn test_little() {
        let n = 15.to_biguint().unwrap();
        let d = 2.to_biguint().unwrap();
        let priv_key = RSAPrivateKey{d, n};

        let msg = [8];

        let res = RSA::sign(&msg, &priv_key).unwrap();

        let expected = [4];

        assert_eq!(res, expected);
    }
}