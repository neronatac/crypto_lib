use crate::symetric::block_ciphers_modes::common::BlockChaining;
use crate::symetric::block_ciphers::common::BlockCipher;
use std::ops::Index;

pub struct CBC<T: BlockCipher>
{
    iv: T::BlockType
}

impl<T> BlockChaining<T> for CBC<T>
where
    T: BlockCipher,
    <T as BlockCipher>::BlockType: Copy,
    <<T as BlockCipher>::BlockType as Index<usize>>::Output: Into<u8>,
    <<T as BlockCipher>::BlockType as Index<usize>>::Output: Copy
{
    fn cipher(&self, cipher: &T, plaintext: &[u8], ciphertext: &mut [u8], key: &T::KeyType) -> Result<(), &'static str> {
        let bs = T::block_size();
        let mut last_cipher = self.iv;

        // check parameters
        if plaintext.len() != ciphertext.len() {
            return Err("Plaintext and ciphertext must have the same length");
        } else if plaintext.len() % bs != 0 {
            return Err("Length of plain/ciphertext is not a multiple of block size")
        }

        // do the chain
        let mut i = 0;
        while i < plaintext.len() {
            let mut xored = vec![0; bs];
            // XOR plaintext and last ciphertext (or IV)
            for j in 0..bs {
                xored[j] = plaintext[i+j] ^ last_cipher[j].into();
            }

            let chunk_p = match xored.as_slice().try_into() {
                Ok(v) => {v}
                Err(_) => {return Err("Error during CBC chaining");}
            };
            let mut chunk_c = match ciphertext[i..i + bs].try_into() {
                Ok(v) => {v}
                Err(_) => {return Err("Error during CBC chaining");}
            };

            match cipher.cipher(&chunk_p, &mut chunk_c, key) {
                Ok(_) => {
                    for j in 0..bs {
                        ciphertext[i+j] = chunk_c[j].into();
                    }
                    last_cipher = chunk_c;
                }
                Err(e) => {return Err(e);}
            }
            i += bs;
        }

        return Ok(());
    }

    fn decipher(&self, cipher: &T, plaintext: &mut [u8], ciphertext: &[u8], key: &T::KeyType) -> Result<(), &'static str> {
        let bs = T::block_size();
        let mut last_cipher = self.iv;

        // check parameters
        if plaintext.len() != ciphertext.len() {
            return Err("Plaintext and ciphertext must have the same length");
        } else if plaintext.len() % bs != 0 {
            return Err("Length of plain/ciphertext is not a multiple of block size")
        }

        // do the chain
        let mut i = 0;
        while i < plaintext.len() {
            let mut chunk_p = match plaintext[i..i + bs].try_into() {
                Ok(v) => {v}
                Err(_) => {return Err("Error during ECB chaining");}
            };
            let chunk_c = match ciphertext[i..i + bs].try_into() {
                Ok(v) => {v}
                Err(_) => {return Err("Error during ECB chaining");}
            };
            match cipher.decipher(&mut chunk_p, &chunk_c, key) {
                Ok(_) => {
                    for j in 0..bs {
                        plaintext[i+j] = chunk_p[j].into() ^ last_cipher[j].into();
                    }
                    last_cipher = chunk_c;
                }
                Err(e) => {return Err(e);}
            }
            i += bs;
        }

        return Ok(());
    }
}

#[cfg(test)]
mod tests_cbc {
    use crate::symetric::block_ciphers::aes::AES128;
    use super::*;

    #[test]
    fn cbc_encrypt_2_blocks() {
        let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
            0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let mut ciphertext = [0;32];
        let expected = [0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D,
            0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2];
        let cbc = CBC{ iv };
        cbc.cipher(&AES128{}, &plain, &mut ciphertext, &key).expect("Error during CBC_AES128 execution");
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn cbc_encrypt_1_block() {
        let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let mut ciphertext = [0;16];
        let expected = [0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D];
        let cbc = CBC{ iv };
        cbc.cipher(&AES128{}, &plain, &mut ciphertext, &key).expect("Error during CBC_AES128 execution");
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn cbc_encrypt_bad_length() {
        let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let mut ciphertext = [0;15];
        let cbc = CBC{ iv };
        let res = cbc.cipher(&AES128{}, &plain, &mut ciphertext, &key);
        assert!(res.is_err());
    }

    #[test]
    fn cbc_encrypt_bad_length2() {
        let plain = [0x6B, 0xC1, 0xBE];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let mut ciphertext = [0;16];
        let cbc = CBC{ iv };
        let res = cbc.cipher(&AES128{}, &plain, &mut ciphertext, &key);
        assert!(res.is_err());
    }

    #[test]
    fn cbc_encrypt_bad_block_length() {
        let plain = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let mut ciphertext = [0;15];
        let cbc = CBC{ iv };
        let res = cbc.cipher(&AES128{}, &plain, &mut ciphertext, &key);
        assert!(res.is_err());
    }

    #[test]
    fn cbc_decrypt_2_blocks() {
        let mut plain = [0;32];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let ciphertext = [0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D,
            0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2];
        let expected = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
            0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51];
        let cbc = CBC{ iv };
        cbc.decipher(&AES128{}, &mut plain, &ciphertext, &key).expect("Error during CBC_AES128 execution");
        assert_eq!(plain, expected);
    }

    #[test]
    fn cbc_decrypt_1_block() {
        let mut plain = [0;16];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let ciphertext = [0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D];
        let expected = [0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A];
        let cbc = CBC{ iv };
        cbc.decipher(&AES128{}, &mut plain, &ciphertext, &key).expect("Error during CBC_AES128 execution");
        assert_eq!(plain, expected);
    }

    #[test]
    fn cbc_decrypt_bad_length() {
        let mut plain = [0;16];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let ciphertext = [0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19];
        let cbc = CBC{ iv };
        let res = cbc.decipher(&AES128{}, &mut plain, &ciphertext, &key);
        assert!(res.is_err());
    }

    #[test]
    fn cbc_decrypt_bad_length2() {
        let mut plain = [0;3];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let ciphertext = [0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D];
        let cbc = CBC{ iv };
        let res = cbc.decipher(&AES128{}, &mut plain, &ciphertext, &key);
        assert!(res.is_err());
    }

    #[test]
    fn cbc_decrypt_bad_block_length() {
        let mut plain = [0;15];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let ciphertext = [0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19];
        let cbc = CBC{ iv };
        let res = cbc.decipher(&AES128{}, &mut plain, &ciphertext, &key);
        assert!(res.is_err());
    }
}