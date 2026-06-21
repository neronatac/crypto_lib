//! Definition of SHA algorithms

// see FIPS 180, RFC3174

use paste::paste;
use crate::hash::common::{generic_update_func, Hash};


fn sha0_expansion(w: &mut [u32; 80]) {
    for t in 16..80 {
        w[t] = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
    }
}


fn sha1_expansion(w: &mut [u32; 80]) {
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }
}


macro_rules! create_sha {
    (0) => {create_sha!(@internal 0);};
    (1) => {create_sha!(@internal 1);};

    (@internal $sha_number:literal) => {
        paste! {
            pub struct [< SHA $sha_number Context>] {
                state: [u32; 5],
            }

            pub struct [< SHA $sha_number>] {
                context: [< SHA $sha_number Context>],
                remaining_bytes: [u8; 63],
                remaining_bytes_len: usize,
                msg_length: u64 // in bits
            }

            impl Hash for [< SHA $sha_number>] {
                const DIGEST_SIZE: usize = 20;
                const BLOCK_SIZE: usize = 64;

                type DigestType = [u8; 20];
                type InitStruct = ();
                type Context = [< SHA $sha_number Context>];

                fn new(_: &Self::InitStruct) -> Self {
                    [< SHA $sha_number>] {
                        context: Self::Context {
                            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
                        },
                        remaining_bytes: [0; 63],
                        remaining_bytes_len: 0,
                        msg_length: 0,
                    }
                }

                generic_update_func!([< process_block_sha $sha_number>] u64);

                fn finalise(&mut self) -> Self::DigestType {
                    let mut cur_block = [0; 64];

                    // take remaining bytes from the previous uncompleted block
                    for i in 0..self.remaining_bytes_len {
                        cur_block[i] = self.remaining_bytes[i];
                    }

                    // pad
                    cur_block[self.remaining_bytes_len] = 0x80;
                    if self.remaining_bytes_len >= 56 {
                        // more than 448 bits, must fill this bock and create another
                        // nothing to do when less than 448 are filled as block is initialized with zeroes
                        cur_block[self.remaining_bytes_len] = 0x80;
                        [< process_block_sha $sha_number>](&mut self.context, &cur_block);
                        cur_block[0..56].fill(0);
                    }

                    // append msg length
                    let len_bytes = self.msg_length.to_be_bytes();
                    for i in 0..8 {
                        cur_block[56 + i] = len_bytes[i];
                    }

                    // process padded block
                    [< process_block_sha $sha_number>](&mut self.context, &cur_block);

                    // return digest
                    let mut ret = [0; 20];
                    for i in 0..5 {
                        ret[i * 4..i * 4 + 4].copy_from_slice(&self.context.state[i].to_be_bytes());
                    }
                    ret
                }
            }

            fn [< process_block_sha $sha_number >](context: &mut [< SHA $sha_number Context>], block: &[u8; 64]) {
                // transform block into u32 words
                let mut w = [0; 80];
                for i in 0..16 {
                    w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
                }

                // expand until w[79]
                [< sha $sha_number _expansion>](&mut w);

                // get A..E
                let mut a = context.state[0];
                let mut b = context.state[1];
                let mut c = context.state[2];
                let mut d = context.state[3];
                let mut e = context.state[4];

                // do rounds
                for t in 0..80 {
                    let tmp = a
                        .rotate_left(5)
                        .wrapping_add(match t {
                            0..=19 => (b & c) | (!b & d),
                            20..=39 => b ^ c ^ d,
                            40..=59 => (b & c) | (b & d) | (c & d),
                            60..=79 => b ^ c ^ d,
                            _ => unreachable!(),
                        })
                        .wrapping_add(e)
                        .wrapping_add(w[t])
                        .wrapping_add(match t {
                            0..=19 => 0x5A827999,
                            20..=39 => 0x6ED9EBA1,
                            40..=59 => 0x8F1BBCDC,
                            60..=79 => 0xCA62C1D6,
                            _ => unreachable!(),
                        });
                    e = d;
                    d = c;
                    c = b.rotate_left(30);
                    b = a;
                    a = tmp;
                }

                // final addition
                context.state[0] = context.state[0].wrapping_add(a);
                context.state[1] = context.state[1].wrapping_add(b);
                context.state[2] = context.state[2].wrapping_add(c);
                context.state[3] = context.state[3].wrapping_add(d);
                context.state[4] = context.state[4].wrapping_add(e);
            }
        }
    };
}

create_sha!(0);
create_sha!(1);


#[cfg(test)]
mod tests_sha0 {
    use super::*;

    #[test]
    fn test_abc() {
        let mut sha0 = SHA0::new(&());

        let data = "abc".as_bytes();

        sha0.update(&data);

        let res = sha0.finalise();
        assert_eq!(res, [0x01, 0x64, 0xB8, 0xA9, 0x14, 0xCD, 0x2A, 0x5E, 0x74, 0xC4, 0xF7, 0xFF, 0x08, 0x2C, 0x4D, 0x97, 0xF1, 0xED, 0xF8, 0x80]);
    }

    #[test]
    fn test_padding_two_blocs() {
        let mut sha0 = SHA0::new(&());

        let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();

        sha0.update(&data);

        let res = sha0.finalise();
        assert_eq!(res, [0xD2, 0x51, 0x6E, 0xE1, 0xAC, 0xFA, 0x5B, 0xAF, 0x33, 0xDF, 0xC1, 0xC4, 0x71, 0xE4, 0x38, 0x44, 0x9E, 0xF1, 0x34, 0xC8]);
    }

    #[test]
    fn test_big() {
        let mut sha0 = SHA0::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        sha0.update(&data);

        let res = sha0.finalise();
        assert_eq!(res, [0x4a, 0xa2, 0x9d, 0x14, 0xd1, 0x71, 0x52, 0x2e, 0xce, 0x47, 0xbe, 0xe8, 0x95, 0x7e, 0x35, 0xa4, 0x1f, 0x3e, 0x9c, 0xff]);
    }

    #[test]
    fn test_big_splitted() {
        let mut sha0 = SHA0::new(&());

        let data1 = "1234567".as_bytes();
        let data2 = "890123456789012345678".as_bytes();
        let data3 = "901234567890123456789012345678901234567890123456".as_bytes();
        let data4 = "7890".as_bytes();

        sha0.update(data1);
        sha0.update(data2);
        sha0.update(data3);
        sha0.update(data4);

        let res = sha0.finalise();
        assert_eq!(res, [0x4a, 0xa2, 0x9d, 0x14, 0xd1, 0x71, 0x52, 0x2e, 0xce, 0x47, 0xbe, 0xe8, 0x95, 0x7e, 0x35, 0xa4, 0x1f, 0x3e, 0x9c, 0xff]);
    }

    #[test]
    fn test_bigbig() {
        let mut sha0 = SHA0::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        sha0.update(&data);

        let res = sha0.finalise();
        assert_eq!(res, [0xbc, 0xbe, 0xd6, 0xdd, 0x21, 0x56, 0xbf, 0x13, 0x5d, 0x42, 0x19, 0x81, 0x24, 0x9a, 0xcd, 0xd3, 0xc9, 0x73, 0x4d, 0x1f]);
    }
}

#[cfg(test)]
mod tests_sha1 {
    use super::*;

    #[test]
    fn test_abc() {
        let mut sha1 = SHA1::new(&());

        let data = "abc".as_bytes();

        sha1.update(&data);

        let res = sha1.finalise();
        assert_eq!(res, [0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D]);
    }

    #[test]
    fn test_padding_two_blocs() {
        let mut sha1 = SHA1::new(&());

        let data = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();

        sha1.update(&data);

        let res = sha1.finalise();
        assert_eq!(res, [0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1]);
    }

    #[test]
    fn test_big() {
        let mut sha1 = SHA1::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        sha1.update(&data);

        let res = sha1.finalise();
        assert_eq!(res, [0x50, 0xab, 0xf5, 0x70, 0x6a, 0x15, 0x09, 0x90, 0xa0, 0x8b, 0x2c, 0x5e, 0xa4, 0x0f, 0xa0, 0xe5, 0x85, 0x55, 0x47, 0x32]);
    }

    #[test]
    fn test_big_splitted() {
        let mut sha1 = SHA1::new(&());

        let data1 = "1234567".as_bytes();
        let data2 = "890123456789012345678".as_bytes();
        let data3 = "901234567890123456789012345678901234567890123456".as_bytes();
        let data4 = "7890".as_bytes();

        sha1.update(data1);
        sha1.update(data2);
        sha1.update(data3);
        sha1.update(data4);

        let res = sha1.finalise();
        assert_eq!(res, [0x50, 0xab, 0xf5, 0x70, 0x6a, 0x15, 0x09, 0x90, 0xa0, 0x8b, 0x2c, 0x5e, 0xa4, 0x0f, 0xa0, 0xe5, 0x85, 0x55, 0x47, 0x32]);
    }

    #[test]
    fn test_bigbig() {
        let mut sha1 = SHA1::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        sha1.update(&data);

        let res = sha1.finalise();
        assert_eq!(res, [0x9a, 0xb9, 0xa9, 0x73, 0xce, 0x40, 0x3f, 0x31, 0xfe, 0x04, 0x15, 0x42, 0x1d, 0xc3, 0x60, 0x8d, 0xf7, 0x24, 0x61, 0x3c]);
    }
}
