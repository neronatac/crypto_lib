//! Definition of MD4 algorithm

// see https://www.rfc-editor.org/rfc/rfc1320

use crate::hash::common::{Hash, generic_update_func};

pub struct MD4Context {
    state: [u32; 4],
}

pub struct MD4 {
    context: MD4Context,
    remaining_bytes: [u8; 63],
    remaining_bytes_len: usize,
    msg_length: u64,  // in bits
}

impl Hash for MD4 {
    const DIGEST_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 64;

    type DigestType = [u8; 16];
    type InitStruct = ();
    type Context = MD4Context;

    fn new(_: &Self::InitStruct) -> Self {
        MD4{
            context: MD4Context{
                state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
            },
            remaining_bytes: [0; 63],
            remaining_bytes_len: 0,
            msg_length: 0,
        }
    }

    generic_update_func!((u64));

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
            process_block(&mut self.context, &cur_block);
            cur_block[0..56].fill(0);
        }

        // append msg length
        let len_bytes = self.msg_length.to_le_bytes();
        for i in 0..8 {
            cur_block[56+i] =  len_bytes[i];
        }

        // process padded block
        process_block(&mut self.context, &cur_block);

        // return digest
        let mut ret = [0; 16];
        for i in 0..4 {
            ret[i*4..i*4+4].copy_from_slice(&self.context.state[i].to_le_bytes());
        }
        ret
    }
}


#[inline(always)]
fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

#[inline(always)]
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

#[inline(always)]
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

#[inline(always)]
fn ff(a: u32, b: u32, c: u32, d: u32, k: u8, s: u8, x: &[u32; 16]) -> u32 {
    f(b, c, d)
        .wrapping_add(a)
        .wrapping_add(x[k as usize])
        .rotate_left(s as u32)
}

#[inline(always)]
fn gg(a: u32, b: u32, c: u32, d: u32, k: u8, s: u8, x: &[u32; 16]) -> u32 {
    g(b, c, d)
        .wrapping_add(a)
        .wrapping_add(x[k as usize])
        .wrapping_add(0x5A827999u32)
        .rotate_left(s as u32)
}

#[inline(always)]
fn hh(a: u32, b: u32, c: u32, d: u32, k: u8, s: u8, x: &[u32; 16]) -> u32 {
    h(b, c, d)
        .wrapping_add(a)
        .wrapping_add(x[k as usize])
        .wrapping_add(0x6ED9EBA1u32)
        .rotate_left(s as u32)
}

fn round1(a: u32, b: u32, c: u32, d: u32, x: &[u32; 16]) -> (u32, u32, u32, u32) {
    let mut ret_a = a;
    let mut ret_b = b;
    let mut ret_c = c;
    let mut ret_d = d;
    
    ret_a = ff(ret_a, ret_b, ret_c, ret_d, 0, 3, x);
    ret_d = ff(ret_d, ret_a, ret_b, ret_c, 1, 7, x);
    ret_c = ff(ret_c, ret_d, ret_a, ret_b, 2, 11, x);
    ret_b = ff(ret_b, ret_c, ret_d, ret_a, 3, 19, x);

    ret_a = ff(ret_a, ret_b, ret_c, ret_d, 4, 3, x);
    ret_d = ff(ret_d, ret_a, ret_b, ret_c, 5, 7, x);
    ret_c = ff(ret_c, ret_d, ret_a, ret_b, 6, 11, x);
    ret_b = ff(ret_b, ret_c, ret_d, ret_a, 7, 19, x);

    ret_a = ff(ret_a, ret_b, ret_c, ret_d, 8, 3, x);
    ret_d = ff(ret_d, ret_a, ret_b, ret_c, 9, 7, x);
    ret_c = ff(ret_c, ret_d, ret_a, ret_b, 10, 11, x);
    ret_b = ff(ret_b, ret_c, ret_d, ret_a, 11, 19, x);

    ret_a = ff(ret_a, ret_b, ret_c, ret_d, 12, 3, x);
    ret_d = ff(ret_d, ret_a, ret_b, ret_c, 13, 7, x);
    ret_c = ff(ret_c, ret_d, ret_a, ret_b, 14, 11, x);
    ret_b = ff(ret_b, ret_c, ret_d, ret_a, 15, 19, x);

    (ret_a, ret_b, ret_c, ret_d)
}

fn round2(a: u32, b: u32, c: u32, d: u32, x: &[u32; 16]) -> (u32, u32, u32, u32) {
    let mut ret_a = a;
    let mut ret_b = b;
    let mut ret_c = c;
    let mut ret_d = d;
    
    ret_a = gg(ret_a, ret_b, ret_c, ret_d, 0, 3, x);
    ret_d = gg(ret_d, ret_a, ret_b, ret_c, 4, 5, x);
    ret_c = gg(ret_c, ret_d, ret_a, ret_b, 8, 9, x);
    ret_b = gg(ret_b, ret_c, ret_d, ret_a, 12, 13, x);

    ret_a = gg(ret_a, ret_b, ret_c, ret_d, 1, 3, x);
    ret_d = gg(ret_d, ret_a, ret_b, ret_c, 5, 5, x);
    ret_c = gg(ret_c, ret_d, ret_a, ret_b, 9, 9, x);
    ret_b = gg(ret_b, ret_c, ret_d, ret_a, 13, 13, x);

    ret_a = gg(ret_a, ret_b, ret_c, ret_d, 2, 3, x);
    ret_d = gg(ret_d, ret_a, ret_b, ret_c, 6, 5, x);
    ret_c = gg(ret_c, ret_d, ret_a, ret_b, 10, 9, x);
    ret_b = gg(ret_b, ret_c, ret_d, ret_a, 14, 13, x);

    ret_a = gg(ret_a, ret_b, ret_c, ret_d, 3, 3, x);
    ret_d = gg(ret_d, ret_a, ret_b, ret_c, 7, 5, x);
    ret_c = gg(ret_c, ret_d, ret_a, ret_b, 11, 9, x);
    ret_b = gg(ret_b, ret_c, ret_d, ret_a, 15, 13, x);

    (ret_a, ret_b, ret_c, ret_d)
}

fn round3(a: u32, b: u32, c: u32, d: u32, x: &[u32; 16]) -> (u32, u32, u32, u32) {
    let mut ret_a = a;
    let mut ret_b = b;
    let mut ret_c = c;
    let mut ret_d = d;
    
    ret_a = hh(ret_a, ret_b, ret_c, ret_d, 0, 3, x);
    ret_d = hh(ret_d, ret_a, ret_b, ret_c, 8, 9, x);
    ret_c = hh(ret_c, ret_d, ret_a, ret_b, 4, 11, x);
    ret_b = hh(ret_b, ret_c, ret_d, ret_a, 12, 15, x);

    ret_a = hh(ret_a, ret_b, ret_c, ret_d, 2, 3, x);
    ret_d = hh(ret_d, ret_a, ret_b, ret_c, 10, 9, x);
    ret_c = hh(ret_c, ret_d, ret_a, ret_b, 6, 11, x);
    ret_b = hh(ret_b, ret_c, ret_d, ret_a, 14, 15, x);

    ret_a = hh(ret_a, ret_b, ret_c, ret_d, 1, 3, x);
    ret_d = hh(ret_d, ret_a, ret_b, ret_c, 9, 9, x);
    ret_c = hh(ret_c, ret_d, ret_a, ret_b, 5, 11, x);
    ret_b = hh(ret_b, ret_c, ret_d, ret_a, 13, 15, x);

    ret_a = hh(ret_a, ret_b, ret_c, ret_d, 3, 3, x);
    ret_d = hh(ret_d, ret_a, ret_b, ret_c, 11, 9, x);
    ret_c = hh(ret_c, ret_d, ret_a, ret_b, 7, 11, x);
    ret_b = hh(ret_b, ret_c, ret_d, ret_a, 15, 15, x);

    (ret_a, ret_b, ret_c, ret_d)
}

fn process_block(context: &mut MD4Context, block: &[u8; 64]) {
    // transform block into u32 words
    let mut block32 = [0; 16];
    for i in 0..16 {
        block32[i] = u32::from_le_bytes(block[i*4..i*4+4].try_into().unwrap());
    }
    
    // do rounds
    let mut a = context.state[0];
    let mut b = context.state[1];
    let mut c = context.state[2];
    let mut d = context.state[3];
    (a, b, c, d)  = round1(a, b, c, d, &block32);
    (a, b, c, d)  = round2(a, b, c, d, &block32);
    (a, b, c, d)  = round3(a, b, c, d, &block32);
    
    // do final addition and save context
    context.state[0] = a.wrapping_add(context.state[0]);
    context.state[1] = b.wrapping_add(context.state[1]);
    context.state[2] = c.wrapping_add(context.state[2]);
    context.state[3] = d.wrapping_add(context.state[3]);
}

#[cfg(test)]
mod tests_md4 {
    use super::*;

    #[test]
    fn test_empty() {
        let mut md4 = MD4::new(&());

        let data = [];

        md4.update(&data);

        let res = md4.finalise();
        assert_eq!(res, [0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0]);
    }

    #[test]
    fn test_small() {
        let mut md4 = MD4::new(&());

        let data = "abc".as_bytes();

        md4.update(data);

        let res = md4.finalise();
        assert_eq!(res, [0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52, 0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d]);
    }

    #[test]
    fn test_big() {
        let mut md4 = MD4::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        md4.update(data);

        let res = md4.finalise();
        assert_eq!(res, [0xe3, 0x3b, 0x4d, 0xdc, 0x9c, 0x38, 0xf2, 0x19, 0x9c, 0x3e, 0x7b, 0x16, 0x4f, 0xcc, 0x05, 0x36]);
    }

    #[test]
    fn test_big_splitted() {
        let mut md4 = MD4::new(&());

        let data1 = "1234567".as_bytes();
        let data2 = "890123456789012345678".as_bytes();
        let data3 = "901234567890123456789012345678901234567890123456".as_bytes();
        let data4 = "7890".as_bytes();

        md4.update(data1);
        md4.update(data2);
        md4.update(data3);
        md4.update(data4);

        let res = md4.finalise();
        assert_eq!(res, [0xe3, 0x3b, 0x4d, 0xdc, 0x9c, 0x38, 0xf2, 0x19, 0x9c, 0x3e, 0x7b, 0x16, 0x4f, 0xcc, 0x05, 0x36]);
    }

    #[test]
    fn test_bigbig() {
        let mut md4 = MD4::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        md4.update(data);

        let res = md4.finalise();
        assert_eq!(res, [0x9f, 0x4c, 0x09, 0x13, 0x4d, 0x5d, 0x5f, 0xa9, 0x37, 0xb6, 0x0d, 0xe4, 0xfd, 0x0c, 0xcd, 0x7a]);
    }
}