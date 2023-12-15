//! Definition of MD2 algorithm

// see https://www.rfc-editor.org/info/rfc1319

use crate::hash::common::Hash;

pub struct MD2Context {
    state: [u8; 16],
    checksum: [u8; 16]
}

pub struct MD2 {
    context: MD2Context,
    remaining_bytes: [u8; 15],
    remaining_bytes_len: usize
}

impl Hash for MD2 {
    type InitStruct = ();
    type Context = MD2Context;
    const DIGEST_SIZE: usize = 16;

    fn new(_: &Self::InitStruct) -> Self {
        MD2{
            context: MD2Context{state: [0; 16], checksum: [0; 16]},
            remaining_bytes: [0; 15],
            remaining_bytes_len: 0
        }
    }

    fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        let mut offset_in_block = self.remaining_bytes_len;
        let max = data.len();
        let mut cur_block = [0; 16];

        // take remaining bytes from previous uncompleted block
        for i in 0..self.remaining_bytes_len {
            cur_block[i] = self.remaining_bytes[i];
        }

        // process blocks until the end
        while offset < max {
            if 16 - offset_in_block <= max - offset { // entire block
                for i in 0..16 - offset_in_block {
                    cur_block[i+offset_in_block] = data[offset + i];
                }
                offset += 16 - offset_in_block;
                offset_in_block = 0;
                self.remaining_bytes_len = 0;
                process_block(&mut self.context, &cur_block);
            } else { // partial block, save to self.remaining_bytes
                for i in 0..max - offset {
                    self.remaining_bytes[i] = data[offset + i];
                }
                self.remaining_bytes_len = max - offset;
                offset = max;
            }
        }
    }

    fn finalise(&mut self) -> [u8; Self::DIGEST_SIZE] {
        let mut cur_block = [0; 16];

        // take remaining bytes from previous uncompleted block
        for i in 0..self.remaining_bytes_len {
            cur_block[i] = self.remaining_bytes[i];
        }

        // pad
        let pad_len = (16 - self.remaining_bytes_len) as u8;
        cur_block[self.remaining_bytes_len..16].fill(pad_len);

        // process padded block
        process_block(&mut self.context, &cur_block);

        // process checksum block
        let checksum = self.context.checksum;
        process_block(&mut self.context, &checksum);

        // return digest
        self.context.state
    }
}

const PI_SUBST: [u8; 256] = [
41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
31, 26, 219, 153, 141, 51, 159, 17, 131, 20
];

fn process_block(context: &mut MD2Context, block: &[u8; 16]) {
    // encrypt block
    let mut x = [0; 48];
    let mut t = 0;
    for i in 0..16 {
        x[i] = context.state[i];
        x[16+i] = block[i];
        x[32+i] = block[i] ^ context.state[i]
    }
    for i in 0..18 {
        for k in 0..48 {
            t = x[k] ^ PI_SUBST[t as usize];
            x[k] = t;
        }
        t = t.wrapping_add(i);
    }

    // update state
    context.state = x[0..16].try_into().unwrap();

    // update checksum
    let mut l = context.checksum[15];
    for i in 0..16 {
        context.checksum[i] = context.checksum[i] ^ PI_SUBST[(block[i] ^ l) as usize];
        l = context.checksum[i];
    }
}


#[cfg(test)]
mod tests_md2 {
    use super::*;

    #[test]
    fn test_empty() {
        let mut md2 = MD2::new(&());

        let data = [];

        md2.update(&data);

        let res = md2.finalise();
        assert_eq!(res, [0x83, 0x50, 0xe5, 0xa3, 0xe2, 0x4c, 0x15, 0x3d, 0xf2, 0x27, 0x5c, 0x9f, 0x80, 0x69, 0x27, 0x73]);
    }

    #[test]
    fn test_small() {
        let mut md2 = MD2::new(&());

        let data = "abc".as_bytes();

        md2.update(data);

        let res = md2.finalise();
        assert_eq!(res, [0xda, 0x85, 0x3b, 0x0d, 0x3f, 0x88, 0xd9, 0x9b, 0x30, 0x28, 0x3a, 0x69, 0xe6, 0xde, 0xd6, 0xbb]);
    }

    #[test]
    fn test_big() {
        let mut md2 = MD2::new(&());

        let data = "12345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes();

        md2.update(data);

        let res = md2.finalise();
        assert_eq!(res, [0xd5, 0x97, 0x6f, 0x79, 0xd8, 0x3d, 0x3a, 0x0d, 0xc9, 0x80, 0x6c, 0x3c, 0x66, 0xf3, 0xef, 0xd8]);
    }

    #[test]
    fn test_big_splitted() {
        let mut md2 = MD2::new(&());

        let data1 = "1234567".as_bytes();
        let data2 = "890123456789012345678".as_bytes();
        let data3 = "901234567890123456789012345678901234567890123456".as_bytes();
        let data4 = "7890".as_bytes();

        md2.update(data1);
        md2.update(data2);
        md2.update(data3);
        md2.update(data4);

        let res = md2.finalise();
        assert_eq!(res, [0xd5, 0x97, 0x6f, 0x79, 0xd8, 0x3d, 0x3a, 0x0d, 0xc9, 0x80, 0x6c, 0x3c, 0x66, 0xf3, 0xef, 0xd8]);
    }
}
