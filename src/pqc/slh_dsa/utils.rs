/// base_2b: splits a byte sequence into a b-bit sequence
/// See Algorithm 4
pub fn base_2b(x: &[u8], b: usize, out_len: usize) -> Vec<u32> {
    // check params
    let min_len = (out_len * b).div_ceil(8);
    if x.len() < min_len {
        panic!("x is too short");
    }
    if b <= 0 || b > 32 {
        panic!("b must be between 1 and 32");
    }

    let mut baseb = Vec::<u32>::with_capacity(out_len);

    let mut in_ = 0;
    let mut bits = 0;
    let mut total = 0;
    
    for _ in 0..out_len {
        while bits < b {
            total = (total << 8) + x[in_] as u32;
            in_ += 1;
            bits += 8;
        }
        bits -= b;
        baseb.push((total >> bits) % (2u32.pow(b as u32)));
    }

    baseb
}

pub fn to_int(x: &[u8]) -> u128 {
    if x.len() > 8 {
        panic!("x is too long");
    }
    let mut total = 0u128;
    for i in 0..x.len() {
        total = 256 * total + x[i] as u128;
    }
    total
}

pub fn to_byte<T: num_traits::PrimInt>(x: T, n: usize) -> Vec<u8> {
    let mut total = x;
    let mut s = vec![0u8; n];

    let mask = T::from(0xFF).unwrap();
    
    for i in 0..n {
        s[n - 1 - i] = (total & mask).to_u8().unwrap();
        total = total.unsigned_shr(8);
    }
    
    s
}