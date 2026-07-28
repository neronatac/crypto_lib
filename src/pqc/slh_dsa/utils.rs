/// base_2b: splits a byte sequence into a b-bit sequence
/// See Algorithm 4
pub fn base_2b(x: &[u8], b: usize, out_len: usize) -> Vec<u32> {
    // check params
    let min_len = ((out_len * b) as f32 / 8f32).ceil() as usize;
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
    
    for out in 0..out_len {
        while bits < b {
            total = (total << 8) + x[out] as u32;
            in_ += 1;
            bits += 8;
        }
        bits -= b;
        baseb.push((total >> bits) % (2u32.pow(b as u32)));
    }

    baseb
}

pub fn to_byte<T: num_traits::ToBytes>(x: T, n: usize) -> Vec<u8> {
    let extend_size = n - x.to_be_bytes().as_ref().len();
    assert!(extend_size > 0);
    
    let mut res = Vec::with_capacity(n);
    
    res.extend(std::iter::repeat(0).take(extend_size));
    res.extend_from_slice(x.to_be_bytes().as_ref());
    
    res
}