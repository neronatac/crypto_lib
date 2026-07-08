//! base_2b: splits a byte sequence into a b-bit sequence
//! See Algorithm 4

use num_traits::{FromPrimitive, PrimInt, Zero, One};

// trait linking integer type to bit-width
pub trait Base2BTypeFromB<const B: usize> {
    type Output: PrimInt + FromPrimitive + Zero + One;
}

// implement the trait for types to handle
impl Base2BTypeFromB<4> for () {
    type Output = u8;
}

pub fn base_2b<const B: usize>(x: &[u8], out_len: usize) -> Vec<<() as Base2BTypeFromB<B>>::Output>
where
    (): Base2BTypeFromB<B>,
{
    type T<const B: usize> = <() as Base2BTypeFromB<B>>::Output;
    let mut baseb = Vec::with_capacity(out_len);

    let mut in_ = 0;
    let mut bits = 0;
    let mut total: u64 = 0;
    let mask: u64 = (1 << B) - 1;

    for _ in 0..out_len {
        while bits < B {
            total = (total << 8) + x[in_] as u64;
            in_ += 1;
            bits += 8;
        }
        bits -= B;
        let val = (total >> bits) & mask;
        baseb.push(T::<B>::from_u64(val).unwrap());
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