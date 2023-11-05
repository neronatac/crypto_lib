use std::convert::TryInto;

pub fn xor_arrays<const COUNT: usize>(a: &[u8; COUNT], b: &[u8; COUNT]) -> [u8; COUNT] {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect::<Vec<u8>>().try_into().unwrap()
}
