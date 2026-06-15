use std::convert::TryInto;

/// XOR two arrays of u8
pub fn xor_arrays<const COUNT: usize>(a: &[u8; COUNT], b: &[u8; COUNT]) -> [u8; COUNT] {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect::<Vec<u8>>().try_into().unwrap()
}

pub fn extract_array_from_slice<const LENGTH: usize, T: Copy+Default>(s: &[T], start: usize) -> Result<[T; LENGTH], &'static str>
{
    let mut ret : [T; LENGTH] = [Default::default();LENGTH];
    for i in 0..LENGTH {
        ret[i] = s[start + i];
    }

    Ok(ret)
}

pub fn check_cipher_params(p: &[u8], c: &[u8], block_size: usize) -> Result<(), &'static str>
{
    if p.len() != c.len() {
        return Err("Plaintext and ciphertext must have the same length");
    } else if p.len() % block_size != 0 {
        return Err("Length of plain/ciphertext is not a multiple of block size")
    }
    Ok(())
}