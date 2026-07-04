use crate::pqc::slh_dsa::adrs::Adrs;

pub struct WOTSPlus<const N: usize, F>
where
    F: Fn(&[u8; N], &[u8; 32], &[u8; N]) -> [u8; N]
{
    f: F,
}

impl<const N: usize, F> WOTSPlus<N, F>
where
    F: Fn(&[u8; N], &[u8; 32], &[u8; N]) -> [u8; N]
{
    pub fn new(f: F) -> Self {
        WOTSPlus{
            f
        }
    }

    fn chain(&self, x: &[u8; N], i: usize, s: usize, seed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
        let tmp = x.clone();
        for j in i..i + s {
            adrs.set_hash_address(j as u32);
            (self.f)(seed, &adrs.as_bytes(), &tmp);
        }
        tmp
    }
}
