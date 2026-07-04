use crate::pqc::slh_dsa::adrs::Adrs;

struct WOTSParameters {
    n: usize,
    lgw: usize,
}

pub struct WOTSPlus {
    parameters: WOTSParameters,
}

impl WOTSPlus {
    pub fn new(n: usize, lgw: usize) -> Self {
        WOTSPlus{
            parameters: WOTSParameters {n, lgw},
        }
    }
}


fn chain(x: &[u8], i: usize, s: usize, seed: &[u8], adrs: Adrs)