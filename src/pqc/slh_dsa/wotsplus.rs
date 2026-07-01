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