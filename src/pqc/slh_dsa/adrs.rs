//! ADRS structure
//! See section 4.2 and 4.3

use std::os::unix::fs::OpenOptionsExt;

enum AdrsType {
    WOTS_HASH = 0,
    WOTS_PK = 1,
    TREE = 2,
    FORS_TREE = 3,
    FORS_ROOTS = 4,
    WOTS_PRF = 5,
    FORS_PRF = 6,
}

pub struct Adrs {
    layer_addr: u32,
    tree_addr: [u8; 12],
    type_: AdrsType,
    contents: [u8; 12],
}

impl Adrs {
    pub fn new(layer_addr: u32, tree_addr: [u8; 12], type_: AdrsType) -> Self {
        Self {
            layer_addr,
            tree_addr,
            type_,
            contents: [0; 12],
        }
    }

    // getters
    fn getKeyPairAddress() -> Option<u32> {
        if
    }
}
