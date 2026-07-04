//! ADRS structure
//! See section 4.2 and 4.3


#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AdrsType {
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
    pub fn get_key_pair_address(self) -> u32 {
        if self.type_ == AdrsType::TREE {
            panic!("Unsupported Adrs type for this operation");
        }

        u32::from_be_bytes(self.contents[0..4].try_into().unwrap())
    }

    pub fn get_tree_index(self) -> u32 {
        if self.type_ == AdrsType::TREE
            || self.type_ == AdrsType::FORS_TREE
            || self.type_ == AdrsType::FORS_PRF {
            return u32::from_be_bytes(self.contents[8..12].try_into().unwrap());
        }

        panic!("Unsupported Adrs type for this operation");
    }

    pub fn set_layer_address(&mut self, layer_addr: u32) {
        self.layer_addr = layer_addr
    }

    pub fn set_tree_address(&mut self, tree_addr: [u8; 12]) {
        self.tree_addr = tree_addr
    }

    pub fn set_type_and_clear(&mut self, type_: AdrsType) {
        self.type_ = type_;
        self.contents = [0; 12];
    }

    pub fn set_key_pair_address(&mut self, key_pair_addr: u32) {
        if self.type_ == AdrsType::TREE {
            panic!("Unsupported Adrs type for this operation");
        }

        self.contents[0..4].copy_from_slice(&key_pair_addr.to_be_bytes());
    }

    pub fn set_chain_address(&mut self, chain_addr: u32) {
        if self.type_ != AdrsType::WOTS_HASH
            && self.type_ != AdrsType::WOTS_PRF {
            panic!("Unsupported Adrs type for this operation");
        }

        self.contents[4..8].copy_from_slice(&chain_addr.to_be_bytes());
    }

    pub fn set_tree_height(&mut self, tree_height: u32) {
        if self.type_ == AdrsType::FORS_PRF && tree_height != 0 {
            panic!("tree_height must be 0 in this case")
        } else if self.type_ != AdrsType::TREE
            && self.type_ != AdrsType::FORS_TREE {
            panic!("Unsupported Adrs type for this operation");
        }

        self.contents[4..8].copy_from_slice(&tree_height.to_be_bytes());
    }

    pub fn set_hash_address(&mut self, hash_address: u32) {
        if self.type_ == AdrsType::WOTS_PRF && hash_address != 0 {
            panic!("hash_address must be 0 in this case")
        }
        else if self.type_ != AdrsType::WOTS_HASH {
            panic!("Unsupported Adrs type for this operation");
        }

        self.contents[8..12].copy_from_slice(&hash_address.to_be_bytes());
    }

    pub fn set_tree_index(&mut self, tree_index: u32) {
        if self.type_ == AdrsType::WOTS_PK
            || self.type_ == AdrsType::WOTS_HASH
            || self.type_ == AdrsType::FORS_ROOTS
            || self.type_ == AdrsType::WOTS_PRF {
            panic!("Unsupported Adrs type for this operation");
        }
        self.contents[8..12].copy_from_slice(&tree_index.to_be_bytes());
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        let mut bytes = [0; 32];

        bytes[0..4].copy_from_slice(&self.layer_addr.to_be_bytes());
        bytes[4..16].copy_from_slice(&self.tree_addr);
        let type32 = self.type_ as u32;
        bytes[16..20].copy_from_slice(&type32.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.contents);

        bytes
    }
}
