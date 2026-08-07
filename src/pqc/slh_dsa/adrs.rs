//! ADRS structure
//! See section 4.2 and 4.3

use std::fmt::Debug;
use std::ops::{Rem, Shr, ShrAssign};
use num_traits::FromBytes;
use crate::pqc::slh_dsa::adrs::AdrsType::WotsHash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TreeAddress<const LEN: usize>(u128);

impl<const LEN: usize> TreeAddress<LEN> {
    pub fn new(val: u128) -> Self {
        Self(val & Self::MASK)
    }
    const MASK: u128 = match 1u128.checked_shl((LEN * 8) as u32) {
        Some(val) => val - 1,
        None => u128::MAX,
    };
    pub fn value(&self) -> u128 {
        self.0
    }
}

impl TreeAddress<12> {
    pub fn to_be_bytes(&self) -> [u8; 12] {
        let full_bytes = self.0.to_be_bytes(); // 16 bytes
        let mut out = [0u8; 12];
        out.copy_from_slice(&full_bytes[4..16]); // Take lower 12 bytes
        out
    }

    pub fn from_be_bytes(bytes: &[u8; 12]) -> Self {
        let mut buf = [0u8; 16];
        buf[4..16].copy_from_slice(bytes);
        Self(u128::from_be_bytes(buf))
    }
}

impl TreeAddress<8> {
    pub fn to_be_bytes(&self) -> [u8; 8] {
        let full_bytes = self.0.to_be_bytes(); // 16 bytes
        let mut out = [0u8; 8];
        out.copy_from_slice(&full_bytes[8..16]); // Take lower 8 bytes
        out
    }

    pub fn from_be_bytes(bytes: &[u8; 8]) -> Self {
        let mut buf = [0u8; 16];
        buf[8..16].copy_from_slice(bytes);
        Self(u128::from_be_bytes(buf))
    }
}

// definitions of operations of TreeAddress (only those that are required... lazy)
impl<const LEN: usize> Shr<usize> for TreeAddress<LEN>{
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        Self::new(self.0.shr(rhs))
    }
}

impl<const LEN: usize> Rem<usize> for TreeAddress<LEN>{
    type Output = Self;

    fn rem(self, rhs: usize) -> Self::Output {
        Self::new(self.0 % rhs as u128)
    }
}

pub trait AdrsTrait<const TREE_ADDR_LEN: usize>: Debug + PartialEq + Eq + Clone + Copy {
    type AsBytesType;
    fn new(layer_addr: usize, tree_addr: TreeAddress<TREE_ADDR_LEN>, type_: AdrsType) -> Self;
    fn new_null() -> Self;
    fn get_key_pair_address(self) -> u32;
    fn get_tree_index(self) -> u32;
    fn set_layer_address(&mut self, layer_addr: usize);
    fn set_tree_address(&mut self, tree_addr: TreeAddress<TREE_ADDR_LEN>);
    fn set_type_and_clear(&mut self, type_: AdrsType);
    fn set_key_pair_address(&mut self, key_pair_addr: u32);
    fn set_chain_address(&mut self, chain_addr: u32);
    fn set_tree_height(&mut self, tree_height: u32);
    fn set_hash_address(&mut self, hash_address: u32);
    fn set_tree_index(&mut self, tree_index: u32);
    fn as_bytes(&self) -> Self::AsBytesType;
}


#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AdrsType {
    WotsHash = 0,
    WotsPk = 1,
    Tree = 2,
    ForsTree = 3,
    ForsRoots = 4,
    WotsPrf = 5,
    ForsPrf = 6,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Adrs {
    layer_addr: u32,
    tree_addr: TreeAddress<12>,
    type_: AdrsType,
    contents: [u8; 12],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AdrsC { // compressed version of ADRS
    layer_addr: u8,
    tree_addr: TreeAddress<8>,
    type_: AdrsType,
    contents: [u8; 12],
}

impl AdrsTrait<12> for Adrs {
    type AsBytesType = [u8; 32];

    fn new(layer_addr: usize, tree_addr: TreeAddress<12>, type_: AdrsType) -> Self {
        Self {
            layer_addr: layer_addr as u32,
            tree_addr,
            type_,
            contents: [0; 12],
        }
    }

    fn new_null() -> Self {
        Adrs{
            layer_addr: 0,
            tree_addr: TreeAddress::<12>::new(0),
            type_: AdrsType::WotsHash,
            contents: [0; 12],
        }
    }

    // getters
    fn get_key_pair_address(self) -> u32 {
        if self.type_ == AdrsType::Tree {
            panic!("Unsupported Adrs type for this operation");
        }

        u32::from_be_bytes(self.contents[0..4].try_into().unwrap())
    }

    fn get_tree_index(self) -> u32 {
        if self.type_ == AdrsType::Tree
            || self.type_ == AdrsType::ForsTree
            || self.type_ == AdrsType::ForsPrf {
            return u32::from_be_bytes(self.contents[8..12].try_into().unwrap());
        }

        panic!("Unsupported Adrs type for this operation");
    }

    fn set_layer_address(&mut self, layer_addr: usize) {
        self.layer_addr = layer_addr as u32;
    }

    fn set_tree_address(&mut self, tree_addr: TreeAddress<12>) {
        self.tree_addr = tree_addr;
    }

    fn set_type_and_clear(&mut self, type_: AdrsType) {
        self.type_ = type_;
        self.contents = [0; 12];
    }

    fn set_key_pair_address(&mut self, key_pair_addr: u32) {
        if self.type_ == AdrsType::Tree {
            panic!("Unsupported Adrs type for this operation");
        }

        self.contents[0..4].copy_from_slice(&key_pair_addr.to_be_bytes());
    }

    fn set_chain_address(&mut self, chain_addr: u32) {
        if self.type_ != AdrsType::WotsHash
            && self.type_ != AdrsType::WotsPrf {
            panic!("Unsupported Adrs type for this operation");
        }

        self.contents[4..8].copy_from_slice(&chain_addr.to_be_bytes());
    }

    fn set_tree_height(&mut self, tree_height: u32) {
        if self.type_ == AdrsType::ForsPrf && tree_height != 0 {
            panic!("tree_height must be 0 in this case")
        } else if self.type_ != AdrsType::Tree
            && self.type_ != AdrsType::ForsTree {
            panic!("Unsupported Adrs type for this operation");
        }

        self.contents[4..8].copy_from_slice(&tree_height.to_be_bytes());
    }

    fn set_hash_address(&mut self, hash_address: u32) {
        if self.type_ == AdrsType::WotsPrf && hash_address != 0 {
            panic!("hash_address must be 0 in this case")
        } else if self.type_ != AdrsType::WotsHash {
            panic!("Unsupported Adrs type for this operation");
        }

        self.contents[8..12].copy_from_slice(&hash_address.to_be_bytes());
    }

    fn set_tree_index(&mut self, tree_index: u32) {
        if self.type_ == AdrsType::WotsPk
            || self.type_ == AdrsType::WotsHash
            || self.type_ == AdrsType::ForsRoots
            || self.type_ == AdrsType::WotsPrf {
            panic!("Unsupported Adrs type for this operation");
        }
        self.contents[8..12].copy_from_slice(&tree_index.to_be_bytes());
    }

    fn as_bytes(&self) -> Self::AsBytesType {
        let mut bytes = [0; 32];

        bytes[0..4].copy_from_slice(&self.layer_addr.to_be_bytes());
        bytes[4..16].copy_from_slice(&self.tree_addr.to_be_bytes());
        let type32 = self.type_ as u32;
        bytes[16..20].copy_from_slice(&type32.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.contents);

        bytes
    }
}

impl AdrsTrait<8> for AdrsC {
    type AsBytesType = [u8; 22];

    fn new(layer_addr: usize, tree_addr: TreeAddress<8>, type_: AdrsType) -> Self {
        Self {
            layer_addr: layer_addr as u8,
            tree_addr,
            type_,
            contents: [0; 12],
        }
    }

    fn new_null() -> Self {
        AdrsC{
            layer_addr: 0,
            tree_addr: TreeAddress::<8>::new(0),
            type_: AdrsType::WotsHash,
            contents: [0; 12],
        }
    }

    fn get_key_pair_address(self) -> u32 {
        if self.type_ == AdrsType::Tree {
            panic!("Unsupported Adrs type for this operation");
        }

        u32::from_be_bytes(self.contents[0..4].try_into().unwrap())
    }

    fn get_tree_index(self) -> u32 {
        if self.type_ == AdrsType::Tree
            || self.type_ == AdrsType::ForsTree
            || self.type_ == AdrsType::ForsPrf {
            return u32::from_be_bytes(self.contents[8..12].try_into().unwrap());
        }

        panic!("Unsupported Adrs type for this operation");
    }

    fn set_layer_address(&mut self, layer_addr: usize) {
        self.layer_addr = layer_addr as u8;
    }

    fn set_tree_address(&mut self, tree_addr: TreeAddress<8>) {
        self.tree_addr = tree_addr;
    }

    fn set_type_and_clear(&mut self, type_: AdrsType) {
        self.type_ = type_;
        self.contents = [0; 12];
    }

    fn set_key_pair_address(&mut self, key_pair_addr: u32) {
        if self.type_ == AdrsType::Tree {
            panic!("Unsupported Adrs type for this operation");
        }

        self.contents[0..4].copy_from_slice(&key_pair_addr.to_be_bytes());
    }

    fn set_chain_address(&mut self, chain_addr: u32) {
        if self.type_ != AdrsType::WotsHash
            && self.type_ != AdrsType::WotsPrf {
            panic!("Unsupported Adrs type for this operation");
        }

        self.contents[4..8].copy_from_slice(&chain_addr.to_be_bytes());
    }

    fn set_tree_height(&mut self, tree_height: u32) {
        if self.type_ == AdrsType::ForsPrf && tree_height != 0 {
            panic!("tree_height must be 0 in this case")
        } else if self.type_ != AdrsType::Tree
            && self.type_ != AdrsType::ForsTree {
            panic!("Unsupported Adrs type for this operation");
        }

        self.contents[4..8].copy_from_slice(&tree_height.to_be_bytes());
    }

    fn set_hash_address(&mut self, hash_address: u32) {
        if self.type_ == AdrsType::WotsPrf && hash_address != 0 {
            panic!("hash_address must be 0 in this case")
        }
        else if self.type_ != AdrsType::WotsHash {
            panic!("Unsupported Adrs type for this operation");
        }

        self.contents[8..12].copy_from_slice(&hash_address.to_be_bytes());
    }

    fn set_tree_index(&mut self, tree_index: u32) {
        if self.type_ == AdrsType::WotsPk
            || self.type_ == AdrsType::WotsHash
            || self.type_ == AdrsType::ForsRoots
            || self.type_ == AdrsType::WotsPrf {
            panic!("Unsupported Adrs type for this operation");
        }
        self.contents[8..12].copy_from_slice(&tree_index.to_be_bytes());
    }

    fn as_bytes(&self) -> Self::AsBytesType {
        let mut bytes = [0; 22];

        bytes[0] = self.layer_addr;
        bytes[1..9].copy_from_slice(&self.tree_addr.to_be_bytes());
        bytes[9] = self.type_ as u8;
        bytes[10..22].copy_from_slice(&self.contents);

        bytes
    }
}
