//! Shared code between hash algorithms

/// Trait implemented by all hash algorithms.
///
/// Each hash has
/// - 1 constant:
///     - DIGEST_SIZE: size of the digest (in bytes)
/// - 2 types:
///     - `InitStruct`: structure used to initialise the context
///     - `Context`: type of the hash context (state and over stuff)
/// - 3 methods:
///     - `new`: static method that returns an initialised instance of the hash
///     - `update`: treats some data
///     - `finalise`: finalises the hash and returns it
///
/// Multiple calls to `update` can be done to treat the data as it was a single big block
/// (i.e. conceptually, `update(a | b) == update(a), update(b)`).
///
/// Do not call `update` after `finalise` was called.
pub trait Hash {
    const DIGEST_SIZE: usize;
    const BLOCK_SIZE: usize;

    type DigestType;   // &[u8; xxx]
    type InitStruct;
    type Context;

    fn new(init_struct: &Self::InitStruct) -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalise(&mut self) -> Self::DigestType;
}

macro_rules! generic_update_func {
    // without message length storing
    ($(($msg_length_type:ty))?) => {
        fn update(&mut self, data: &[u8]) {
            let mut cur_block = [0; Self::BLOCK_SIZE];
    
            $(
                // update msg_length if necessary
                self.msg_length += data.len() as $msg_length_type * 8;
            )?
    
            // take remaining bytes from previous uncompleted block
            for i in 0..self.remaining_bytes_len {
                cur_block[i] = self.remaining_bytes[i];
            }
    
            // process blocks until the end
            let mut offset = 0;
            while offset < data.len() {
                cur_block[self.remaining_bytes_len] = data[offset];
    
                self.remaining_bytes_len += 1;
                offset += 1;
                
                if self.remaining_bytes_len == Self::BLOCK_SIZE {
                    process_block(&mut self.context, &cur_block);
                    self.remaining_bytes_len = 0;
                }
            }
            
            // save remaining bytes
            for i in 0..self.remaining_bytes_len {
                self.remaining_bytes[i] = cur_block[i];
            }
        }
    };
}
pub(super) use generic_update_func;