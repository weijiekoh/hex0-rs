use alloy_sol_types::sol;

sol! {
    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        uint32 result; 
    }
}

pub fn hex0(n: u32) -> u32 {
    n
}
