#[derive(serde::Serialize, serde::Deserialize)]
pub struct PublicInputs {
    pub source_bytes: Vec<u8>,
    pub expected_hash: [u8; 32],
}

pub fn hex0(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut hold = 0u8;
    let mut toggle = false;
    let mut chars = input.iter().peekable();

    while let Some(c) = chars.next() {
        if let Some(digit) = char::to_digit((*c).into(), 16) {
            if toggle {
                output.push((hold << 4) | (digit as u8));
                hold = 0;
            } else {
                hold = digit as u8;
            }
            toggle = !toggle;
        } else if *c == b'#' || *c == b';' {
            while let Some(&nc) = chars.peek() {
                if *nc == b'\n' {
                    break;
                }
                chars.next();
            }
        }
    }

    output
}

#[cfg(test)]
pub mod tests {
    use crate::hex0;
    use sha2::{Digest, Sha256};

    pub fn cases() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "../hex0_src/hex1_AMD64.hex0",
                "c264a212d2b0e1f1bcf34217ed7876bb9324bd7e29cd902bb1cad4d9f45f1cf8",
            ),
            (
                "../hex0_src/hex1_riscv32.hex0",
                "35a66d6ca6fedcb8e37d5e521ea22c7eda5cf5962eb1455a9b34b8861797ed89",
            ),
            (
                "../hex0_src/hex1_riscv64.hex0",
                "2c0037d9455f282d5612c1cf280b6a681a33ee1fd633375276e4a816101a3574",
            ),
            (
                "../hex0_src/hex1_x86.hex0",
                "30da8f019c21e71d9ea60b374272209956256958d21f698c0b757c8fa560c9cf",
            ),
        ]
    }

    #[test]
    pub fn test_hex0() {
        for case in cases() {
            let filepath = case.0;
            let expected_hash_str = case.1;

            let input_bytes = std::fs::read(filepath).expect("failed to read input file");

            let output = hex0(&input_bytes);

            let mut hasher = Sha256::new();
            hasher.update(output);
            let hash_array: [u8; 32] = hasher.finalize().into();

            let expected_hash_bytes = hex::decode(expected_hash_str).expect("Invalid hex string");
            let expected_hash: [u8; 32] = expected_hash_bytes
                .try_into()
                .expect("Expected hash must be 32 bytes");

            assert_eq!(hash_array, expected_hash, "Hash mismatch");
        }
    }
}
