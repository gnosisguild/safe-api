use sha2::{Digest, Sha256};

/// SAFE tag computation constants (matching Noir implementation)
const ABSORB_FLAG: u32 = 0x80000000;
const SQUEEZE_FLAG: u32 = 0x00000000;

/// Computes a unique tag for a sponge instance based on its IO pattern and domain separator.
/// This matches the Noir implementation exactly.
///
/// # Arguments
/// - `io_pattern`: Vector of 32-bit encoded operations defining the sponge's usage pattern.
///               Each word has MSB=1 for ABSORB operations, MSB=0 for SQUEEZE operations.
/// - `domain_separator`: 64-byte domain separator for cross-protocol security.
///
/// # Returns
/// A u128 representing the 128-bit tag (equivalent to Field in Noir).
pub fn compute_tag(io_pattern: &[u32], domain_separator: &[u8; 64]) -> u128 {
    // Step 1: Parse and aggregate consecutive operations of the same type
    let mut encoded_words = Vec::new();
    let mut current_absorb_sum = 0;
    let mut current_squeeze_sum = 0;
    let mut last_was_absorb = false;

    for &encoded_word in io_pattern {
        if encoded_word > 0 {
            // Parse operation type from MSB and length from lower 31 bits
            let is_absorb = (encoded_word & ABSORB_FLAG) != 0;
            let length = encoded_word & 0x7FFFFFFF; // Clear MSB to get length

            if is_absorb {
                if last_was_absorb {
                    // Aggregate consecutive ABSORB operations
                    current_absorb_sum += length;
                } else {
                    // Start new ABSORB sequence
                    if current_squeeze_sum > 0 {
                        // Flush previous SQUEEZE sequence
                        encoded_words.push(SQUEEZE_FLAG | current_squeeze_sum);
                        current_squeeze_sum = 0;
                    }
                    current_absorb_sum = length;
                }
                last_was_absorb = true;
            } else {
                if !last_was_absorb {
                    // Aggregate consecutive SQUEEZE operations
                    current_squeeze_sum += length;
                } else {
                    // Start new SQUEEZE sequence
                    if current_absorb_sum > 0 {
                        // Flush previous ABSORB sequence
                        encoded_words.push(ABSORB_FLAG | current_absorb_sum);
                        current_absorb_sum = 0;
                    }
                    current_squeeze_sum = length;
                }
                last_was_absorb = false;
            }
        }
    }

    // Flush remaining operations
    if current_absorb_sum > 0 {
        encoded_words.push(ABSORB_FLAG | current_absorb_sum);
    }
    if current_squeeze_sum > 0 {
        encoded_words.push(SQUEEZE_FLAG | current_squeeze_sum);
    }

    // Step 3: Serialize to byte string and append domain separator (following SAFE spec 2.3).
    let mut input_bytes = Vec::new();

    // Serialize encoded words to bytes (big-endian as per SAFE spec).
    for &word in &encoded_words {
        input_bytes.extend_from_slice(&word.to_be_bytes());
    }

    // Append domain separator.
    input_bytes.extend_from_slice(domain_separator);

    // Step 4: Hash with SHA256 and truncate to 128 bits (following SAFE spec 2.3).
    let mut hasher = Sha256::new();
    hasher.update(&input_bytes);
    let hash_bytes = hasher.finalize();

    // Convert first 128 bits (16 bytes) to u128 (equivalent to Field in Noir).
    let mut tag_value: u128 = 0;
    for i in 0..16 {
        tag_value = tag_value * 256 + (hash_bytes[i] as u128);
    }

    tag_value
}

/// Helper function to convert hex string to bytes
fn hex_to_bytes(hex: &str) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    let hex_clean = hex.replace("0x", "");
    for (i, chunk) in hex_clean.as_bytes().chunks(2).enumerate() {
        if i < 64 {
            let byte_str = std::str::from_utf8(chunk).unwrap();
            bytes[i] = u8::from_str_radix(byte_str, 16).unwrap();
        }
    }
    bytes
}

fn main() {
    println!("SAFE Tag Computation Test (Rust)\n");

    // Test cases matching the Noir implementation examples

    // Test 1: Basic hashing pattern [3, 1] (ABSORB(3), SQUEEZE(1))
    let io_pattern1 = vec![0x80000003, 0x00000001];
    let domain_separator1 =
        hex_to_bytes("414243440000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    let tag1 = compute_tag(&io_pattern1, &domain_separator1);
    println!("Test 1: Pattern [0x80000003, 0x00000001] (ABSORB(3), SQUEEZE(1))");
    println!("Domain separator: 0x41424344...");
    println!("Tag: 0x{:032x}", tag1);
    println!();

    // Test 2: Merkle tree pattern [1, 1, 1] (ABSORB(1), ABSORB(1), SQUEEZE(1))
    let io_pattern2 = vec![0x80000001, 0x80000001, 0x00000001];
    let domain_separator2 =
        hex_to_bytes("414243440000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    let tag2 = compute_tag(&io_pattern2, &domain_separator2);
    println!(
        "Test 2: Pattern [0x80000001, 0x80000001, 0x00000001] (ABSORB(1), ABSORB(1), SQUEEZE(1))"
    );
    println!("Domain separator: 0x41424344...");
    println!("Tag: 0x{:032x}", tag2);
    println!();

    // Test 3: Commitment pattern [3, 1] (ABSORB(3), SQUEEZE(1))
    let io_pattern3 = vec![0x80000003, 0x00000001];
    let domain_separator3 =
        hex_to_bytes("4142434400000000000000000000000000000000000000000000000000000000");
    let tag3 = compute_tag(&io_pattern3, &domain_separator3);
    println!("Test 3: Pattern [0x80000003, 0x00000001] (ABSORB(3), SQUEEZE(1)) - Commitment");
    println!("Domain separator: 0x41424344...");
    println!("Tag: 0x{:032x}", tag3);
    println!();

    // Test 4: Multiple squeeze pattern [3, 2] (ABSORB(3), SQUEEZE(2))
    let io_pattern4 = vec![0x80000003, 0x00000002];
    let domain_separator4 =
        hex_to_bytes("4142434400000000000000000000000000000000000000000000000000000000");
    let tag4 = compute_tag(&io_pattern4, &domain_separator4);
    println!("Test 4: Pattern [0x80000003, 0x00000002] (ABSORB(3), SQUEEZE(2))");
    println!("Domain separator: 0x41424344...");
    println!("Tag: 0x{:032x}", tag4);
    println!();

    // Test 5: Zero length pattern [0, 1] (ABSORB(0), SQUEEZE(1))
    let io_pattern5 = vec![0x80000000, 0x00000001];
    let domain_separator5 =
        hex_to_bytes("4142434400000000000000000000000000000000000000000000000000000000");
    let tag5 = compute_tag(&io_pattern5, &domain_separator5);
    println!("Test 5: Pattern [0x80000000, 0x00000001] (ABSORB(0), SQUEEZE(1))");
    println!("Domain separator: 0x41424344...");
    println!("Tag: 0x{:032x}", tag5);
    println!();

    // Test 6: Different domain separators (should produce different tags)
    let io_pattern6 = vec![0x80000003, 0x00000001]; // ABSORB(3), SQUEEZE(1)
    let domain_separator6a =
        hex_to_bytes("4142434400000000000000000000000000000000000000000000000000000000");
    let domain_separator6b =
        hex_to_bytes("4243444500000000000000000000000000000000000000000000000000000000");
    let tag6a = compute_tag(&io_pattern6, &domain_separator6a);
    let tag6b = compute_tag(&io_pattern6, &domain_separator6b);
    println!("Test 6: Different domain separators");
    println!(
        "Pattern [0x80000003, 0x00000001] with domain 0x41424344... -> Tag: 0x{:032x}",
        tag6a
    );
    println!(
        "Pattern [0x80000003, 0x00000001] with domain 0x42434445... -> Tag: 0x{:032x}",
        tag6b
    );
    println!("Tags are different: {}", tag6a != tag6b);
    println!();

    // Test 7: Aggregation example from SAFE spec [3, 3, 3] -> [6, 3]
    let io_pattern7 = vec![0x80000003, 0x80000003, 0x00000003];
    let domain_separator7 =
        hex_to_bytes("414200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    let tag7 = compute_tag(&io_pattern7, &domain_separator7);
    println!("Test 7: Aggregation pattern [0x80000003, 0x80000003, 0x00000003] (ABSORB(3), ABSORB(3), SQUEEZE(3))");
    println!("Should aggregate to: ABSORB(6), SQUEEZE(3)");
    println!("Domain separator: 0x4142...");
    println!("Tag: 0x{:032x}", tag7);
    println!();

    // Test 8: Your specific pattern [2, 2, 2] (ABSORB(2), SQUEEZE(2), ABSORB(2))
    let io_pattern8 = vec![0x80000002, 0x00000002, 0x80000002];
    let domain_separator8 =
        hex_to_bytes("4142434400000000000000000000000000000000000000000000000000000000");
    let tag8 = compute_tag(&io_pattern8, &domain_separator8);
    println!("Test 8: Your pattern [0x80000002, 0x00000002, 0x80000002] (ABSORB(2), SQUEEZE(2), ABSORB(2))");
    println!("Domain separator: 0x41424344...");
    println!("Tag: 0x{:032x}", tag8);
    println!();

    // Test 9: Aggregation demonstration - your example
    let io_pattern9a = vec![0x80000001, 0x80000001, 0x00000001];
    let io_pattern9b = vec![0x80000002, 0x00000001];
    let domain_separator9 =
        hex_to_bytes("4142434400000000000000000000000000000000000000000000000000000000");
    let tag9a = compute_tag(&io_pattern9a, &domain_separator9);
    let tag9b = compute_tag(&io_pattern9b, &domain_separator9);
    println!("Test 9: Aggregation demonstration");
    println!("Original: [0x80000001, 0x80000001, 0x00000001] (ABSORB(1), ABSORB(1), SQUEEZE(1))");
    println!("Aggregated: [0x80000002, 0x00000001] (ABSORB(2), SQUEEZE(1))");
    println!("Original tag: 0x{:032x}", tag9a);
    println!("Aggregated tag: 0x{:032x}", tag9b);
    println!("Tags match: {}", tag9a == tag9b);
    println!();
}
