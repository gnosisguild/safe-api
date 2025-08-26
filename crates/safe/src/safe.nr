use poseidon::poseidon2_permutation;
use sha256::sha256_var;

/// SAFE (Sponge API for Field Elements)
///
/// This module provides a complete implementation of the SAFE API in Noir as defined in:
/// "SAFE (Sponge API for Field Elements) - A Toolbox for ZK Hash Applications"
/// see https://hackmd.io/bHgsH6mMStCVibM_wYvb2w#22-Sponge-state for more details.
///
/// SAFE provides a unified interface for cryptographic sponge functions that can be
/// instantiated with various permutations to create hash functions, MACs, authenticated
/// encryption schemes, and other cryptographic primitives for ZK proof systems.
///
/// This implementation follows the SAFE specification exactly, providing:
/// - Complete API: START, ABSORB, SQUEEZE, FINISH operations.
/// - Full security: Domain separation, tag computation, IO pattern validation.
/// - Poseidon2 integration: Field-friendly permutation for ZK systems.
/// - Specification compliance: All operations follow SAFE spec 2.4 exactly.
/// - Natural API design: Variable-length inputs, automatic length detection from IO patterns.
///
/// # API Design
///
/// The API is designed for natural usage while maintaining type safety:
/// - `absorb(input: [Field])`: Accepts variable-length arrays, no padding required.
/// - `squeeze()`: Returns a vector with field element(s).
/// - IO patterns automatically determine operation lengths for validation.

/// Rate parameter for the sponge construction (number of field elements that can be absorbed per permutation call).
global RATE: u32 = 3;

/// Capacity parameter for the sponge construction (security parameter, typically 1-2 field elements).
global CAPACITY: u32 = 1;

/// Total state size (rate + capacity) in field elements.
global STATE_SIZE: u32 = RATE + CAPACITY;

/// IO Pattern encoding constants (from SAFE spec 2.3).
///
/// These constants are used for encoding operation types in the 32-bit word format:
/// - MSB set to 1 for ABSORB operations
/// - MSB set to 0 for SQUEEZE operations

/// Flag for ABSORB operations (MSB = 1)
global ABSORB_FLAG: u32 = 0x80000000;

/// Flag for SQUEEZE operations (MSB = 0)
global SQUEEZE_FLAG: u32 = 0x00000000;

/// SAFE Sponge State (following spec 2.2)
///
/// The sponge state consists of the permutation state, tag, position counters,
/// and IO pattern tracking as defined in the SAFE specification.
///
/// # Generic Parameters
/// - `L`: The length of the IO pattern array
///
/// # Fields
/// - `state`: Permutation state V in F^n (rate + capacity elements)
/// - `tag`: Parameter tag T used for instance differentiation
/// - `absorb_pos`: Current absorb position (<= n-c)
/// - `squeeze_pos`: Current squeeze position (<= n-c)
/// - `io_pattern`: Expected IO pattern for validation (encoded 32-bit words)
/// - `io_count`: Current operation count for pattern tracking
pub struct SafeSponge<let L: u32> {
    /// Permutation state V in F^n (rate + capacity elements).
    state: [Field; STATE_SIZE],
    /// Parameter tag T used for instance differentiation.
    tag: Field,
    /// Current absorb position (<= n-c).
    absorb_pos: u32,
    /// Current squeeze position (<= n-c).
    squeeze_pos: u32,
    /// Expected IO pattern for validation.
    io_pattern: [u32; L],
    /// Current operation count for pattern tracking (spec 2.4: io_count).
    io_count: u32,
}

impl<let L: u32> SafeSponge<L> {
    /// Initializes a new SAFE sponge instance with the given IO pattern and domain separator (following spec 2.4).
    ///
    /// # Arguments
    /// - `io_pattern`: Array of 32-bit encoded operations defining the expected sequence of ABSORB/SQUEEZE calls.
    ///               Each word has MSB=1 for ABSORB operations, MSB=0 for SQUEEZE operations.
    /// - `domain_separator`: 64-byte domain separator for cross-protocol security.
    ///
    /// # Returns
    /// A new `SafeSponge` instance with initialized state
    pub fn start(io_pattern: [u32; L], domain_separator: [u8; 64]) -> SafeSponge<L> {
        // Compute tag from IO pattern and domain separator (spec 2.3).
        let tag = compute_tag(io_pattern, domain_separator);

        let mut state = [0; STATE_SIZE];
        // Initialize capacity with tag (spec 2.4).
        // Add T to the first 128 bits of the state.
        state[0] = tag;

        SafeSponge { state, tag, absorb_pos: 0, squeeze_pos: 0, io_pattern, io_count: 0 }
    }

    /// Absorbs field elements into the sponge state, interleaving permutation calls as needed (following spec 2.4).
    ///
    /// The number of elements to absorb is automatically validated against the IO pattern.
    /// This method accepts variable-length arrays, making it natural to use without padding.
    ///
    /// # Arguments
    /// - `input`: Array of field elements to absorb (variable length, must match IO pattern)
    pub fn absorb(&mut self, input: [Field]) {
        let length = input.len() as u32;

        // Validate against IO pattern.
        assert(self.io_count < L);

        // Parse expected operation from io_pattern (encoded word)
        let expected_encoded_word = self.io_pattern[self.io_count];
        let is_expected_absorb = (expected_encoded_word & ABSORB_FLAG) != 0;
        let expected_length = expected_encoded_word & 0x7FFFFFFF;

        // Validate operation type and length
        assert(is_expected_absorb, "Expected ABSORB operation");
        assert(expected_length == length, "Length mismatch");

        // Process each element naturally (no unnecessary iterations).
        for i in 0..length {
            // If absorb_pos == (n-c) then permute and reset (spec 2.4).
            if self.absorb_pos == RATE {
                // n-c = RATE.
                self.state = self.permute();
                self.absorb_pos = 0;
            }

            // Add X[i] to state at absorb_pos (spec 2.4).
            // Note: absorb_pos is the rate position, not capacity position.
            self.state[self.absorb_pos + CAPACITY] =
                self.state[self.absorb_pos + CAPACITY] + input[i];
            self.absorb_pos += 1;
        }

        // Verify that the encoded word matches the expected pattern.
        let encoded_word = ABSORB_FLAG | length;
        assert(encoded_word == expected_encoded_word);

        self.io_count += 1;

        // Force permute at start of next SQUEEZE (spec 2.4).
        self.squeeze_pos = RATE;
    }

    /// Extracts field elements from the sponge state, interleaving permutation calls as needed (following spec 2.4).
    ///
    /// The number of elements to squeeze is automatically determined from the IO pattern.
    pub fn squeeze(&mut self) -> Vec<Field> {
        // Parse expected operation from io_pattern (encoded word)
        let expected_encoded_word = self.io_pattern[self.io_count];
        let is_expected_squeeze = (expected_encoded_word & ABSORB_FLAG) == 0;
        let length = expected_encoded_word & 0x7FFFFFFF;

        // Validate operation type
        assert(is_expected_squeeze, "Expected SQUEEZE operation");

        let mut output = Vec::new();

        // SQUEEZE implementation following spec 2.4.
        // If length==0, loop won't execute (spec 2.4).
        for _ in 0..length {
            // If squeeze_pos==(n-c) then permute and reset (spec 2.4).
            if self.squeeze_pos == RATE {
                // n-c = RATE.
                self.state = self.permute();
                self.squeeze_pos = 0;
                self.absorb_pos = 0;
            }
            // Set Y[i] to state element at squeeze_pos (spec 2.4).
            output.push(self.state[self.squeeze_pos + CAPACITY]);
            self.squeeze_pos += 1;
        }

        // Verify that the encoded word matches the expected pattern.
        let encoded_word = SQUEEZE_FLAG | length;
        assert(encoded_word == expected_encoded_word);

        self.io_count += 1;
        output
    }

    /// Finalizes the sponge instance, verifying that all expected operations have been performed and clearing the internal state for security (following spec 2.4).
    ///
    /// This function is used to ensure that the sponge instance has been used correctly and to prevent information leakage.
    pub fn finish(&mut self) {
        // Check that io_count equals the length of the IO pattern expected (spec 2.4).
        assert(self.io_count == L, "IO pattern not completed");

        // Erase the state and its variables (spec 2.4).
        self.state = [0; STATE_SIZE];
        self.absorb_pos = 0;
        self.squeeze_pos = 0;
        self.io_count = 0;
    }

    /// Permute the state using Poseidon2 (following spec 2.4).
    ///
    /// Applies the Poseidon2 permutation to the current state.
    /// This is the core cryptographic primitive of the sponge construction.
    ///
    /// # Returns
    /// New state after permutation
    fn permute(self) -> [Field; STATE_SIZE] {
        poseidon2_permutation(self.state, STATE_SIZE)
    }
}

/// Computes a unique tag for a sponge instance based on its IO pattern and domain separator.
/// The tag is used to ensure that distinct instances behave like distinct functions.
///
/// # Arguments
/// - `io_pattern`: Array of 32-bit encoded operations defining the sponge's usage pattern.
///               Each word has MSB=1 for ABSORB operations, MSB=0 for SQUEEZE operations.
/// - `domain_separator`: 64-byte domain separator for cross-protocol security.
///
/// # Returns
/// A field element representing the 128-bit tag.
pub fn compute_tag<let L: u32>(io_pattern: [u32; L], domain_separator: [u8; 64]) -> Field {
    // Step 1: Parse and aggregate consecutive operations of the same type
    let mut encoded_words = [0; L]; // Support up to L operations.
    let mut word_count = 0;
    let mut current_absorb_sum = 0;
    let mut current_squeeze_sum = 0;
    let mut last_was_absorb = false;

    for i in 0..L {
        if io_pattern[i] > 0 {
            // Parse operation type from MSB and length from lower 31 bits
            let is_absorb = (io_pattern[i] & ABSORB_FLAG) != 0;
            let length = io_pattern[i] & 0x7FFFFFFF; // Clear MSB to get length

            if is_absorb {
                if last_was_absorb {
                    // Aggregate consecutive ABSORB operations
                    current_absorb_sum += length;
                } else {
                    // Start new ABSORB sequence
                    if current_squeeze_sum > 0 {
                        // Flush previous SQUEEZE sequence
                        encoded_words[word_count] = SQUEEZE_FLAG | current_squeeze_sum;
                        word_count += 1;
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
                        encoded_words[word_count] = ABSORB_FLAG | current_absorb_sum;
                        word_count += 1;
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
        encoded_words[word_count] = ABSORB_FLAG | current_absorb_sum;
        word_count += 1;
    }
    if current_squeeze_sum > 0 {
        encoded_words[word_count] = SQUEEZE_FLAG | current_squeeze_sum;
        word_count += 1;
    }

    // Step 2: Serialize to byte string and append domain separator (following SAFE spec 2.3).
    // Create a fixed-size array for SHA256 input (max 256 bytes should be enough).
    let mut input_bytes = [0; 256];
    let mut byte_count = 0;

    // Serialize encoded words to bytes (big-endian as per SAFE spec).
    for i in 0..word_count {
        if byte_count + 4 <= 256 {
            let word = encoded_words[i];
            input_bytes[byte_count] = (word >> 24) as u8;
            input_bytes[byte_count + 1] = (word >> 16) as u8;
            input_bytes[byte_count + 2] = (word >> 8) as u8;
            input_bytes[byte_count + 3] = word as u8;
            byte_count += 4;
        }
    }

    // Append domain separator.
    for i in 0..64 {
        if byte_count + i < 256 {
            input_bytes[byte_count + i] = domain_separator[i];
        }
    }
    byte_count += 64;

    // Step 3: Hash with SHA256 and truncate to 128 bits (following SAFE spec 2.3).
    let hash_bytes = sha256_var(input_bytes, byte_count as u64);

    // Convert first 128 bits (16 bytes) to field element.
    let mut tag_value: Field = 0;
    for i in 0..16 {
        tag_value = tag_value * 256 + (hash_bytes[i] as Field);
    }

    tag_value
}

#[test]
fn test_consecutive_absorb_aggregation() {
    // Test that consecutive ABSORB operations are properly aggregated
    let domain_separator = [
        0x41, 0x42, 0x43, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ];

    // Test pattern: ABSORB(1), ABSORB(1), SQUEEZE(1)
    let io_pattern = [0x80000001, 0x80000002, 0x00000001];

    let tag = compute_tag(io_pattern, domain_separator);

    let aggregated_pattern = [0x80000003, 0x00000001];
    let aggregated_tag = compute_tag(aggregated_pattern, domain_separator);

    // The tags should be identical because the patterns are equivalent after aggregation
    assert(tag == aggregated_tag, "Consecutive ABSORB operations should aggregate to the same tag");

}
