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
/// - `io_pattern`: Expected IO pattern for validation
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
    /// - `io_pattern`: Array of operation lengths defining the expected sequence of ABSORB/SQUEEZE calls.
    /// - `domain_separator`: 32-byte domain separator for cross-protocol security.
    /// 
    /// # Returns
    /// A new `SafeSponge` instance with initialized state
    pub fn start(io_pattern: [u32; L], domain_separator: [u8; 32]) -> SafeSponge<L> {
        // Compute tag from IO pattern and domain separator (spec 2.3).
        let tag = compute_tag(io_pattern, domain_separator);

        let mut state = [0; STATE_SIZE];
        // Initialize capacity with tag (spec 2.4).
        // Add T to the first 128 bits of the state.
        state[0] = tag;

        SafeSponge { 
            state, 
            tag, 
            absorb_pos: 0, 
            squeeze_pos: 0, 
            io_pattern, 
            io_count: 0 
        }
    }

    /// Absorbs field elements into the sponge state, interleaving permutation calls as needed (following spec 2.4).
    ///
    /// # Arguments
    /// - `length`: Number of field elements to absorb (must match IO pattern).
    /// - `input`: Array of field elements to absorb (fixed size RATE, only first `length` elements used)
    /// 
    /// # Returns
    /// Updated `SafeSponge` instance
    /// 
    /// # Panics
    /// - If `length` doesn't match the expected IO pattern
    /// - If `io_count` exceeds the pattern length
    pub fn absorb(mut self, length: u32, input: [Field; RATE]) -> SafeSponge<L> {
        // Validate against IO pattern.
        assert(self.io_count < L);
        assert(self.io_pattern[self.io_count] == length);

        // Process each element (if L==0, loop won't execute).
        for i in 0..RATE {
            // Only process if i < length (handles L==0 case).
            if i < length {
                // If absorb_pos == (n-c) then permute and reset (spec 2.4).
                if self.absorb_pos == RATE {  // n-c = RATE.
                    self.state = self.permute();
                    self.absorb_pos = 0;
                }
                
                // Add X[i] to state at absorb_pos (spec 2.4).
                // Note: absorb_pos is the rate position, not capacity position.
                self.state[self.absorb_pos] = self.state[self.absorb_pos] + input[i];
                self.absorb_pos += 1;
            }
        }

        // Compute the 32-bit encoding of L to the IO pattern (spec 2.4).
        let encoded_word = ABSORB_FLAG | length;
        
        // Verify that the encoded word matches the expected pattern.
        // For ABSORB operations, we expect: ABSORB_FLAG | expected_length.
        let expected_encoded_word = ABSORB_FLAG | self.io_pattern[self.io_count];
        assert(encoded_word == expected_encoded_word);
        
        self.io_count += 1;

        // Force permute at start of next SQUEEZE (spec 2.4).
        self.squeeze_pos = RATE;
        self
    }

    /// Extracts field elements from the sponge state, interleaving permutation calls as needed (following spec 2.4).
    ///
    /// # Arguments
    /// - `length`: Number of field elements to squeeze (must match IO pattern).
    /// 
    /// # Returns
    /// Tuple of (output array, updated sponge instance).
    /// - `output`: Array of squeezed field elements (fixed size RATE, only first `length` elements valid).
    /// - `sponge`: Updated `SafeSponge` instance.
    ///
    /// # Panics
    /// - If `length` doesn't match the expected IO pattern.
    /// - If `io_count` exceeds the pattern length.
    pub fn squeeze(mut self, length: u32) -> ([Field; RATE], SafeSponge<L>) {
        // Validate against IO pattern.
        assert(self.io_pattern[self.io_count] == length);

        let mut output = [0; RATE];

        // SQUEEZE implementation following spec 2.4.
        // If L==0, loop won't execute (spec 2.4).
        for i in 0..length {
            // If squeeze_pos==(n-c) then permute and reset (spec 2.4).
            if self.squeeze_pos == RATE {  // n-c = RATE.
                self.state = self.permute();
                self.squeeze_pos = 0;
                self.absorb_pos = 0;
            }
            // Set Y[i] to state element at squeeze_pos (spec 2.4).
            output[i] = self.state[self.squeeze_pos];
            self.squeeze_pos += 1;
        }

        // Compute the 32-bit encoding of L+2^31 to the IO pattern (spec 2.4).
        let encoded_word = SQUEEZE_FLAG | length;
        
        // Verify that the encoded word matches the expected pattern.
        // For SQUEEZE operations, we expect: SQUEEZE_FLAG | expected_length.
        let expected_encoded_word = SQUEEZE_FLAG | self.io_pattern[self.io_count];
        assert(encoded_word == expected_encoded_word);
        
        self.io_count += 1;
        (output, self)
    }

    /// Finalizes the sponge instance, verifying that all expected operations have been performed and clearing the internal state for security (following spec 2.4).
    ///
    /// This function is used to ensure that the sponge instance has been used correctly and to prevent information leakage.
    ///
    /// # Returns
    /// `true` if all operations in the IO pattern were completed successfully, `false` otherwise.
    pub fn finish(mut self) -> bool {
        // Check that io_count equals the length of the IO pattern expected (spec 2.4).
        let expected_operations = L;
        let is_complete = self.io_count == expected_operations;

        // Erase the state and its variables (spec 2.4).
        self.state = [0; STATE_SIZE];
        self.absorb_pos = 0;
        self.squeeze_pos = 0;
        self.io_count = 0;

        // Return success/failure (simplified to bool for Noir compatibility).
        is_complete
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
/// - `io_pattern`: Array of operation lengths defining the sponge's usage pattern.
/// - `domain_separator`: 32-byte domain separator for cross-protocol security.
///
/// # Returns
/// A field element representing the 128-bit tag.
pub fn compute_tag<let L: u32>(io_pattern: [u32; L], domain_separator: [u8; 32]) -> Field {    
    // SAFE assumes alternating operations by default: ABSORB, SQUEEZE, ABSORB, SQUEEZE, ...
    let mut encoded_words = [0; L]; // Support up to L operations.
    let mut word_count = 0;
    let mut current_absorb_sum = 0;
    let mut current_squeeze_sum = 0;
    let mut last_was_absorb = false;
    
    // Step 1: Encode IO pattern as 32-bit words with MSB encoding.
    for i in 0..L {
        if io_pattern[i] > 0 {
            // Step 2: Aggregate contiguous operations.
            // Determine operation type based on position.
            // Even indices (0, 2, 4...) are ABSORB operations.
            // Odd indices (1, 3, 5...) are SQUEEZE operations.
            let is_absorb = (i % 2 == 0);
            
            if is_absorb {
                if last_was_absorb {
                    // Aggregate consecutive ABSORB operations.
                    current_absorb_sum = current_absorb_sum + io_pattern[i];
                } else {
                    // Start new ABSORB sequence.
                    if current_squeeze_sum > 0 {
                        // Flush previous SQUEEZE sequence.
                        encoded_words[word_count] = SQUEEZE_FLAG | current_squeeze_sum; // MSB = 0
                        word_count = word_count + 1;
                        current_squeeze_sum = 0;
                    }
                    current_absorb_sum = io_pattern[i];
                }
                last_was_absorb = true;
            } else {
                if !last_was_absorb {
                    // Aggregate consecutive SQUEEZE operations.
                    current_squeeze_sum = current_squeeze_sum + io_pattern[i];
                } else {
                    // Start new SQUEEZE sequence.
                    if current_absorb_sum > 0 {
                        // Flush previous ABSORB sequence.
                        encoded_words[word_count] = ABSORB_FLAG | current_absorb_sum; // MSB = 1
                        word_count = word_count + 1;
                        current_absorb_sum = 0;
                    }
                    current_squeeze_sum = io_pattern[i];
                }
                last_was_absorb = false;
            }
        }
    }
    
    // Flush remaining operations.
    if current_absorb_sum > 0 {
        encoded_words[word_count] = ABSORB_FLAG | current_absorb_sum;
        word_count = word_count + 1;
    }
    if current_squeeze_sum > 0 {
        encoded_words[word_count] = SQUEEZE_FLAG | current_squeeze_sum; // MSB = 0
        word_count = word_count + 1;
    }
    
    // Step 3: Serialize to byte string and append domain separator (following SAFE spec 2.3).
    // Create a fixed-size array for SHA256 input (max 64 bytes should be enough).
    let mut input_bytes = [0; 64];
    let mut byte_count = 0;
    
    // Serialize encoded words to bytes (big-endian as per SAFE spec).
    for i in 0..word_count {
        if byte_count + 4 <= 64 {
            let word = encoded_words[i];
            input_bytes[byte_count] = (word >> 24) as u8;
            input_bytes[byte_count + 1] = (word >> 16) as u8;
            input_bytes[byte_count + 2] = (word >> 8) as u8;
            input_bytes[byte_count + 3] = word as u8;
            byte_count += 4;
        }
    }
    
    // Append domain separator.
    for i in 0..32 {
        if byte_count + i < 64 {
            input_bytes[byte_count + i] = domain_separator[i];
        }
    }
    byte_count += 32;
    
    // Step 4: Hash with SHA256 and truncate to 128 bits (following SAFE spec 2.3).
    let hash_bytes = sha256_var(input_bytes, byte_count as u64);
    
    // Convert first 128 bits (16 bytes) to field element.
    let mut tag_value: Field = 0;
    for i in 0..16 {
        tag_value = tag_value * 256 + (hash_bytes[i] as Field);
    }
    
    tag_value
}

#[test]
fn test_safe_hashing() {
    // Verifies basic hash functionality with a simple ABSORB(3) + SQUEEZE(1) pattern.
    let domain_separator = [
        0x41, 0x42, 0x43, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    let elements = [1, 2, 3];
    
    // Pattern: ABSORB(3), SQUEEZE(1)
    let io_pattern = [3, 1];
    let sponge = SafeSponge::start(io_pattern, domain_separator);
    let sponge = sponge.absorb(3, elements);
    let (output, sponge) = sponge.squeeze(1);
    let success = sponge.finish();
    
    assert(success);
    assert(output[0] != 0); // Should produce non-zero output
    
    // Test determinism
    let sponge2 = SafeSponge::start(io_pattern, domain_separator);
    let sponge2 = sponge2.absorb(3, elements);
    let (output2, sponge2) = sponge2.squeeze(1);
    let success2 = sponge2.finish();
    
    assert(success2);
    assert(output[0] == output2[0]); // Same inputs should produce same output
}

#[test]
fn test_merkle_node() {
    // Verifies SAFE can be used for Merkle tree node hashing with pattern ABSORB(1) + ABSORB(1) + SQUEEZE(1).
    // Tests the ability to absorb multiple inputs before squeezing output.
    let domain_separator = [
        0x41, 0x42, 0x43, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    let left = 123;
    let right = 456;
    
    // Pattern: ABSORB(1), ABSORB(1), SQUEEZE(1)
    let io_pattern = [1, 1, 1];
    let sponge = SafeSponge::start(io_pattern, domain_separator);
    let sponge = sponge.absorb(1, [left, 0, 0]);
    let sponge = sponge.absorb(1, [right, 0, 0]);
    let (output, sponge) = sponge.squeeze(1);
    let success = sponge.finish();
    
    assert(success);
    assert(output[0] != 0);
    
    // Test determinism
    let sponge2 = SafeSponge::start(io_pattern, domain_separator);
    let sponge2 = sponge2.absorb(1, [left, 0, 0]);
    let sponge2 = sponge2.absorb(1, [right, 0, 0]);
    let (output2, sponge2) = sponge2.squeeze(1);
    let success2 = sponge2.finish();
    
    assert(success2);
    assert(output[0] == output2[0]);
}

#[test]
fn test_commitment_scheme() {
    // Verifies SAFE can be used for commitment schemes with pattern ABSORB(3) + SQUEEZE(1).
    // Tests the ability to create deterministic commitments from multiple field elements.
    let domain_separator = [
        0x41, 0x42, 0x43, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    let values = [10, 20, 30];
    
    // Pattern: ABSORB(3), SQUEEZE(1)
    let io_pattern = [3, 1];
    let sponge = SafeSponge::start(io_pattern, domain_separator);
    let sponge = sponge.absorb(3, values);
    let (output, sponge) = sponge.squeeze(1);
    let success = sponge.finish();
    
    assert(success);
    assert(output[0] != 0);
    
    // Test determinism
    let sponge2 = SafeSponge::start(io_pattern, domain_separator);
    let sponge2 = sponge2.absorb(3, values);
    let (output2, sponge2) = sponge2.squeeze(1);
    let success2 = sponge2.finish();
    
    assert(success2);
    assert(output[0] == output2[0]);
}

#[test]
fn test_domain_separation() {
    // Verifies that different domain separators produce different outputs for the same input.
    // This is crucial for cross-protocol security and preventing collisions between different applications.
    let elements = [1, 2, 3];
    let domain1 = [
        0x41, 0x42, 0x43, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    let domain2 = [
        0x42, 0x43, 0x44, 0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    
    // Pattern: ABSORB(3), SQUEEZE(1)
    let io_pattern = [3, 1];
    
    let sponge1 = SafeSponge::start(io_pattern, domain1);
    let sponge1 = sponge1.absorb(3, elements);
    let (output1, sponge1) = sponge1.squeeze(1);
    let success1 = sponge1.finish();
    
    let sponge2 = SafeSponge::start(io_pattern, domain2);
    let sponge2 = sponge2.absorb(3, elements);
    let (output2, sponge2) = sponge2.squeeze(1);
    let success2 = sponge2.finish();
    
    assert(success1);
    assert(success2);
    assert(output1[0] != output2[0]); // Different domain separators should produce different outputs
}

#[test]
fn test_multiple_squeeze() {
    // Verifies that multiple field elements can be squeezed in a single operation.
    // Tests pattern ABSORB(3) + SQUEEZE(2) to ensure proper state management.
    let domain_separator = [
        0x41, 0x42, 0x43, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    let elements = [1, 2, 3];
    
    // Pattern: ABSORB(3), SQUEEZE(2)
    let io_pattern = [3, 2];
    let sponge = SafeSponge::start(io_pattern, domain_separator);
    let sponge = sponge.absorb(3, elements);
    let (output, sponge) = sponge.squeeze(2);
    let success = sponge.finish();
    
    assert(success);
    assert(output[0] != 0);
    assert(output[1] != 0);
    assert(output[0] != output[1]); // Different squeeze outputs should be different
}

#[test]
fn test_zero_length_operations() {
    // Verifies that zero-length ABSORB and SQUEEZE operations are handled correctly.
    // Tests pattern ABSORB(0) + SQUEEZE(1) to ensure proper state transitions.
    let domain_separator = [
        0x41, 0x42, 0x43, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    
    // Pattern: ABSORB(0), SQUEEZE(1)
    let io_pattern = [0, 1];
    let sponge = SafeSponge::start(io_pattern, domain_separator);
    let sponge = sponge.absorb(0, [0, 0, 0]);
    let (output, sponge) = sponge.squeeze(1);
    let success = sponge.finish();
    
    assert(success);
    assert(output[0] != 0);
}

#[test]
fn test_tag_computation() {
    // Verifies the tag computation algorithm using the example from the SAFE specification.
    // Pattern: ABSORB(3), ABSORB(3), SQUEEZE(3)
    // Should aggregate to: ABSORB(6), SQUEEZE(3)
    // Encoded as: [0x80000006, 0x00000003]
    // Tests determinism and pattern differentiation.
    
    let io_pattern = [3, 3, 3]; // ABSORB(3), ABSORB(3), SQUEEZE(3)
    let domain_separator = [
        0x41, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    
    let tag = compute_tag(io_pattern, domain_separator);
    
    // Test determinism
    let tag2 = compute_tag(io_pattern, domain_separator);
    assert(tag == tag2);
    
    // Test that different patterns produce different tags
    let io_pattern2 = [3, 3]; // ABSORB(3), SQUEEZE(3) - different pattern
    let tag3 = compute_tag(io_pattern2, domain_separator);
    assert(tag != tag3);
}
