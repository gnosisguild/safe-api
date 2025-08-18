use poseidon::{poseidon2_permutation, poseidon::bn254::hash_16};

global RATE: u32 = 3;
global CAPACITY: u32 = 1;
global WIDTH: u32 = 4;

pub struct SafeSponge<let L: u32, let S: u32> {
    state: [Field; WIDTH],
    out: Vec<Field>,
    absorb_pos: u32,
    squeeze_pos: u32,
    io_pattern: [u32; L],
    io_count: u32,
}

impl<let L: u32, let S: u32> SafeSponge<L, S> {
    pub fn start(pattern: [u32; L], tag: Field, domain_separator: Field) -> SafeSponge<L, S> {
        let mut sponge = SafeSponge::<L, S> {
            state: [0; WIDTH],
            out: Vec::new(),
            absorb_pos: 0,
            squeeze_pos: 0,
            io_pattern: pattern,
            io_count: 0,
        };

        let calculated_tag = Self::compute_tag(pattern, domain_separator);
        assert_eq(calculated_tag, tag);

        sponge.state[0] = tag;
        sponge
    }

    pub fn absorb(mut self, input: [Field; S]) -> SafeSponge<L, S> {
        assert(self.io_pattern[self.io_count] as u32 == S);

        for i in 0..self.io_pattern[self.io_count] {
            if self.absorb_pos == RATE {
                self.state = poseidon2_permutation(self.state, self.state.len());
                self.absorb_pos = 0;
            }
            let pos = self.absorb_pos + CAPACITY;
            self.state[pos] = self.state[pos] + input[i];
            self.absorb_pos += 1;
        }
        self.io_count += 1;
        self.squeeze_pos = RATE;
        self
    }

    pub fn squeeze(mut self) -> Vec<Field> {
        for _ in 0..self.io_pattern[self.io_count] {
            if self.squeeze_pos == RATE {
                self.state = poseidon2_permutation(self.state, self.state.len());
                self.squeeze_pos = 0;
                self.absorb_pos = 0;
            }
            self.out.push(self.state[self.squeeze_pos + CAPACITY]);
            self.squeeze_pos += 1;
        }
        self.io_count += 1;
        self.out
    }

    pub fn finish(mut self) {
        // Clear the state
        self.state = [0; WIDTH];
        self.out = Vec::new();
        self.io_count = 0;
        self.io_pattern = [0; L];
        self.squeeze_pos = 0;
        self.absorb_pos = 0;
    }

    pub fn compute_tag(pattern: [u32; L], domain: Field) -> Field {
        // We will hash in blocks of 16 Fields using hash_16.
        // Encoding: [domain, L, pattern[0], pattern[1], ..., pattern[L-1]] then chaining
        // as: tag = H(block0); for next blocks use tag as first element.
        let mut block: [Field; 16] = [0; 16];
        let mut k: u32 = 0;

        // Put domain first
        block[0] = domain;
        k = 1;

        // Stream the pattern
        for i in 0..L {
            if k == 16 {
                // Hash the full block
                let h = hash_16(block);
                // Prepare next block, chaining: put the previous hash in position 0
                block = [0; 16];
                block[0] = h;
                k = 1;
            }
            block[k] = pattern[i] as Field;
            k += 1;
        }

        // Finalize: hash the last partial block (even if exactly full we already hashed above)
        // If we never hashed (short inputs), tag is defined by hashing this one block.
        let final_tag = hash_16(block);
        final_tag
    }
}

#[test]
fn test_safe_sponge() {
    let pattern = [5, 4];
    let mut safe = SafeSponge::start(
        pattern,
        0x223e46c3a63ed39f17682abaff1b6561caf974ccadc4b9e816fae5993d16c0d9,
        0,
    );
    safe = safe.absorb([1, 2, 3, 4, 5]);
    let result = safe.squeeze();

    println(result);

    assert(result.len() == 4);
    assert(result.get(0) == 0x01e2e49d0d341a48346cf6df647d812c562a337d61634d8ebee0797a71901fd8);
    assert(result.get(1) == 0x146289d0818f5cb9ba7060e0ebc0d88a5a1148f57af54dac1e83967623ebc834);
    assert(result.get(2) == 0x0e4bdf45d8f61305f5d861021eb34ff044d917aca4bb4849e3661daa6a062fa1);
    assert(result.get(3) == 0x246fed2656cb253cc638d2232dd9f767f2fc36fced080fd889cc4d8fd10b897f);

    safe.finish();
}

#[test]
fn test_safe_sponge_multiple_absorb() {
    let pattern = [3, 2];
    let mut safe = SafeSponge::start(
        pattern,
        0x2ce43dd4e7553231e29325dd45d383d35c236272b523e1332314f9a00152e1ec,
        0,
    );
    safe = safe.absorb([1, 2, 3]);
    let result = safe.squeeze();

    println(result);

    assert(result.len() == 2);
    assert(result.get(0) == 0x0d91ba7239806111cada752c7dbde279709151cccdf415988744fb382faef072);
    assert(result.get(1) == 0x2d9aff23fc194b1a45821691249820ac6542abf9d6c92fb579bf95b9c54166b0);

    safe.finish();
}
