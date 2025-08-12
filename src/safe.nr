use poseidon::poseidon2_permutation;
use std::{field::bytes32_to_field, hash::blake3};

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
    pub fn start(pattern: [u8; L], tag: Field, domain_seperator: [u8; 32]) -> SafeSponge<L, S> {
        let mut sponge = SafeSponge::<L, S> {
            state: [0; WIDTH],
            out: Vec::new(),
            absorb_pos: 0,
            squeeze_pos: 0,
            io_pattern: pattern.map(|x| x as u32),
            io_count: 0,
        };
        let domain_seperator = blake3(domain_seperator);
        let pattern = blake3(pattern);
        let append = domain_seperator.as_slice().append(pattern);
        let appended_array = blake3::<32>(append.as_array());
        let calculated_tag = bytes32_to_field(appended_array);

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
}

#[test]
fn test_safe_sponge() {
    let pattern = [5, 4];
    let mut safe = SafeSponge::start(
        pattern,
        0x08b20edb93602bbdcddacf7b28c57ba11c1b4188bf7cdd66e0d32e1db041068f,
        [0; 32],
    );
    safe = safe.absorb([1, 2, 3, 4, 5]);
    let result = safe.squeeze();

    assert(result.len() == 4);
    assert(result.get(0) == 0x22400c5a571bb23765d5ec1352d9e2b12d5c24eb54d1188fca42ef011412d0d8);
    assert(result.get(1) == 0x2d9a6124e55f9307a44b8809f5ef14a07f67bf7fc969d006778d2234f9cc18bd);
    assert(result.get(2) == 0x2800bfb105e87f76928dce25ab31dcb9e295b80cb3517dba1782277fe03f460e);
    assert(result.get(3) == 0x06bcdcb4f5d18213897fb8508cbe12caa22f21f4f685857efcb79700fc323688);

    safe.finish();
}

#[test]
fn test_safe_sponge_multiple_absorb() {
    let pattern = [3, 2];
    let mut safe = SafeSponge::start(
        pattern,
        0x0c981e5ec918f5d95d2e88366524edf338bed5331e8a55af3b9aebbc451d4be2,
        [0; 32],
    );
    safe = safe.absorb([1, 2, 3]);
    let result = safe.squeeze();

    assert(result.len() == 2);
    assert(result.get(0) == 0x20c307ccabdf9b175700090466b3471499ea0514ebe050b9f3965556ac8e147e);
    assert(result.get(1) == 0x22609a64b2d3b2c6459c61696ebaa12d16be6196ef66cfb68de6a516f3073ea0);

    safe.finish();
}
