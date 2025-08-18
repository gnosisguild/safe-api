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
    pub fn start(pattern: [u32; L], tag: Field, domain_seperator: Field) -> SafeSponge<L, S> {
        let mut sponge = SafeSponge::<L, S> {
            state: [0; WIDTH],
            out: Vec::new(),
            absorb_pos: 0,
            squeeze_pos: 0,
            io_pattern: pattern,
            io_count: 0,
        };
        let mut zero = [0; 16];
        zero[0] = domain_seperator;
        for i in 1..L {
            if L % 16 == 0 {
                let holder = hash_16(zero);
                zero = [0; 16];
                zero[0] = holder;
            }
            zero[i] = pattern[i] as Field;
        }
        let calculated_tag = hash_16(zero);

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
        0x188b25f8d7181aa8d25c5d9da0650bd456f2e891ba1165a7d7a371ecf9e5c12c,
        0,
    );
    safe = safe.absorb([1, 2, 3, 4, 5]);
    let result = safe.squeeze();

    assert(result.len() == 4);
    assert(result.get(0) == 0x2e93970152fc09029be9dce91ed8b1ede410d58b3b0e1f8acfc600c8af2eabcd);
    assert(result.get(1) == 0x159831dc86f04867f0b528eca2571bde1cf5a5e685a2b8be7b2fcd948c57184b);
    assert(result.get(2) == 0x23da05280dd17582862339e12e12e998d309910c72598c3704fec7387ccc389f);
    assert(result.get(3) == 0x01fb8df70f6cbf333f82d1371e194dc0b83983b8cd8752771577082d777e8065);

    safe.finish();
}

#[test]
fn test_safe_sponge_multiple_absorb() {
    let pattern = [3, 2];
    let mut safe = SafeSponge::start(
        pattern,
        0x2024ff18acb4bf8067ca89a4c7521bad1555ffe7ea04af3695a065644613ce24,
        0,
    );
    safe = safe.absorb([1, 2, 3]);
    let result = safe.squeeze();

    assert(result.len() == 2);
    assert(result.get(0) == 0x247283ff17cf3478300c6446d96dd98995af4eefc391adc2a2429be99419b3e6);
    assert(result.get(1) == 0x2e6d85985c9def9a62a456e152b4e76b93e4aee731880f12ec884c0b27badf63);

    safe.finish();
}
