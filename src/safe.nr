global RATE: u32 = 15;
global CAPACITY: u32 = 1;
global WIDTH: u32 = 16;

pub struct SafeSponge<let L: u32, let S: u32> {
    state: [Field; WIDTH],
    out: Vec<Field>,
    absorb_pos: u32,
    squeeze_pos: u32,
    io_pattern: [u32; L],
    io_count: u32,
}

impl<let L: u32, let S: u32> SafeSponge<L, S> {
    pub fn start(pattern: [u32; L], tag: Field) -> SafeSponge<L, S> {
        let mut sponge = SafeSponge::<L, S> {
            state: [0; WIDTH],
            out: Vec::new(),
            absorb_pos: 0,
            squeeze_pos: 0,
            io_pattern: pattern,
            io_count: 0,
        };
        sponge.state[0] = tag;
        sponge
    }

    pub fn absorb(mut self, input: [Field; S]) -> SafeSponge<L, S> {
        assert(self.io_pattern[self.io_count] as u32 == S);

        for i in 0..self.io_pattern[self.io_count] {
            if self.absorb_pos == RATE {
                self.state = poseidon2::bn254::perm::x5_16(self.state);
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
                self.state = poseidon2::bn254::perm::x5_16(self.state);
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
    let mut safe = SafeSponge::start(pattern, 14699256703807541932168660170536);
    safe = safe.absorb([1, 2, 3, 4, 5]);

    let result = safe.squeeze();

    assert(result.len() == 4);
    assert(result.get(0) == 0x226b428d95e9bee18a2c3b5d6ca573806fcd1652dcacb60ee7d028aaed4a4afa);
    assert(result.get(1) == 0x2d0988766d22af2854b118aba010d2f7cea7fc8ea49b797b8a2b2bebddc6106d);
    assert(result.get(2) == 0x2f24d1067f4e0c339d2c0e21dc4be1f12266e98081208a49b660cbbc6cf15818);
    assert(result.get(3) == 0x1d2df12b8766fd5f40689f3511aa0335b17e1e9e7242936e6c2e751bc912e049);

    safe.finish();
}

#[test]
fn test_safe_sponge_multiple_absorb() {
    let pattern = [3, 2];
    let mut safe = SafeSponge::start(pattern, 14699256703807541932168660170536);
    safe = safe.absorb([1, 2, 3]);
    let result = safe.squeeze();

    assert(result.len() == 2);
    assert(result.get(0) == 0x11f1116ff8b58f72f37ddb269746b54d8e0baa61e162b2b725734468616d079a);
    assert(result.get(1) == 0x14366db7277ee6a774429ab3f9a519b8e75b93527c877084d2981371fad951c0);

    safe.finish();
}
