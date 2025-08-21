use dep::safe::safe::SafeSponge;

// This is a simple example of how to use the SAFE API to hash a message.
// Taken from [test_safe_hashing] on SAFE implementation.
fn main() {
    let domain_separator = [
        0x41, 0x42, 0x43, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];

    // Pattern: ABSORB(0), SQUEEZE(1)
    let io_pattern = [0, 1];
    let sponge = SafeSponge::start(io_pattern, domain_separator);
    let sponge = sponge.absorb([]); // Natural empty array for ABSORB(0)
    let (output, sponge) = sponge.squeeze(); // No length parameter needed!
    let success = sponge.finish();

    assert(success);
    assert(output[0] != 0);
}
