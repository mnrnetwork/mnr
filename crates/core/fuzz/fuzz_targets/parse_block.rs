#![no_main]
use libfuzzer_sys::fuzz_target;

// A block blob must either parse (and then re-hash deterministically) or
// return an error; it must never panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = mnr_core::hash::parse_block(data) {
        assert_eq!(mnr_core::hash::block_hash(data), Ok(parsed.hash));
    }
});
