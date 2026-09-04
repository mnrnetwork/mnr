#![no_main]
use libfuzzer_sys::fuzz_target;
use mnr_core::epee::{canonical, parse, VOLATILE_KEYS};

/// The epee reader must never panic on any input, and canonicalisation must
/// be deterministic: two passes over the same tree give the same tree, and
/// dropping the volatile keys is idempotent.
fuzz_target!(|data: &[u8]| {
    let Ok(root) = parse(data) else { return };
    let once = canonical(&root, VOLATILE_KEYS);
    let twice = canonical(&once, VOLATILE_KEYS);
    assert_eq!(once, twice, "canonical is not idempotent");
    for k in VOLATILE_KEYS {
        assert!(!once.contains_key(*k));
    }
});
