#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = mnr_core::hash::parse_tx(data) {
        // Agrees with the hashing entry point on the same bytes.
        assert_eq!(Some(p.hash), mnr_core::hash::tx_hash(data).ok());
        assert!(p.weight >= p.blob_size);
    }
});
