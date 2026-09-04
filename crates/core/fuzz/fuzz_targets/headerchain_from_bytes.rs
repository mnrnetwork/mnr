#![no_main]
use libfuzzer_sys::fuzz_target;
use mnr_core::headerchain::HeaderChain;

// Anything that loads must serialise back to the same bytes.
fuzz_target!(|data: &[u8]| {
    if let Ok(chain) = HeaderChain::from_bytes(data) {
        assert_eq!(chain.to_bytes(), data);
    }
});
