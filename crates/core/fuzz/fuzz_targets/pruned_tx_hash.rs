#![no_main]
use libfuzzer_sys::fuzz_target;

// First 32 bytes play the node-supplied prunable hash, the rest is the blob.
fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let prunable: [u8; 32] = data[..32].try_into().unwrap();
    let _ = mnr_core::hash::pruned_tx_hash(&data[32..], prunable);
});
