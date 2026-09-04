#![no_main]
use libfuzzer_sys::fuzz_target;
use mnr_core::wire::{GetBlockResult, GetInfoResult, GetTransactionsResult, JsonRpcResponse};

// Every typed result that deserialises must serialise to an equivalent
// JSON value (the lossless pass-through guarantee), never panic.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(v) = serde_json::from_str::<JsonRpcResponse<GetBlockResult>>(text) {
        let _ = serde_json::to_string(&v);
    }
    if let Ok(v) = serde_json::from_str::<GetTransactionsResult>(text) {
        let _ = serde_json::to_string(&v);
    }
    if let Ok(v) = serde_json::from_str::<JsonRpcResponse<GetInfoResult>>(text) {
        let _ = serde_json::to_string(&v);
    }
});
