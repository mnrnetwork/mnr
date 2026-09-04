#![no_main]
use libfuzzer_sys::fuzz_target;
use mnr_core::wire::{GetBlockResult, GetInfoResult, GetTransactionsResult, JsonRpcResponse};
use serde_json::Value;

/// A typed result that deserialises must serialise back to the same JSON
/// value: this is the lossless pass-through guarantee the relay relies on.
fn round_trips<T: serde::de::DeserializeOwned + serde::Serialize>(text: &str) {
    let Ok(typed) = serde_json::from_str::<T>(text) else { return };
    let original: Value = serde_json::from_str(text).expect("typed parse implies valid JSON");
    let again: Value = serde_json::to_value(&typed).expect("serialise");
    assert_eq!(original, again, "typed round-trip changed the JSON");
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    round_trips::<JsonRpcResponse<GetBlockResult>>(text);
    round_trips::<GetTransactionsResult>(text);
    round_trips::<JsonRpcResponse<GetInfoResult>>(text);
});
