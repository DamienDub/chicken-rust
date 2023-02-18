mod utils;

use base64::{engine::general_purpose, Engine as _};
use hex;
use sha1::{Digest, Sha1};
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, chicken-rust!");
}

#[wasm_bindgen]
pub fn sha1() -> String {
    let mut hasher = Sha1::new();
    hasher.update(b"Hello, world!");
    let result = hasher.finalize();
    return hex::encode(result);
}

#[wasm_bindgen]
pub fn base64_encode(orig: &str) -> String {
    //let orig = b"data";
    let encoded = general_purpose::STANDARD_NO_PAD.encode(orig);
    return encoded;
}

#[wasm_bindgen]
pub fn base64_decode(orig: &str) -> String {
    match general_purpose::STANDARD_NO_PAD.decode(orig) {
        Ok(result) => match String::from_utf8(result) {
            Ok(string_result) => string_result,
            Err(_) => String::from("Invalid UTF-8 encoding"),
        },
        Err(_) => String::from("Failed to decode base64 string"),
    }
}
