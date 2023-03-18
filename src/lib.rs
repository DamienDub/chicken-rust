mod utils;

use base64::{engine::general_purpose, Engine as _};
use hex;
use sha1::{Digest, Sha1};
use urlencoding::{decode, encode};
use wasm_bindgen::prelude::*;

use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};


// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[derive(Debug)]
pub struct RustError {
    pub message: String,
}

use wasm_bindgen::JsValue;
impl From<RustError> for JsValue {
    fn from(error: RustError) -> Self {
        JsValue::from_str(&error.message)
    }
}

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, chicken-rust!");
}

#[wasm_bindgen]
pub fn sha1(input: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(input);
    return hex::encode(hasher.finalize());
}

#[wasm_bindgen]
pub fn base64_encode(input: &str) -> String {
    return general_purpose::STANDARD_NO_PAD.encode(input);
}

#[wasm_bindgen]
pub fn base64_decode(input: &str) -> Result<String, RustError> {
    match general_purpose::STANDARD_NO_PAD.decode(input) {
        Ok(result) => match String::from_utf8(result) {
            Ok(string_result) => Ok(string_result),
            Err(_) => Err(RustError {
                message: "Failed to turn bytes into UTF-8 string".to_string(),
            }),
        },
        Err(_) => Err(RustError {
            message: "Failed to decode base 64 string".to_string(),
        }),
    }
}

#[wasm_bindgen]
pub fn url_encode(input: &str) -> String {
    return encode(input);
}

#[wasm_bindgen]
pub fn url_decode(input: &str) -> Result<String, RustError> {
    match decode(input) {
        Ok(string_result) => Ok(string_result),
        Err(_) => Err(RustError {
            message: "Failed to decode encoded URL".to_string(),
        }),
    }
}

#[wasm_bindgen]
pub fn aes_encrypt() -> String {

    let key = GenericArray::from([0u8; 16]);
    let mut block = GenericArray::from([42u8; 16]);

    let cipher = Aes128::new(&key);

    let block_copy = block.clone();

// Encrypt block in-place
cipher.encrypt_block(&mut block);

// And decrypt it back
cipher.decrypt_block(&mut block);
assert_eq!(block, block_copy);

    return "ok".to_string();
}