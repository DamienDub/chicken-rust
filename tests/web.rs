//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

use chicken_rust::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn pass() {
    assert_eq!(1 + 1, 2);
}

#[wasm_bindgen_test]
fn pass_aes_cbc_128_encrypt_decrypt() {
    let encrypted = aes_cbc_128_encrypt(
        "Well hello there",
        "00112233445566778899AABBCCDDEEFF",
        "11111111111111111111111111111111",
    )
    .unwrap();
    let decrypted = aes_cbc_128_decrypt(
        &encrypted,
        "00112233445566778899AABBCCDDEEFF",
        "11111111111111111111111111111111",
    )
    .unwrap();
    assert_eq!(decrypted, "Well hello there");
}
