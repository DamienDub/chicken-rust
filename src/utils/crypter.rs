use aes::{Aes128, Aes192, Aes256};
use base64::{engine::general_purpose, Engine as _};
use block_padding::Pkcs7;
use cbc::Decryptor as CbcDecryptor;
use cbc::Encryptor as CbcEncryptor;
use cipher::{BlockCipher, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use des::{Des, TdesEde2, TdesEde3};
use ecb::Decryptor as EcbDecryptor;
use ecb::Encryptor as EcbEncryptor;
use hex;

pub fn des_cbc_encrypt(
    key: &str,
    iv: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_64 = [0x42; 8];
    decode_hex_key_64(key, &mut key_bytes_64).unwrap();

    // Get IV as bytes
    let mut iv_bytes = [0x42; 8];
    decode_hex_iv_64(iv, &mut iv_bytes).unwrap();

    // Encrypt
    let cipher = CbcEncryptor::<Des>::new(&key_bytes_64.into(), &iv_bytes.into());
    return cbc_encrypt(cipher, get_buffer(plaintext), plaintext.len(), hex_output);
}

pub fn des_cbc_decrypt(
    key: &str,
    iv: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_64 = [0x42; 8];
    decode_hex_key_64(key, &mut key_bytes_64).unwrap();

    // Get IV as bytes
    let mut iv_bytes = [0x42; 8];
    decode_hex_iv_64(iv, &mut iv_bytes).unwrap();

    // Decrypt
    let cipher = CbcDecryptor::<Des>::new(&key_bytes_64.into(), &iv_bytes.into());
    return cbc_decrypt(cipher, decode_input(ciphertext, hex_input).unwrap());
}

pub fn des_ecb_encrypt(
    key: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_64 = [0x42; 8];
    decode_hex_key_64(key, &mut key_bytes_64).unwrap();

    // Encrypt
    let cipher = EcbEncryptor::<Des>::new(&key_bytes_64.into());
    return ecb_encrypt(cipher, get_buffer(plaintext), plaintext.len(), hex_output);
}

pub fn des_ecb_decrypt(
    key: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_64 = [0x42; 8];
    decode_hex_key_64(key, &mut key_bytes_64).unwrap();

    // Decrypt
    let cipher = EcbDecryptor::<Des>::new(&key_bytes_64.into());
    return ecb_decrypt(cipher, decode_input(ciphertext, hex_input).unwrap());
}

pub fn tripledes_keying2_cbc_encrypt(
    key: &str,
    iv: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    decode_hex_key_128(key, &mut key_bytes_128).unwrap();

    // Get IV as bytes
    let mut iv_bytes = [0x42; 8];
    decode_hex_iv_64(iv, &mut iv_bytes).unwrap();

    // Encrypt
    let cipher = CbcEncryptor::<TdesEde2>::new(&key_bytes_128.into(), &iv_bytes.into());
    return cbc_encrypt(cipher, get_buffer(plaintext), plaintext.len(), hex_output);
}

pub fn tripledes_keying2_cbc_decrypt(
    key: &str,
    iv: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    decode_hex_key_128(key, &mut key_bytes_128).unwrap();

    // Get IV as bytes
    let mut iv_bytes = [0x42; 8];
    decode_hex_iv_64(iv, &mut iv_bytes).unwrap();

    // Get ciphertext as bytes
    let buffer = decode_input(ciphertext, hex_input).unwrap();

    // Decrypt
    let cipher = CbcDecryptor::<TdesEde2>::new(&key_bytes_128.into(), &iv_bytes.into());
    return cbc_decrypt(cipher, buffer);
}

pub fn tripledes_keying3_cbc_encrypt(
    key: &str,
    iv: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_192 = [0x42; 24];
    decode_hex_key_192(key, &mut key_bytes_192).unwrap();

    // Get IV as bytes
    let mut iv_bytes = [0x42; 8];
    decode_hex_iv_64(iv, &mut iv_bytes).unwrap();

    // Encrypt
    let cipher = CbcEncryptor::<TdesEde3>::new(&key_bytes_192.into(), &iv_bytes.into());
    return cbc_encrypt(cipher, get_buffer(plaintext), plaintext.len(), hex_output);
}

pub fn tripledes_keying3_cbc_decrypt(
    key: &str,
    iv: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_192 = [0x42; 24];
    decode_hex_key_192(key, &mut key_bytes_192).unwrap();

    // Get IV as bytes
    let mut iv_bytes = [0x42; 8];
    decode_hex_iv_64(iv, &mut iv_bytes).unwrap();

    // Decrypt
    let cipher = CbcDecryptor::<TdesEde3>::new(&key_bytes_192.into(), &iv_bytes.into());
    return cbc_decrypt(cipher, decode_input(ciphertext, hex_input).unwrap());
}

pub fn tripledes_keying2_ecb_encrypt(
    key: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    decode_hex_key_128(key, &mut key_bytes_128).unwrap();

    // Encrypt
    let cipher = EcbEncryptor::<TdesEde2>::new(&key_bytes_128.into());
    return ecb_encrypt(cipher, get_buffer(plaintext), plaintext.len(), hex_output);
}

pub fn tripledes_keying2_ecb_decrypt(
    key: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    decode_hex_key_128(key, &mut key_bytes_128).unwrap();

    // Decrypt
    let cipher = EcbDecryptor::<TdesEde2>::new(&key_bytes_128.into());
    return ecb_decrypt(cipher, decode_input(ciphertext, hex_input).unwrap());
}

pub fn tripledes_keying3_ecb_encrypt(
    key: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_192 = [0x42; 24];
    decode_hex_key_192(key, &mut key_bytes_192).unwrap();

    // Encrypt
    let cipher = EcbEncryptor::<TdesEde3>::new(&key_bytes_192.into());
    return ecb_encrypt(cipher, get_buffer(plaintext), plaintext.len(), hex_output);
}

pub fn tripledes_keying3_ecb_decrypt(
    key: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_192 = [0x42; 24];
    decode_hex_key_192(key, &mut key_bytes_192).unwrap();

    // Decrypt
    let cipher = EcbDecryptor::<TdesEde3>::new(&key_bytes_192.into());
    return ecb_decrypt(cipher, decode_input(ciphertext, hex_input).unwrap());
}

pub fn aes_128_cbc_encrypt(
    key: &str,
    iv: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes = [0x42; 16];
    decode_hex_key_128(key, &mut key_bytes).unwrap();

    // Get IV as bytes
    let mut iv_bytes = [0x42; 16];
    decode_hex_iv_128(iv, &mut iv_bytes).unwrap();

    // Encrypt
    let cipher = CbcEncryptor::<Aes128>::new(&key_bytes.into(), &iv_bytes.into());
    return cbc_encrypt(cipher, get_buffer(plaintext), plaintext.len(), hex_output);
}

pub fn aes_192_cbc_encrypt(
    key: &str,
    iv: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes = [0x42; 24];
    decode_hex_key_192(key, &mut key_bytes).unwrap();

    // Get IV as bytes
    let mut iv_bytes = [0x42; 16];
    decode_hex_iv_128(iv, &mut iv_bytes).unwrap();

    // Encrypt
    let cipher = CbcEncryptor::<Aes192>::new(&key_bytes.into(), &iv_bytes.into());
    return cbc_encrypt(cipher, get_buffer(plaintext), plaintext.len(), hex_output);
}

pub fn aes_256_cbc_encrypt(
    key: &str,
    iv: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes = [0x42; 32];
    decode_hex_key_256(key, &mut key_bytes).unwrap();

    // Get IV as bytes
    let mut iv_bytes = [0x42; 16];
    decode_hex_iv_128(iv, &mut iv_bytes).unwrap();

    // Encrypt
    let cipher = CbcEncryptor::<Aes256>::new(&key_bytes.into(), &iv_bytes.into());
    return cbc_encrypt(cipher, get_buffer(plaintext), plaintext.len(), hex_output);
}

pub fn aes_128_cbc_decrypt(
    key: &str,
    iv: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes = [0x42; 16];
    decode_hex_key_128(key, &mut key_bytes).unwrap();

    // Get IV as bytes
    let mut iv_bytes = [0x42; 16];
    decode_hex_iv_128(iv, &mut iv_bytes).unwrap();

    // Decrypt
    let cipher = CbcDecryptor::<Aes128>::new(&key_bytes.into(), &iv_bytes.into());
    return cbc_decrypt(cipher, decode_input(ciphertext, hex_input).unwrap());
}

pub fn aes_192_cbc_decrypt(
    key: &str,
    iv: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes = [0x42; 24];
    decode_hex_key_192(key, &mut key_bytes).unwrap();

    // Get IV as bytes
    let mut iv_bytes = [0x42; 16];
    decode_hex_iv_128(iv, &mut iv_bytes).unwrap();

    // Decrypt
    let cipher = CbcDecryptor::<Aes192>::new(&key_bytes.into(), &iv_bytes.into());
    return cbc_decrypt(cipher, decode_input(ciphertext, hex_input).unwrap());
}

pub fn aes_256_cbc_decrypt(
    key: &str,
    iv: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes = [0x42; 32];
    decode_hex_key_256(key, &mut key_bytes).unwrap();

    // Get IV as bytes
    let mut iv_bytes = [0x42; 16];
    decode_hex_iv_128(iv, &mut iv_bytes).unwrap();

    // Decrypt
    let cipher = CbcDecryptor::<Aes256>::new(&key_bytes.into(), &iv_bytes.into());
    return cbc_decrypt(cipher, decode_input(ciphertext, hex_input).unwrap());
}

pub fn aes_128_ecb_encrypt(
    key: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes = [0x42; 16];
    decode_hex_key_128(key, &mut key_bytes).unwrap();

    // Encrypt
    let cipher = EcbEncryptor::<Aes128>::new(&key_bytes.into());
    return ecb_encrypt(cipher, get_buffer(plaintext), plaintext.len(), hex_output);
}

pub fn aes_192_ecb_encrypt(
    key: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes = [0x42; 24];
    decode_hex_key_192(key, &mut key_bytes).unwrap();

    // Encrypt
    let cipher = EcbEncryptor::<Aes192>::new(&key_bytes.into());
    return ecb_encrypt(cipher, get_buffer(plaintext), plaintext.len(), hex_output);
}

pub fn aes_256_ecb_encrypt(
    key: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes = [0x42; 32];
    decode_hex_key_256(key, &mut key_bytes).unwrap();

    // Encrypt
    let cipher = EcbEncryptor::<Aes256>::new(&key_bytes.into());
    return ecb_encrypt(cipher, get_buffer(plaintext), plaintext.len(), hex_output);
}

pub fn aes_128_ecb_decrypt(
    key: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes = [0x42; 16];
    decode_hex_key_128(key, &mut key_bytes).unwrap();

    // Decrypt
    let cipher = EcbDecryptor::<Aes128>::new(&key_bytes.into());
    return ecb_decrypt(cipher, decode_input(ciphertext, hex_input).unwrap());
}

pub fn aes_192_ecb_decrypt(
    key: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes = [0x42; 24];
    decode_hex_key_192(key, &mut key_bytes).unwrap();

    // Decrypt
    let cipher = EcbDecryptor::<Aes192>::new(&key_bytes.into());
    return ecb_decrypt(cipher, decode_input(ciphertext, hex_input).unwrap());
}

pub fn aes_256_ecb_decrypt(
    key: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes = [0x42; 32];
    decode_hex_key_256(key, &mut key_bytes).unwrap();

    // Decrypt
    let cipher = EcbDecryptor::<Aes256>::new(&key_bytes.into());
    return ecb_decrypt(cipher, decode_input(ciphertext, hex_input).unwrap());
}

fn closest_upper_multiple_(number: usize, multiple: usize) -> usize {
    let remainder = number % multiple;
    if remainder == 0 {
        number
    } else {
        number + multiple - remainder
    }
}

fn decode_hex_key_64(key: &str, key_bytes: &mut [u8; 8]) -> Result<(), &'static str> {
    let result: Vec<u8> = decode_hex_key(key).unwrap();
    if result.len() != 8 {
        return Err("The key must be 8 bytes long");
    }
    key_bytes.copy_from_slice(&result);

    return Ok(());
}

fn decode_hex_key_128(key: &str, key_bytes: &mut [u8; 16]) -> Result<(), &'static str> {
    let result: Vec<u8> = decode_hex_key(key).unwrap();
    if result.len() != 16 {
        return Err("The key must be 16 bytes long");
    }
    key_bytes.copy_from_slice(&result);

    return Ok(());
}

fn decode_hex_key_192(key: &str, key_bytes: &mut [u8; 24]) -> Result<(), &'static str> {
    let result: Vec<u8> = decode_hex_key(key).unwrap();
    if result.len() != 24 {
        return Err("The key must be 24 bytes long");
    }
    key_bytes.copy_from_slice(&result);

    return Ok(());
}

fn decode_hex_key_256(key: &str, key_bytes: &mut [u8; 32]) -> Result<(), &'static str> {
    let result: Vec<u8> = decode_hex_key(key).unwrap();
    if result.len() != 32 {
        return Err("The key must be 32 bytes long");
    }
    key_bytes.copy_from_slice(&result);

    return Ok(());
}

fn decode_hex_key(key: &str) -> Result<Vec<u8>, &'static str> {
    match hex::decode(key) {
        Ok(decoded) => Ok(decoded),
        Err(_) => {
            return Err("The key is not an hexadecimal string");
        }
    }
}

fn decode_hex_iv_64(key: &str, iv_bytes: &mut [u8; 8]) -> Result<(), &'static str> {
    let result: Vec<u8> = decode_hex_iv(key).unwrap();
    if result.len() != 8 {
        return Err("The IV must be 8 bytes long");
    }
    iv_bytes.copy_from_slice(&result);

    return Ok(());
}

fn decode_hex_iv_128(key: &str, iv_bytes: &mut [u8; 16]) -> Result<(), &'static str> {
    let result: Vec<u8> = decode_hex_iv(key).unwrap();
    if result.len() != 16 {
        return Err("The IV must be 16 bytes long");
    }
    iv_bytes.copy_from_slice(&result);

    return Ok(());
}

fn decode_hex_iv(key: &str) -> Result<Vec<u8>, &'static str> {
    match hex::decode(key) {
        Ok(decoded) => Ok(decoded),
        Err(_) => {
            return Err("The IV is not an hexadecimal string");
        }
    }
}

// Copy plaintext to a buffer with a length that is a multiple of 128
fn get_buffer(plaintext: &str) -> Vec<u8> {
    let plaintext_len = plaintext.len();
    let mut buf = vec![0u8; closest_upper_multiple_(plaintext_len, 128)];
    buf[..plaintext_len].copy_from_slice(&plaintext.as_bytes());
    return buf;
}

fn decode_input(input: &str, hex_input: bool) -> Result<Vec<u8>, &'static str> {
    if hex_input {
        match hex::decode(input) {
            Ok(bytes_result) => Ok(bytes_result),
            Err(_) => return Err("The input text is not an hexadecimal string"),
        }
    } else {
        match general_purpose::STANDARD.decode(input) {
            Ok(bytes_result) => Ok(bytes_result),
            Err(_) => return Err("The input text is not a base 64 string"),
        }
    }
}

fn cbc_encrypt<C: BlockEncryptMut + BlockCipher>(
    cipher: CbcEncryptor<C>,
    mut buffer: Vec<u8>,
    length: usize,
    hex_output: bool,
) -> Result<String, &'static str> {
    match cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, length) {
        Ok(result) => return Ok(encode_output(result, hex_output)),
        Err(_) => return Err("Failed to perform CBC encryption"),
    }
}

fn cbc_decrypt<C: BlockDecryptMut + BlockCipher>(
    cipher: CbcDecryptor<C>,
    mut buffer: Vec<u8>,
) -> Result<String, &'static str> {
    match cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer) {
        Ok(bytes_result) => encode_output_to_str(bytes_result),
        Err(_) => Err("Failed to perform CBC decryption"),
    }
}

fn ecb_encrypt<C: BlockEncryptMut + BlockCipher>(
    cipher: EcbEncryptor<C>,
    mut buffer: Vec<u8>,
    length: usize,
    hex_output: bool,
) -> Result<String, &'static str> {
    match cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, length) {
        Ok(result) => return Ok(encode_output(result, hex_output)),
        Err(_) => return Err("Failed to perform ECB encryption"),
    }
}

fn ecb_decrypt<C: BlockDecryptMut + BlockCipher>(
    cipher: EcbDecryptor<C>,
    mut buffer: Vec<u8>,
) -> Result<String, &'static str> {
    match cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer) {
        Ok(bytes_result) => encode_output_to_str(bytes_result),
        Err(_) => Err("Failed to perform ECB decryption"),
    }
}

fn encode_output(output: &[u8], hex_output: bool) -> String {
    if hex_output {
        return hex::encode(&output);
    } else {
        return general_purpose::STANDARD.encode(&output);
    }
}

fn encode_output_to_str(output: &[u8]) -> Result<String, &'static str> {
    match std::str::from_utf8(output) {
        Ok(string_result) => Ok(string_result.to_string()),
        Err(_) => Err("Failed to encode bytes to UTF-8 string"),
    }
}
