use base64::{engine::general_purpose, Engine as _};
use hex;
use rand::Rng;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha256Digest, Sha256};
use urlencoding::{decode, encode};

// AES
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};

use gloo_console::log;

pub fn base64_encode(input: &str) -> String {
    return general_purpose::STANDARD.encode(input);
}

pub fn base64_decode(input: &str) -> String {
    match general_purpose::STANDARD.decode(input) {
        Ok(result) => match String::from_utf8(result) {
            Ok(string_result) => return string_result,
            Err(_) => return "Failed to turn bytes into UTF-8 string".to_string(),
        },
        Err(_) => return "Failed to decode base 64 string".to_string(),
    }
}

pub fn url_encode(input: &str) -> String {
    return encode(input);
}

pub fn url_decode(input: &str) -> String {
    match decode(input) {
        Ok(string_result) => string_result,
        Err(_) => return "Failed to decode encoded URL".to_string(),
    }
}

pub fn sha1_hash(input: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(input);
    let result = hasher.finalize();
    return hex::encode(result);
}

pub fn sha256_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    return hex::encode(result);
}

pub fn random_string_generate(
    length: usize,
    with_lowercase: bool,
    with_uppercase: bool,
    with_numbers: bool,
) -> String {
    if !with_lowercase && !with_uppercase && !with_numbers {
        return "You must choose something".to_string();
    }

    let mut charset: Vec<u8> = Vec::new();
    if with_lowercase {
        charset.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz");
    }
    if with_uppercase {
        charset.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if with_numbers {
        charset.extend_from_slice(b"0123456789");
    }

    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
}

pub fn aes_cbc_encrypt(
    key_size: usize,
    key: &str,
    iv: &str,
    plaintext: &str,
    hex_output: bool,
) -> String {
    // Get key size in bytes
    let key_size_bytes = match key_size {
        128 => 16,
        192 => 24,
        256 => 32,
        _ => return "The key size must be 128, 192, or 256".to_string(),
    };

    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    let mut key_bytes_192 = [0x42; 24];
    let mut key_bytes_256 = [0x42; 32];
    match hex::decode(key) {
        Ok(bytes_result) => {
            if key_size_bytes != bytes_result.len() {
                return "The key does not have a correct length".to_string();
            }
            match key_size {
                128 => key_bytes_128.copy_from_slice(&bytes_result),
                192 => key_bytes_192.copy_from_slice(&bytes_result),
                256 => key_bytes_256.copy_from_slice(&bytes_result),
                _ => return "The key size must be 128, 192, or 256".to_string(),
            };
        }
        Err(_) => {
            return "The key is not an hexadecimal string".to_string();
        }
    }

    // Get IV as bytes
    let mut iv_bytes = [0x42; 16];
    match hex::decode(iv) {
        Ok(result) => {
            if result.len() != 16 {
                return "The IV is not 16 bytes length".to_string();
            }
            iv_bytes.copy_from_slice(&result)
        }
        Err(_) => {
            return "The IV is not an hexadecimal string".to_string();
        }
    }

    // Make buffer with proper length
    let plaintext_len = plaintext.len();
    let mut buf = vec![0u8; closest_upper_multiple_(plaintext_len, 128)];
    buf[..plaintext_len].copy_from_slice(&plaintext.as_bytes());

    // Encrypt
    match key_size {
        128 => {
            type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
            match Aes128CbcEnc::new(&key_bytes_128.into(), &iv_bytes.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_len)
            {
                Ok(result) => {
                    if hex_output {
                        return hex::encode(&result);
                    } else {
                        return general_purpose::STANDARD.encode(&result);
                    }
                }
                Err(_) => return "Failed to perform AES-128 encryption".to_string(),
            }
        }
        192 => {
            type Aes192CbcEnc = cbc::Encryptor<aes::Aes192>;
            match Aes192CbcEnc::new(&key_bytes_192.into(), &iv_bytes.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_len)
            {
                Ok(result) => {
                    if hex_output {
                        return hex::encode(&result);
                    } else {
                        return general_purpose::STANDARD.encode(&result);
                    }
                }
                Err(_) => return "Failed to perform AES-192 encryption".to_string(),
            }
        }
        256 => {
            type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
            match Aes256CbcEnc::new(&key_bytes_256.into(), &iv_bytes.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_len)
            {
                Ok(result) => {
                    if hex_output {
                        return hex::encode(&result);
                    } else {
                        return general_purpose::STANDARD.encode(&result);
                    }
                }
                Err(_) => return "Failed to perform AES-256 encryption".to_string(),
            }
        }
        _ => return "The key size must be 128, 192, or 256".to_string(),
    };
}

pub fn aes_cbc_decrypt(
    key_size: usize,
    key: &str,
    iv: &str,
    ciphertext: &str,
    hex_input: bool,
) -> String {
    // Get key size in bytes
    let key_size_bytes = match key_size {
        128 => 16,
        192 => 24,
        256 => 32,
        _ => return "The key size must be 128, 192, or 256".to_string(),
    };

    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    let mut key_bytes_192 = [0x42; 24];
    let mut key_bytes_256 = [0x42; 32];
    match hex::decode(key) {
        Ok(bytes_result) => {
            if key_size_bytes != bytes_result.len() {
                return "The key does not have a correct length".to_string();
            }
            match key_size {
                128 => key_bytes_128.copy_from_slice(&bytes_result),
                192 => key_bytes_192.copy_from_slice(&bytes_result),
                256 => key_bytes_256.copy_from_slice(&bytes_result),
                _ => return "The key size must be 128, 192, or 256".to_string(),
            };
        }
        Err(_) => {
            return "The key is not an hexadecimal string".to_string();
        }
    }

    // Get IV as bytes
    let mut iv_bytes = [0x42; 16];
    match hex::decode(iv) {
        Ok(result) => {
            if result.len() != 16 {
                return "The IV is not 16 bytes length".to_string();
            }
            iv_bytes.copy_from_slice(&result)
        }
        Err(_) => {
            return "The IV is not an hexadecimal string".to_string();
        }
    }

    // Get ciphertext as bytes
    let mut ciphertext_bytes: Vec<u8>;
    if hex_input {
        match hex::decode(ciphertext) {
            Ok(bytes_result) => ciphertext_bytes = bytes_result,
            Err(_) => return "The ciphertext is not an hexadecimal string".to_string(),
        }
    } else {
        match general_purpose::STANDARD.decode(ciphertext) {
            Ok(bytes_result) => ciphertext_bytes = bytes_result,
            Err(_) => return "The ciphertext is not a base 64 string".to_string(),
        }
    }

    // Decrypt
    match key_size {
        128 => {
            type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
            match Aes128CbcDec::new(&key_bytes_128.into(), &iv_bytes.into())
                .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
            {
                Ok(bytes_result) => match std::str::from_utf8(bytes_result) {
                    Ok(string_result) => string_result.to_string(),
                    Err(_) => "Failed to perform AES-128 decryption".to_string(),
                },
                Err(_) => "Failed to perform AES-128 decryption".to_string(),
            }
        }
        192 => {
            type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
            match Aes192CbcDec::new(&key_bytes_192.into(), &iv_bytes.into())
                .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
            {
                Ok(bytes_result) => match std::str::from_utf8(bytes_result) {
                    Ok(string_result) => string_result.to_string(),
                    Err(_) => "Failed to perform AES-192 decryption".to_string(),
                },
                Err(_) => "Failed to perform AES-192 decryption".to_string(),
            }
        }
        256 => {
            type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
            match Aes256CbcDec::new(&key_bytes_256.into(), &iv_bytes.into())
                .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
            {
                Ok(bytes_result) => match std::str::from_utf8(bytes_result) {
                    Ok(string_result) => string_result.to_string(),
                    Err(_) => "Failed to perform AES-256 decryption".to_string(),
                },
                Err(_) => "Failed to perform AES-256 decryption".to_string(),
            }
        }
        _ => return "The key size must be 128, 192, or 256".to_string(),
    }
}

pub fn aes_ecb_encrypt(key_size: usize, key: &str, plaintext: &str, hex_output: bool) -> String {
    // Get key size in bytes
    let key_size_bytes = match key_size {
        128 => 16,
        192 => 24,
        256 => 32,
        _ => return "The key size must be 128, 192, or 256".to_string(),
    };

    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    let mut key_bytes_192 = [0x42; 24];
    let mut key_bytes_256 = [0x42; 32];
    match hex::decode(key) {
        Ok(bytes_result) => {
            if key_size_bytes != bytes_result.len() {
                return "The key does not have a correct length".to_string();
            }
            match key_size {
                128 => key_bytes_128.copy_from_slice(&bytes_result),
                192 => key_bytes_192.copy_from_slice(&bytes_result),
                256 => key_bytes_256.copy_from_slice(&bytes_result),
                _ => return "The key size must be 128, 192, or 256".to_string(),
            };
        }
        Err(_) => {
            return "The key is not an hexadecimal string".to_string();
        }
    }

    // Make buffer with proper length
    let plaintext_len = plaintext.len();
    let mut buf = vec![0u8; closest_upper_multiple_(plaintext_len, 128)];
    buf[..plaintext_len].copy_from_slice(&plaintext.as_bytes());

    // Encrypt
    match key_size {
        128 => {
            type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
            match Aes128EcbEnc::new(&key_bytes_128.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_len)
            {
                Ok(result) => {
                    if hex_output {
                        return hex::encode(&result);
                    } else {
                        return general_purpose::STANDARD.encode(&result);
                    }
                }
                Err(_) => return "Failed to perform AES-128 encryption".to_string(),
            }
        }
        192 => {
            type Aes192EcbEnc = ecb::Encryptor<aes::Aes192>;
            match Aes192EcbEnc::new(&key_bytes_192.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_len)
            {
                Ok(result) => {
                    if hex_output {
                        return hex::encode(&result);
                    } else {
                        return general_purpose::STANDARD.encode(&result);
                    }
                }
                Err(_) => return "Failed to perform AES-192 encryption".to_string(),
            }
        }
        256 => {
            type Aes256EcbEnc = ecb::Encryptor<aes::Aes256>;
            match Aes256EcbEnc::new(&key_bytes_256.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_len)
            {
                Ok(result) => {
                    if hex_output {
                        return hex::encode(&result);
                    } else {
                        return general_purpose::STANDARD.encode(&result);
                    }
                }
                Err(_) => return "Failed to perform AES-256 encryption".to_string(),
            }
        }
        _ => return "The key size must be 128, 192, or 256".to_string(),
    };
}

pub fn aes_ecb_decrypt(key_size: usize, key: &str, ciphertext: &str, hex_input: bool) -> String {
    // Get key size in bytes
    let key_size_bytes = match key_size {
        128 => 16,
        192 => 24,
        256 => 32,
        _ => return "The key size must be 128, 192, or 256".to_string(),
    };

    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    let mut key_bytes_192 = [0x42; 24];
    let mut key_bytes_256 = [0x42; 32];
    match hex::decode(key) {
        Ok(bytes_result) => {
            if key_size_bytes != bytes_result.len() {
                return "The key does not have a correct length".to_string();
            }
            match key_size {
                128 => key_bytes_128.copy_from_slice(&bytes_result),
                192 => key_bytes_192.copy_from_slice(&bytes_result),
                256 => key_bytes_256.copy_from_slice(&bytes_result),
                _ => return "The key size must be 128, 192, or 256".to_string(),
            };
        }
        Err(_) => {
            return "The key is not an hexadecimal string".to_string();
        }
    }

    // Get ciphertext as bytes
    let mut ciphertext_bytes: Vec<u8>;
    if hex_input {
        match hex::decode(ciphertext) {
            Ok(bytes_result) => ciphertext_bytes = bytes_result,
            Err(_) => return "The ciphertext is not an hexadecimal string".to_string(),
        }
    } else {
        match general_purpose::STANDARD.decode(ciphertext) {
            Ok(bytes_result) => ciphertext_bytes = bytes_result,
            Err(_) => return "The ciphertext is not a base 64 string".to_string(),
        }
    }

    // Decrypt
    match key_size {
        128 => {
            type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;
            match Aes128EcbDec::new(&key_bytes_128.into())
                .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
            {
                Ok(bytes_result) => match std::str::from_utf8(bytes_result) {
                    Ok(string_result) => string_result.to_string(),
                    Err(_) => "Failed to perform AES-128 decryption".to_string(),
                },
                Err(_) => "Failed to perform AES-128 decryption".to_string(),
            }
        }
        192 => {
            type Aes192EcbDec = ecb::Decryptor<aes::Aes192>;
            match Aes192EcbDec::new(&key_bytes_192.into())
                .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
            {
                Ok(bytes_result) => match std::str::from_utf8(bytes_result) {
                    Ok(string_result) => string_result.to_string(),
                    Err(_) => "Failed to perform AES-192 decryption".to_string(),
                },
                Err(_) => "Failed to perform AES-192 decryption".to_string(),
            }
        }
        256 => {
            type Aes256EcbDec = ecb::Decryptor<aes::Aes256>;
            match Aes256EcbDec::new(&key_bytes_256.into())
                .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
            {
                Ok(bytes_result) => match std::str::from_utf8(bytes_result) {
                    Ok(string_result) => string_result.to_string(),
                    Err(_) => "Failed to perform AES-256 decryption".to_string(),
                },
                Err(_) => "Failed to perform AES-256 decryption".to_string(),
            }
        }
        _ => return "The key size must be 128, 192, or 256".to_string(),
    }
}

fn closest_upper_multiple_(number: usize, multiple: usize) -> usize {
    let remainder = number % multiple;
    if remainder == 0 {
        number
    } else {
        number + multiple - remainder
    }
}
