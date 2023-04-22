use base64::{engine::general_purpose, Engine as _};
use hex;
use urlencoding::{decode, encode};
use sha2::{Sha256, Digest};

// AES
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

pub fn base64_encode(input: &str) -> String {
    return general_purpose::STANDARD_NO_PAD.encode(input);
}

pub fn base64_decode(input: &str) -> String {
    match general_purpose::STANDARD_NO_PAD.decode(input) {
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

pub fn hash_sha1(){

}

pub fn sha256_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    return hex::encode(result);
}

pub fn aes_cbc_128_encrypt(plaintext: &str, key: &str, iv: &str) -> String {
    // Get plaintext as bytes
    let plaintext = plaintext.as_bytes();

    // Get key as bytes
    let mut key_bytes = [0x42; 16];
    match hex::decode(key) {
        Ok(bytes_result) => {
            if bytes_result.len() != 16 {
                return "The key is not 16 bytes length".to_string();
            }
            key_bytes.copy_from_slice(&bytes_result)
        }
        Err(_) => {
            return "The key is not an hexadecimal string".to_string();
        }
    }

    // Get IV as bytes
    let mut iv_bytes = [0x24; 16];
    match hex::decode(iv) {
        Ok(bytes_result) => {
            if bytes_result.len() != 16 {
                return "The IV is not 16 bytes length".to_string();
            }
            iv_bytes.copy_from_slice(&bytes_result)
        }
        Err(_) => {
            return "The IV is not an hexadecimal string".to_string();
        }
    }

    // Make buffer with proper length
    let plaintext_len = plaintext.len();
    let mut buf = vec![0u8; closest_upper_multiple_(plaintext_len, 128)];
    buf[..plaintext_len].copy_from_slice(&plaintext);

    // Encrypt
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
    match Aes128CbcEnc::new(&key_bytes.into(), &iv_bytes.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_len)
    {
        Ok(bytes_result) => return hex::encode(&bytes_result),
        Err(_) => return "Failed to perform AES encryption".to_string(),
    }
}

pub fn aes_cbc_128_decrypt(ciphertext: &str, key: &str, iv: &str) -> String {
    // Get ciphertext as bytes
    let mut ciphertext_bytes: Vec<u8>;
    match hex::decode(ciphertext) {
        Ok(bytes_result) => {
            ciphertext_bytes = bytes_result;
        }
        Err(_) => return "The ciphertext is not an hexadecimal string".to_string(),
    }

    // Get key as bytes
    let mut key_bytes = [0x42; 16];
    match hex::decode(key) {
        Ok(bytes_result) => {
            if bytes_result.len() != 16 {
                return "The key is not 16 bytes length".to_string();
            }
            key_bytes.copy_from_slice(&bytes_result)
        }
        Err(_) => return "The key is not an hexadecimal string".to_string(),
    }

    // Get IV as bytes
    let mut iv_bytes = [0x24; 16];
    match hex::decode(iv) {
        Ok(bytes_result) => {
            if bytes_result.len() != 16 {
                return "The IV is not 16 bytes length".to_string();
            }
            iv_bytes.copy_from_slice(&bytes_result)
        }
        Err(_) => return "The IV is not an hexadecimal string".to_string(),
    }

    // Decrypt
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
    match Aes128CbcDec::new(&key_bytes.into(), &iv_bytes.into())
        .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
    {
        Ok(bytes_result) => match std::str::from_utf8(bytes_result) {
            Ok(string_result) => string_result.to_string(),
            Err(_) => "Failed to perform AES decryption".to_string(),
        },
        Err(_) => "Failed to perform AES decryption".to_string(),
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
