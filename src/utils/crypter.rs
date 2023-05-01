use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use base64::{engine::general_purpose, Engine as _};
use hex;

pub fn aes_cbc_encrypt(
    key_size: usize,
    key: &str,
    iv: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key size in bytes
    let key_size_bytes = match key_size {
        128 => 16,
        192 => 24,
        256 => 32,
        _ => return Err("The key size must be 128, 192, or 256"),
    };

    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    let mut key_bytes_192 = [0x42; 24];
    let mut key_bytes_256 = [0x42; 32];
    match hex::decode(key) {
        Ok(bytes_result) => {
            if key_size_bytes != bytes_result.len() {
                return Err("The key does not have a correct length");
            }
            match key_size {
                128 => key_bytes_128.copy_from_slice(&bytes_result),
                192 => key_bytes_192.copy_from_slice(&bytes_result),
                256 => key_bytes_256.copy_from_slice(&bytes_result),
                _ => return Err("The key size must be 128, 192, or 256"),
            };
        }
        Err(_) => {
            return Err("The key is not an hexadecimal string");
        }
    }

    // Get IV as bytes
    let mut iv_bytes = [0x42; 16];
    match hex::decode(iv) {
        Ok(result) => {
            if result.len() != 16 {
                return Err("The IV is not 16 bytes length");
            }
            iv_bytes.copy_from_slice(&result)
        }
        Err(_) => {
            return Err("The IV is not an hexadecimal string");
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
                        return Ok(hex::encode(&result));
                    } else {
                        return Ok(general_purpose::STANDARD.encode(&result));
                    }
                }
                Err(_) => return Err("Failed to perform AES-128 encryption"),
            }
        }
        192 => {
            type Aes192CbcEnc = cbc::Encryptor<aes::Aes192>;
            match Aes192CbcEnc::new(&key_bytes_192.into(), &iv_bytes.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_len)
            {
                Ok(result) => {
                    if hex_output {
                        return Ok(hex::encode(&result));
                    } else {
                        return Ok(general_purpose::STANDARD.encode(&result));
                    }
                }
                Err(_) => return Err("Failed to perform AES-192 encryption"),
            }
        }
        256 => {
            type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
            match Aes256CbcEnc::new(&key_bytes_256.into(), &iv_bytes.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_len)
            {
                Ok(result) => {
                    if hex_output {
                        return Ok(hex::encode(&result));
                    } else {
                        return Ok(general_purpose::STANDARD.encode(&result));
                    }
                }
                Err(_) => return Err("Failed to perform AES-256 encryption"),
            }
        }
        _ => return Err("The key size must be 128, 192, or 256"),
    };
}

pub fn aes_cbc_decrypt(
    key_size: usize,
    key: &str,
    iv: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key size in bytes
    let key_size_bytes = match key_size {
        128 => 16,
        192 => 24,
        256 => 32,
        _ => return Err("The key size must be 128, 192, or 256"),
    };

    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    let mut key_bytes_192 = [0x42; 24];
    let mut key_bytes_256 = [0x42; 32];
    match hex::decode(key) {
        Ok(bytes_result) => {
            if key_size_bytes != bytes_result.len() {
                return Err("The key does not have a correct length");
            }
            match key_size {
                128 => key_bytes_128.copy_from_slice(&bytes_result),
                192 => key_bytes_192.copy_from_slice(&bytes_result),
                256 => key_bytes_256.copy_from_slice(&bytes_result),
                _ => return Err("The key size must be 128, 192, or 256"),
            };
        }
        Err(_) => {
            return Err("The key is not an hexadecimal string");
        }
    }

    // Get IV as bytes
    let mut iv_bytes = [0x42; 16];
    match hex::decode(iv) {
        Ok(result) => {
            if result.len() != 16 {
                return Err("The IV is not 16 bytes length");
            }
            iv_bytes.copy_from_slice(&result)
        }
        Err(_) => {
            return Err("The IV is not an hexadecimal string");
        }
    }

    // Get ciphertext as bytes
    let mut ciphertext_bytes: Vec<u8>;
    if hex_input {
        match hex::decode(ciphertext) {
            Ok(bytes_result) => ciphertext_bytes = bytes_result,
            Err(_) => return Err("The ciphertext is not an hexadecimal string"),
        }
    } else {
        match general_purpose::STANDARD.decode(ciphertext) {
            Ok(bytes_result) => ciphertext_bytes = bytes_result,
            Err(_) => return Err("The ciphertext is not a base 64 string"),
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
                    Ok(string_result) => Ok(string_result.to_string()),
                    Err(_) => Err("Failed to perform AES-128 decryption"),
                },
                Err(_) => Err("Failed to perform AES-128 decryption"),
            }
        }
        192 => {
            type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
            match Aes192CbcDec::new(&key_bytes_192.into(), &iv_bytes.into())
                .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
            {
                Ok(bytes_result) => match std::str::from_utf8(bytes_result) {
                    Ok(string_result) => Ok(string_result.to_string()),
                    Err(_) => Err("Failed to perform AES-192 decryption"),
                },
                Err(_) => Err("Failed to perform AES-192 decryption"),
            }
        }
        256 => {
            type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
            match Aes256CbcDec::new(&key_bytes_256.into(), &iv_bytes.into())
                .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
            {
                Ok(bytes_result) => match std::str::from_utf8(bytes_result) {
                    Ok(string_result) => Ok(string_result.to_string()),
                    Err(_) => Err("Failed to perform AES-256 decryption"),
                },
                Err(_) => Err("Failed to perform AES-256 decryption"),
            }
        }
        _ => return Err("The key size must be 128, 192, or 256"),
    }
}

pub fn aes_ecb_encrypt(
    key_size: usize,
    key: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key size in bytes
    let key_size_bytes = match key_size {
        128 => 16,
        192 => 24,
        256 => 32,
        _ => return Err("The key size must be 128, 192, or 256"),
    };

    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    let mut key_bytes_192 = [0x42; 24];
    let mut key_bytes_256 = [0x42; 32];
    match hex::decode(key) {
        Ok(bytes_result) => {
            if key_size_bytes != bytes_result.len() {
                return Err("The key does not have a correct length");
            }
            match key_size {
                128 => key_bytes_128.copy_from_slice(&bytes_result),
                192 => key_bytes_192.copy_from_slice(&bytes_result),
                256 => key_bytes_256.copy_from_slice(&bytes_result),
                _ => return Err("The key size must be 128, 192, or 256"),
            };
        }
        Err(_) => {
            return Err("The key is not an hexadecimal string");
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
                        return Ok(hex::encode(&result));
                    } else {
                        return Ok(general_purpose::STANDARD.encode(&result));
                    }
                }
                Err(_) => return Err("Failed to perform AES-128 encryption"),
            }
        }
        192 => {
            type Aes192EcbEnc = ecb::Encryptor<aes::Aes192>;
            match Aes192EcbEnc::new(&key_bytes_192.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_len)
            {
                Ok(result) => {
                    if hex_output {
                        return Ok(hex::encode(&result));
                    } else {
                        return Ok(general_purpose::STANDARD.encode(&result));
                    }
                }
                Err(_) => return Err("Failed to perform AES-192 encryption"),
            }
        }
        256 => {
            type Aes256EcbEnc = ecb::Encryptor<aes::Aes256>;
            match Aes256EcbEnc::new(&key_bytes_256.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_len)
            {
                Ok(result) => {
                    if hex_output {
                        return Ok(hex::encode(&result));
                    } else {
                        return Ok(general_purpose::STANDARD.encode(&result));
                    }
                }
                Err(_) => return Err("Failed to perform AES-256 encryption"),
            }
        }
        _ => return Err("The key size must be 128, 192, or 256"),
    };
}

pub fn aes_ecb_decrypt(
    key_size: usize,
    key: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key size in bytes
    let key_size_bytes = match key_size {
        128 => 16,
        192 => 24,
        256 => 32,
        _ => return Err("The key size must be 128, 192, or 256"),
    };

    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    let mut key_bytes_192 = [0x42; 24];
    let mut key_bytes_256 = [0x42; 32];
    match hex::decode(key) {
        Ok(bytes_result) => {
            if key_size_bytes != bytes_result.len() {
                return Err("The key does not have a correct length");
            }
            match key_size {
                128 => key_bytes_128.copy_from_slice(&bytes_result),
                192 => key_bytes_192.copy_from_slice(&bytes_result),
                256 => key_bytes_256.copy_from_slice(&bytes_result),
                _ => return Err("The key size must be 128, 192, or 256"),
            };
        }
        Err(_) => {
            return Err("The key is not an hexadecimal string");
        }
    }

    // Get ciphertext as bytes
    let mut ciphertext_bytes: Vec<u8>;
    if hex_input {
        match hex::decode(ciphertext) {
            Ok(bytes_result) => ciphertext_bytes = bytes_result,
            Err(_) => return Err("The ciphertext is not an hexadecimal string"),
        }
    } else {
        match general_purpose::STANDARD.decode(ciphertext) {
            Ok(bytes_result) => ciphertext_bytes = bytes_result,
            Err(_) => return Err("The ciphertext is not a base 64 string"),
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
                    Ok(string_result) => Ok(string_result.to_string()),
                    Err(_) => Err("Failed to perform AES-128 decryption"),
                },
                Err(_) => Err("Failed to perform AES-128 decryption"),
            }
        }
        192 => {
            type Aes192EcbDec = ecb::Decryptor<aes::Aes192>;
            match Aes192EcbDec::new(&key_bytes_192.into())
                .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
            {
                Ok(bytes_result) => match std::str::from_utf8(bytes_result) {
                    Ok(string_result) => Ok(string_result.to_string()),
                    Err(_) => Err("Failed to perform AES-192 decryption"),
                },
                Err(_) => Err("Failed to perform AES-192 decryption"),
            }
        }
        256 => {
            type Aes256EcbDec = ecb::Decryptor<aes::Aes256>;
            match Aes256EcbDec::new(&key_bytes_256.into())
                .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
            {
                Ok(bytes_result) => match std::str::from_utf8(bytes_result) {
                    Ok(string_result) => Ok(string_result.to_string()),
                    Err(_) => Err("Failed to perform AES-256 decryption"),
                },
                Err(_) => Err("Failed to perform AES-256 decryption"),
            }
        }
        _ => return Err("The key size must be 128, 192, or 256"),
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
