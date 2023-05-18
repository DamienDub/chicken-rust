use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use base64::{engine::general_purpose, Engine as _};
use hex;

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

    // Copy plaintext to a buffer with a length that is a multiple of 128
    let mut buf = get_buffer_128(plaintext);

    // Encrypt
    type TdesCbcEnc = cbc::Encryptor<des::TdesEde2>;
    match TdesCbcEnc::new(&key_bytes_128.into(), &iv_bytes.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
    {
        Ok(result) => return Ok(encode_output_to_hex(result, hex_output)),
        Err(_) => return Err("Failed to perform 3-DES encryption"),
    }
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
    let mut ciphertext_bytes = decode_input(ciphertext, hex_input).unwrap();

    // Decrypt
    type TdesCbcDec = cbc::Decryptor<des::TdesEde2>;
    match TdesCbcDec::new(&key_bytes_128.into(), &iv_bytes.into())
        .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
    {
        Ok(bytes_result) => encode_output_to_str(bytes_result),
        Err(_) => Err("Failed to perform 3-DES decryption"),
    }
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

    // Copy plaintext to a buffer with a length that is a multiple of 128
    let mut buf = get_buffer_128(plaintext);

    // Encrypt
    type TdesCbcEnc = cbc::Encryptor<des::TdesEde3>;
    match TdesCbcEnc::new(&key_bytes_192.into(), &iv_bytes.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
    {
        Ok(result) => return Ok(encode_output_to_hex(result, hex_output)),
        Err(_) => return Err("Failed to perform 3-DES encryption"),
    }
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

    // Get ciphertext as bytes
    let mut ciphertext_bytes = decode_input(ciphertext, hex_input).unwrap();

    // Decrypt
    type TdesCbcDec = cbc::Decryptor<des::TdesEde3>;
    match TdesCbcDec::new(&key_bytes_192.into(), &iv_bytes.into())
        .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
    {
        Ok(bytes_result) => encode_output_to_str(bytes_result),
        Err(_) => Err("Failed to perform 3-DES decryption"),
    }
}

pub fn tripledes_keying2_ecb_encrypt(
    key: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    decode_hex_key_128(key, &mut key_bytes_128).unwrap();

    // Copy plaintext to a buffer with a length that is a multiple of 128
    let mut buf = get_buffer_128(plaintext);

    // Encrypt
    type TdesEcbEnc = ecb::Encryptor<des::TdesEde2>;
    match TdesEcbEnc::new(&key_bytes_128.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
    {
        Ok(result) => return Ok(encode_output_to_hex(result, hex_output)),
        Err(_) => return Err("Failed to perform 3-DES encryption"),
    }
}

pub fn tripledes_keying2_ecb_decrypt(
    key: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    decode_hex_key_128(key, &mut key_bytes_128).unwrap();

    // Get ciphertext as bytes
    let mut ciphertext_bytes = decode_input(ciphertext, hex_input).unwrap();

    // Decrypt
    type TdesEcbDec = ecb::Decryptor<des::TdesEde2>;
    match TdesEcbDec::new(&key_bytes_128.into()).decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
    {
        Ok(bytes_result) => encode_output_to_str(bytes_result),
        Err(_) => Err("Failed to perform 3-DES decryption"),
    }
}

pub fn tripledes_keying3_ecb_encrypt(
    key: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_192 = [0x42; 24];
    decode_hex_key_192(key, &mut key_bytes_192).unwrap();

    // Copy plaintext to a buffer with a length that is a multiple of 128
    let mut buf = get_buffer_128(plaintext);

    // Encrypt
    type TdesEcbEnc = ecb::Encryptor<des::TdesEde3>;
    match TdesEcbEnc::new(&key_bytes_192.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
    {
        Ok(result) => return Ok(encode_output_to_hex(result, hex_output)),
        Err(_) => return Err("Failed to perform 3-DES encryption"),
    }
}

pub fn tripledes_keying3_ecb_decrypt(
    key: &str,
    ciphertext: &str,
    hex_input: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_192 = [0x42; 24];
    decode_hex_key_192(key, &mut key_bytes_192).unwrap();

    // Get ciphertext as bytes
    let mut ciphertext_bytes = decode_input(ciphertext, hex_input).unwrap();

    // Decrypt
    type TdesEcbDec = ecb::Decryptor<des::TdesEde3>;
    match TdesEcbDec::new(&key_bytes_192.into()).decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
    {
        Ok(bytes_result) => encode_output_to_str(bytes_result),
        Err(_) => Err("Failed to perform 3-DES decryption"),
    }
}

pub fn aes_cbc_encrypt(
    key_size: usize,
    key: &str,
    iv: &str,
    plaintext: &str,
    hex_output: bool,
) -> Result<String, &'static str> {
    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    let mut key_bytes_192 = [0x42; 24];
    let mut key_bytes_256 = [0x42; 32];
    match key_size {
        128 => decode_hex_key_128(key, &mut key_bytes_128).unwrap(),
        192 => decode_hex_key_192(key, &mut key_bytes_192).unwrap(),
        256 => decode_hex_key_256(key, &mut key_bytes_256).unwrap(),
        _ => return Err("The key size must be 128, 192, or 256"),
    }

    // Get IV as bytes
    let mut iv_bytes = [0x42; 16];
    decode_hex_iv_128(iv, &mut iv_bytes).unwrap();

    // Copy plaintext to a buffer with a length that is a multiple of 128
    let mut buf = get_buffer_128(plaintext);

    // Encrypt
    match key_size {
        128 => {
            type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
            match Aes128CbcEnc::new(&key_bytes_128.into(), &iv_bytes.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            {
                Ok(result) => return Ok(encode_output_to_hex(result, hex_output)),
                Err(_) => return Err("Failed to perform AES-128 encryption"),
            }
        }
        192 => {
            type Aes192CbcEnc = cbc::Encryptor<aes::Aes192>;
            match Aes192CbcEnc::new(&key_bytes_192.into(), &iv_bytes.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            {
                Ok(result) => return Ok(encode_output_to_hex(result, hex_output)),
                Err(_) => return Err("Failed to perform AES-192 encryption"),
            }
        }
        256 => {
            type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
            match Aes256CbcEnc::new(&key_bytes_256.into(), &iv_bytes.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            {
                Ok(result) => return Ok(encode_output_to_hex(result, hex_output)),
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
    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    let mut key_bytes_192 = [0x42; 24];
    let mut key_bytes_256 = [0x42; 32];
    match key_size {
        128 => decode_hex_key_128(key, &mut key_bytes_128).unwrap(),
        192 => decode_hex_key_192(key, &mut key_bytes_192).unwrap(),
        256 => decode_hex_key_256(key, &mut key_bytes_256).unwrap(),
        _ => return Err("The key size must be 128, 192, or 256"),
    }

    // Get IV as bytes
    let mut iv_bytes = [0x42; 16];
    decode_hex_iv_128(iv, &mut iv_bytes).unwrap();

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
                Ok(bytes_result) => encode_output_to_str(bytes_result),
                Err(_) => Err("Failed to perform AES-128 decryption"),
            }
        }
        192 => {
            type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;
            match Aes192CbcDec::new(&key_bytes_192.into(), &iv_bytes.into())
                .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
            {
                Ok(bytes_result) => encode_output_to_str(bytes_result),
                Err(_) => Err("Failed to perform AES-192 decryption"),
            }
        }
        256 => {
            type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
            match Aes256CbcDec::new(&key_bytes_256.into(), &iv_bytes.into())
                .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
            {
                Ok(bytes_result) => encode_output_to_str(bytes_result),
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
    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    let mut key_bytes_192 = [0x42; 24];
    let mut key_bytes_256 = [0x42; 32];
    match key_size {
        128 => decode_hex_key_128(key, &mut key_bytes_128).unwrap(),
        192 => decode_hex_key_192(key, &mut key_bytes_192).unwrap(),
        256 => decode_hex_key_256(key, &mut key_bytes_256).unwrap(),
        _ => return Err("The key size must be 128, 192, or 256"),
    }

    // Copy plaintext to a buffer with a length that is a multiple of 128
    let mut buf = get_buffer_128(plaintext);

    // Encrypt
    match key_size {
        128 => {
            type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
            match Aes128EcbEnc::new(&key_bytes_128.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            {
                Ok(result) => return Ok(encode_output_to_hex(result, hex_output)),
                Err(_) => return Err("Failed to perform AES-128 encryption"),
            }
        }
        192 => {
            type Aes192EcbEnc = ecb::Encryptor<aes::Aes192>;
            match Aes192EcbEnc::new(&key_bytes_192.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            {
                Ok(result) => return Ok(encode_output_to_hex(result, hex_output)),
                Err(_) => return Err("Failed to perform AES-192 encryption"),
            }
        }
        256 => {
            type Aes256EcbEnc = ecb::Encryptor<aes::Aes256>;
            match Aes256EcbEnc::new(&key_bytes_256.into())
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            {
                Ok(result) => return Ok(encode_output_to_hex(result, hex_output)),
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
    // Get key as bytes
    let mut key_bytes_128 = [0x42; 16];
    let mut key_bytes_192 = [0x42; 24];
    let mut key_bytes_256 = [0x42; 32];
    match key_size {
        128 => decode_hex_key_128(key, &mut key_bytes_128).unwrap(),
        192 => decode_hex_key_192(key, &mut key_bytes_192).unwrap(),
        256 => decode_hex_key_256(key, &mut key_bytes_256).unwrap(),
        _ => return Err("The key size must be 128, 192, or 256"),
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
                Ok(bytes_result) => encode_output_to_str(bytes_result),
                Err(_) => Err("Failed to perform AES-128 decryption"),
            }
        }
        192 => {
            type Aes192EcbDec = ecb::Decryptor<aes::Aes192>;
            match Aes192EcbDec::new(&key_bytes_192.into())
                .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
            {
                Ok(bytes_result) => encode_output_to_str(bytes_result),
                Err(_) => Err("Failed to perform AES-192 decryption"),
            }
        }
        256 => {
            type Aes256EcbDec = ecb::Decryptor<aes::Aes256>;
            match Aes256EcbDec::new(&key_bytes_256.into())
                .decrypt_padded_mut::<Pkcs7>(&mut ciphertext_bytes)
            {
                Ok(bytes_result) => encode_output_to_str(bytes_result),
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

fn get_buffer_128(plaintext: &str) -> Vec<u8> {
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

fn encode_output_to_hex(output: &[u8], hex_output: bool) -> String {
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
