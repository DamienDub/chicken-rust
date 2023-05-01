use base64::{engine::general_purpose, Engine as _};
use urlencoding::{decode, encode};

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
