use hex;
use digest::Digest;

pub fn md5_hash(input: &str) -> String {
    let mut hasher = md5::Md5::new();
    hasher.update(input);
    let result = hasher.finalize();
    return hex::encode(result);
}

pub fn sha1_hash(input: &str) -> String {
    let mut hasher = sha1::Sha1::new();
    hasher.update(input);
    let result = hasher.finalize();
    return hex::encode(result);
}

pub fn sha256_hash(input: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    return hex::encode(result);
}
