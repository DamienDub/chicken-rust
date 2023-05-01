use hex;
use sha1::Digest;

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
