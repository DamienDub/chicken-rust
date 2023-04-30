use yew_router::prelude::*;

#[derive(Clone, Routable, PartialEq)]
pub enum Route {
    #[at("/")]
    Home,

    #[at("/encode")]
    Encode,

    #[at("/encode/base64")]
    EncodeBase64,

    #[at("/encode/url")]
    EncodeUrl,

    #[at("/decode")]
    Decode,

    #[at("/decode/base64")]
    DecodeBase64,

    #[at("/decode/url")]
    DecodeUrl,

    #[at("/generate")]
    Generate,

    #[at("/generate/randomString")]
    GenerateRandomString,

    #[at("/hash")]
    Hash,

    #[at("/hash/sha1")]
    HashSha1,

    #[at("/hash/sha256")]
    HashSha256,

    #[at("/encrypt")]
    Encrypt,

    #[at("/encrypt/aes")]
    EncryptAes,

    #[at("/decrypt")]
    Decrypt,

    #[at("/decrypt/aes")]
    DecryptAes,

    #[at("/test")]
    Test,

    #[not_found]
    #[at("/404")]
    NotFound,
}
