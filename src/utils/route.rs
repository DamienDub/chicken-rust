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

    #[at("/hash")]
    Hash,

    #[at("/encrypt")]
    Encrypt,

    #[at("/decrypt")]
    Decrypt,


    #[not_found]
    #[at("/404")]
    NotFound,
}
