// use gloo_console::log;
use yew::prelude::*;
use yew_router::prelude::*;

use wasm_bindgen::{JsCast};
use web_sys::HtmlTextAreaElement;

use base64::{engine::general_purpose, Engine as _};
use hex;
use urlencoding::{decode, encode};

// AES
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

#[derive(Clone, Routable, PartialEq)]
enum Route {
    #[at("/")]
    Home,

    #[at("/encode")]
    Encode,

    #[at("/encode/base64")]
    Base64,

    #[not_found]
    #[at("/404")]
    NotFound,
}

fn switch(routes: Route) -> Html {
    match routes {
        Route::Home => html! {
           <Home />
        },
        Route::Encode => html! {
            <Encode />
        },
        Route::Base64 => html! {
            <Base64 />
        },
        Route::NotFound => html! { <main><h1>{ "You got lost ?" }</h1></main> },
    }
}

#[function_component(App)]
pub fn app() -> Html {
    html! {
        <BrowserRouter>
            <Switch<Route> render={switch} /> // <- must be child of <BrowserRouter>
        </BrowserRouter>
    }
}

#[function_component(Home)]
pub fn home() -> Html {
    let navigator = use_navigator().unwrap();

    html! {
        <main>
            <h1>{ "Welcome to Chicken Rust" }</h1>
            <span class="subtitle">{ "Fast. Secure. Open source" }</span>


            <br /><br />

            // <div>
            //     <p> {"Base 64 encoding of test: "} { base64_encode("test") }</p>
            //     <p> {"Base 64 decoding of dGVzdA: "} { base64_decode("dGVzdA") }</p>
            //     <p> {"URL encoding of http://site.com/ye ye ye: "} { url_encode("http://site.com/ye ye ye") }</p>
            //     <p> {"URL decoding of http%3A%2F%2Fsite.com%2Fye%20ye%20yee: "} { url_decode("http%3A%2F%2Fsite.com%2Fye%20ye%20ye") }</p>
            //     <p> {"AES encryption: "} { aes_cbc_128_encrypt("Anna tu sens mauvais des fesses", "00112233445566778899AABBCCDDEEFF", "11111111111111111111111111111111") }</p>
            //     <p> {"AES decryption of previous message: "} { aes_cbc_128_decrypt("2bddb633cad52eb64c05aa283c0ced7b846f8468266c09f801ba118976dd459a", "00112233445566778899AABBCCDDEEFF", "11111111111111111111111111111111") }</p>
            // </div>


            <span class="subtitle">{ "What would you like to do ?" }</span>

            <div>
                <button onclick={Callback::from(move |_| navigator.push(&Route::Encode))}>{ "I want to encode" }</button>
            </div>

            <div>
            <button>{ "I want to decode" }</button>
        </div>

        </main>
    }
}

#[function_component(Encode)]
fn encode() -> Html {
    let navigator = use_navigator().unwrap();

    html! {
        <main>
        <div>
            <h1>{ "Encode with" }</h1>
            <div>
                <button onclick={Callback::from(move |_| navigator.push(&Route::Base64))}>{ "Base 64" }</button>
            </div>
            <div>
                <button>{ "URL encoding" }</button>
            </div>
        </div>
        </main>
    }
}

#[function_component(Base64)]
fn base64() -> Html {


    let onclick = Callback::from(move |_: MouseEvent| {

        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();
        
        let ti_element = document.get_element_by_id("ti").unwrap();
        let ti_textarea = ti_element.dyn_into::<HtmlTextAreaElement>().unwrap();
        let ti_textarea_content = ti_textarea.value();

        let to_element = document.get_element_by_id("to").unwrap();
        let to_textarea = to_element.dyn_into::<HtmlTextAreaElement>().unwrap();

        to_textarea.set_value(&base64_encode(ti_textarea_content.as_str()));
    });

    html! {
        <main>
            <div>
                <h1>{ "Please enter some text" }</h1>

                <div>
                    <textarea id="ti" />
                </div>

                <div>
                    <button onclick={onclick}>{ "Encode" }</button>
                </div>

                <div>
                    <textarea id="to" />
                </div>
            </div>
        </main>
    }
}

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
