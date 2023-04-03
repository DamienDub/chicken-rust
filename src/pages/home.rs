use yew::prelude::*;
use yew_router::prelude::*;

use crate::utils::route::Route;

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
