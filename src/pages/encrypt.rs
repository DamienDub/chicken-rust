use yew::prelude::*;
use yew_router::prelude::*;

use wasm_bindgen::JsCast;
use web_sys::HtmlInputElement;
use web_sys::HtmlSelectElement;
use web_sys::HtmlTextAreaElement;

use crate::utils::route::Route;

use crate::utils::transformer::*;

#[function_component(Encrypt)]
pub fn encrypt() -> Html {

    let navigator1 = use_navigator().unwrap();
    let to_aes = Callback::from(move |_| navigator1.push(&Route::EncryptAes));

    html! {
        <main>
            <h1>{ "Encrypt with..." }</h1>
            <div>
                <button onclick={to_aes}>{ "AES" }</button>
            </div>
        </main>
    }
}

#[function_component(EncryptAes)]
pub fn encrypt_aes() -> Html {

    let onclick = Callback::from(move |_: MouseEvent| {
                
        
        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();

        let mode_element = document.get_element_by_id("mode").unwrap();
        let mode_input = mode_element.dyn_into::<HtmlSelectElement>().unwrap();
        let mode = mode_input.value();

        let iv_element = document.get_element_by_id("iv").unwrap();
        let iv_input = iv_element.dyn_into::<HtmlInputElement>().unwrap();
        let iv = iv_input.value();

        let key_element = document.get_element_by_id("key").unwrap();
        let key_input = key_element.dyn_into::<HtmlInputElement>().unwrap();
        let key = key_input.value();

        let output_element = document.get_element_by_id("output").unwrap();
        let output_input = output_element.dyn_into::<HtmlSelectElement>().unwrap();
        let output = output_input.value();
        let is_hex = output == "hexadecimal";

        let ti_element = document.get_element_by_id("ti").unwrap();
        let ti_input = ti_element.dyn_into::<HtmlTextAreaElement>().unwrap();
        let ti = ti_input.value();

        let to_element = document.get_element_by_id("to").unwrap();
        let to_textarea = to_element.dyn_into::<HtmlTextAreaElement>().unwrap();

        match mode.as_str() {
            "cbc" => {to_textarea.set_value(aes_cbc_encrypt(128, key.as_str(), iv.as_str(), ti.as_str(), is_hex).as_str())}
            "ecb" => {to_textarea.set_value(aes_ecb_encrypt(128, key.as_str(), ti.as_str(), is_hex).as_str())}
            _ =>  {to_textarea.set_value("Wrong mode value") }
        }

    });

    html! {
        <main>
            <div>
                <h1>{ "Please enter an IV, a key some text to encrypt" }</h1>

                <div>
                    <label for="mode">{ "Mode" }</label>
                    <br />
                    <select id="mode">
                        <option value="cbc" selected=true>{"CBC"}</option>
                        <option value="ecb">{"ECB"}</option>
                    </select>
                </div>

                <br />

                <div>
                    <label for="iv">{ "IV (hexadecimal)" }</label>
                    <br />
                    <input type="text" id="iv" min="32" max="32" value="00000000000000000000000000000000"/>
                </div>

                <br />

                <div>
                    <label for="key">{ "Key (hexadecimal)" }</label>
                    <br />
                    <input type="text" id="key" min="32" max="64" value="00112233445566778899AABBCCDDEEFF"/>
                </div>

                <br />

                <div>
                    <label for="output">{ "Output" }</label>
                    <br />
                    <select id="output">
                        <option value="base64" selected=true>{"Base 64"}</option>
                        <option value="hexadecimal">{"Hexadecimal"}</option>
                    </select>
                </div>

                <br />

                <div>
                    <label for="ti">{ "Text to encrypt" }</label>
                    <br />
                    <textarea id="ti" />
                </div>

                <br />

                <div>
                    <button onclick={onclick}>{ "Encrypt" }</button>
                </div>

                <br />

                <div>
                    <textarea id="to" />
                </div>
            </div>
        </main>
    }
}
