use yew::prelude::*;
use yew_router::prelude::*;

use crate::utils::route::Route;

use crate::utils::crypter::*;
use crate::utils::html::*;

#[function_component(Decrypt)]
pub fn encrypt() -> Html {
    let navigator1 = use_navigator().unwrap();
    let to_aes = Callback::from(move |_| navigator1.push(&Route::DecryptAes));

    html! {
        <main>
            <h1>{ "Decrypt with..." }</h1>
            <div>
                <button onclick={to_aes}>{ "AES" }</button>
            </div>
        </main>
    }
}

#[function_component(DecryptAes)]
pub fn decrypt_aes() -> Html {
    let onclick = Callback::from(move |_: MouseEvent| {
        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();

        let mode_input = get_select_element(&document, "mode");
        let mode = mode_input.value();

        let iv_input = get_input_element(&document, "iv");
        let iv = iv_input.value();

        let key_input = get_input_element(&document, "key");
        let key = key_input.value();

        let input_input = get_select_element(&document, "input");
        let input = input_input.value();
        let is_hex = input == "hexadecimal";

        let ti_input = get_textarea_element(&document, "ti");
        let ti = ti_input.value();

        let to_textarea = get_textarea_element(&document, "to");

        match mode.as_str() {
            "cbc" => match aes_128_cbc_decrypt(key.as_str(), iv.as_str(), ti.as_str(), is_hex) {
                Ok(result) => to_textarea.set_value(result.as_str()),
                Err(error) => to_textarea.set_value(error),
            },
            "ecb" => match aes_128_ecb_decrypt(key.as_str(), ti.as_str(), is_hex) {
                Ok(result) => to_textarea.set_value(result.as_str()),
                Err(error) => to_textarea.set_value(error),
            },
            _ => to_textarea.set_value("Wrong mode value"),
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
                    <label for="input">{ "Input" }</label>
                    <br />
                    <select id="input">
                        <option value="base64" selected=true>{"Base 64"}</option>
                        <option value="hexadecimal">{"Hexadecimal"}</option>
                    </select>
                </div>

                <br />

                <div>
                    <label for="ti">{ "Text to decrypt" }</label>
                    <br />
                    <textarea id="ti" />
                </div>

                <br />

                <div>
                    <button {onclick}>{ "Decrypt" }</button>
                </div>

                <br />

                <div>
                    <textarea id="to" />
                </div>
            </div>
        </main>
    }
}
