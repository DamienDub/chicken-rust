use yew::prelude::*;
use yew_router::prelude::*;

use wasm_bindgen::JsCast;
use web_sys::HtmlSelectElement;

use crate::utils::route::Route;

use crate::utils::crypter::*;
use crate::utils::html::*;

#[function_component(Encrypt)]
pub fn encrypt() -> Html {
    let navigator1 = use_navigator().unwrap();
    let to_aes = Callback::from(move |_| navigator1.push(&Route::EncryptAes));

    html! {
        <main>
            <br />
            <br />
            <span><Link<Route> to={Route::Home}>{ "Home" }</Link<Route>> {" / Encrypt" }</span>
            <hr />
            <br />
            <br />
            
            <h2>{ "Encrypt with..." }</h2>

            <div style="text-align: center;">
                <button onclick={to_aes}>{ "AES" }</button>
            </div>
        </main>
    }
}

#[function_component(EncryptAes)]
pub fn encrypt_aes() -> Html {
    let is_cbc = use_state(|| true);
    let on_mode_click = {
        let is_cbc = is_cbc.clone();
        move |_| {
            let window = web_sys::window().unwrap();
            let document = window.document().unwrap();

            let mode_element = document.get_element_by_id("mode").unwrap();
            let mode_input = mode_element.dyn_into::<HtmlSelectElement>().unwrap();
            let mode = mode_input.value();

            is_cbc.set(mode == "cbc");
        }
    };

    let onclick = Callback::from(move |_| {
        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();

        let mode_input = get_select_element(&document, "mode");
        let mode = mode_input.value();

        let iv_input = get_input_element(&document, "iv");
        let iv = iv_input.value();

        let key_input = get_input_element(&document, "key");
        let key = key_input.value();

        let output_input = get_select_element(&document, "output");
        let output = output_input.value();
        let is_hex = output == "hexadecimal";

        let ti_input = get_textarea_element(&document, "ti");
        let ti = ti_input.value();

        let to_textarea = get_textarea_element(&document, "to");

        match mode.as_str() {
            "cbc" => match aes_128_cbc_encrypt(key.as_str(), iv.as_str(), ti.as_str(), is_hex) {
                Ok(result) => to_textarea.set_value(result.as_str()),
                Err(error) => to_textarea.set_value(error),
            },
            "ecb" => match aes_128_ecb_encrypt(key.as_str(), ti.as_str(), is_hex) {
                Ok(result) => to_textarea.set_value(result.as_str()),
                Err(error) => to_textarea.set_value(error),
            },
            _ => to_textarea.set_value("Wrong mode value"),
        }
    });

    html! {
        <main>
            <div>

                <br />
                <br />
                <span>
                    <Link<Route> to={Route::Home}>{ "Home" }</Link<Route>> 
                    {" / " }
                    <Link<Route> to={Route::Encrypt}>{ "Encrypt" }</Link<Route>>
                    {" / AES" }
                </span>

                <hr />
                <br />

                <div>
                    <label for="mode">{ "Mode" }</label>
                    <br />
                    <select id="mode" onclick={on_mode_click}>
                        <option value="cbc" selected=true >{"CBC"}</option>
                        <option value="ecb" >{"ECB"}</option>
                    </select>
                </div>

                <br />

                if *is_cbc {

                    <div>
                        <label for="iv">{ "Initial vector (in hexadecimal)" }</label>
                        <br />
                        <input type="text" id="iv" min="32" max="32" value="00000000000000000000000000000000"/>
                    </div>

                    <br />
                }

                <div>
                    <label for="key">{ "Key (in hexadecimal)" }</label>
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
                    <textarea id="ti" placeholder="Any text you want..."/>
                </div>

                <br />

                <div style="text-align:center">
                    <button {onclick}>{ "Encrypt" }</button>
                </div>

                <br />

                <div>
                    <textarea id="to" placeholder="Here is the AES encrypted output"/>
                </div>
            </div>
        </main>
    }
}
