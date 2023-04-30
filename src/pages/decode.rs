use yew::prelude::*;
use yew_router::prelude::*;

use crate::utils::route::Route;

use wasm_bindgen::JsCast;
use web_sys::HtmlTextAreaElement;

use crate::utils::transformer::*;

#[function_component(Decode)]
pub fn decode() -> Html {

    let navigator1 = use_navigator().unwrap();
    let to_base64 = Callback::from(move |_| navigator1.push(&Route::DecodeBase64));

    let navigator2 = use_navigator().unwrap();
    let to_url = Callback::from(move |_| navigator2.push(&Route::DecodeUrl));

    html! {
        <main>
        <div>
            <h1>{ "Decode with" }</h1>
            <div>
                 <button onclick={to_base64}>{ "Base 64" }</button>
            </div>
            <div>
                <button onclick={to_url}>{ "URL decoding" }</button>
            </div>
        </div>
        </main>
    }
}

#[function_component(DecodeBase64)]
pub fn decode_base64() -> Html {
    let onclick = Callback::from(move |_: MouseEvent| {
        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();

        let ti_element = document.get_element_by_id("ti").unwrap();
        let ti_textarea = ti_element.dyn_into::<HtmlTextAreaElement>().unwrap();
        let ti_textarea_content = ti_textarea.value();

        let to_element = document.get_element_by_id("to").unwrap();
        let to_textarea = to_element.dyn_into::<HtmlTextAreaElement>().unwrap();

        to_textarea.set_value(&base64_decode(ti_textarea_content.as_str()));
    });

    html! {
        <main>
            <div>
                <h1>{ "Please enter some Base 64 text" }</h1>

                <div>
                    <textarea id="ti" />
                </div>

                <br />

                <div>
                    <button onclick={onclick}>{ "Decode" }</button>
                </div>

                <br />

                <div>
                    <textarea id="to" />
                </div>
            </div>
        </main>
    }
}


#[function_component(DecodeUrl)]
pub fn decode_url() -> Html {
    let onclick = Callback::from(move |_: MouseEvent| {
        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();

        let ti_element = document.get_element_by_id("ti").unwrap();
        let ti_textarea = ti_element.dyn_into::<HtmlTextAreaElement>().unwrap();
        let ti_textarea_content = ti_textarea.value();

        let to_element = document.get_element_by_id("to").unwrap();
        let to_textarea = to_element.dyn_into::<HtmlTextAreaElement>().unwrap();

        to_textarea.set_value(&url_decode(ti_textarea_content.as_str()));
    });

    html! {
        <main>
            <div>
                <h1>{ "Please enter an encoded URL" }</h1>

                <div>
                    <textarea id="ti" />
                </div>

                <br />

                <div>
                    <button onclick={onclick}>{ "Decode" }</button>
                </div>

                <br />

                <div>
                    <textarea id="to" />
                </div>
            </div>
        </main>
    }
}