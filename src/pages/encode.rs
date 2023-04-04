use yew::prelude::*;
use yew_router::prelude::*;

use crate::utils::route::Route;

use wasm_bindgen::JsCast;
use web_sys::HtmlTextAreaElement;

use crate::utils::transformer::*;

#[function_component(Encode)]
pub fn encode() -> Html {
    let navigator = use_navigator().unwrap();

    html! {
        <main>
        <div>
            <h1>{ "Encode with" }</h1>
            <div>
                 <button onclick={Callback::from(move |_| navigator.push(&Route::EncodeBase64))}>{ "Base 64" }</button>
            </div>
            <div>
                <button>{ "URL encoding" }</button>
            </div>
        </div>
        </main>
    }
}


#[function_component(Decode)]
pub fn decode() -> Html {
    let navigator = use_navigator().unwrap();

    html! {
        <main>
        <div>
            <h1>{ "Decode with" }</h1>
            <div>
                 <button onclick={Callback::from(move |_| navigator.push(&Route::DecodeBase64))}>{ "Base 64" }</button>
            </div>
            <div>
                <button>{ "URL encoding" }</button>
            </div>
        </div>
        </main>
    }
}

#[function_component(EncodeBase64)]
pub fn encode_base64() -> Html {
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