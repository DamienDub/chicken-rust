use yew::prelude::*;
use yew_router::prelude::*;

use crate::utils::route::Route;

use wasm_bindgen::JsCast;
use web_sys::HtmlTextAreaElement;

use crate::utils::transformer::*;

#[function_component(Encode)]
pub fn encode() -> Html {

    let navigator1 = use_navigator().unwrap();
    let to_base64 = Callback::from(move |_| navigator1.push(&Route::EncodeBase64));

    let navigator2 = use_navigator().unwrap();
    let to_url = Callback::from(move |_| navigator2.push(&Route::EncodeUrl));

    html! {
        <main>
        <div>
            <h1>{ "Encode with" }</h1>
            <div>
                 <button onclick={to_base64}>{ "Base 64" }</button>
            </div>
            <div>
                <button onclick={to_url}>{ "URL encoding" }</button>
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

                <br />

                <div>
                    <button onclick={onclick}>{ "Encode" }</button>
                </div>

                <br />

                <div>
                    <textarea id="to" />
                </div>
            </div>
        </main>
    }
}


#[function_component(EncodeUrl)]
pub fn encode_url() -> Html {
    let onclick = Callback::from(move |_: MouseEvent| {
        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();

        let ti_element = document.get_element_by_id("ti").unwrap();
        let ti_textarea = ti_element.dyn_into::<HtmlTextAreaElement>().unwrap();
        let ti_textarea_content = ti_textarea.value();

        let to_element = document.get_element_by_id("to").unwrap();
        let to_textarea = to_element.dyn_into::<HtmlTextAreaElement>().unwrap();

        to_textarea.set_value(&url_encode(ti_textarea_content.as_str()));
    });

    html! {
        <main>
            <div>
                <h1>{ "Please enter some URL" }</h1>

                <div>
                    <textarea id="ti" />
                </div>

                <br />

                <div>
                    <button onclick={onclick}>{ "Encode" }</button>
                </div>

                <br />

                <div>
                    <textarea id="to" />
                </div>
            </div>
        </main>
    }
}