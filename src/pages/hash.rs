use yew::prelude::*;
use yew_router::prelude::*;

use wasm_bindgen::JsCast;
use web_sys::HtmlTextAreaElement;

use crate::utils::route::Route;

use crate::utils::transformer::*;

#[function_component(Hash)]
pub fn hash() -> Html {
    let navigator1 = use_navigator().unwrap();
    let to_sha1 = Callback::from(move |_| navigator1.push(&Route::HashSha1));

    let navigator2 = use_navigator().unwrap();
    let to_sha256 = Callback::from(move |_| navigator2.push(&Route::HashSha256));

    html! {
        <main>
            <h1>{ "Hash with..." }</h1>
            <div>
                 <button onclick={to_sha1}>{ "SHA-1" }</button>
            </div>
            <div>
                 <button onclick={to_sha256}>{ "SHA-256" }</button>
            </div>
        </main>
    }
}

#[function_component(HashSha1)]
pub fn hash_sha1() -> Html {
    let onclick = Callback::from(move |_: MouseEvent| {
        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();

        let ti_element = document.get_element_by_id("ti").unwrap();
        let ti_textarea = ti_element.dyn_into::<HtmlTextAreaElement>().unwrap();
        let ti_textarea_content = ti_textarea.value();

        let to_element = document.get_element_by_id("to").unwrap();
        let to_textarea = to_element.dyn_into::<HtmlTextAreaElement>().unwrap();

        to_textarea.set_value(&sha1_hash(ti_textarea_content.as_str()));
    });

    html! {
        <main>
            <div>
                <h1>{ "Please enter some text to hash" }</h1>

                <div>
                    <textarea id="ti" />
                </div>

                <br />

                <div>
                    <button onclick={onclick}>{ "Hash" }</button>
                </div>

                <br />

                <div>
                    <textarea id="to" />
                </div>
            </div>
        </main>
    }
}

#[function_component(HashSha256)]
pub fn hash_sha256() -> Html {
    let onclick = Callback::from(move |_: MouseEvent| {
        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();

        let ti_element = document.get_element_by_id("ti").unwrap();
        let ti_textarea = ti_element.dyn_into::<HtmlTextAreaElement>().unwrap();
        let ti_textarea_content = ti_textarea.value();

        let to_element = document.get_element_by_id("to").unwrap();
        let to_textarea = to_element.dyn_into::<HtmlTextAreaElement>().unwrap();

        to_textarea.set_value(&sha256_hash(ti_textarea_content.as_str()));
    });

    html! {
        <main>
            <div>
                <h1>{ "Please enter some text to hash" }</h1>

                <div>
                    <textarea id="ti" />
                </div>

                <br />

                <div>
                    <button onclick={onclick}>{ "Hash" }</button>
                </div>

                <br />

                <div>
                    <textarea id="to" />
                </div>
            </div>
        </main>
    }
}
