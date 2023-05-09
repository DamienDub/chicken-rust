use yew::prelude::*;
use yew_router::prelude::*;

use crate::utils::route::Route;

use crate::utils::coder::*;
use crate::utils::html::*;

#[function_component(Encode)]
pub fn encode() -> Html {
    let navigator1 = use_navigator().unwrap();
    let to_base64 = Callback::from(move |_| navigator1.push(&Route::EncodeBase64));

    let navigator2 = use_navigator().unwrap();
    let to_url = Callback::from(move |_| navigator2.push(&Route::EncodeUrl));

    html! {
        <main>
        <div>
            <br />
            <br />
            <span><Link<Route> to={Route::Home}>{ "Home" }</Link<Route>> {" / Encode" }</span>
            <hr />
            
            <h3>{ "Encoding to..." }</h3>

            <div style="text-align: center;">
                <div>
                    <button onclick={to_base64}>{ "UTF-8 then Base 64" }</button>
                </div>
                <br />
                <div>
                    <button onclick={to_url}>{ "URL encoding" }</button>
                </div>
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

        let ti_textarea = get_textarea_element(&document, "ti");
        let ti_textarea_content = ti_textarea.value();

        let to_textarea = get_textarea_element(&document, "to");

        to_textarea.set_value(&base64_encode(ti_textarea_content.as_str()));
    });

    html! {
        <main>
            <div>

                <br />
                <br />
                <span>
                    <Link<Route> to={Route::Home}>{ "Home" }</Link<Route>> 
                    {" / " }
                    <Link<Route> to={Route::Encode}>{ "Encode" }</Link<Route>>
                    {" / Base 64" }
                </span>
                <hr />

                <h3>{ "Please enter some text" }</h3>

                <div style="text-align: center;">
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
            </div>
        </main>
    }
}

#[function_component(EncodeUrl)]
pub fn encode_url() -> Html {
    let onclick = Callback::from(move |_: MouseEvent| {
        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();

        let ti_textarea = get_textarea_element(&document, "ti");
        let ti_textarea_content = ti_textarea.value();

        let to_textarea = get_textarea_element(&document, "to");

        to_textarea.set_value(&url_encode(ti_textarea_content.as_str()));
    });

    html! {
        <main>
            <div>

                <br />
                <br />
                <span>
                    <Link<Route> to={Route::Home}>{ "Home" }</Link<Route>> 
                    {" / " }
                    <Link<Route> to={Route::Encode}>{ "Encode" }</Link<Route>>
                    {" / URL Encoding" }
                </span>
                <hr />

                <h3>{ "Please enter some URL" }</h3>

                <div style="text-align: center;">
                    <div>
                        <textarea id="ti" />
                    </div>

                    <br />

                    <div>
                        <button {onclick}>{ "Encode" }</button>
                    </div>

                    <br />

                    <div>
                        <textarea id="to" />
                    </div>
                </div>
            </div>
        </main>
    }
}
