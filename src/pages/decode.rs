use yew::prelude::*;
use yew_router::prelude::*;

use crate::utils::route::Route;

use crate::utils::coder::*;
use crate::utils::html::*;

#[function_component(Decode)]
pub fn decode() -> Html {
    let navigator1 = use_navigator().unwrap();
    let to_base64 = Callback::from(move |_| navigator1.push(&Route::DecodeBase64));

    let navigator2 = use_navigator().unwrap();
    let to_url = Callback::from(move |_| navigator2.push(&Route::DecodeUrl));

    html! {
        <main>
        <div>
            
            <br />
            <br />
            <span><Link<Route> to={Route::Home}>{ "Home" }</Link<Route>> {" / Decode" }</span>
            <hr />
            <br />
            <br />
            
            <h2>{ "Decode with..." }</h2>

            <div style="text-align: center;">
                <div>
                    <button onclick={to_base64}>{ "Base 64" }</button>
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

#[function_component(DecodeBase64)]
pub fn decode_base64() -> Html {
    let onclick = Callback::from(move |_: MouseEvent| {
        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();

        let ti_textarea = get_textarea_element(&document, "ti");
        let ti_textarea_content = ti_textarea.value();

        let to_textarea = get_textarea_element(&document, "to");

        match base64_decode(ti_textarea_content.as_str()) {
            Ok(result) => to_textarea.set_value(result.as_str()),
            Err(error) => to_textarea.set_value(error),
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
                    <Link<Route> to={Route::Decode}>{ "Decode" }</Link<Route>>
                    {" / Base 64" }
                </span>

                <hr />
                <br />

                <textarea id="ti" style="min-height:100px" placeholder="Write the text to decode in here" />                      
            
                <br />
                <br />

                <div style="text-align:center">
                    <button {onclick} >{ "Decode" }</button>
                </div>

                <br />

                <textarea id="to" style="min-height:100px" placeholder="Here is the base 64 decoded output"/>


            </div>
        </main>
    }
}

#[function_component(DecodeUrl)]
pub fn decode_url() -> Html {
    let onclick = Callback::from(move |_: MouseEvent| {
        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();

        let ti_input = get_input_element(&document, "ti");
        let ti_input_content = ti_input.value();

        let to_input = get_input_element(&document, "to");

        match url_decode(ti_input_content.as_str()) {
            Ok(result) => to_input.set_value(result.as_str()),
            Err(error) => to_input.set_value(error),
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
                    <Link<Route> to={Route::Decode}>{ "Decode" }</Link<Route>>
                    {" / URL Decoding" }
                </span>
                <hr />
                <br />

                <input type="text" id="ti" placeholder="Write down the URL to decode in here"/>

                <br />
                <br />

                <div style="text-align: center;">
                    <button {onclick} >{ "Decode" }</button>
                </div>

                <br />

                <input type="text" id="to" placeholder="Here is the URL decoded output"/>

            </div>
        </main>
    }
}
