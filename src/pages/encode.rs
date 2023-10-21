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
            
            <h3>{ "What type of encoding are we looking for ?" }</h3>

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
            <div >

                <br />
                <br />
                <span>
                    <Link<Route> to={Route::Home}>{ "Home" }</Link<Route>> 
                    {" / " }
                    <Link<Route> to={Route::Encode}>{ "Encode" }</Link<Route>>
                    {" / Base 64" }
                </span>

                <hr />
                <br />

                <textarea id="ti" style="min-height:100px" placeholder="Write the text to encode in here" />                      
            
                <br />
                <br />

                <div style="text-align:center">
                    <button {onclick} >{ "Encode" }</button>
                </div>

                <br />

                <textarea id="to" style="min-height:100px" placeholder="Here is the base 64 encoded output"/>
                
            </div>
        </main>
    }
}

#[function_component(EncodeUrl)]
pub fn encode_url() -> Html {
    let onclick = Callback::from(move |_: MouseEvent| {
        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();

        let ti_input = get_input_element(&document, "ti");
        let ti_input_content = ti_input.value();

        let to_input = get_input_element(&document, "to");

        to_input.set_value(&url_encode(ti_input_content.as_str()));
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
                <br />


                <input type="text" id="ti" placeholder="Write down the URL to encode in here"/>

                <br />
                <br />

                <div style="text-align: center;">
                    <button {onclick} >{ "Encode" }</button>
                </div>

                <br />

                <input type="text" id="to" placeholder="Here is the URL encoded output"/>
                
            </div>
        </main>
    }
}
