use yew::prelude::*;
use yew_router::prelude::*;

use crate::utils::route::Route;

use crate::utils::hasher::*;
use crate::utils::html::*;

#[function_component(Hash)]
pub fn hash() -> Html {
    let navigator1 = use_navigator().unwrap();
    let to_sha1 = Callback::from(move |_| navigator1.push(&Route::HashSha1));

    let navigator2 = use_navigator().unwrap();
    let to_sha256 = Callback::from(move |_| navigator2.push(&Route::HashSha256));

    html! {
        <main>

            <br />
            <br />
            <span><Link<Route> to={Route::Home}>{ "Home" }</Link<Route>> {" / Hash" }</span>
            <hr />
            <br />
            <br />
            
            <h2>{ "Hash with..." }</h2>

            <div style="text-align:center">
                 <button onclick={to_sha1}>{ "SHA-1" }</button>
            </div>

            <div style="text-align:center">
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

        let ti_textarea = get_textarea_element(&document, "ti");
        let ti_textarea_content = ti_textarea.value();

        let to_textarea = get_textarea_element(&document, "to");

        to_textarea.set_value(&sha1_hash(ti_textarea_content.as_str()));
    });

    html! {
        <main>
            <div>

                <br />
                <br />
                <span>
                    <Link<Route> to={Route::Home}>{ "Home" }</Link<Route>> 
                    {" / " }
                    <Link<Route> to={Route::Hash}>{ "Hash" }</Link<Route>>
                    {" / SHA-1" }
                </span>

                <hr />
                <br />

                <textarea id="ti" style="min-height:100px" placeholder="Any text to hash in here..." />
                
                <br />
                <br />

                <div style="text-align:center">
                    <button {onclick}>{ "Hash" }</button>
                </div>

                <br />

                <div>
                    <textarea id="to" style="min-height:100px" placeholder="Here is the SHA-1 hash output"/>
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

        let ti_textarea = get_textarea_element(&document, "ti");
        let ti_textarea_content = ti_textarea.value();

        let to_textarea = get_textarea_element(&document, "to");

        to_textarea.set_value(&sha256_hash(ti_textarea_content.as_str()));
    });

    html! {
        <main>
            <div>
                
                <br />
                <br />
                <span>
                    <Link<Route> to={Route::Home}>{ "Home" }</Link<Route>> 
                    {" / " }
                    <Link<Route> to={Route::Hash}>{ "Hash" }</Link<Route>>
                    {" / SHA-256" }
                </span>

                <hr />
                <br />

                <div>
                    <textarea id="ti"  style="min-height:100px" placeholder="Any text to hash in here..."/>
                </div>

                <br />
                <br />

                <div style="text-align:center">
                    <button onclick={onclick}>{ "Hash" }</button>
                </div>

                <br />

                <div>
                    <textarea id="to" style="min-height:100px" placeholder="Here is the SHA-256 hash output"/>
                </div>
            </div>
        </main>
    }
}
