use yew::prelude::*;
use yew_router::prelude::*;

use crate::utils::route::Route;

#[function_component(Home)]
pub fn home() -> Html {
    let navigator1 = use_navigator().unwrap();
    let to_encode = Callback::from(move |_: MouseEvent| {
        navigator1.push(&Route::Encode);
    });

    let navigator2 = use_navigator().unwrap();
    let to_decode = Callback::from(move |_: MouseEvent| {
        navigator2.push(&Route::Decode);
    });

    let navigator3 = use_navigator().unwrap();
    let to_generate = Callback::from(move |_: MouseEvent| {
        navigator3.push(&Route::Generate);
    });

    let navigator4 = use_navigator().unwrap();
    let to_hash = Callback::from(move |_: MouseEvent| {
        navigator4.push(&Route::Hash);
    });

    let navigator5 = use_navigator().unwrap();
    let to_encrypt = Callback::from(move |_: MouseEvent| {
        navigator5.push(&Route::Encrypt);
    });

    let navigator6 = use_navigator().unwrap();
    let to_decrypt = Callback::from(move |_: MouseEvent| {
        navigator6.push(&Route::Decrypt);
    });

    html! {
        <main>
            <h1>{ "Welcome to Chicken Rust" }</h1>
            <span class="subtitle">{ "Fast. Confidential. Open source" }</span>

            <br /><br />

            <span class="subtitle">{ "What would you like to do ?" }</span>

            <div>
                <button onclick={to_encode}>{ "I want to encode" }</button>
            </div>

            <div>
                <button onclick={to_decode}>{ "I want to decode" }</button>
            </div>

            <div>
                <button onclick={to_generate}>{ "I want to generate" }</button>
            </div>

            <div>
                <button onclick={to_hash}>{ "I want to hash" }</button>
            </div>

            <div>
                <button onclick={to_encrypt}>{ "I want to encrypt" }</button>
            </div>

            <div>
                <button onclick={to_decrypt}>{ "I want to decrypt" }</button>
            </div>

        </main>
    }
}
