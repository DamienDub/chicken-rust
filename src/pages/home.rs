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
            <h1>{ "Chicken Rust" }</h1>
            <span class="subtitle">

            <u class="tooltip">{ "Fast" }
                <span class="tooltiptext">
                    {"Built with "} <a href="https://yew.rs">{"Yew"}</a> {" and "} <a href="https://www.rust-lang.org">{"Rust"}</a> { " in order to run at near-native speed."}
                </span>
            </u>
            { ", "}
            <u class="tooltip">{ "private" }
                <span class="tooltiptext">
                    {"No cookie stored, no HTTP request sent. Everything happens in your browser. "}
                </span>
            </u>
            { " and "}
            <u class="tooltip">{ "open source" }
                <span class="tooltiptext">
                    {"Check out the code on the "}  <a href="https://github.com/DamienDub/chicken-rust">{"Github repository"} {"."}</a>
                </span>
            </u>
            {" text toolbox" }

            </span>

            <br />
            <hr />
            <br />
            <br />

            <span class="subtitle">{ "What are we doing today ?" }</span>

            <br />

            <div>
                // <span class="clue">{"?"}</span> 
                // {" "}
                <button onclick={to_encode}>{ "Text encoding" }</button>
                {" / "}
                <button onclick={to_decode}>{ "Text decoding" }</button>
                // {" "}
                // <span class="clue">{"?"}</span> 
            </div>

            <br />

            <div>
                <button onclick={to_encrypt}>{ "Text encryption" }</button> {" / "} <button onclick={to_decrypt}>{ "Text decryption" }</button>
            </div>

            <br />

            <div>
                <button onclick={to_hash}>{ "Text hashing" }</button>
            </div>

            <br />

            <div>
                <button onclick={to_generate}>{ "Text generation" }</button>
            </div>

        </main>
    }
}
