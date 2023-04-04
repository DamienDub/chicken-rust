use yew::prelude::*;
use yew_router::prelude::*;

use crate::utils::route::Route;


#[function_component(Encrypt)]
pub fn encrypt() -> Html {
    let navigator = use_navigator().unwrap();

    html! {
        <main>
            <h1>{ "Encrypt with..." }</h1>
            <div>
                 <button onclick={}>{ "AES-256" }</button>
            </div>
        </main>
    }
}

