use yew::prelude::*;
use yew_router::prelude::*;

use crate::utils::route::Route;


#[function_component(Hash)]
pub fn hash() -> Html {
    let navigator = use_navigator().unwrap();

    html! {
        <main>
            <h1>{ "Hash with..." }</h1>
            <div>
                 <button onclick={}>{ "SHA-1" }</button>
            </div>
            <div>
                 <button onclick={}>{ "SHA-256" }</button>
            </div>
        </main>
    }
}

