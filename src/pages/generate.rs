use yew::prelude::*;
use yew_router::prelude::*;

use crate::utils::route::Route;


#[function_component(Generate)]
pub fn generate() -> Html {
    let navigator = use_navigator().unwrap();

    html! {
        <main>
            <h1>{ "What would you like to generate ?" }</h1>
            <div>
                //  <button onclick={}>{ "A random string" }</button>
            </div>
        </main>
    }
}

