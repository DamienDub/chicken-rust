// use gloo_console::log;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::pages::encode::Encode;
use crate::pages::encode::EncodeBase64;
use crate::pages::home::Home;
use crate::utils::route::Route;

fn switch(routes: Route) -> Html {
    match routes {
        Route::Home => html! {
           <Home />
        },
        Route::Encode => html! {
            <Encode />
        },
        Route::EncodeBase64 => html! {
            <EncodeBase64 />
        },
        Route::NotFound => html! { <main><h1>{ "You got lost ?" }</h1></main> },
    }
}

#[function_component(App)]
pub fn app() -> Html {
    html! {
        <BrowserRouter>
            <Switch<Route> render={switch} /> // <- must be child of <BrowserRouter>
        </BrowserRouter>
    }
}
