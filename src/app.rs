// use gloo_console::log;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::pages::home::*;
use crate::pages::encode::*;
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
        Route::Decode => html! {
            <Decode />
        },
        Route::DecodeBase64 => html! {
            <DecodeBase64 />
        },

        Route::Generate => html! {
           
        },

        Route::Hash => html! {
           
        },

        Route::Encrypt => html! {
           
        },

        Route::Decrypt => html! {
           
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
