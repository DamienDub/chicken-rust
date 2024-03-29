// use gloo_console::log;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::pages::encode::*;
use crate::pages::decode::*;
use crate::pages::encrypt::*;
use crate::pages::decrypt::*;
use crate::pages::generate::*;
use crate::pages::hash::*;
use crate::pages::home::*;
use crate::pages::test::*;
use crate::utils::route::Route;

fn switch(routes: Route) -> Html {
    match routes {
        Route::Home => html! { <Home /> },
        Route::Encode => html! { <Encode /> },
        Route::EncodeBase64 => html! { <EncodeBase64 /> },
        Route::EncodeUrl => html! { <EncodeUrl /> },
        Route::Decode => html! { <Decode /> },
        Route::DecodeBase64 => html! { <DecodeBase64 /> },
        Route::DecodeUrl => html! { <DecodeUrl /> },
        Route::Generate => html! { <Generate /> },
        Route::GenerateRandomString => html! { <GenerateRandomString /> },
        Route::Hash => html! {<Hash />},
        Route::HashSha1 => html! {<HashSha1 />},
        Route::HashSha256 => html! {<HashSha256 />},
        Route::Encrypt => html! {< Encrypt />},
        Route::EncryptAes => html! {<EncryptAes />},
        Route::Decrypt => html! {< Decrypt />},
        Route::DecryptAes => html! {<DecryptAes />},
        Route::Test => html! {<Test />},
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
