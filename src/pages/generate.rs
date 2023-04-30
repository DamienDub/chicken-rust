use yew::prelude::*;
use yew_router::prelude::*;

use crate::utils::route::Route;

use wasm_bindgen::JsCast;
use web_sys::HtmlInputElement;
use web_sys::HtmlTextAreaElement;

use gloo_console::log;

use crate::utils::transformer::*;

#[function_component(Generate)]
pub fn generate() -> Html {
    let navigator1 = use_navigator().unwrap();
    let to_random_string = Callback::from(move |_| navigator1.push(&Route::GenerateRandomString));

    html! {
        <main>
            <h1>{ "What would you like to generate ?" }</h1>
            <div>
                  <button onclick={to_random_string}>{ "A random string" }</button>
            </div>
        </main>
    }
}

#[function_component(GenerateRandomString)]
pub fn generate_random_string() -> Html {
    let onclick = Callback::from(move |_: MouseEvent| {
        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();

        let length_element = document.get_element_by_id("length").unwrap();
        let length_input = length_element.dyn_into::<HtmlInputElement>().unwrap();
        let length = length_input.value().parse::<usize>().unwrap();

        let with_lowercase_element = document.get_element_by_id("withLowercase").unwrap();
        let with_lowercase_input = with_lowercase_element
            .dyn_into::<HtmlInputElement>()
            .unwrap();
        let with_lowercase = with_lowercase_input.checked();

        let with_uppercase_element = document.get_element_by_id("withUppercase").unwrap();
        let with_uppercase_input = with_uppercase_element
            .dyn_into::<HtmlInputElement>()
            .unwrap();
        let with_uppercase = with_uppercase_input.checked();

        let with_numbers_element = document.get_element_by_id("withNumbers").unwrap();
        let with_numbers_input = with_numbers_element.dyn_into::<HtmlInputElement>().unwrap();
        let with_numbers = with_numbers_input.checked();

        let to_element = document.get_element_by_id("to").unwrap();
        let to_textarea = to_element.dyn_into::<HtmlTextAreaElement>().unwrap();
        to_textarea.set_value(
            random_string_generate(length, with_lowercase, with_uppercase, with_numbers).as_str(),
        );
    });

    html! {
        <main>
            <div>
                <h1>{ "Generate a string with" }</h1>

                <div>
                    <label for="length">{ "Number of characters" }</label>
                    <br />
                    <input type="number" id="length" min="1" max="128" step="1" value="8"/>
                </div>

                <br />

                <div>
                    <label for="withLowercase">{ "With lowercase characters" }</label>
                    <br />
                    <input type="checkbox" id="withLowercase" checked=false />
                </div>

                <br />

                <div>
                    <label for="withUppercase">{ "With uppercase characters" }</label>
                    <br />
                    <input type="checkbox" id="withUppercase" />
                </div>

                <br />

                <div>
                    <label for="withNumbers">{ "With numbers" }</label>
                    <br />
                    <input type="checkbox" id="withNumbers" />
                </div>

                <br />

                <div>
                    <button onclick={onclick}>{ "Generate" }</button>
                </div>

                <br />

                <div>
                    <textarea id="to" />
                </div>
            </div>
        </main>
    }
}
