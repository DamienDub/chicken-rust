use yew::prelude::*;
use yew_router::prelude::*;

use crate::utils::route::Route;

use crate::utils::generator::*;
use crate::utils::html::*;

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

        let length_input = get_input_element(&document, "length");
        let length = length_input.value().parse::<usize>().unwrap();

        let with_lowercase_input = get_input_element(&document, "withLowercase");
        let with_lowercase = with_lowercase_input.checked();

        let with_uppercase_input = get_input_element(&document, "withUppercase");
        let with_uppercase = with_uppercase_input.checked();

        let with_numbers_input = get_input_element(&document, "withNumbers");
        let with_numbers = with_numbers_input.checked();

        let to_textarea = get_textarea_element(&document, "to");

        match random_string_generate(length, with_lowercase, with_uppercase, with_numbers) {
            Ok(result) => to_textarea.set_value(result.as_str()),
            Err(error) => to_textarea.set_value(error),
        }
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
                    <button {onclick}>{ "Generate" }</button>
                </div>

                <br />

                <div>
                    <textarea id="to" />
                </div>
            </div>
        </main>
    }
}
