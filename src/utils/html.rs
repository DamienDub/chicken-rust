use wasm_bindgen::JsCast;
use web_sys::Document;
use web_sys::HtmlInputElement;
use web_sys::HtmlSelectElement;
use web_sys::HtmlTextAreaElement;

pub fn get_input_element(document: &Document, id: &str) -> HtmlInputElement {
    let element = document.get_element_by_id(id).unwrap();
    return element.dyn_into::<HtmlInputElement>().unwrap();
}

pub fn get_select_element(document: &Document, id: &str) -> HtmlSelectElement {
    let element = document.get_element_by_id(id).unwrap();
    return element.dyn_into::<HtmlSelectElement>().unwrap();
}

pub fn get_textarea_element(document: &Document, id: &str) -> HtmlTextAreaElement {
    let element = document.get_element_by_id(id).unwrap();
    return element.dyn_into::<HtmlTextAreaElement>().unwrap();
}
