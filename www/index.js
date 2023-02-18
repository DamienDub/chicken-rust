import * as wasm from "chicken-rust";

console.log("SHA-1: " + wasm.sha1("test"));

try {

    let base64_encoded = wasm.base64_encode("test")
    console.log("Base 64 encoded string: " + base64_encoded);

    let base64_decoded = wasm.base64_decode(base64_encoded)
    console.log("Base 64 decoded string: " + base64_decoded);
}
catch (error) {
    console.error(error);
}

try {

    let url_encoded = wasm.url_encode("https://chickenrust.com?var= Go go go");
    console.log("URL encoded: " + url_encoded);

    let url_decoded = wasm.url_decode(url_encoded);
    console.log("URL decoded: " + url_decoded);
}
catch (error) {
    console.error(error);
}