import * as wasm from "chicken-rust";

console.log(wasm.sha1());
console.log(wasm.base64_encode("test"));
console.log(wasm.base64_decode(wasm.base64_encode("test")));