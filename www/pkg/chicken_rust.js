import * as wasm from "./chicken_rust_bg.wasm";
import { __wbg_set_wasm } from "./chicken_rust_bg.js";
__wbg_set_wasm(wasm);
export * from "./chicken_rust_bg.js";
