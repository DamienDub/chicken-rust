# Chicken Rust

## What is it

Chicken Rust is a web application for manipulating text data.
It is built with [Yew](https://yew.rs), a Rust-based frontend framework.

## Installation

If you don't already have it installed, it's time to install Rust: <https://www.rust-lang.org/tools/install>.
The rest of this guide assumes a typical Rust installation which contains both `rustup` and Cargo.

To compile Rust to WASM, we need to have the `wasm32-unknown-unknown` target installed.
If you don't already have it, install it with the following command:

```bash
rustup target add wasm32-unknown-unknown
```

Now that we have our basics covered, it's time to install the star of the show: [Trunk].
Simply run the following command to install it:

```bash
cargo install trunk wasm-bindgen-cli
```

And you're done.

## Running

```bash
trunk serve
```

Rebuilds the app whenever a change is detected and runs a local server to host it.

There's also the `trunk watch` command which does the same thing but without hosting it.

## Release

```bash
trunk build --release
```

This builds the app in release mode similar to `cargo build --release`.
You can also pass the `--release` flag to `trunk serve` if you need to get every last drop of performance.

Unless overwritten, the output will be located in the `dist` directory.

## Contributing

We welcome contributions. If you'd like to contribute to the project, please follow these steps:

- Fork the repository
- Create a new branch: git checkout -b my-new-feature
- Make your changes and commit them: git commit -am 'Add some feature'
- Push to the branch: git push origin my-new-feature
- Submit a pull request

## License

This code is released under the Apache 2.0 license.



