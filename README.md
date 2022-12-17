# cert-tester

This is a small Rust app to run TLS certificate(s) through the same parser that `rustls`-based TLS stacks use. 
It allows someone to determine why a certificate would be failing in an environment that uses it with much more detail then
a production deployment and standard version of `webpki` would provide.

This project contains forked versions of *ring* and `webpki` that have extra debug printing added to them, which allow you
to get a more descriptive failure message when certificates are rejected instead of the current `BadDer` error, which covers
too many error cases to be useful on its own.

## Usage

To use this, follow these steps:
1. Checkout this repository and make sure you have Rust installed.
2. Download the certificate file you want to check.
3. Run `cargo run -- /path/to/your/cert.pem <your-domain.tld>` in a terminal.
4. Observe the results.

If the certificate fails with a non-detailed error, you will probably need to add your own `println!` debugging to find problem's source.
Contributions adding new logging for observed failure cases are welcome.

## History

This tool is used internally at 1Password to help debug certificate parsing errors that various users encounter. It has been open sourced
to help provide a "quick and easy" option for others in similar positions to do the same.

## License

This crate is licensed under the MIT license. See each crate's license under `vendored/` for their own licensing.