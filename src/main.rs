//! Tool for debugging TLS issues that originate from the rustls/webpki
//! certificate handling stack.

use std::convert::TryFrom;
use std::env;
use std::fs;
use webpki::{DnsNameRef, EndEntityCert};

// Normalize a certificate export from the browser:
// * From Chrome (file download): [ee_cert] (array with only end-entity)
// * From Firefox (URL copy): [ee_cert, cert_1, cert_2, ..., root_cert] (array with full-chain)
fn normalize_export(encoded_data: &str) -> Vec<String> {
    let mut certs = Vec::new();

    let data = encoded_data
        .trim_start_matches("about:certificate?cert=")
        .split("&cert=");

    for d in data {
        if d.contains('%') {
            let decoded = urlencoding::decode(d).expect("Failed to decode URL string");
            certs.push(decoded.into_owned());
        } else {
            certs.push(d.to_owned());
        }
    }

    certs
}

// Attempt to print cert metadata for troubleshooting context.
// This is a no-op for invalid certs, we're interest in `webpki` errors, not `x509_parser` errors.
fn maybe_print_cert_metadata(decoded_cert: &[u8]) {
    if let Ok((_, x509_cert)) = x509_parser::parse_x509_certificate(decoded_cert) {
        println!("\tX.509 Subject: {}", x509_cert.subject());
        if let Ok(Some(extension)) = x509_cert.tbs_certificate.subject_alternative_name() {
            println!(
                "\tX.509 Alternative Subject(s): {:?}",
                extension.value.general_names
            );
        }
        println!("\tX.509 Issuer: {}", x509_cert.issuer());
        println!(
            "\tX.509 serial: {}",
            x509_cert.tbs_certificate.raw_serial_as_string()
        );
        println!("\tX.509 version: {:?}", x509_cert.tbs_certificate.version());
        println!("\tX.509 CA? {}", x509_cert.tbs_certificate.is_ca());
    }
}

fn main() {
    let mut args = env::args().skip(1);
    let input_file = args.next().expect("supply an input certificate (chain)");

    let domain_name = args.next().expect("supply a domain name to check against");
    let domain_name = DnsNameRef::try_from_ascii_str(&domain_name).unwrap();

    let encoded_input = fs::read_to_string(input_file).unwrap();
    let encoded_certs = normalize_export(&encoded_input);

    for (i, encoded_cert) in encoded_certs.iter().enumerate() {
        println!("Loading cert...");

        let encoded_cert: String = encoded_cert
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('-'))
            .collect();

        let decoded_cert = base64::decode_config(encoded_cert.trim(), base64::STANDARD_NO_PAD)
            .expect("requested cert wasn't base64");

        // Print for more context
        maybe_print_cert_metadata(&decoded_cert);

        // Only end-entity: should match the provided domain name.
        if i == 0 {
            let cert = EndEntityCert::try_from(decoded_cert.as_slice())
                .expect("failed to parse certificate");

            cert.verify_is_valid_for_dns_name(domain_name)
                .expect("certificate had the wrong domain name");
        }

        println!("cert was all good");
    }
}
