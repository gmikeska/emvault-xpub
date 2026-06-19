//! Generate a deterministic 12-word BIP-39 mnemonic from a labeled entropy.
//!
//! Used once to author the `.env` fixture's 5th signer; left in the repo so
//! anyone can reproduce the fixture by running it again. Run with:
//!
//! ```bash
//! cargo run --features test-utils --example check_mnemonics
//! ```

#[cfg(feature = "test-utils")]
fn main() {
    // Distinct 16-byte entropies, each labelled. We pick patterns that are
    // obviously synthetic so the resulting mnemonic is clearly a test
    // vector rather than a real wallet seed.
    let entropies: [(&str, [u8; 16]); 1] =
        [("signer 5 (asterism-xpub-coldcard)", *b"asterism-xpub-c5")];
    for (label, entropy) in entropies {
        match bip39::Mnemonic::from_entropy(&entropy) {
            Ok(m) => println!("{label}: {m}"),
            Err(e) => println!("{label}: ERR {e:?}"),
        }
    }
}

#[cfg(not(feature = "test-utils"))]
fn main() {
    eprintln!("rebuild with --features test-utils");
}
