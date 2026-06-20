//! Tiny helper that prints a descriptor key for the first BIP-39 mnemonic
//! in `asterism-xpub/.env`. Useful for manually exercising browser-side
//! onboarding flows that consume the canonical descriptor-key shape.
//!
//! Run with:
//!
//!     cargo run --example print_descriptor_key --features test-utils
//!
//! Prints exactly one line to stdout: the descriptor key.

#[cfg(feature = "test-utils")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use asterism_core::Signer;

    let env_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env");
    dotenvy::from_path(&env_path).ok();

    let fixture = asterism_xpub::TestFederationFixture::from_env()?;
    let signers = fixture.build_test_signers()?;
    let first = signers.first().ok_or("no signers in fixture")?;
    let s = first.external_signer();

    let fp = s.fingerprint();
    let body = s.derivation_path().to_string();
    let xpub = s.xpub().to_string();
    println!("[{fp}/{body}]{xpub}");
    Ok(())
}

#[cfg(not(feature = "test-utils"))]
fn main() {
    eprintln!("Build with --features test-utils to run this example.");
}
