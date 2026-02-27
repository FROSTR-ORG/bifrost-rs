mod frost_flow;

use anyhow::Result;
use frost_flow::FrostSigningConfig;

fn main() -> Result<()> {
    let config = FrostSigningConfig {
        threshold: 2,
        max_signers: 3,
        message: b"hello from FROST over BIP-340".to_vec(),
    };

    println!("Starting FROST BIP-340 starter flow...");
    println!("threshold={}, max_signers={}", config.threshold, config.max_signers);

    // This starter intentionally wires the app structure first.
    // Fill these methods with real `frost-secp256k1-tr` round logic.
    let session = frost_flow::prepare_session(&config)?;
    let _sig = frost_flow::run_signing_rounds(&session)?;
    frost_flow::verify_group_signature(&session)?;

    println!("Starter flow completed (skeleton). Implement round logic next.");
    Ok(())
}
