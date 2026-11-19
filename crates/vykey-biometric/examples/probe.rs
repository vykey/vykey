//! Manual check of the platform pieces, without a vault:
//!
//! ```sh
//! cargo run -p vykey-biometric --example probe            # reader status
//! cargo run -p vykey-biometric --example probe -- keyring # store/load/remove a test key
//! cargo run -p vykey-biometric --example probe -- verify  # scan a finger (30 s)
//! ```

use vykey_biometric::{Cancel, Error, VERIFY_TIMEOUT};

fn main() -> Result<(), Error> {
    println!("reader: {:?}", vykey_biometric::availability());
    match std::env::args().nth(1).as_deref() {
        Some("keyring") => {
            let id = "probe-test";
            let meta = vykey_core::VaultMeta {
                id: id.into(),
                name: "probe".into(),
                salt: Vec::new(),
                verifier: Vec::new(),
                wrapped_key: None,
                created_at: 0,
                updated_at: 0,
            };
            let key = zeroize::Zeroizing::new([7u8; 32]);
            vykey_biometric::store_key(id, &key)?;
            println!("stored, has_key = {}", vykey_biometric::has_key(id));
            // The verifier is empty, so the key is "stale" and gets removed.
            println!("open → {:?}", vykey_biometric::open(meta)?.is_some());
            println!("after open, has_key = {}", vykey_biometric::has_key(id));
            vykey_biometric::remove_key(id)?;
        }
        Some("verify") => {
            // Optional timeout in seconds as the second argument.
            let timeout = std::env::args()
                .nth(2)
                .and_then(|s| s.parse().ok())
                .map_or(VERIFY_TIMEOUT, std::time::Duration::from_secs);
            let verdict =
                vykey_biometric::verify(&Cancel::new(), timeout, |e| println!("event: {e:?}"))?;
            println!("verdict: {verdict:?}");
        }
        _ => {}
    }
    Ok(())
}
