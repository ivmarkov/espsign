use std::fs::{self, File};
use std::path::PathBuf;

use log::info;

use rand::thread_rng;

use espsign::rsa::pkcs8::DecodePrivateKey;
use espsign::rsa::RsaPrivateKey;
use espsign::{AsyncIo, SBV2RsaSignatureBlock};

/// Sign `image` with private key `key` and save the signed image as `signed`.
/// Also, generate the hash of the private key and save it as `hash`
fn main() {
    let key = PathBuf::from("/home/foo/private-key.pem");
    let image = PathBuf::from("/home/foo/factory-app");
    let signed = PathBuf::from("/home/foo/factory-app-signed");
    let hash = PathBuf::from("/home/foo/efuse-sb-hash");

    let mut buf = [0; 65536];

    let priv_key = RsaPrivateKey::from_pkcs8_pem(&fs::read_to_string(&key).unwrap()).unwrap();

    info!("Signing image `{}`...", image.display());

    embassy_futures::block_on(async {
        let block = SBV2RsaSignatureBlock::sign(
            &priv_key,
            &mut thread_rng(),
            &mut buf,
            AsyncIo::new(File::open(image).unwrap()),
            AsyncIo::new(File::create(&signed).unwrap()),
        )
        .await
        .unwrap();

        info!("Image signed and saved to `{}`", signed.display());

        block
            .save_pubkey_hash(AsyncIo::new(File::create(&hash).unwrap()))
            .await
            .unwrap();

        info!("Hash saved to `{}`", hash.display());
    });
}
