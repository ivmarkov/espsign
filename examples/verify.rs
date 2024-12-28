use std::fs::File;
use std::path::PathBuf;

use log::info;

use espsign::{AsyncIo, SBV2RsaSignatureBlock};

/// Verify that `image` is properly signed
fn main() {
    let image = PathBuf::from("/home/foo/factory-app-signed");

    let mut buf = [0; 65536];

    info!("Verifying image `{}`...", image.display());

    embassy_futures::block_on(SBV2RsaSignatureBlock::load_and_verify(
        &mut buf,
        AsyncIo::new(File::open(image).unwrap()),
    ))
    .unwrap();

    info!("Image verified successfully");
}
