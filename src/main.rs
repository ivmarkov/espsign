use std::convert::Infallible;

use embedded_io_async::{ErrorType, Read, Write};
use espsign::{ImageType, NullWrite};

use rand::thread_rng;

use rsa::pkcs8::DecodePrivateKey;

static PRIV: &str = include_str!("../private-key.pem");
static IMAGE: &[u8] = include_bytes!("../sl");

pub struct AsyncIo<W>(W);

impl<W> ErrorType for AsyncIo<W> {
    type Error = core::convert::Infallible;
}

impl<R> Read for AsyncIo<R>
where
    R: std::io::Read,
{
    async fn read(&mut self, data: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(self.0.read(data).unwrap())
    }
}

impl<W> Write for AsyncIo<W>
where
    W: std::io::Write,
{
    async fn write(&mut self, data: &[u8]) -> Result<usize, Self::Error> {
        Ok(self.0.write(data).unwrap())
    }
}

fn main() {
    let priv_key = espsign::rsa::RsaPrivateKey::from_pkcs8_pem(PRIV).unwrap();

    let mut buf = [0; 8192];

    let mut out = std::fs::File::create("out").unwrap();
    let mut sha = std::fs::File::create("sha").unwrap();

    let mut rng = thread_rng();

    embassy_futures::block_on(async {
        let signature = espsign::SBV2RsaSignatureBlock::sign(
            &priv_key,
            &mut rng,
            &mut buf,
            IMAGE,
            ImageType::App,
            AsyncIo(&mut out),
        )
        .await
        .unwrap();

        signature.save_pubkey_hash(AsyncIo(&mut sha)).await.unwrap();
    });

    drop(out);

    let out = std::fs::File::open("out").unwrap();

    embassy_futures::block_on(async {
        espsign::SBV2RsaSignatureBlock::load_and_verify(&mut buf, AsyncIo(out), ImageType::App)
            .await
            .unwrap();
    });

    println!("Hello, world!");
}
