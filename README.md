# espsign

A utility for signing ESP32 firmware images for ESP RSA Secure Boot V2

[![CI](https://github.com/ivmarkov/espsign/actions/workflows/ci.yml/badge.svg)](https://github.com/ivmarkov/espsign/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/espsign.svg)](https://crates.io/crates/espsign)
[![Matrix](https://img.shields.io/matrix/esp-rs:matrix.org?label=join%20matrix&color=BEC5C9&logo=matrix)](https://matrix.to/#/#esp-rs:matrix.org)

## Highlights

* Pure-Rust
* `no_std` (but needs `alloc`) **library interface** for:
  * Signing
  * Verifying
  * Generating key SHA-256 E-FUSE signature
* Command line interface

## Examples

### Command line

Install the command line utility

```sh
cargo install --force --git https://github.com/ivmarkov/espsign
```

Generate a new PEM signing key in file `foo`:

```sh
espsign gen-key foo
```

Generate a new password-protected with `pass` PEM signing key in file `foo`, and with E-FUSE SHA-256 hash in file `hash`:

```sh
espsign gen-key -p pass -s hash foo
```

Sign an app image `firmware` using a pre-generated PEM signing key from file `foo`

```sh
espsign sign -k foo firmware-padded firmware-signed
```

> NOTE: App image should first be padded to 64K alignment with e.g. [esptools](https://github.com/ivmarkov/esptools):

```sh
esptools tool --chip esp32s3 elf2image --version 2 --secure-pad-v2 --output firmware-padded firmware
```

Verify a signed app image `firmware-signed`

```sh
espsign verify firmware-signed
```

### Library

Verify an image. [Other examples](examples).

```rust
use std::fs::File;
use std::path::PathBuf;

use log::info;

use espsign::{AsyncIo, ImageType, SBV2RsaSignatureBlock};

/// Verify that `image` is properly signed
fn main() {
    let image = PathBuf::from("/home/foo/factory-app-signed");

    let mut buf = [0; 65536];

    info!("Verifying image `{}`...", image.display());

    embassy_futures::block_on(SBV2RsaSignatureBlock::load_and_verify(
        &mut buf,
        AsyncIo::new(File::open(image).unwrap()),
        ImageType::App,
    ))
    .unwrap();

    info!("Image verified successfully");
}
```
