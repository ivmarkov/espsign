//! A command-line interface to the `espsign` crate.

use std::io::{self, Write as _};
use std::path::{self, Path, PathBuf};

use anyhow::Context;

use clap::{ColorChoice, Parser, Subcommand, ValueEnum};

use embedded_io_async::{ErrorType, Read, Write};

use espsign::rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use espsign::rsa::RsaPrivateKey;
use espsign::SBV2RsaPubKey;

use log::{debug, info, LevelFilter};

use rand::thread_rng;

use rsa::pkcs8::LineEnding;

/// Sign and verify ESP32 images for ESP RSA Secure Boot V2
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, arg_required_else_help = true, color = ColorChoice::Auto)]
struct Cli {
    /// Verbosity
    #[arg(short = 'l', long, default_value = "regular")]
    verbosity: Verbosity,

    #[command(subcommand)]
    command: Option<Command>,
}

/// Command
#[derive(Subcommand, Debug)]
enum Command {
    /// Generate signing key (RSA-3072 private key) in PEM or DER format
    GenKey {
        /// Signing key type
        #[arg(short = 't', long, default_value = "pem")]
        key_type: KeyType,

        /// Password to use for protecting the signing key (optional, if not specified the signing key will be unprotected)
        #[arg(short = 'p', long)]
        key_password: Option<String>,

        /// Verifying key E-FUSE SHA-256 hash output file
        #[arg(short = 's', long)]
        hash: Option<PathBuf>,

        /// Signing key output file
        key: PathBuf,
    },
    /// Generate the SHA-256 hash for the supplied signing key (to be burned in the ESP32 E-FUSE)
    Hash {
        /// Signing key type
        #[arg(short = 't', long, default_value = "pem")]
        key_type: KeyType,

        /// Password used for protecting the signing key (optional)
        #[arg(short = 'p', long)]
        key_password: Option<String>,

        /// Signing key input file
        key: PathBuf,

        /// Verifying key E-FUSE SHA-256 hash output file
        hash: PathBuf,
    },
    /// Sign an image using the supplied signing key
    Sign {
        /// Signing key input file
        #[arg(short, long)]
        key: PathBuf,

        /// Signing key type
        #[arg(short = 't', long, default_value = "pem")]
        key_type: KeyType,

        /// Password used for protecting the signing key (optional)
        #[arg(short = 'p', long)]
        key_password: Option<String>,

        /// Image type
        #[arg(short, long, default_value = "app")]
        image_type: ImageType,

        /// Verifying key E-FUSE SHA-256 hash output file (optional)
        #[arg(short = 's', long)]
        hash: Option<PathBuf>,

        /// The input file of the image to sign
        image: PathBuf,

        /// Signed image output file
        signed: PathBuf,
    },
    /// Verify an already signed image using its embedded signature block
    Verify {
        /// Image type
        #[arg(short, long, default_value = "app")]
        image_type: ImageType,

        /// The image file to verify
        image: PathBuf,
    },
}

/// Verbosity
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Verbosity {
    Silent,
    #[default]
    Regular,
    Verbose,
}

impl Verbosity {
    fn log_level(&self) -> LevelFilter {
        match self {
            Self::Silent => LevelFilter::Off,
            Self::Regular => LevelFilter::Info,
            Self::Verbose => LevelFilter::Debug,
        }
    }
}

/// Key type
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum KeyType {
    /// PEM key
    #[default]
    Pem,
    /// DER key
    Der,
}

impl KeyType {
    fn load(
        &self,
        path: &Path,
        password: Option<&str>,
    ) -> anyhow::Result<espsign::rsa::RsaPrivateKey> {
        let path = path::absolute(path)
            .with_context(|| format!("Parsing key path `{}` failed", path.display()))?;

        let key = if let Some(password) = password {
            info!(
                "Loading password-protected signing key from `{}` (this will take some time)...",
                path.display()
            );

            let key = match self {
                Self::Pem => espsign::rsa::RsaPrivateKey::from_pkcs8_encrypted_pem(
                    &std::fs::read_to_string(path).context("Loading key failed")?,
                    password,
                )
                .context("Parsing PEM signature key failed")?,
                Self::Der => espsign::rsa::RsaPrivateKey::from_pkcs8_encrypted_der(
                    &std::fs::read(path).context("Loading key failed")?,
                    password,
                )
                .context("Parsing DER signature key failed")?,
            };

            info!("Signing key loaded");

            key
        } else {
            debug!("Loading signing key from `{}`...", path.display());

            let key = match self {
                Self::Pem => espsign::rsa::RsaPrivateKey::from_pkcs8_pem(
                    &std::fs::read_to_string(path).context("Loading key failed")?,
                )
                .context("Parsing PEM signature key failed")?,
                Self::Der => espsign::rsa::RsaPrivateKey::from_pkcs8_der(
                    &std::fs::read(path).context("Loading key failed")?,
                )
                .context("Parsing DER signature key failed")?,
            };

            debug!("Signing key loaded");

            key
        };

        Ok(key)
    }

    fn save(&self, key: &RsaPrivateKey, path: &Path, password: Option<&str>) -> anyhow::Result<()> {
        let path = path::absolute(path)
            .with_context(|| format!("Parsing key path `{}` failed", path.display()))?;

        if let Some(password) = password {
            info!("Key generation complete, saving with password protection (this will take some time)...");

            match self {
                Self::Pem => std::fs::write(
                    &path,
                    key.to_pkcs8_encrypted_pem(thread_rng(), password.as_bytes(), LineEnding::LF)
                        .context("Generating PEM signature key failed")?,
                )
                .context("Saving key failed")?,
                Self::Der => std::fs::write(
                    &path,
                    key.to_pkcs8_encrypted_der(thread_rng(), password.as_bytes())
                        .context("Generating DER signature key failed")?
                        .as_bytes(),
                )
                .context("Saving key failed")?,
            }

            info!("Password-protected key saved to `{}`", path.display());
        } else {
            debug!("Key generation complete, saving...");

            match self {
                Self::Pem => std::fs::write(
                    &path,
                    key.to_pkcs8_pem(LineEnding::LF)
                        .context("Generating PEM signature key failed")?,
                )
                .context("Saving key failed")?,
                Self::Der => std::fs::write(
                    &path,
                    key.to_pkcs8_der()
                        .context("Generating DER signature key failed")?
                        .as_bytes(),
                )
                .context("Saving key failed")?,
            }

            info!("Key saved to `{}`", path.display());
        }

        Ok(())
    }
}

/// Image type
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ImageType {
    /// App image
    #[default]
    App,
    /// Bootloader image
    Bootloader,
}

impl From<ImageType> for espsign::ImageType {
    fn from(image_type: ImageType) -> Self {
        match image_type {
            ImageType::App => Self::App,
            ImageType::Bootloader => Self::Bootloader,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    env_logger::builder()
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .filter_level(args.verbosity.log_level())
        .init();

    if let Some(command) = args.command {
        let result = match command {
            Command::GenKey {
                key_type,
                key_password,
                key,
                hash,
            } => gen_key(key_type, key_password, key, hash),
            Command::Hash {
                key_type,
                key_password,
                key,
                hash,
            } => hash_key(key_type, key_password, key, hash),
            Command::Sign {
                key_type,
                key_password,
                key,
                image_type,
                image,
                signed,
                hash,
            } => sign_image(key_type, key_password, key, image_type, image, signed, hash),
            Command::Verify { image_type, image } => verify_image(image_type, image),
        };

        if let Err(err) = result {
            log::error!("{:#}", err);
            std::process::exit(1);
        }
    }

    Ok(())
}

fn gen_key(
    key_type: KeyType,
    key_password: Option<String>,
    key: PathBuf,
    hash: Option<PathBuf>,
) -> anyhow::Result<()> {
    info!("Generating RSA-3072 private key (this will take some time)...");

    let priv_key =
        RsaPrivateKey::new(&mut thread_rng(), 3072).context("Generating RSA key failed")?;

    key_type.save(&priv_key, &key, key_password.as_deref())?;

    let hash = hash
        .map(|hash| {
            path::absolute(&hash)
                .with_context(|| format!("Parsing hash path `{}` failed", hash.display()))
        })
        .transpose()?;

    if let Some(hash) = hash {
        embassy_futures::block_on(SBV2RsaPubKey::create(&priv_key.to_public_key()).save_hash(
            FileAsyncIo(std::fs::File::create(&hash).context("Saving hash failed")?),
        ))?;

        info!("Hash saved to `{}`", hash.display());
    }

    Ok(())
}

fn hash_key(
    key_type: KeyType,
    key_password: Option<String>,
    key: PathBuf,
    hash: PathBuf,
) -> anyhow::Result<()> {
    let priv_key = key_type.load(&key, key_password.as_deref())?;

    let hash = path::absolute(&hash)
        .with_context(|| format!("Parsing hash path `{}` failed", hash.display()))?;

    embassy_futures::block_on(SBV2RsaPubKey::create(&priv_key.to_public_key()).save_hash(
        FileAsyncIo(std::fs::File::create(&hash).context("Saving hash failed")?),
    ))?;

    info!("Hash saved to `{}`", hash.display());

    Ok(())
}

fn sign_image(
    key_type: KeyType,
    key_password: Option<String>,
    key: PathBuf,
    image_type: ImageType,
    image: PathBuf,
    signed: PathBuf,
    hash: Option<PathBuf>,
) -> anyhow::Result<()> {
    let mut buf = [0; 65536];

    let priv_key = key_type.load(&key, key_password.as_deref())?;

    let image = path::absolute(&image)
        .with_context(|| format!("Parsing image path `{}` failed", image.display()))?;

    info!("Signing image `{}`...", image.display());

    let signed = path::absolute(&signed)
        .with_context(|| format!("Parsing signed image path `{}` failed", signed.display()))?;
    let hash = hash
        .map(|hash| {
            path::absolute(&hash)
                .with_context(|| format!("Parsing hash path `{}` failed", hash.display()))
        })
        .transpose()?;

    embassy_futures::block_on(async {
        let block = espsign::SBV2RsaSignatureBlock::sign(
            &priv_key,
            &mut thread_rng(),
            &mut buf,
            FileAsyncIo(std::fs::File::open(image).context("Loading image failed")?),
            image_type.into(),
            FileAsyncIo(std::fs::File::create(&signed).context("Saving signed image failed")?),
        )
        .await?;

        info!("Image signed and saved to `{}`", signed.display());

        if let Some(hash) = hash {
            block
                .save_pubkey_hash(FileAsyncIo(
                    std::fs::File::create(&hash).context("Saving hash failed")?,
                ))
                .await?;

            info!("Hash saved to `{}`", hash.display());
        }

        Ok::<_, anyhow::Error>(())
    })?;

    Ok(())
}

fn verify_image(image_type: ImageType, image: PathBuf) -> anyhow::Result<()> {
    let image = path::absolute(&image)
        .with_context(|| format!("Parsing image path `{}` failed", image.display()))?;

    info!("Verifying image `{}`...", image.display());

    let mut buf = [0; 8192];

    embassy_futures::block_on(espsign::SBV2RsaSignatureBlock::load_and_verify(
        &mut buf,
        FileAsyncIo(std::fs::File::open(image).context("Loading image failed")?),
        image_type.into(),
    ))?;

    info!("Image verified successfully");

    Ok(())
}

/// A wrapper for types implementing `std::io::Read` and `std::io::Write` to implement `Read` and `Write` for async I/O.
struct FileAsyncIo<T>(T);

impl<T> ErrorType for FileAsyncIo<T> {
    type Error = io::Error;
}

impl<T> Read for FileAsyncIo<T>
where
    T: std::io::Read,
{
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.0.read(buf)
    }
}

impl<T> Write for FileAsyncIo<T>
where
    T: std::io::Write,
{
    async fn write(&mut self, data: &[u8]) -> Result<usize, Self::Error> {
        self.0.write(data)
    }
}
