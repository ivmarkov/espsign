//! Utilities for ESP Secure Boot V2 RSA signature block verification and signing
//!
//! For now, only Secure Boot V2 is supported, with the RSA-based signature block,
//! as this is what seemingly Espressif recommends*. In future, it can be extended
//! with support for ECC signatures, as well as Secure Boot V1.
//!
//! The module is `no_std` (but needs `alloc` because Rust Crypto RSA needs it)
//! so that it can also be used on the chip itself for e.g. verifying image signatures
//! during OTA updates for baremetal apps. Note though that the on-chip verification
//! would be slow(er), because the Esp RSA and SHA peripherals are not utilized yet.
//!
//! * https://docs.espressif.com/projects/esp-idf/en/v5.3.1/esp32h2/security/secure-boot-v2.html#signature-block-format
#![no_std]
#![warn(clippy::large_futures)] 

use alloc::boxed::Box;

use core::fmt::{self, Debug, Display};
use core::marker::PhantomData;

use embedded_io_async::{Error, ErrorType, Read, ReadExactError, Write};

use log::info;

use num_bigint::{traits::ModInverse, ToBigUint};
use num_traits::cast::ToPrimitive;

use rand::{CryptoRng, RngCore};
use rsa::{traits::PublicKeyParts, BigUint, Pss, RsaPrivateKey, RsaPublicKey};

use sha2::{Digest, Sha256};

extern crate alloc;

/// The RSA crate is re-exported for user convenience
/// so that users of the lib do not have to explicitly depend on it
pub mod rsa {
    pub use ::rsa::*;
}

/// A null writer that writes to nowhere
/// Implements the `Write` trait from `embedded-io-async`
pub struct NullWrite<E>(PhantomData<fn() -> E>);

impl<E> Default for NullWrite<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> NullWrite<E> {
    /// Create a new null writer
    pub const fn new() -> Self {
        Self(PhantomData::<fn() -> E>)
    }
}

impl<E> ErrorType for NullWrite<E>
where
    E: Error,
{
    type Error = E;
}

impl<E> Write for NullWrite<E>
where
    E: Error,
{
    async fn write(&mut self, data: &[u8]) -> Result<usize, Self::Error> {
        Ok(data.len())
    }
}

/// Errors that can occur during verification
#[derive(Debug)]
pub enum VerifyError<E> {
    /// IO error
    Io(E),
    /// Unexpected EOF
    Eof,
    /// Invalid ESP signature block (wrong magic byte, wrong version or CRC does not match)
    InvalidSignatureBlock,
    /// Invalid Sha256 hash
    InvalidHash,
    /// Invalid RSA-PSS signature
    InvalidSignature,
    /// Signed image is not padded correctly (to 64K for app images and to 4K for bootloader images)
    InvalidImageLen,
}

impl<E> VerifyError<E> {
    /// Map the IO error to another one
    pub fn map<E2>(self, f: impl FnOnce(E) -> E2) -> VerifyError<E2> {
        match self {
            VerifyError::Io(e) => VerifyError::Io(f(e)),
            VerifyError::Eof => VerifyError::Eof,
            VerifyError::InvalidSignatureBlock => VerifyError::InvalidSignatureBlock,
            VerifyError::InvalidHash => VerifyError::InvalidHash,
            VerifyError::InvalidSignature => VerifyError::InvalidSignature,
            VerifyError::InvalidImageLen => VerifyError::InvalidImageLen,
        }
    }
}

impl<E> From<ReadExactError<E>> for VerifyError<E> {
    fn from(e: ReadExactError<E>) -> Self {
        match e {
            ReadExactError::UnexpectedEof => Self::Eof,
            ReadExactError::Other(e) => Self::Io(e),
        }
    }
}

impl<E> Display for VerifyError<E>
where
    E: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {:?}", e),
            Self::Eof => write!(f, "Unexpected EOF"),
            Self::InvalidSignatureBlock => write!(f, "Invalid signature block"),
            Self::InvalidHash => write!(f, "Invalid hash"),
            Self::InvalidSignature => write!(f, "Invalid signature"),
            Self::InvalidImageLen => write!(f, "Invalid image length"),
        }
    }
}

/// Type of image to sign or verify
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ImageType {
    /// Bootloader image (image will/should be padded to 4K boundary)
    Bootloader,
    /// Application image (image will/should be padded to 64K boundary)
    App,
}

impl ImageType {
    /// Get the alignment for the image type
    pub fn align(&self) -> usize {
        match self {
            ImageType::Bootloader => 4096,
            ImageType::App => 4096, //65536,
        }
    }
}

/// ESP Secure Boot V2 RSA Public key
///
/// Embedded in the signature block below, as well as used as-is for
/// generating the public key SHA-256 signature that needs to be burned into E-FUSE
///
/// This type is `repr(C)` and `repr(packed)` so that it can be directly transmuted from a memory-mapped
/// region of the ESP32 flash memory, if necessary. In other words, its memory layout represents exactly the
/// layout of a serialized ESP Secure Boot V2 RSA public key.
#[repr(C)]
#[repr(packed)]
pub struct SBV2RsaPubKey {
    /// RSA Public Modulus used for signature verification. (value ‘n’ in RFC8017).
    ///
    /// NOTE: LE order instead of (regular) BE order, as the Esp RSA peripheral uses LE.
    rsa_public_modulus: [u8; 384],
    /// RSA Public Exponent used for signature verification (value ‘e’ in RFC8017).
    ///
    /// NOTE: LE order instead of (regular) BE order, as the Esp RSA peripheral uses LE.
    rsa_public_exponent: [u8; 4],
    /// Pre-calculated `R`, derived from ‘n’.
    ///
    /// NOTE: LE order instead of (regular) BE order, as the Esp RSA peripheral uses LE.
    rsa_precalc_r: [u8; 384],
    /// Pre-calculated `M`, derived from ‘n’
    /// NOTE: LE order instead of (regular) BE order, as the Esp RSA peripheral uses LE.
    rsa_precalc_m: [u8; 4],
}

impl SBV2RsaPubKey {
    /// Create a new Secure Boot V2 RSA public key from the given RSA public key
    pub fn create(pub_key: &RsaPublicKey) -> Self {
        let mut this = Self::new_empty();

        this.fill(pub_key);

        this
    }

    /// Save the Sha256 hash of the public key to the output
    ///
    /// The saved hash should then be burned into E-FUSE with the `espefuse` tool
    /// when Secure Boot V2 is being enabled for the Esp chip
    ///
    /// # Arguments
    /// * `out` - Output to write the hash to
    pub async fn save_hash<W>(&self, mut out: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        let mut hasher = Sha256::new();

        self.fill_hash(&mut hasher);

        out.write_all(&hasher.finalize()).await?;

        Ok(())
    }

    /// Load the Secure Boot V2 RSA public key from the input
    ///
    /// # Arguments
    /// * `read` - Input to read the public key from
    async fn load<R>(&mut self, mut read: R) -> Result<(), ReadExactError<R::Error>>
    where
        R: Read,
    {
        read.read_exact(&mut self.rsa_public_modulus).await?;
        read.read_exact(&mut self.rsa_public_exponent).await?;
        read.read_exact(&mut self.rsa_precalc_r).await?;
        read.read_exact(&mut self.rsa_precalc_m).await?;

        Ok(())
    }

    /// Save the Secure Boot V2 RSA public key to the output
    ///
    /// # Arguments
    /// * `out` - Output to write the public key to
    async fn save<W>(&self, mut out: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        out.write_all(&self.rsa_public_modulus).await?;
        out.write_all(&self.rsa_public_exponent).await?;
        out.write_all(&self.rsa_precalc_r).await?;
        out.write_all(&self.rsa_precalc_m).await?;

        Ok(())
    }

    /// Convert the Secure Boot V2 RSA public key to an RSA public key
    fn pub_key(&self) -> RsaPublicKey {
        RsaPublicKey::new(
            BigUint::from_bytes_le(&self.rsa_public_modulus),
            BigUint::from_bytes_le(&self.rsa_public_exponent),
        )
        .unwrap()
    }

    /// Fill the Sha256 hash of the public key into the provided hasher
    fn fill_hash(&self, hasher: &mut Sha256) {
        hasher.update(self.rsa_public_modulus);
        hasher.update(self.rsa_public_exponent);
        hasher.update(self.rsa_precalc_r);
        hasher.update(self.rsa_precalc_m);
    }

    /// Create a new empty Secure Boot V2 RSA public key in unitialized state
    const fn new_empty() -> Self {
        Self {
            rsa_public_modulus: [0; 384],
            rsa_public_exponent: [0; 4],
            rsa_precalc_r: [0; 384],
            rsa_precalc_m: [0; 4],
        }
    }

    /// Fill (initialize) the Secure Boot V2 RSA public key with the given RSA public key
    fn fill(&mut self, pub_key: &RsaPublicKey) {
        // https://github.com/espressif/esptool/blob/6cc002c4bd0de6a5b1afa630a59c7cbaac44ab86/espsecure/__init__.py#L325
        let m = -pub_key
            .n()
            .mod_inverse(1.to_biguint().unwrap() << 32)
            .unwrap();

        // https://github.com/espressif/esptool/blob/6cc002c4bd0de6a5b1afa630a59c7cbaac44ab86/espsecure/__init__.py#L327
        let rr = 1.to_biguint().unwrap() << (pub_key.n().bits() * 2);
        let rinv = rr % pub_key.n();

        self.rsa_public_modulus
            .copy_from_slice(&pub_key.n().to_bytes_le());
        self.rsa_public_exponent
            .copy_from_slice(&pub_key.e().to_u32().unwrap().to_le_bytes());
        self.rsa_precalc_r.copy_from_slice(&rinv.to_bytes_le());
        self.rsa_precalc_m.copy_from_slice(&m.to_bytes_le().1); // TODO: What to do with the `Sign` component?
    }
}

/// ESP Secure Boot V2 RSA Signature Block
/// https://docs.espressif.com/projects/esp-idf/en/stable/esp32/security/secure-boot-v2.html#signature-block-format
///
/// This type is `repr(C)` and `repr(packed)` so that it can be directly transmuted from a memory-mapped
/// region of the ESP32 flash memory, if necessary. In other words, its memory layout represents exactly the
/// layout of a serialized ESP Secure Boot V2 RSA signature block.
///
/// Algorithms based on https://github.com/espressif/esptool/blob/master/espsecure
///
/// Note 1: The rest of the 4K page/sector containing the signature should be filled with 0xFF.
/// Note 2: APP images are padded to 64K (!) boundary with 0xFFs, so the signature block is the
///         first 4K block following the 64K aligned and padded image
///         ESP IDF bootloader image seems to only be padded to 4K boundary
/// Note 3: The partition table - at least with Secure Boot V2 - seems unsigned
#[repr(C)]
#[repr(packed)]
pub struct SBV2RsaSignatureBlock {
    /// Magic byte. Always 0xe7
    magic: u8,
    /// Version number byte. Always 0x02
    version: u8,
    /// Padding bytes. Reserved. Should be zero.
    padding: [u8; 2],
    /// SHA-256 hash of only the image content, not including the signature block.
    sha256: [u8; 32],
    /// RSA public key
    rsa_pub_key: SBV2RsaPubKey,
    /// RSA-PSS Signature result (section 8.1.1 of RFC8017) of image content,
    /// computed using following PSS parameters:
    /// SHA256 hash, MGF1 function, salt length 32 bytes, default trailer field (0xBC).
    ///
    /// NOTE: LE order instead of (regular) BE order, as the Esp RSA peripheral uses LE.
    rsa_pss_signature: [u8; 384],
    /// CRC32 of the preceding 1196 bytes. LE order.
    crc32: [u8; 4],
    /// Zero padding to length 1216 bytes.
    padding2: [u8; 16],
}

impl SBV2RsaSignatureBlock {
    /// The size of a SBV2 RSA signature block (padded with 0xFF to 4K)
    const PAGE_SIZE: usize = 4096;

    /// The magic byte for the signature block (at offset 0)
    const MAGIC_BYTE: u8 = 0xe7;

    /// The version byte for the signature block (at offset 1)
    const VERSION: u8 = 2;

    /// Sign an image and write the padded image and the signature block to the output
    ///
    /// # Arguments
    /// * `priv_key` - RSA private key to sign the image with
    /// * `rng` - Random number generator
    /// * `buf` - Buffer to use for reading the image.
    /// * `image` - Image to sign
    /// * `image_type` - Type of image to sign
    /// * `out` - Output to write the padded image and the signature block to
    pub async fn sign<C, R, W>(
        priv_key: &RsaPrivateKey,
        rng: &mut C,
        buf: &mut [u8],
        image: R,
        image_type: ImageType,
        mut out: W,
    ) -> Result<Self, R::Error>
    where
        C: RngCore + CryptoRng,
        R: Read,
        W: Write,
        W::Error: Into<R::Error>,
    {
        let block = Self::create(priv_key, rng, buf, image, image_type, Some(&mut out)).await?;

        block.save(out, Some(buf)).await.map_err(Into::into)?;

        Ok(block)
    }

    /// Load and verify an image and its signature block
    ///
    /// # Arguments
    /// * `buf` - Buffer to use for reading the image.
    ///   NOTE: The buffer should be bigger than 4096 bytes, or else this method would panic!
    /// * `image` - Image to verify
    /// * `image_type` - Type of image to verify
    pub async fn load_and_verify<R>(
        buf: &mut [u8],
        mut image: R,
        image_type: ImageType,
    ) -> Result<&Self, VerifyError<R::Error>>
    where
        R: Read,
    {
        if buf.len() <= Self::PAGE_SIZE {
            panic!("Buffer too small; should be > {}B", Self::PAGE_SIZE);
        }

        let mut size = 0;
        let mut offset = 0;

        let mut hasher = Sha256::new();

        loop {
            let read = image.read(&mut buf[offset..]).await.unwrap();

            offset += read;
            size += read;

            if buf.len() == offset || read == 0 {
                hasher.update(&buf[..offset - Self::PAGE_SIZE]);

                buf.copy_within(offset - Self::PAGE_SIZE.., 0);
                offset = Self::PAGE_SIZE;
            }

            if read == 0 {
                break;
            }
        }

        if offset != Self::PAGE_SIZE || (size - Self::PAGE_SIZE) % image_type.align() != 0 {
            Err(VerifyError::InvalidImageLen)?;
        }

        // Transmute the last page into the signature block to save memory
        // Possible, because we are `repr(C)` and `repr(packed)`
        let block = unsafe { (buf.as_ptr() as *const Self).as_ref() }.unwrap();
        // let mut block = Self::new_empty();
        // block
        //     .load(&mut &buf[..Self::PAGE_SIZE])
        //     .await
        //     .map_err(|e| e.map(|e| match e {}))?;

        let digest = hasher.finalize();

        block.verify_image_hash(digest.as_ref())?;

        Ok(block)
    }

    /// Create a new Secure Boot V2 RSA signature block from the provided RSA private key and image
    ///
    /// The creation of the signature block means the provided image will be signed.
    ///
    /// # Arguments
    /// * `priv_key` - RSA private key to sign the image with
    /// * `rng` - Random number generator
    /// * `buf` - Buffer to use for reading the image.
    /// * `image` - Image to sign
    /// * `image_type` - Type of image to sign
    /// * `out` - Optional output to write the padded image to
    pub async fn create<C, R, W>(
        priv_key: &RsaPrivateKey,
        rng: &mut C,
        buf: &mut [u8],
        image: R,
        image_type: ImageType,
        out: Option<W>,
    ) -> Result<Self, R::Error>
    where
        C: RngCore + CryptoRng,
        R: Read,
        W: Write,
        W::Error: Into<R::Error>,
    {
        let mut block = Self::new_empty();

        block
            .fill(priv_key, rng, buf, image, out, image_type.align())
            .await?;

        Ok(block)
    }

    /// Load a Secure Boot V2 RSA signature block from the input
    ///
    /// # Arguments
    /// * `read` - Input to read the signature block from
    pub async fn load<R>(&mut self, mut read: R) -> Result<(), VerifyError<R::Error>>
    where
        R: Read,
    {
        self.clear();

        let mut bt = [0; 2];
        read.read_exact(&mut bt).await?;

        if bt[0] != Self::MAGIC_BYTE || bt[1] != Self::VERSION {
            Err(VerifyError::InvalidSignatureBlock)?;
        }

        self.magic = bt[0];
        self.version = bt[1];

        read.read_exact(&mut self.padding).await?;
        read.read_exact(&mut self.sha256).await?;
        self.rsa_pub_key.load(&mut read).await?;
        read.read_exact(&mut self.rsa_pss_signature).await?;
        read.read_exact(&mut self.crc32).await?;
        read.read_exact(&mut self.padding2).await?;

        if self.crc32 != self.crc32() {
            Err(VerifyError::InvalidSignatureBlock)?;
        }

        Ok(())
    }

    /// Save the Secure Boot V2 RSA signature block to the output
    ///
    /// # Arguments
    /// * `out` - Output to write the signature block to
    /// * `padded` - Whether to pad the output to 4K
    ///   In that case, the function needs a non-zero buffer to perform the padding
    pub async fn save<W>(&self, mut out: W, padded: Option<&mut [u8]>) -> Result<(), W::Error>
    where
        W: Write,
    {
        out.write_all(&[self.magic]).await?;
        out.write_all(&[self.version]).await?;
        out.write_all(&self.padding).await?;
        out.write_all(&self.sha256).await?;
        self.rsa_pub_key.save(&mut out).await?;
        out.write_all(&self.rsa_pss_signature).await?;
        out.write_all(&self.crc32).await?;
        out.write_all(&self.padding2).await?;

        if let Some(buf) = padded {
            let mut remainder = Self::PAGE_SIZE - core::mem::size_of_val(self);

            if remainder != 0 {
                buf.fill(0xff);

                while remainder > 0 {
                    let len = core::cmp::min(remainder, buf.len());
                    out.write_all(&buf[..len]).await?;
                    remainder -= len;
                }
            }
        }

        Ok(())
    }

    /// Save the Sha256 hash of the public key to the output
    ///
    /// The saved hash should then be burned into E-FUSE with the `espefuse` tool
    /// when Secure Boot V2 is being enabled for the Esp chip
    ///
    /// # Arguments
    /// * `out` - Output to write the hash to
    pub async fn save_pubkey_hash<W>(&self, out: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.rsa_pub_key.save_hash(out).await
    }

    /// Verify an image assuming this signature block is for that image
    ///
    /// # Arguments
    /// * `buf` - Buffer to use for reading the image.
    /// * `image` - Image to verify
    /// * `image_type` - Type of image to verify
    pub async fn verify<R>(
        &self,
        buf: &mut [u8],
        image: R,
        image_type: ImageType,
    ) -> Result<(), VerifyError<R::Error>>
    where
        R: Read,
    {
        let mut hasher = Sha256::new();

        let aligned = Self::read_write_hash(
            &mut hasher,
            buf,
            image,
            Option::<NullWrite<R::Error>>::None,
            image_type.align(),
            true,
        )
        .await
        .map_err(VerifyError::Io)?;

        if !aligned {
            Err(VerifyError::InvalidImageLen)?;
        }

        let digest = hasher.finalize();
        let hashed = digest.as_ref();

        self.verify_image_hash(hashed)?;

        Ok(())
    }

    /// Verify the Sha-256 hash of an image against this signature block
    ///
    /// Arguments
    /// * `hash` - Sha-256 hash to verify
    pub fn verify_image_hash<E>(&self, hash: &[u8]) -> Result<(), VerifyError<E>> {
        if hash != self.sha256 {
            Err(VerifyError::InvalidHash)?;
        }

        let pub_key = self.rsa_pub_key.pub_key();
        let pss = Pss::new_with_salt::<Sha256>(32);

        let mut signature = [0; 384];
        signature.copy_from_slice(&self.rsa_pss_signature);
        signature.reverse(); // To BE

        pub_key
            .verify(pss, hash, &signature)
            .map_err(|_| VerifyError::InvalidSignature)?;

        Ok(())
    }

    /// Create an empty Secure Boot V2 RSA signature block in unitialized state
    const fn new_empty() -> Self {
        Self {
            magic: Self::MAGIC_BYTE,
            version: Self::VERSION,
            padding: [0; 2],
            sha256: [0; 32],
            rsa_pub_key: SBV2RsaPubKey::new_empty(),
            rsa_pss_signature: [0; 384],
            crc32: [0; 4],
            padding2: [0; 16],
        }
    }

    /// Fill the Secure Boot V2 RSA signature block with the provided RSA private key and image
    /// essentially signing the image this way.
    ///
    /// # Arguments
    /// * `priv_key` - RSA private key to sign the image with
    /// * `rng` - Random number generator
    /// * `buf` - Buffer to use for reading the image.
    /// * `image` - Image to sign
    /// * `out` - Optional output to write the padded image to
    /// * `align` - Alignment for the output image
    async fn fill<C, R, W>(
        &mut self,
        priv_key: &RsaPrivateKey,
        rng: &mut C,
        buf: &mut [u8],
        image: R,
        out: Option<W>,
        align: usize,
    ) -> Result<(), R::Error>
    where
        C: RngCore + CryptoRng,
        R: Read,
        W: Write,
        W::Error: Into<R::Error>,
    {
        self.clear();
        self.fill_pub_key(&priv_key.to_public_key());
        self.fill_hash(buf, image, out, align).await?;
        self.fill_signature(rng, priv_key);
        self.fill_crc32();

        Ok(())
    }

    /// Reset the Secure Boot V2 RSA signature block to its initial uninitialized state
    fn clear(&mut self) {
        *self = Self::new_empty();
    }

    /// Fill the Secure Boot V2 RSA public key fuilds with the provided RSA public key
    fn fill_pub_key(&mut self, pub_key: &RsaPublicKey) {
        self.rsa_pub_key.fill(pub_key);
    }

    /// Fill the Secure Boot V2 RSA-PSS signature field with the signature of the Sha256 hash
    fn fill_signature<C: RngCore + CryptoRng>(&mut self, rng: &mut C, priv_key: &RsaPrivateKey) {
        let pss = Pss::new_with_salt::<Sha256>(32);

        let signature: Box<[u8]> = priv_key
            .sign_with_rng(rng, pss, &self.sha256)
            .unwrap()
            .into();

        self.rsa_pss_signature.copy_from_slice(signature.as_ref());
        self.rsa_pss_signature.reverse(); // To LE
    }

    /// Fill the Sha256 hash of the image into the Secure Boot V2 RSA signature block
    async fn fill_hash<R, W>(
        &mut self,
        buf: &mut [u8],
        image: R,
        out: Option<W>,
        align: usize,
    ) -> Result<(), R::Error>
    where
        R: Read,
        W: Write,
        W::Error: Into<R::Error>,
    {
        let mut hasher = Sha256::new();

        Self::read_write_hash(&mut hasher, buf, image, out, align, false).await?;

        self.sha256.copy_from_slice(hasher.finalize().as_ref());

        Ok(())
    }

    /// Fill the CRC32 field of the Secure Boot V2 RSA signature block
    fn fill_crc32(&mut self) {
        let crc32 = self.crc32();

        self.crc32.copy_from_slice(&crc32);
    }

    /// Calculate the CRC32 of the Secure Boot V2 RSA signature block
    fn crc32(&self) -> [u8; 4] {
        // CRC-32/ISO-HDLC
        const CRC32: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);

        let mut crc = CRC32.digest();
        crc.update(&[self.magic]);
        crc.update(&[self.version]);
        crc.update(&self.padding);
        crc.update(&self.sha256);
        crc.update(&self.rsa_pub_key.rsa_public_modulus);
        crc.update(&self.rsa_pub_key.rsa_public_exponent);
        crc.update(&self.rsa_pub_key.rsa_precalc_r);
        crc.update(&self.rsa_pub_key.rsa_precalc_m);
        crc.update(&self.rsa_pss_signature);

        let checksum = crc.finalize();

        checksum.to_le_bytes()
    }

    /// Read and write and image to the hasher and to the optional output
    async fn read_write_hash<R, W>(
        hasher: &mut Sha256,
        buf: &mut [u8],
        mut image: R,
        mut out: Option<W>,
        align: usize,
        check_align: bool,
    ) -> Result<bool, R::Error>
    where
        R: Read,
        W: Write,
        W::Error: Into<R::Error>,
    {
        let mut size: usize = 0;

        loop {
            let read = image.read(buf).await?;
            if read == 0 {
                break;
            }

            Self::write_hash(hasher, &buf[..read], out.as_mut())
                .await
                .map_err(Into::into)?;

            size += read;
        }

        let mut remainder = align - size % align;

        if remainder != align {
            if check_align {
                return Ok(false);
            }

            info!("Image size ({size}B) is not a multiple of {align}B. Padding {remainder}B with 0xFF");

            buf.fill(0xff);

            while remainder > 0 {
                let to_write = remainder.min(buf.len());

                Self::write_hash(hasher, &buf[..to_write], out.as_mut())
                    .await
                    .map_err(Into::into)?;

                remainder -= to_write;
            }
        }

        Ok(true)
    }

    /// Write data to the hasher and to the optional output
    async fn write_hash<W>(
        hasher: &mut Sha256,
        data: &[u8],
        mut out: Option<W>,
    ) -> Result<(), W::Error>
    where
        W: Write,
    {
        if let Some(write) = out.as_mut() {
            write.write_all(data).await.map_err(Into::into)?;
        }

        hasher.update(data);

        Ok(())
    }
}

#[cfg(all(test, feature = "pem"))]
mod test {
    use core::convert::Infallible;

    use alloc::vec::Vec;
    
    use embedded_io_async::{ErrorType, Write};
    
    use super::ImageType;
    
    use rand_core::{CryptoRng, RngCore};
    
    use rsa::pkcs8::DecodePrivateKey;
    
    extern crate alloc;
    
    static PRIV_KEY: &str = r#"
-----BEGIN PRIVATE KEY-----
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
HLi+/wQ5736LzHUphwOfBDZZ
-----END PRIVATE KEY-----
"#;
    
    static IMAGE: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    
    struct Rng(u8);
    
    impl RngCore for Rng {
        fn next_u32(&mut self) -> u32 {
            let mut result = [0; 4];
            self.fill_bytes(&mut result);
    
            u32::from_le_bytes(result)
        }
    
        fn next_u64(&mut self) -> u64 {
            let mut result = [0; 8];
            self.fill_bytes(&mut result);
    
            u64::from_le_bytes(result)
        }
    
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for i in dest {
                *i = self.0;
                self.0 += 1;
            }
        }
    
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    
    impl CryptoRng for Rng {}
    
    struct AsyncIo<T>(T);
    
    impl<T> ErrorType for AsyncIo<T> {
        type Error = Infallible;
    }
    
    impl Write for AsyncIo<&mut Vec<u8>> {
        async fn write(&mut self, data: &[u8]) -> Result<usize, Self::Error> {
            self.0.extend_from_slice(data);
    
            Ok(data.len())
        }
    }

    /// A test that signs and then verifies an image
    #[test]
    fn test() {
        let priv_key = super::rsa::RsaPrivateKey::from_pkcs8_pem(PRIV_KEY).unwrap();
    
        let mut buf = [0; 5000];
    
        let mut out = Vec::new();
        let mut sha = Vec::new();
    
        let mut rng = Rng(0);
    
        embassy_futures::block_on(async {
            let signature = super::SBV2RsaSignatureBlock::sign(
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
            assert_eq!(
                &sha,
                &[
                    30, 21, 221, 150, 46, 88, 111, 119, 133, 133, 196, 203, 78, 206, 138, 61, 161, 155,
                    150, 228, 98, 141, 122, 31, 230, 50, 91, 84, 133, 136, 157, 166
                ]
            );
    
            super::SBV2RsaSignatureBlock::load_and_verify(
                &mut buf,
                &mut out.as_ref(),
                ImageType::App,
            )
            .await
            .unwrap();
        });
    }
}
