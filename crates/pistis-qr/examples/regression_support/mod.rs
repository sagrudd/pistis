use image::{ImageFormat, ImageReader, Limits};
use std::io::{Cursor, Read};

pub const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TEXT_BYTES: usize = 16_384;
const MAX_DIMENSION: u32 = 4096;
const MAX_PIXELS: u64 = 8 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum AcquisitionError {
    InputRead,
    InputTooLarge,
    InvalidPNG,
    ImageDimensions,
    NoQR,
    MultipleQR,
    UndecodableQR,
    InvalidText,
}

impl AcquisitionError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InputRead => "input_read",
            Self::InputTooLarge => "input_too_large",
            Self::InvalidPNG => "invalid_png",
            Self::ImageDimensions => "image_dimensions",
            Self::NoQR => "no_qr",
            Self::MultipleQR => "multiple_qr",
            Self::UndecodableQR => "undecodable_qr",
            Self::InvalidText => "invalid_text",
        }
    }
}

pub struct AcquiredQR(String);

impl std::fmt::Debug for AcquiredQR {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcquiredQR")
            .field("text", &"[redacted]")
            .finish()
    }
}

impl AcquiredQR {
    pub fn text(&self) -> &str {
        &self.0
    }
}

pub fn bounded_read(reader: impl Read, limit: usize) -> Result<Vec<u8>, AcquisitionError> {
    let mut bytes = Vec::new();
    let limit = limit.min(MAX_IMAGE_BYTES);
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| AcquisitionError::InputRead)?;
    if bytes.len() > limit {
        return Err(AcquisitionError::InputTooLarge);
    }
    Ok(bytes)
}

pub fn acquire_text(bytes: &[u8]) -> Result<AcquiredQR, AcquisitionError> {
    if bytes.len() > MAX_TEXT_BYTES {
        return Err(AcquisitionError::InputTooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| AcquisitionError::InvalidText)?;
    // Acquisition is opaque. Each production parser enforces its own framing;
    // normalising whitespace here could upgrade an invalid frame into a valid one.
    if text.is_empty() {
        return Err(AcquisitionError::InvalidText);
    }
    Ok(AcquiredQR(text.to_owned()))
}

pub fn acquire_png(bytes: &[u8]) -> Result<AcquiredQR, AcquisitionError> {
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(AcquisitionError::InputTooLarge);
    }
    let (width, height) = ImageReader::with_format(Cursor::new(bytes), ImageFormat::Png)
        .into_dimensions()
        .map_err(|_| AcquisitionError::InvalidPNG)?;
    if width == 0
        || height == 0
        || width > MAX_DIMENSION
        || height > MAX_DIMENSION
        || u64::from(width) * u64::from(height) > MAX_PIXELS
    {
        return Err(AcquisitionError::ImageDimensions);
    }
    let mut reader = ImageReader::with_format(Cursor::new(bytes), ImageFormat::Png);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);
    let image = reader
        .decode()
        .map_err(|_| AcquisitionError::InvalidPNG)?
        .into_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(image);
    let grids = prepared.detect_grids();
    match grids.len() {
        0 => Err(AcquisitionError::NoQR),
        1 => {
            let (_, text) = grids[0]
                .decode()
                .map_err(|_| AcquisitionError::UndecodableQR)?;
            acquire_text(text.as_bytes())
        }
        _ => Err(AcquisitionError::MultipleQR),
    }
}
