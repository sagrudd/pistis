use image::{GrayImage, ImageFormat, Luma};
use qrcode::{Color, QrCode};
use std::{
    io::{Cursor, Write},
    process::ExitCode,
};
#[path = "regression_support/mod.rs"]
mod acquisition;

use acquisition::{MAX_TEXT_BYTES, acquire_png, acquire_text, bounded_read};

fn roundtrip() -> Result<(), &'static str> {
    let bytes = bounded_read(std::io::stdin().lock(), MAX_TEXT_BYTES)
        .map_err(|_| "fixture_input_failed")?;
    let text = acquire_text(&bytes).map_err(|_| "fixture_text_failed")?;
    let code = QrCode::new(text.text()).map_err(|_| "fixture_encoding_failed")?;
    let width = code.width();
    let scale = 5;
    let pixels = u32::try_from((width + 8) * scale).map_err(|_| "fixture_dimensions_failed")?;
    let image = GrayImage::from_fn(pixels, pixels, |x, y| {
        let x = x as usize / scale;
        let y = y as usize / scale;
        let dark = (4..width + 4).contains(&x)
            && (4..width + 4).contains(&y)
            && code[(x - 4, y - 4)] == Color::Dark;
        Luma([if dark { 0 } else { 255 }])
    });
    let mut png = Cursor::new(Vec::new());
    image
        .write_to(&mut png, ImageFormat::Png)
        .map_err(|_| "fixture_png_failed")?;
    let decoded = acquire_png(png.get_ref()).map_err(|error| error.code())?;
    if decoded.text() != text.text() {
        return Err("fixture_roundtrip_mismatch");
    }
    std::io::stdout()
        .lock()
        .write_all(decoded.text().as_bytes())
        .map_err(|_| "fixture_pipe_failed")
}

fn main() -> ExitCode {
    match roundtrip() {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            eprintln!("{code}");
            ExitCode::FAILURE
        }
    }
}
