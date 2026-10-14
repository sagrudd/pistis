use image::{GrayImage, ImageFormat, Luma};
use qrcode::{Color, QrCode};
use std::io::Cursor;
#[path = "../examples/regression_support/mod.rs"]
mod acquisition;

use acquisition::{
    AcquisitionError, MAX_IMAGE_BYTES, MAX_TEXT_BYTES, acquire_png, acquire_text, bounded_read,
};

fn qr_image(text: &str) -> GrayImage {
    let code = QrCode::new(text).unwrap();
    let width = code.width();
    let scale = 5;
    let pixels = u32::try_from((width + 8) * scale).unwrap();
    GrayImage::from_fn(pixels, pixels, |x, y| {
        let x = x as usize / scale;
        let y = y as usize / scale;
        let dark = (4..width + 4).contains(&x)
            && (4..width + 4).contains(&y)
            && code[(x - 4, y - 4)] == Color::Dark;
        Luma([if dark { 0 } else { 255 }])
    })
}

fn png(image: &GrayImage) -> Vec<u8> {
    let mut output = Cursor::new(Vec::new());
    image.write_to(&mut output, ImageFormat::Png).unwrap();
    output.into_inner()
}

#[test]
fn real_png_and_rotated_screenshot_decode_exactly() {
    let text = "PISTIS1:fixture-content-is-not-authentication";
    let original = qr_image(text);
    for image in [original.clone(), image::imageops::rotate90(&original)] {
        let mut screenshot = GrayImage::from_pixel(900, 600, Luma([240]));
        image::imageops::replace(&mut screenshot, &image, 173, 111);
        let acquired = acquire_png(&png(&screenshot)).unwrap();
        assert_eq!(acquired.text(), text);
        assert!(!format!("{acquired:?}").contains("fixture-content"));
    }
    let with_newline = "PISTIS1:invalid-as-a-frame\n";
    assert_eq!(
        acquire_png(&png(&qr_image(with_newline))).unwrap().text(),
        with_newline
    );
}

#[test]
fn zero_and_multiple_symbols_fail_closed() {
    assert_eq!(
        acquire_png(&png(&GrayImage::from_pixel(200, 200, Luma([255])))).unwrap_err(),
        AcquisitionError::NoQR
    );
    assert_eq!(AcquisitionError::NoQR.code(), "no_qr");
    let qr = qr_image("PISTIS1:one-symbol-only");
    let mut image = GrayImage::from_pixel(qr.width() * 2 + 80, qr.height() + 40, Luma([255]));
    image::imageops::replace(&mut image, &qr, 10, 10);
    image::imageops::replace(&mut image, &qr, i64::from(qr.width()) + 60, 10);
    assert_eq!(
        acquire_png(&png(&image)).unwrap_err(),
        AcquisitionError::MultipleQR
    );
}

#[test]
fn bounded_input_and_dimensions_reject_before_scan() {
    assert_eq!(
        bounded_read(Cursor::new(vec![0; 17]), 16).unwrap_err(),
        AcquisitionError::InputTooLarge
    );
    assert_eq!(
        acquire_png(&vec![0; MAX_IMAGE_BYTES + 1]).unwrap_err(),
        AcquisitionError::InputTooLarge
    );
    assert_eq!(
        acquire_png(&png(&GrayImage::from_pixel(4097, 1, Luma([255])))).unwrap_err(),
        AcquisitionError::ImageDimensions
    );
    assert_eq!(
        acquire_png(b"not-a-png").unwrap_err(),
        AcquisitionError::InvalidPNG
    );
}

#[test]
fn text_is_bounded_and_not_silently_normalised() {
    assert_eq!(
        acquire_text(b"PISTIS1:frame\n").unwrap().text(),
        "PISTIS1:frame\n"
    );
    for text in [&b""[..], &[0xff][..]] {
        assert_eq!(
            acquire_text(text).unwrap_err(),
            AcquisitionError::InvalidText
        );
    }
    for text in ["QR\r\n", "QR\nembedded", "QR:界", " QR "] {
        assert_eq!(acquire_text(text.as_bytes()).unwrap().text(), text);
    }
    assert_eq!(
        acquire_text(&vec![b'a'; MAX_TEXT_BYTES + 1]).unwrap_err(),
        AcquisitionError::InputTooLarge
    );
}
