use crate::{MAX_TRANSFER_TEXT_BYTES, QrError};
use qrcode::bits::Bits;
use qrcode::types::Version;
use qrcode::{EcLevel, QrCode};

/// One deterministic QR module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Module {
    /// A light module.
    Light,
    /// A dark module.
    Dark,
}

/// Square QR module matrix, excluding any presentation quiet zone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleMatrix {
    width: usize,
    modules: Vec<Module>,
}

impl ModuleMatrix {
    /// Returns the width and height in modules.
    #[must_use]
    pub const fn width(&self) -> usize {
        self.width
    }

    /// Returns the module at zero-based coordinates.
    #[must_use]
    pub fn get(&self, x: usize, y: usize) -> Option<Module> {
        if x >= self.width || y >= self.width {
            return None;
        }
        self.modules.get(y * self.width + x).copied()
    }

    /// Returns modules in row-major order.
    #[must_use]
    pub fn modules(&self) -> &[Module] {
        &self.modules
    }
}

/// Renders an ASCII transfer in byte mode with error-correction level M.
///
/// The returned matrix excludes the quiet zone so platform adapters can apply
/// an appropriate scale and the mandatory four-module light border.
///
/// # Errors
///
/// Returns an error when the text is non-ASCII, exceeds the transport bound,
/// or cannot fit a QR symbol at error-correction level M.
pub fn render(transfer: &str) -> Result<ModuleMatrix, QrError> {
    if transfer.len() > MAX_TRANSFER_TEXT_BYTES {
        return Err(QrError::TooLarge);
    }
    if !transfer.is_ascii() {
        return Err(QrError::NonAscii);
    }
    let code = byte_mode_code(transfer.as_bytes())?;
    let width = code.width();
    let modules = code
        .to_colors()
        .into_iter()
        .map(|color| {
            if color == qrcode::Color::Dark {
                Module::Dark
            } else {
                Module::Light
            }
        })
        .collect();
    Ok(ModuleMatrix { width, modules })
}

fn byte_mode_code(data: &[u8]) -> Result<QrCode, QrError> {
    for number in 1..=40 {
        let mut bits = Bits::new(Version::Normal(number));
        if bits.push_byte_data(data).is_err() || bits.push_terminator(EcLevel::M).is_err() {
            continue;
        }
        if let Ok(code) = QrCode::with_bits(bits, EcLevel::M) {
            return Ok(code);
        }
    }
    Err(QrError::Unrepresentable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TransferKind, TransferRef, encode};
    use pistis_canonical::{Value, to_vec};
    use std::collections::BTreeMap;

    fn text() -> String {
        let payload = to_vec(&Value::Map(BTreeMap::from([(0, Value::Unsigned(1))]))).unwrap();
        encode(TransferRef {
            kind: TransferKind::Challenge,
            payload: &payload,
            signature: &[0x5a; 64],
        })
        .unwrap()
    }

    #[test]
    fn renders_deterministic_square_byte_mode_matrix_at_level_m() {
        let first = render(&text()).unwrap();
        let second = render(&text()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.width(), 49);
        assert_eq!(first.modules().len(), first.width() * first.width());
        assert_eq!(first.get(0, 0), Some(Module::Dark));
        assert_eq!(first.get(first.width(), 0), None);
    }

    #[test]
    fn rejects_non_ascii_and_oversized_render_input() {
        assert_eq!(render("é"), Err(QrError::NonAscii));
        assert_eq!(
            render(&"A".repeat(MAX_TRANSFER_TEXT_BYTES + 1)),
            Err(QrError::TooLarge)
        );
    }

    #[test]
    fn version_40_m_accepts_the_normative_text_bound_in_byte_mode() {
        let matrix = render(&"A".repeat(MAX_TRANSFER_TEXT_BYTES)).unwrap();
        assert_eq!(matrix.width(), 177);
    }
}
