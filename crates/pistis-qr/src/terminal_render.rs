use crate::{Module, ModuleMatrix, QrError, render};
use std::error::Error;
use std::fmt;

const QUIET_ZONE_MODULES: usize = 4;
const MAX_MODULE_SCALE: u8 = 4;

/// The terminal-safe glyph repertoire used to draw a QR matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GlyphSet {
    /// Portable seven-bit output using two character cells per module.
    Ascii,
    /// UTF-8 half-block output using one cell per module and two module rows
    /// per terminal line.
    Unicode,
}

/// QR module polarity relative to the terminal's configured colours.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModulePolarity {
    /// Dark QR modules use foreground glyphs and light modules use background
    /// cells. This is appropriate for a light terminal background.
    DarkOnLight,
    /// Light QR modules use foreground glyphs and dark modules use background
    /// cells. This is appropriate for a dark terminal background.
    LightOnDark,
}

/// Explicit, bounded terminal capabilities selected by the CLI adapter.
///
/// Environment variables and terminal responses are deliberately not accepted
/// here. The adapter may inspect them to construct a profile, but rendering is
/// deterministic for a given profile and transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalProfile {
    /// Available terminal columns.
    pub columns: usize,
    /// Supported glyph repertoire.
    pub glyphs: GlyphSet,
    /// Module polarity selected for the configured terminal colours.
    pub polarity: ModulePolarity,
    /// Integer module scale in the inclusive range 1 through 4.
    pub module_scale: u8,
}

/// One complete terminal QR rendering, including its four-module quiet zone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalQr {
    text: String,
    columns: usize,
    rows: usize,
    glyphs: GlyphSet,
}

impl TerminalQr {
    /// Returns terminal-safe text terminated by a newline.
    ///
    /// ASCII mode contains only space, `#`, and line feed. Unicode mode
    /// additionally contains only the block elements `▄`, `▀`, and `█`.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns the exact number of character cells in every rendered line.
    #[must_use]
    pub const fn columns(&self) -> usize {
        self.columns
    }

    /// Returns the number of rendered terminal lines.
    #[must_use]
    pub const fn rows(&self) -> usize {
        self.rows
    }

    /// Returns the glyph repertoire used for this rendering.
    #[must_use]
    pub const fn glyphs(&self) -> GlyphSet {
        self.glyphs
    }
}

/// A terminal QR presentation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalRenderError {
    /// QR frame or matrix rendering failed.
    Qr(QrError),
    /// The requested integer module scale is outside 1 through 4.
    InvalidScale,
    /// The complete QR symbol and quiet zone do not fit the terminal.
    TooNarrow {
        /// Columns needed without cropping.
        required: usize,
        /// Columns reported as available.
        available: usize,
    },
}

impl fmt::Display for TerminalRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Qr(error) => write!(formatter, "{error}"),
            Self::InvalidScale => {
                formatter.write_str("terminal QR module scale must be between 1 and 4")
            }
            Self::TooNarrow {
                required,
                available,
            } => write!(
                formatter,
                "terminal is too narrow for QR output: requires {required} columns, has {available}"
            ),
        }
    }
}

impl Error for TerminalRenderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Qr(error) => Some(error),
            Self::InvalidScale | Self::TooNarrow { .. } => None,
        }
    }
}

impl From<QrError> for TerminalRenderError {
    fn from(error: QrError) -> Self {
        Self::Qr(error)
    }
}

/// Renders a transfer as a terminal-safe QR symbol.
///
/// The renderer preserves the mandatory four-module quiet zone and refuses to
/// crop output. It emits no escape, carriage-return, tab, bidi, hyperlink, or
/// other terminal control sequence. Callers must print explanatory metadata
/// separately after applying their own untrusted-text sanitisation.
///
/// # Errors
///
/// Returns an error when the transfer cannot be rendered, the scale is
/// unsupported, arithmetic cannot be represented, or the symbol does not fit
/// within the declared terminal width.
pub fn render_for_terminal(
    transfer: &str,
    profile: TerminalProfile,
) -> Result<TerminalQr, TerminalRenderError> {
    let matrix = render(transfer)?;
    render_matrix(&matrix, profile)
}

fn render_matrix(
    matrix: &ModuleMatrix,
    profile: TerminalProfile,
) -> Result<TerminalQr, TerminalRenderError> {
    if !(1..=MAX_MODULE_SCALE).contains(&profile.module_scale) {
        return Err(TerminalRenderError::InvalidScale);
    }
    let scale = usize::from(profile.module_scale);
    let module_span = matrix
        .width()
        .checked_add(QUIET_ZONE_MODULES * 2)
        .and_then(|width| width.checked_mul(scale))
        .ok_or(TerminalRenderError::InvalidScale)?;
    let cell_width = match profile.glyphs {
        GlyphSet::Ascii => 2,
        GlyphSet::Unicode => 1,
    };
    let required = module_span
        .checked_mul(cell_width)
        .ok_or(TerminalRenderError::InvalidScale)?;
    if required > profile.columns {
        return Err(TerminalRenderError::TooNarrow {
            required,
            available: profile.columns,
        });
    }

    let rows = match profile.glyphs {
        GlyphSet::Ascii => module_span,
        GlyphSet::Unicode => module_span.div_ceil(2),
    };
    let capacity = required
        .checked_add(1)
        .and_then(|line| line.checked_mul(rows))
        .ok_or(TerminalRenderError::InvalidScale)?;
    let mut text = String::with_capacity(capacity);
    match profile.glyphs {
        GlyphSet::Ascii => render_ascii(&mut text, matrix, module_span, scale, profile.polarity),
        GlyphSet::Unicode => {
            render_unicode(&mut text, matrix, module_span, scale, profile.polarity);
        }
    }
    Ok(TerminalQr {
        text,
        columns: required,
        rows,
        glyphs: profile.glyphs,
    })
}

fn render_ascii(
    output: &mut String,
    matrix: &ModuleMatrix,
    module_span: usize,
    scale: usize,
    polarity: ModulePolarity,
) {
    for y in 0..module_span {
        for x in 0..module_span {
            let foreground = is_foreground(matrix, x, y, scale, polarity);
            output.push_str(if foreground { "##" } else { "  " });
        }
        output.push('\n');
    }
}

fn render_unicode(
    output: &mut String,
    matrix: &ModuleMatrix,
    module_span: usize,
    scale: usize,
    polarity: ModulePolarity,
) {
    for y in (0..module_span).step_by(2) {
        for x in 0..module_span {
            let upper = is_foreground(matrix, x, y, scale, polarity);
            let lower = if y + 1 < module_span {
                is_foreground(matrix, x, y + 1, scale, polarity)
            } else {
                polarity == ModulePolarity::LightOnDark
            };
            output.push(match (upper, lower) {
                (false, false) => ' ',
                (true, false) => '▀',
                (false, true) => '▄',
                (true, true) => '█',
            });
        }
        output.push('\n');
    }
}

fn is_foreground(
    matrix: &ModuleMatrix,
    scaled_x: usize,
    scaled_y: usize,
    scale: usize,
    polarity: ModulePolarity,
) -> bool {
    let module_x = scaled_x / scale;
    let module_y = scaled_y / scale;
    let dark = module_x
        .checked_sub(QUIET_ZONE_MODULES)
        .zip(module_y.checked_sub(QUIET_ZONE_MODULES))
        .and_then(|(x, y)| matrix.get(x, y))
        == Some(Module::Dark);
    match polarity {
        ModulePolarity::DarkOnLight => dark,
        ModulePolarity::LightOnDark => !dark,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TransferKind, TransferRef, encode};
    use pistis_canonical::{Value, to_vec};
    use pistis_crypto::sha256;
    use std::collections::BTreeMap;

    fn transfer() -> String {
        let payload = to_vec(&Value::Map(BTreeMap::from([(0, Value::Unsigned(1))]))).unwrap();
        encode(TransferRef {
            kind: TransferKind::Challenge,
            payload: &payload,
            signature: &[0x5a; 64],
        })
        .unwrap()
    }

    fn profile(glyphs: GlyphSet) -> TerminalProfile {
        TerminalProfile {
            columns: 200,
            glyphs,
            polarity: ModulePolarity::DarkOnLight,
            module_scale: 1,
        }
    }

    #[test]
    fn ascii_profile_is_deterministic_and_preserves_quiet_zone() {
        let first = render_for_terminal(&transfer(), profile(GlyphSet::Ascii)).unwrap();
        let second = render_for_terminal(&transfer(), profile(GlyphSet::Ascii)).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.columns(), 114);
        assert_eq!(first.rows(), 57);
        assert!(
            first
                .text()
                .lines()
                .take(4)
                .all(|line| line == " ".repeat(114))
        );
        assert!(
            first
                .text()
                .lines()
                .all(|line| line.len() == first.columns())
        );
    }

    #[test]
    fn unicode_profile_halves_dimensions_without_cropping() {
        let rendered = render_for_terminal(&transfer(), profile(GlyphSet::Unicode)).unwrap();
        assert_eq!(rendered.columns(), 57);
        assert_eq!(rendered.rows(), 29);
        assert_eq!(
            sha256(rendered.text().as_bytes()).into_bytes(),
            [
                0x02, 0xf5, 0x05, 0x14, 0x0b, 0x67, 0xb7, 0x9b, 0x67, 0xd7, 0x84, 0x02, 0x78, 0x2a,
                0x84, 0xb9, 0x87, 0x9b, 0x18, 0x98, 0x46, 0xc0, 0x96, 0xe0, 0x2d, 0xe5, 0x8e, 0x0d,
                0xf3, 0x8b, 0xc4, 0xf9,
            ]
        );
        assert_eq!(rendered.text().lines().count(), rendered.rows());
        assert!(
            rendered
                .text()
                .lines()
                .all(|line| line.chars().count() == rendered.columns())
        );
    }

    #[test]
    fn refuses_narrow_output_and_invalid_scales() {
        let mut narrow = profile(GlyphSet::Unicode);
        narrow.columns = 56;
        assert_eq!(
            render_for_terminal(&transfer(), narrow),
            Err(TerminalRenderError::TooNarrow {
                required: 57,
                available: 56,
            })
        );

        let mut invalid = profile(GlyphSet::Unicode);
        invalid.module_scale = 0;
        assert_eq!(
            render_for_terminal(&transfer(), invalid),
            Err(TerminalRenderError::InvalidScale)
        );
    }

    #[test]
    fn output_has_no_terminal_injection_alphabet() {
        for glyphs in [GlyphSet::Ascii, GlyphSet::Unicode] {
            let rendered = render_for_terminal(&transfer(), profile(glyphs)).unwrap();
            assert!(!rendered.text().contains('\u{1b}'));
            assert!(!rendered.text().contains('\r'));
            assert!(!rendered.text().contains('\t'));
            assert!(
                rendered
                    .text()
                    .chars()
                    .all(|character| matches!(character, ' ' | '#' | '\n' | '▀' | '▄' | '█'))
            );
        }
    }

    #[test]
    fn inversion_changes_modules_and_quiet_zone_deterministically() {
        let normal = render_for_terminal(&transfer(), profile(GlyphSet::Unicode)).unwrap();
        let mut inverted_profile = profile(GlyphSet::Unicode);
        inverted_profile.polarity = ModulePolarity::LightOnDark;
        let inverted = render_for_terminal(&transfer(), inverted_profile).unwrap();
        assert_ne!(normal.text(), inverted.text());
        assert!(
            inverted
                .text()
                .lines()
                .next()
                .unwrap()
                .chars()
                .all(|c| c == '█')
        );
        assert!(
            inverted
                .text()
                .lines()
                .last()
                .unwrap()
                .chars()
                .all(|c| c == '█')
        );
    }
}
