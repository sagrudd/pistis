use crate::OutputProfile;
use pistis_protocol::{
    FirstDevicePresentationError, MAX_FIRST_DEVICE_FRAME_BYTES, verify_first_device_presentation,
};
use pistis_qr::{
    GlyphSet, ModulePolarity, TerminalProfile, encode_enrolment_frame, render_for_terminal,
};
use std::io::{BufRead, Read, Write};

const ENTER_ALT_SCREEN: &[u8] = b"\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H";
const LEAVE_ALT_SCREEN: &[u8] = b"\x1b[2J\x1b[H\x1b[?25h\x1b[?1049l";

/// Coarse protected-presentation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrolmentPresentationError {
    /// Standard input was interactive rather than an inherited pipe.
    UnprotectedInput,
    /// Standard output or the acknowledgement channel was not a terminal.
    NoAttendedTerminal,
    /// Input was empty, truncated, trailing, oversized, or failed verification.
    Rejected,
    /// The QR cannot be rendered safely on the current terminal.
    Presentation,
}

impl From<FirstDevicePresentationError> for EnrolmentPresentationError {
    fn from(_: FirstDevicePresentationError) -> Self {
        Self::Rejected
    }
}

/// Non-secret terminal and verification inputs for one attended presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrolmentPresentationOptions {
    /// Whether standard input was observed as a pipe.
    pub input_is_pipe: bool,
    /// Whether standard output was observed as a terminal.
    pub output_is_terminal: bool,
    /// Requested terminal glyph profile.
    pub profile: OutputProfile,
    /// Requested module polarity.
    pub inverted: bool,
    /// Current terminal width.
    pub columns: usize,
    /// Reviewed GitHub App configuration digest.
    pub expected_app_configuration_digest: [u8; 32],
    /// Current Unix epoch milliseconds.
    pub now_ms: u64,
}

/// Verify and render one first-device presentation without emitting its bytes.
///
/// `input_is_pipe` and `output_is_terminal` are observations made by the
/// executable from already-open descriptors. `acknowledgement` is the
/// controlling terminal, never the producer pipe.
///
/// # Errors
///
/// Returns only coarse errors and writes no invitation or transfer text to
/// diagnostics. The alternate screen and cursor are restored on every normal
/// return, I/O failure, and panic unwind.
pub fn present_first_device<R: Read, W: Write, A: BufRead>(
    input: R,
    output: &mut W,
    acknowledgement: &mut A,
    options: EnrolmentPresentationOptions,
) -> Result<(), EnrolmentPresentationError> {
    if !options.input_is_pipe {
        return Err(EnrolmentPresentationError::UnprotectedInput);
    }
    if !options.output_is_terminal {
        return Err(EnrolmentPresentationError::NoAttendedTerminal);
    }
    let mut bounded = input.take((MAX_FIRST_DEVICE_FRAME_BYTES + 1) as u64);
    let mut frame = Vec::new();
    bounded
        .read_to_end(&mut frame)
        .map_err(|_| EnrolmentPresentationError::Rejected)?;
    if frame.is_empty() || frame.len() > MAX_FIRST_DEVICE_FRAME_BYTES {
        return Err(EnrolmentPresentationError::Rejected);
    }
    let verified = verify_first_device_presentation(
        &frame,
        options.expected_app_configuration_digest,
        options.now_ms,
    )?;
    let transfer =
        encode_enrolment_frame(&frame).map_err(|_| EnrolmentPresentationError::Rejected)?;
    let glyphs = match options.profile {
        OutputProfile::Unicode | OutputProfile::Auto => GlyphSet::Unicode,
        OutputProfile::Ascii => GlyphSet::Ascii,
    };
    let polarity = if options.inverted {
        ModulePolarity::LightOnDark
    } else {
        ModulePolarity::DarkOnLight
    };
    let rendered = render_for_terminal(
        &transfer,
        TerminalProfile {
            columns: options.columns,
            glyphs,
            polarity,
            module_scale: 1,
        },
    )
    .map_err(|_| EnrolmentPresentationError::Presentation)?;
    let screen = AlternateScreen::enter(output)?;
    writeln!(
        screen.writer,
        "SENSITIVE FIRST-DEVICE INVITATION — do not record this screen\n\
         Installation: {}\nOrigin: {}\nExpires (Unix ms): {}\n\
         On the phone, open Pistis → Enrol first device and scan this QR.\n",
        verified.installation_name, verified.https_origin, verified.expires_at_ms
    )
    .and_then(|()| screen.writer.write_all(rendered.text().as_bytes()))
    .and_then(|()| {
        screen
            .writer
            .write_all(b"\nPress Enter immediately after the phone accepts the scan.\n")
    })
    .and_then(|()| screen.writer.flush())
    .map_err(|_| EnrolmentPresentationError::Presentation)?;
    let mut acknowledgement_line = String::new();
    acknowledgement
        .read_line(&mut acknowledgement_line)
        .map_err(|_| EnrolmentPresentationError::Presentation)?;
    if acknowledgement_line != "\n" && acknowledgement_line != "\r\n" {
        return Err(EnrolmentPresentationError::Presentation);
    }
    screen.leave()
}

struct AlternateScreen<'a, W: Write> {
    writer: &'a mut W,
    active: bool,
}

impl<'a, W: Write> AlternateScreen<'a, W> {
    fn enter(writer: &'a mut W) -> Result<Self, EnrolmentPresentationError> {
        writer
            .write_all(ENTER_ALT_SCREEN)
            .and_then(|()| writer.flush())
            .map_err(|_| EnrolmentPresentationError::Presentation)?;
        Ok(Self {
            writer,
            active: true,
        })
    }

    fn leave(mut self) -> Result<(), EnrolmentPresentationError> {
        self.restore()
            .map_err(|_| EnrolmentPresentationError::Presentation)
    }

    fn restore(&mut self) -> std::io::Result<()> {
        if self.active {
            self.active = false;
            self.writer
                .write_all(LEAVE_ALT_SCREEN)
                .and_then(|()| self.writer.flush())?;
        }
        Ok(())
    }
}

impl<W: Write> Drop for AlternateScreen<'_, W> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
