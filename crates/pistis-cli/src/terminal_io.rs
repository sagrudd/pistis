use crate::{CeremonyError, ChallengePresentation, CliIo, OutputProfile};
use pistis_qr::{
    GlyphSet, ModulePolarity, TerminalProfile, read_response_transfer, render_for_terminal,
};
use std::io::{BufRead, Write};

/// Terminal presentation and protected-input adapter.
pub struct TerminalIo<R, W> {
    reader: R,
    writer: W,
    columns: usize,
    utf8: bool,
    protected_input: bool,
}

impl<R, W> TerminalIo<R, W> {
    /// Creates an adapter from explicit, already reviewed terminal properties.
    ///
    /// `protected_input` must be false for an echoing interactive terminal.
    #[must_use]
    pub const fn new(
        reader: R,
        writer: W,
        columns: usize,
        utf8: bool,
        protected_input: bool,
    ) -> Self {
        Self {
            reader,
            writer,
            columns,
            utf8,
            protected_input,
        }
    }

    /// Returns owned input and output handles.
    pub fn into_inner(self) -> (R, W) {
        (self.reader, self.writer)
    }
}

impl<R: BufRead, W: Write> CliIo for TerminalIo<R, W> {
    fn write_text(&mut self, text: &str) -> Result<(), CeremonyError> {
        self.writer
            .write_all(text.as_bytes())
            .and_then(|()| self.writer.flush())
            .map_err(|_| CeremonyError::Presentation)
    }

    fn write_qr(&mut self, presentation: ChallengePresentation<'_>) -> Result<(), CeremonyError> {
        let glyphs = match presentation.profile {
            OutputProfile::Unicode => GlyphSet::Unicode,
            OutputProfile::Auto if self.utf8 => GlyphSet::Unicode,
            OutputProfile::Ascii | OutputProfile::Auto => GlyphSet::Ascii,
        };
        let polarity = if presentation.inverted {
            ModulePolarity::LightOnDark
        } else {
            ModulePolarity::DarkOnLight
        };
        let rendered = render_for_terminal(
            presentation.transfer,
            TerminalProfile {
                columns: self.columns,
                glyphs,
                polarity,
                module_scale: 1,
            },
        )
        .map_err(|_| CeremonyError::Presentation)?;
        self.writer
            .write_all(rendered.text().as_bytes())
            .and_then(|()| self.writer.flush())
            .map_err(|_| CeremonyError::Presentation)
    }

    fn read_response(&mut self, _: usize) -> Result<String, CeremonyError> {
        if !self.protected_input {
            return Err(CeremonyError::Interrupted);
        }
        read_response_transfer(&mut self.reader).map_err(|_| CeremonyError::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pistis_canonical::{Value, to_vec};
    use pistis_qr::{SIGNATURE_BYTES, TransferKind, TransferRef, encode};
    use std::io::Cursor;

    fn response() -> String {
        let payload = to_vec(&Value::Map([(0, Value::Unsigned(1))].into())).unwrap();
        encode(TransferRef {
            kind: TransferKind::Response,
            payload: &payload,
            signature: &[7; SIGNATURE_BYTES],
        })
        .unwrap()
    }

    #[test]
    fn protected_input_validates_exact_transfer_and_interactive_refuses() {
        let transfer = response();
        let mut io = TerminalIo::new(
            Cursor::new(format!("{transfer}\n")),
            Vec::new(),
            200,
            true,
            true,
        );
        assert_eq!(io.read_response(2_331).unwrap(), transfer);

        let mut io = TerminalIo::new(Cursor::new(response()), Vec::new(), 200, true, false);
        assert_eq!(io.read_response(2_331), Err(CeremonyError::Interrupted));
    }
}
