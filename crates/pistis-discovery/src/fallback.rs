/// One transport attempt in deterministic preference order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferAttempt {
    /// Previously authenticated currently valid pairwise endpoint.
    PairedLocal,
    /// Discovery candidate matching the authenticated endpoint binding.
    DiscoveredLocal,
    /// Signed HTTPS endpoint hint.
    SignedHttpsHint,
    /// Response encoded for QR transfer.
    ResponseQr,
}

const ORDER: [TransferAttempt; 4] = [
    TransferAttempt::PairedLocal,
    TransferAttempt::DiscoveredLocal,
    TransferAttempt::SignedHttpsHint,
    TransferAttempt::ResponseQr,
];

/// Bounded network failure that may advance transport selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptFailure {
    /// Permission was denied or restricted.
    PermissionDenied,
    /// Discovery or connectivity API is unavailable.
    Unavailable,
    /// No candidate arrived before the deadline.
    Timeout,
    /// Candidate or pin validation rejected the network path.
    CandidateRejected,
    /// Interface or address family changed.
    NetworkChanged,
}

/// Terminal rejection from challenge or response security verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportRejection {
    /// Signed challenge was rejected.
    ChallengeRejected,
    /// Enrolled-device response was rejected.
    ResponseRejected,
}

/// Current deterministic transfer-selection state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionState {
    /// A bounded attempt is active.
    Attempting(TransferAttempt),
    /// Response QR is ready for presentation.
    QrReady,
    /// Security verification failed; transport fallback is prohibited.
    Rejected(TransportRejection),
}

/// Deterministic transport-only fallback state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferPlan {
    index: usize,
    state: SelectionState,
}

impl TransferPlan {
    /// Starts with the strongest preferred transport.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            index: 0,
            state: SelectionState::Attempting(ORDER[0]),
        }
    }

    /// Returns the current state.
    #[must_use]
    pub const fn state(self) -> SelectionState {
        self.state
    }

    /// Advances after a bounded transport failure.
    pub fn advance(&mut self, _failure: AttemptFailure) {
        if !matches!(self.state, SelectionState::Attempting(_)) {
            return;
        }
        self.index += 1;
        self.state = if self.index == ORDER.len() - 1 {
            SelectionState::QrReady
        } else {
            SelectionState::Attempting(ORDER[self.index])
        };
    }

    /// Records a terminal security rejection without trying a weaker transport.
    pub fn reject(&mut self, rejection: TransportRejection) {
        self.state = SelectionState::Rejected(rejection);
    }
}

impl Default for TransferPlan {
    fn default() -> Self {
        Self::new()
    }
}
