//! Pistis protocol primitives.
//!
//! Challenge state is deliberately kept independent of transports. A challenge
//! can be consumed exactly once, and only before its expiry.

mod first_device;

pub use first_device::{
    AuthorityDescriptor, FirstDevicePresentation, FirstDevicePresentationError,
    MAX_FIRST_DEVICE_FRAME_BYTES, MobileEnrolmentInvitation, verify_first_device_presentation,
};
pub use pistis_domain::ChallengeId;
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

const RANDOM_VALUE_BYTES: usize = 32;
const IDENTIFIER_BYTES: usize = 16;

/// A cryptographically random, single-use challenge value.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Nonce([u8; RANDOM_VALUE_BYTES]);

impl Nonce {
    /// Constructs a nonce from bytes supplied by a trusted random source.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; RANDOM_VALUE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; RANDOM_VALUE_BYTES] {
        &self.0
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Nonce([REDACTED])")
    }
}

/// Milliseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnixTimeMillis(u64);

impl UnixTimeMillis {
    /// Constructs a timestamp.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the timestamp value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn checked_add(self, lifetime: Duration) -> Result<Self, ChallengeError> {
        let millis =
            u64::try_from(lifetime.as_millis()).map_err(|_| ChallengeError::InvalidLifetime)?;
        self.0
            .checked_add(millis)
            .map(Self)
            .ok_or(ChallengeError::InvalidLifetime)
    }
}

/// Source of wall-clock time, injectable for deterministic tests.
pub trait Clock: Send + Sync {
    /// Returns the current time.
    ///
    /// # Errors
    ///
    /// Returns [`ChallengeError::Clock`] when a valid timestamp is unavailable.
    fn now(&self) -> Result<UnixTimeMillis, ChallengeError>;
}

/// System wall clock.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<UnixTimeMillis, ChallengeError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ChallengeError::Clock)?;
        let millis = u64::try_from(elapsed.as_millis()).map_err(|_| ChallengeError::Clock)?;
        Ok(UnixTimeMillis(millis))
    }
}

/// Source of random bytes, injectable for deterministic tests.
pub trait RandomSource: Send + Sync {
    /// Fills `destination` with cryptographically secure random bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ChallengeError::Randomness`] when the source fails.
    fn fill(&self, destination: &mut [u8]) -> Result<(), ChallengeError>;
}

/// Operating-system cryptographic random source.
#[derive(Debug, Default)]
pub struct SystemRandom;

impl RandomSource for SystemRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), ChallengeError> {
        getrandom::fill(destination).map_err(|_| ChallengeError::Randomness)
    }
}

/// A challenge issued to a claimant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Challenge {
    /// Opaque identifier used for state lookup.
    pub id: ChallengeId,
    /// Single-use random value bound into the signed response.
    pub nonce: Nonce,
    /// Exclusive upper bound on validity.
    pub expires_at: UnixTimeMillis,
}

impl Challenge {
    /// Validates that this challenge has not reached its exclusive expiry.
    ///
    /// # Errors
    ///
    /// Returns [`ChallengeError::Expired`] at or after the expiry timestamp.
    pub fn validate_expiry(&self, now: UnixTimeMillis) -> Result<(), ChallengeError> {
        if now < self.expires_at {
            Ok(())
        } else {
            Err(ChallengeError::Expired)
        }
    }
}

/// Challenge creation or consumption failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeError {
    /// The clock could not provide a valid timestamp.
    Clock,
    /// The operating system random source failed.
    Randomness,
    /// Lifetime was zero or could not be represented.
    InvalidLifetime,
    /// An identifier collision occurred.
    IdentifierCollision,
    /// No active challenge has this identifier.
    UnknownChallenge,
    /// The supplied nonce does not match the issued challenge.
    NonceMismatch,
    /// The challenge has reached its exclusive expiry.
    Expired,
    /// Synchronised state was poisoned by a panic.
    StateUnavailable,
}

impl fmt::Display for ChallengeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Clock => "clock unavailable",
            Self::Randomness => "secure randomness unavailable",
            Self::InvalidLifetime => "invalid challenge lifetime",
            Self::IdentifierCollision => "challenge identifier collision",
            Self::UnknownChallenge => "unknown or already consumed challenge",
            Self::NonceMismatch => "challenge nonce mismatch",
            Self::Expired => "challenge expired",
            Self::StateUnavailable => "challenge state unavailable",
        })
    }
}

impl std::error::Error for ChallengeError {}

/// Thread-safe in-memory challenge lifecycle manager.
///
/// A production durable store must provide the same atomic compare-and-delete
/// semantics as [`consume`](Self::consume).
pub struct ChallengeStore {
    clock: Arc<dyn Clock>,
    random: Arc<dyn RandomSource>,
    active: Mutex<HashMap<ChallengeId, Challenge>>,
}

impl ChallengeStore {
    /// Creates a store using operating-system time and randomness.
    #[must_use]
    pub fn system() -> Self {
        Self::new(Arc::new(SystemClock), Arc::new(SystemRandom))
    }

    /// Creates a store with injectable dependencies.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, random: Arc<dyn RandomSource>) -> Self {
        Self {
            clock,
            random,
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Issues a challenge with an exclusive expiry.
    ///
    /// # Errors
    ///
    /// Returns an error when the lifetime, clock, random source, synchronised
    /// state, or generated identifier is invalid.
    pub fn issue(&self, lifetime: Duration) -> Result<Challenge, ChallengeError> {
        if lifetime.is_zero() {
            return Err(ChallengeError::InvalidLifetime);
        }
        let now = self.clock.now()?;
        let expires_at = now.checked_add(lifetime)?;
        let mut nonce = [0_u8; RANDOM_VALUE_BYTES];
        let mut id = [0_u8; IDENTIFIER_BYTES];
        self.random.fill(&mut nonce)?;
        self.random.fill(&mut id)?;
        let challenge = Challenge {
            id: ChallengeId::from_bytes(id),
            nonce: Nonce(nonce),
            expires_at,
        };
        let mut active = self
            .active
            .lock()
            .map_err(|_| ChallengeError::StateUnavailable)?;
        if active.contains_key(&challenge.id) {
            return Err(ChallengeError::IdentifierCollision);
        }
        active.insert(challenge.id, challenge.clone());
        Ok(challenge)
    }

    /// Atomically validates and consumes an active challenge.
    ///
    /// The nonce is compared before deletion. Expired challenges are deleted,
    /// while a nonce mismatch leaves the legitimate challenge available.
    ///
    /// # Errors
    ///
    /// Returns an error when the clock or state is unavailable, or when the
    /// challenge is unknown, expired, or does not match the nonce.
    pub fn consume(&self, id: ChallengeId, nonce: Nonce) -> Result<(), ChallengeError> {
        let now = self.clock.now()?;
        let mut active = self
            .active
            .lock()
            .map_err(|_| ChallengeError::StateUnavailable)?;
        let challenge = active.get(&id).ok_or(ChallengeError::UnknownChallenge)?;
        if now >= challenge.expires_at {
            active.remove(&id);
            return Err(ChallengeError::Expired);
        }
        if !bool::from(challenge.nonce.0.ct_eq(&nonce.0)) {
            return Err(ChallengeError::NonceMismatch);
        }
        active.remove(&id);
        Ok(())
    }
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::system()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Barrier,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    struct TestClock(AtomicU64);

    impl Clock for TestClock {
        fn now(&self) -> Result<UnixTimeMillis, ChallengeError> {
            Ok(UnixTimeMillis(self.0.load(Ordering::SeqCst)))
        }
    }

    struct TestRandom(AtomicUsize);

    impl RandomSource for TestRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), ChallengeError> {
            let value = u8::try_from(self.0.fetch_add(1, Ordering::SeqCst) + 1)
                .map_err(|_| ChallengeError::Randomness)?;
            destination.fill(value);
            Ok(())
        }
    }

    fn fixture() -> (Arc<TestClock>, Arc<ChallengeStore>) {
        let clock = Arc::new(TestClock(AtomicU64::new(1_000)));
        let store = Arc::new(ChallengeStore::new(
            clock.clone(),
            Arc::new(TestRandom(AtomicUsize::new(0))),
        ));
        (clock, store)
    }

    #[test]
    fn issues_independent_nonce_identifier_and_expiry() {
        let (_, store) = fixture();
        let challenge = store.issue(Duration::from_secs(5)).unwrap();
        assert_eq!(challenge.nonce.as_bytes(), &[1; 32]);
        assert_eq!(challenge.id.as_bytes(), &[2; 16]);
        assert_eq!(challenge.expires_at, UnixTimeMillis(6_000));
    }

    #[test]
    fn rejects_zero_lifetime() {
        let (_, store) = fixture();
        assert_eq!(
            store.issue(Duration::ZERO),
            Err(ChallengeError::InvalidLifetime)
        );
    }

    #[test]
    fn expiry_is_exclusive_and_consumed_failures_stay_failed() {
        let (clock, store) = fixture();
        let challenge = store.issue(Duration::from_millis(5)).unwrap();
        clock.0.store(1_005, Ordering::SeqCst);
        assert_eq!(
            store.consume(challenge.id, challenge.nonce),
            Err(ChallengeError::Expired)
        );
        assert_eq!(
            store.consume(challenge.id, challenge.nonce),
            Err(ChallengeError::UnknownChallenge)
        );
    }

    #[test]
    fn nonce_mismatch_does_not_destroy_valid_challenge() {
        let (_, store) = fixture();
        let challenge = store.issue(Duration::from_secs(1)).unwrap();
        assert_eq!(
            store.consume(challenge.id, Nonce::from_bytes([9; 32])),
            Err(ChallengeError::NonceMismatch)
        );
        assert_eq!(store.consume(challenge.id, challenge.nonce), Ok(()));
    }

    #[test]
    fn replay_is_rejected() {
        let (_, store) = fixture();
        let challenge = store.issue(Duration::from_secs(1)).unwrap();
        assert_eq!(store.consume(challenge.id, challenge.nonce), Ok(()));
        assert_eq!(
            store.consume(challenge.id, challenge.nonce),
            Err(ChallengeError::UnknownChallenge)
        );
    }

    #[test]
    fn exactly_one_concurrent_consumer_succeeds() {
        let (_, store) = fixture();
        let challenge = store.issue(Duration::from_secs(1)).unwrap();
        let barrier = Arc::new(Barrier::new(9));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                store.consume(challenge.id, challenge.nonce)
            }));
        }
        barrier.wait();
        let successes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .fold(0, |count, result| count + usize::from(result.is_ok()));
        assert_eq!(successes, 1);
    }
}
