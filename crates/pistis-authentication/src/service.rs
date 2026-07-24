use crate::{
    AuditEvent, AuthenticatedSessionId, ChallengeContext, ChallengeDocument, Completion, Decision,
    DeviceDirectory, LoginHandle, LoginStatus, PreAuthSessionId, PublicFailure, RandomSource,
    ResponseEnvelope, ServiceError, TransferMode, UnixTimeMillis,
    schema::{decode_response, encode_challenge},
};
use pistis_crypto::{SignatureSuite, sha256, verify};
use pistis_domain::{ChallengeId, InstallationId, UserId};
use pistis_qr::{TransferKind, decode as decode_qr};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
struct Ceremony {
    pre_auth: Option<PreAuthSessionId>,
    challenge: ChallengeDocument,
    state: State,
}

#[derive(Clone)]
enum State {
    Pending,
    ResponseAvailable {
        response: ResponseEnvelope,
        transfer: TransferMode,
    },
    Denied,
    Failed(PublicFailure),
    Cancelled,
    Expired,
    Completed(Completion),
}

#[derive(Default)]
struct Store {
    ceremonies: HashMap<LoginHandle, Ceremony>,
    sessions: HashMap<AuthenticatedSessionId, UserId>,
    audit: Vec<AuditEvent>,
}

/// In-memory reference implementation of the authentication application flow.
///
/// All security-relevant mutations occur under one synchronization boundary.
/// A durable adapter must provide equivalent rollback-capable transaction
/// semantics for challenge consumption, pre-auth rotation, session insertion,
/// and audit insertion.
pub struct AuthenticationService {
    installation_id: InstallationId,
    devices: Arc<dyn DeviceDirectory>,
    random: Arc<dyn RandomSource>,
    store: Mutex<Store>,
}

impl AuthenticationService {
    /// Creates a framework-neutral service.
    #[must_use]
    pub fn new(
        installation_id: InstallationId,
        devices: Arc<dyn DeviceDirectory>,
        random: Arc<dyn RandomSource>,
    ) -> Self {
        Self {
            installation_id,
            devices,
            random,
            store: Mutex::new(Store::default()),
        }
    }

    /// Starts a ceremony without creating an authenticated session.
    ///
    /// # Errors
    ///
    /// Fails closed on invalid expiry, randomness failure, collision, or
    /// unavailable synchronized state.
    pub fn initiate(
        &self,
        pre_auth: PreAuthSessionId,
        context: ChallengeContext,
        now: UnixTimeMillis,
        expires_at: UnixTimeMillis,
    ) -> Result<(LoginHandle, ChallengeDocument), ServiceError> {
        if now >= expires_at {
            return Err(ServiceError::Conflict);
        }
        let mut handle = [0; 32];
        let mut challenge_id = [0; 16];
        let mut nonce = [0; 32];
        self.random.fill(&mut handle)?;
        self.random.fill(&mut challenge_id)?;
        self.random.fill(&mut nonce)?;
        let handle = LoginHandle::from_bytes(handle);
        let challenge = ChallengeDocument {
            issued_at: now,
            expires_at,
            challenge_id: ChallengeId::from_bytes(challenge_id),
            installation_id: self.installation_id,
            user_id: context.user_id,
            external_identity_id: context.external_identity_id,
            installation_key_id: context.installation_key_id,
            nonce,
            audience: context.audience,
            installation_name: context.installation_name,
            local_username: context.local_username,
            display_context_digest: context.display_context_digest,
            installation_fingerprint: context.installation_fingerprint,
            endpoint_hints: context.endpoint_hints,
        };
        // Enforce every schema bound before retaining authoritative state.
        encode_challenge(&challenge)?;
        let mut store = self.store.lock().map_err(|_| ServiceError::Unavailable)?;
        if store.ceremonies.contains_key(&handle) {
            return Err(ServiceError::Unavailable);
        }
        store.ceremonies.insert(
            handle,
            Ceremony {
                pre_auth: Some(pre_auth),
                challenge: challenge.clone(),
                state: State::Pending,
            },
        );
        Ok((handle, challenge))
    }

    /// Stages a directly submitted signed response without authenticating.
    ///
    /// # Errors
    ///
    /// Rejects unknown, expired, terminal, or already populated ceremonies.
    pub fn submit_direct(
        &self,
        handle: LoginHandle,
        response: ResponseEnvelope,
        now: UnixTimeMillis,
    ) -> Result<(), ServiceError> {
        self.stage(handle, response, TransferMode::Direct, now)
    }

    /// Stages a checksummed response-QR transfer.
    ///
    /// # Errors
    ///
    /// Rejects malformed envelope bytes and all failures documented by
    /// [`submit_direct`](Self::submit_direct).
    pub fn submit_response_qr(
        &self,
        handle: LoginHandle,
        transfer_text: &str,
        now: UnixTimeMillis,
    ) -> Result<(), ServiceError> {
        let (canonical, signature) = decode_qr(transfer_text, TransferKind::Response)
            .map_err(|_| ServiceError::InvalidResponse)?;
        let response = ResponseEnvelope::new(canonical, signature)?;
        self.stage(handle, response, TransferMode::ResponseQr, now)
    }

    fn stage(
        &self,
        handle: LoginHandle,
        response: ResponseEnvelope,
        transfer: TransferMode,
        now: UnixTimeMillis,
    ) -> Result<(), ServiceError> {
        // Re-apply bounds even if an adapter constructed this public struct.
        let response = ResponseEnvelope::new(response.canonical, response.signature)?;
        let mut store = self.store.lock().map_err(|_| ServiceError::Unavailable)?;
        let ceremony = store
            .ceremonies
            .get_mut(&handle)
            .ok_or(ServiceError::NotFound)?;
        expire(ceremony, now);
        match &ceremony.state {
            State::Pending => {
                ceremony.state = State::ResponseAvailable { response, transfer };
                Ok(())
            }
            State::ResponseAvailable {
                response: existing, ..
            } if existing == &response => Ok(()),
            _ => Err(ServiceError::Conflict),
        }
    }

    /// Returns a redacted browser-safe status without consuming state.
    ///
    /// # Errors
    ///
    /// A wrong pre-authentication session and an unknown handle are deliberately
    /// indistinguishable.
    pub fn poll(
        &self,
        handle: LoginHandle,
        pre_auth: PreAuthSessionId,
        now: UnixTimeMillis,
    ) -> Result<LoginStatus, ServiceError> {
        let mut store = self.store.lock().map_err(|_| ServiceError::Unavailable)?;
        let ceremony = store
            .ceremonies
            .get_mut(&handle)
            .filter(|ceremony| ceremony.pre_auth == Some(pre_auth))
            .ok_or(ServiceError::NotFound)?;
        expire(ceremony, now);
        Ok(status(&ceremony.state))
    }

    /// Verifies and atomically completes a staged response.
    ///
    /// This is the only operation that creates an authenticated session. The
    /// challenge becomes terminal, the pre-authentication session is rotated,
    /// the authenticated session is inserted, and the audit event is retained
    /// in the same critical section.
    ///
    /// # Errors
    ///
    /// Returns a coarse state error. Verification failures are retained as a
    /// redacted terminal status and never create a session.
    pub fn complete(
        &self,
        handle: LoginHandle,
        pre_auth: PreAuthSessionId,
        now: UnixTimeMillis,
    ) -> Result<Completion, ServiceError> {
        let mut store = self.store.lock().map_err(|_| ServiceError::Unavailable)?;
        let ceremony = store
            .ceremonies
            .get(&handle)
            .filter(|ceremony| ceremony.pre_auth == Some(pre_auth))
            .ok_or(ServiceError::NotFound)?
            .clone();
        if now >= ceremony.challenge.expires_at {
            if let Some(value) = store.ceremonies.get_mut(&handle) {
                value.state = State::Expired;
            }
            return Err(ServiceError::Conflict);
        }
        let State::ResponseAvailable { response, transfer } = ceremony.state else {
            return Err(ServiceError::Conflict);
        };
        let parsed = match decode_response(&response.canonical) {
            Ok(value) => value,
            Err(error) => {
                fail(&mut store, handle, PublicFailure::Rejected);
                return Err(error);
            }
        };
        if parsed.challenge_id != ceremony.challenge.challenge_id
            || parsed.installation_id != ceremony.challenge.installation_id
            || parsed.user_id != ceremony.challenge.user_id
            || parsed.external_identity_id != ceremony.challenge.external_identity_id
            || parsed.nonce != ceremony.challenge.nonce
            || parsed.challenge_digest
                != sha256(&encode_challenge(&ceremony.challenge)?).into_bytes()
            || parsed.issued_at < ceremony.challenge.issued_at
            || parsed.issued_at > now
            || parsed.user_verified_at < parsed.issued_at
            || parsed.user_verified_at > now
            || parsed.user_verified_at >= ceremony.challenge.expires_at
        {
            fail(&mut store, handle, PublicFailure::Rejected);
            return Err(ServiceError::InvalidResponse);
        }
        let Some(device) = self.devices.resolve(parsed.device_id) else {
            fail(&mut store, handle, PublicFailure::InactiveDevice);
            return Err(ServiceError::InvalidResponse);
        };
        if !device.active || device.key_id != parsed.key_id {
            fail(&mut store, handle, PublicFailure::InactiveDevice);
            return Err(ServiceError::InvalidResponse);
        }
        if verify(
            SignatureSuite::Es256,
            &device.public_key,
            &response.canonical,
            &response.signature,
        )
        .is_err()
        {
            fail(&mut store, handle, PublicFailure::Rejected);
            return Err(ServiceError::InvalidResponse);
        }
        if parsed.decision == Decision::Deny {
            if let Some(value) = store.ceremonies.get_mut(&handle) {
                value.state = State::Denied;
            }
            return Err(ServiceError::Conflict);
        }

        let mut session = [0; 32];
        self.random.fill(&mut session)?;
        let session_id = AuthenticatedSessionId::from_bytes(session);
        if store.sessions.contains_key(&session_id) {
            return Err(ServiceError::Unavailable);
        }
        let completion = Completion {
            session_id,
            device_id: device.device_id,
            completed_at: now,
        };
        // No fallible operation follows the first mutation: this is the
        // in-memory reference transaction's commit section.
        store
            .sessions
            .insert(session_id, ceremony.challenge.user_id);
        store.audit.push(AuditEvent {
            login: handle,
            user_id: ceremony.challenge.user_id,
            device_id: device.device_id,
            transfer,
            at: now,
        });
        if let Some(value) = store.ceremonies.get_mut(&handle) {
            value.pre_auth = None;
            value.state = State::Completed(completion);
        }
        Ok(completion)
    }

    /// Cancels a pending or response-available ceremony.
    ///
    /// # Errors
    ///
    /// Rejects unknown, mismatched, expired, or terminal ceremonies.
    pub fn cancel(
        &self,
        handle: LoginHandle,
        pre_auth: PreAuthSessionId,
        now: UnixTimeMillis,
    ) -> Result<(), ServiceError> {
        let mut store = self.store.lock().map_err(|_| ServiceError::Unavailable)?;
        let ceremony = store
            .ceremonies
            .get_mut(&handle)
            .filter(|ceremony| ceremony.pre_auth == Some(pre_auth))
            .ok_or(ServiceError::NotFound)?;
        expire(ceremony, now);
        match ceremony.state {
            State::Pending | State::ResponseAvailable { .. } => {
                ceremony.state = State::Cancelled;
                Ok(())
            }
            _ => Err(ServiceError::Conflict),
        }
    }

    /// Reports whether an authenticated session exists.
    #[must_use]
    pub fn is_authenticated(&self, session: AuthenticatedSessionId) -> bool {
        self.store
            .lock()
            .map(|store| store.sessions.contains_key(&session))
            .unwrap_or(false)
    }

    /// Returns a snapshot of non-secret audit events.
    #[must_use]
    pub fn audit_events(&self) -> Vec<AuditEvent> {
        self.store
            .lock()
            .map(|store| store.audit.clone())
            .unwrap_or_default()
    }
}

fn expire(ceremony: &mut Ceremony, now: UnixTimeMillis) {
    if now >= ceremony.challenge.expires_at
        && matches!(
            ceremony.state,
            State::Pending | State::ResponseAvailable { .. }
        )
    {
        ceremony.state = State::Expired;
    }
}

fn fail(store: &mut Store, handle: LoginHandle, failure: PublicFailure) {
    if let Some(value) = store.ceremonies.get_mut(&handle) {
        value.state = State::Failed(failure);
    }
}

fn status(state: &State) -> LoginStatus {
    match state {
        State::Pending => LoginStatus::Pending,
        State::ResponseAvailable { .. } => LoginStatus::ResponseAvailable,
        State::Denied => LoginStatus::Denied,
        State::Failed(failure) => LoginStatus::Failed(*failure),
        State::Cancelled => LoginStatus::Cancelled,
        State::Expired => LoginStatus::Expired,
        State::Completed(completion) => {
            let _ = completion;
            LoginStatus::Completed
        }
    }
}
