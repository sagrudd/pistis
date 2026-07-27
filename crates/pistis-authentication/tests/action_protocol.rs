use pistis_authentication::{
    ActionApprovalChallenge, ActionDescriptor, ActionEnvironment, ActionResource,
    ActionResourceKind, ChallengeDocument, Decision, UnixTimeMillis, action_descriptor_digest,
    decode_action_challenge, decode_action_descriptor, decode_action_response, decode_challenge,
    encode_action_challenge, encode_action_descriptor, encode_action_response, encode_challenge,
};
use pistis_canonical::{Value, from_slice, to_vec};
use pistis_crypto::sha256;
use pistis_domain::{ChallengeId, DeviceId, ExternalIdentityId, InstallationId, KeyId, UserId};

fn descriptor() -> ActionDescriptor {
    ActionDescriptor {
        executable_path: "/usr/bin/samtools".into(),
        executable_sha256: [0x21; 32],
        arguments: vec![
            "samtools".into(),
            "view".into(),
            "--output".into(),
            "result.bam".into(),
            "sample.bam".into(),
        ],
        working_directory: "/analysis/run-42".into(),
        environment: vec![
            ActionEnvironment {
                name: "LANG".into(),
                value: "C.UTF-8".into(),
            },
            ActionEnvironment {
                name: "OMP_NUM_THREADS".into(),
                value: "8".into(),
            },
        ],
        resources: vec![
            ActionResource {
                kind: ActionResourceKind::Input,
                identifier: "file:///analysis/run-42/sample.bam".into(),
                sha256: Some([0x31; 32]),
            },
            ActionResource {
                kind: ActionResourceKind::Output,
                identifier: "file:///analysis/run-42/result.bam".into(),
                sha256: None,
            },
        ],
    }
}

fn challenge(action: ActionDescriptor) -> ActionApprovalChallenge {
    ActionApprovalChallenge {
        issued_at: UnixTimeMillis(1_000),
        expires_at: UnixTimeMillis(61_000),
        installation_id: InstallationId::from_bytes([1; 16]),
        installation_key_id: KeyId::from_bytes([2; 32]),
        challenge_id: ChallengeId::from_bytes([3; 16]),
        nonce: [4; 32],
        user_id: UserId::from_bytes([5; 16]),
        external_identity_id: ExternalIdentityId::from_bytes([6; 16]),
        audience: "cluster.example:terminal".into(),
        installation_name: "Analysis workstation".into(),
        local_username: "scientist".into(),
        installation_fingerprint: [7; 32],
        action,
    }
}

#[test]
fn descriptor_and_challenge_have_stable_closed_round_trips() {
    let descriptor = descriptor();
    let descriptor_bytes = encode_action_descriptor(&descriptor).unwrap();
    assert_eq!(
        decode_action_descriptor(&descriptor_bytes).unwrap(),
        descriptor
    );
    assert_eq!(
        action_descriptor_digest(&descriptor).unwrap(),
        [
            219, 106, 171, 87, 223, 7, 121, 41, 200, 191, 180, 76, 7, 84, 22, 210, 142, 180, 188,
            212, 76, 157, 140, 50, 164, 232, 244, 64, 54, 251, 109, 142,
        ]
    );

    let challenge = challenge(descriptor);
    let challenge_bytes = encode_action_challenge(&challenge).unwrap();
    assert_eq!(
        decode_action_challenge(&challenge_bytes).unwrap(),
        challenge
    );
}

#[test]
fn response_binds_every_exact_challenge_byte() {
    let original = challenge(descriptor());
    let response = encode_action_response(
        &original,
        DeviceId::from_bytes([8; 16]),
        KeyId::from_bytes([9; 32]),
        Decision::Approve,
        UnixTimeMillis(2_000),
        UnixTimeMillis(2_100),
    )
    .unwrap();
    let decoded = decode_action_response(&response).unwrap();
    assert_eq!(
        decoded.challenge_digest,
        sha256(&encode_action_challenge(&original).unwrap()).into_bytes()
    );

    let mut substituted = original.clone();
    substituted.action.arguments[1] = "sort".into();
    assert_ne!(
        decoded.challenge_digest,
        sha256(&encode_action_challenge(&substituted).unwrap()).into_bytes()
    );
}

#[test]
fn login_and_action_protocols_cannot_downgrade_into_each_other() {
    let action_bytes = encode_action_challenge(&challenge(descriptor())).unwrap();
    assert!(decode_challenge(&action_bytes).is_err());

    let login = ChallengeDocument {
        issued_at: UnixTimeMillis(1_000),
        expires_at: UnixTimeMillis(61_000),
        installation_id: InstallationId::from_bytes([1; 16]),
        installation_key_id: KeyId::from_bytes([2; 32]),
        challenge_id: ChallengeId::from_bytes([3; 16]),
        nonce: [4; 32],
        user_id: UserId::from_bytes([5; 16]),
        external_identity_id: ExternalIdentityId::from_bytes([6; 16]),
        audience: "cluster.example:terminal".into(),
        installation_name: "Analysis workstation".into(),
        local_username: "scientist".into(),
        display_context_digest: [7; 32],
        installation_fingerprint: [8; 32],
        endpoint_hints: vec![],
    };
    assert!(decode_action_challenge(&encode_challenge(&login).unwrap()).is_err());
}

#[test]
fn rejects_unsorted_duplicate_secret_like_and_relative_bindings() {
    let mut value = descriptor();
    value.environment.swap(0, 1);
    assert!(encode_action_descriptor(&value).is_err());

    let mut value = descriptor();
    value.environment.push(value.environment[1].clone());
    assert!(encode_action_descriptor(&value).is_err());

    let mut value = descriptor();
    value.environment[0].name = "token".into();
    assert!(encode_action_descriptor(&value).is_err());

    let mut value = descriptor();
    value.executable_path = "samtools".into();
    assert!(encode_action_descriptor(&value).is_err());
}

#[test]
fn unknown_nested_and_top_level_fields_fail_closed() {
    let bytes = encode_action_descriptor(&descriptor()).unwrap();
    let Value::Map(mut fields) = from_slice(&bytes).unwrap() else {
        panic!("descriptor must be a map");
    };
    fields.insert(99, Value::Text("unknown".into()));
    assert!(decode_action_descriptor(&to_vec(&Value::Map(fields)).unwrap()).is_err());

    let bytes = encode_action_descriptor(&descriptor()).unwrap();
    let Value::Map(mut fields) = from_slice(&bytes).unwrap() else {
        panic!("descriptor must be a map");
    };
    let Some(Value::Array(environment)) = fields.get_mut(&6) else {
        panic!("environment must be an array");
    };
    let Value::Map(first) = &mut environment[0] else {
        panic!("environment binding must be a map");
    };
    first.insert(9, Value::Text("unknown".into()));
    assert!(decode_action_descriptor(&to_vec(&Value::Map(fields)).unwrap()).is_err());
}
