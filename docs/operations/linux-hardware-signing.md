# Linux hardware signing operations

This runbook records the operator boundary proposed by
[ADR 0024](../adr/0024-linux-hardware-signing-providers.md). It is not an
activation procedure. Do not install tools, change device permissions,
provision keys, or enable a production signer until specialist review accepts
the ADR and the chosen provider implementation is qualified.

## Deployment matrix

| Authority host | Supported direction | Required qualification |
| --- | --- | --- |
| Physical host with TPM2 | Local TPM2 provider | TPM/TSS versions, device access, provisioning, restart, lockout, replacement |
| VM with vTPM | TPM2 only after explicit approval | Snapshot, clone, rollback, migration, hypervisor trust, duplicate-key exclusion |
| Host or VM with local/passed-through HSM | PKCS#11 provider | Module digest, device path, token/key identity, mechanism, session and restart behaviour |
| Host using network HSM | PKCS#11 provider | Module plus network trust, availability, credential delivery, recovery |
| Jenkins/DASObjectStore worker only | No signer | Proof that only verified Monas context is consumed |
| Authority host with no accepted provider | Unsupported | Production authority remains disabled |

TPM2-first and PKCS#11-second describe implementation order. They are not a
runtime fallback order.

## Preflight evidence

Read-only discovery may record:

- operating-system and kernel version;
- presence of TPM resource-manager or HSM device nodes;
- provider library and package versions;
- configured service identity and coarse access result;
- supported P-256/ES256 mechanism;
- public provider identity suitable for later comparison; and
- whether the host is physical, virtual, or a keyless worker.

Do not change groups, udev rules, systemd units, TPM ownership, HSM tokens,
slots, keys, PINs, or provider state during preflight. Do not infer production
support from a device node alone.

## Provisioning gate

The reviewed provider command must:

1. require an explicit provider and configuration;
2. create or reopen one non-exportable P-256 key;
3. reject ambiguous or mismatched existing keys;
4. emit only the canonical public key, Pistis key identifier, and a redacted
   provider locator;
5. verify a test signature locally against that public key; and
6. produce an operator record containing no authorisation value.

The public identity is enrolled through the accepted installation-trust
process. A discovered replacement key is never trusted automatically.

## Service activation

The authority service starts only when:

- exactly one provider is configured;
- its pinned implementation and packages match the qualified record;
- the expected public key and key identifier match;
- least-privilege device/module access succeeds;
- a bounded readiness signature verifies locally; and
- Prosopikon and Monas authority configuration is otherwise complete.

Any mismatch fails before the public authentication route begins listening.
Provider loss after startup makes new signing unavailable and never selects
another provider.

## Rotation and recovery

Retain the public identity, provider configuration shape, package provenance,
revocation record, and audit evidence. Never back up private-key material,
PINs, authorisation values, or live provider sessions.

For TPM clear, HSM loss, key mismatch, untrusted VM clone/rollback,
unrecoverable lockout, or device replacement:

1. disable signing;
2. revoke the old installation key and invalidate affected sessions;
3. investigate and retain redacted incident evidence;
4. provision a new non-exportable key;
5. enrol its public identity through the approved trust ceremony; and
6. re-run native provider and end-to-end qualification.

## Jenkins evidence

The authoritative dossier pins the source revisions, lockfiles, provider
packages/modules, public identity, host class, test commands, and redacted
results. Hardware-gated tests run on an enrolled native authority candidate.
Ordinary build agents remain keyless. No production private key, PIN,
authorisation value, or reusable provider credential enters Jenkins.
