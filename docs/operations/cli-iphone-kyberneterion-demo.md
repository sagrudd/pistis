# CLI, iPhone, web QR, and workflow-selection demonstration

This is the bounded demonstration contract for the funding-review path. It is
safe to run with the checked-in fixtures, but it is **not** a production
authentication claim. The machine-readable shape is
[`fixtures/demonstration/cli-iphone-kyberneterion-v1.json`](../../fixtures/demonstration/cli-iphone-kyberneterion-v1.json).
Its `verdict` remains `not_run` until a clean, pinned cross-repository
Expedition has retained the evidence.

## What the audience sees

1. An administrator creates the immutable Prosopikon user and starts the
   first-device ceremony. The terminal receives the invitation through a
   protected pipe:

   ```console
   pistis enrolment present --stdin
   ```

   The CLI enters an attended alternate screen and renders a QR. It shows only
   the installation, HTTPS origin, three trust words, and expiry; it never
   prints the raw `PISTIS1:` transfer or an invitation secret.
2. The user opens Pistis on an iPhone, scans the QR, checks the origin and
   trust words, and confirms with Face ID or the device passcode. The app
   verifies the authority descriptor and exact registration before one
   Keychain/Secure Enclave update. The device private key does not leave the
   phone.
3. The user opens the Monas web shell. Monas displays a fresh audience-bound
   login QR. The same iPhone signs only the displayed `monas:web` request; the
   response is consumed once and only then is the browser session issued.
4. In Kyberneterion, the user selects `bioinformatics.rnaseq.v1`. The product
   supplies the exact action descriptor to Pistis. The phone displays the
   ordered command, resource references, workflow audience, and expiry before
   approval. A generic Monas login cannot authorise this action.

The approved action is represented by the exact command below. This is an
illustrative workflow selection and must not be executed against production
data from this repository:

```console
pistis auth exec -- /usr/bin/nextflow run rnaseq.nf --input das://demo/input
```

The action digest is calculated from the ordered argument vector and the
versioned exact-action descriptor. Kyberneterion, not the browser, owns the
workflow selection; Pistis owns the human approval; Monas owns the audience
session; downstream products must use the resulting evidence references.

## Demo safety and negative cases

The checked-in fixture uses no provider, signing, XCP-ng, Kubernetes, object
store, or Jenkins credentials. Keep `verdict: not_run` and
`live_credentials_used: false` until the governed Expedition has run. A
response, challenge, registration envelope, cookie, capability, or private
key must never be copied into a slide, issue, terminal log, or screenshot.

Run the negative cases alongside the happy path:

- replay the response;
- change the Monas or Kyberneterion audience;
- revoke the iPhone device;
- advance beyond the challenge expiry; and
- substitute one workflow argument or output reference.

Every case must stop before a Monas session, workflow dispatch, Kubernetes
workload, or durable DASObjectStore mutation. Only the redacted failure
category and correlation identifier belong in the dossier.

## Evidence hand-off

The demo fixture is an input to the Jenkins/Expedition dossier. The retained
record must pin the Pistis, Prosopikon, Monas, Kyberneterion, DASObjectStore,
Oikodome, and Jenkins revisions, plus lockfile and fixture digests. It must
also include a redacted physical-iPhone observation for the scan, local user
verification, signed response, and Keychain update. Synthetic fixtures prove
the contract shape only; they do not replace that device observation.
