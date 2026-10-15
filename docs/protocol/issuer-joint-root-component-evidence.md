# INT-07 joint Root phone component evidence

This continues the reserved iOS 0.27.0 build 74 source batch from published
`8fd8c37a32165c138106ff5c9716a7be98c4cc3d`. It retains the actual own-session
credential through the existing-key ACK flow, validates the complete joint
permission descriptor and signature originals, obtains the prepared Site Root
handoff through the pinned native transport, and terminally cancels that handoff
after every exclusively owned confirmation attempt. It exposes a narrow request
encoder so the app can use the existing canonical wire without exposing the
generic internal CBOR encoder. No package, lock, Xcode or version input changed.

## Exact source and test evidence

The source was composed from all 662 verified S7 Git blobs, then the 27 reviewed
S8–S13 overlay rows and two reviewed compilation repairs. The resulting 669-file
map is SHA256 `5c033c9588839e21c1c78a220771296c06996ddbe8ae3e351d1415425136e010`.
All mapped files were verified before and after the final native run. The later
publication changes only this evidence note and the changelog.

On the Apple builder, 12 portable protocol cases passed on the composed source.
The additive public-wire vector/bounds case passed after the first compilation
repair. All 16 selected platform cases then passed with the unsigned simulator
app, including ACK lifecycle, native session/transport, fixed Site Root transport
and signature-invocation deadline tests. This is 29 distinct applicable passing
cases across 29 executions, with unchanged-family applicability across the two
repairs; it is not a fresh whole-phone suite or physical-device qualification.

The final platform process exited 0. Raw output SHA256:
`e7311a28a0c36d7c09f4f25c5bb917b25e30bcc7d336d8c2881bce07192236b7`.
The owned process group and simulator were verified absent. The temporary
simulator mapping was restored to its original default. Generated outputs and
retained evidence/caches together used 1,541,419,008 allocated bytes under the
same aggregate 8 GiB bound; free space was 50,370,375,680 bytes at completion.

Earlier failure history records two output-registration refusals before any
build. One has a retained raw failure receipt; the second is owner-reported in
the linked task history, with raw output unavailable. The first actual app
compile found an inaccessible internal encoder; the
next test-target compile found an asynchronous call in a synchronous assertion.
The narrow public encoder and explicit awaited negative test repair these
causes without changing wire semantics or weakening assertions. The final
unprovisioned simulator rejection proves rejection only; its test name does not
establish independent instrumentation of key non-invocation.

The raw final recipe's portable-applicability prose labels the additive case
SC1_R2 because of a label replacement. The actual process receipts show that
case executed in SC1_R1; SC1_R2 ran only platform tests. This correction is
retained without rewriting the raw receipt or inventing another execution.

## Remaining acceptance

The server must supply genuine current Site permission and the held W owner,
fresh Jenkins/query/observer authority, physical P/G3 and loaded Thes ownership,
and signed PRE/read/POST originals. Component tests do not supply those origins.
Final companion/Kanon binding, combined native qualification, supported release
checks, genuine Jenkins CI, applicable owner disposition and normal protected
merges remain required. No phone reinstall, physical Face ID, new trust, key
creation, live signing, installation, activation or INT-07 closure is established.
The Rust source selected for Pistis #526 remains a separate exact revision.
