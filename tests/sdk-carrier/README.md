# Selected SDK importing consumer

This independent development manifest imports all four actual package sources;
it does not copy their modules or provide an authority context. Its fixture
check uses retained public canonical/signature bytes and the real verifier,
COSE framing and protocol API. It is not a native producer or a replacement
for the existing component unit/integration/negative tests and example.

The genuine native Cargo-generated lock is tracked. Its accepted SHA-256 is
add65165f00db9a80e723056e85fd2bcde957cea39629387414c7b90bae4ef64.
All external identities and checksums match the accepted root lock; its
normalised dependency edges are a subset because this consumer selects fewer
features. Only crypto-bigint 0.7.10 is present in this carrier.

Compilation and execution of this carrier remain pending. The maintained Alma
route must compile/run the importing consumer and the original component tests
and example, then retain MSRV, strict and current security results for their
exact graphs. Do not hand-edit resolver output. Whole-Pistis Monas/API 0.86
remains an uncleared graph with crypto-bigint 0.5.5. A selected carrier lock
cannot establish whole-workspace, Core, Prox or Thes acceptance.
Use a complete tracked checkout with the existing fixtures when qualifying;
sparse source authoring is not the qualification input.
