Current SiteRoot phone preparation v1
====================================

The fixed ``/auth/pistis/v1/issuer-site-root/current`` POST uses the existing
own native AuthenticateSession profile, exact enrolled HTTPS origin/pin and
``application/cbor`` without cookies. Its request is closed array4
``[1,b"issuer-site-current-prepare-v1",freshPhoneNonce32,currentSiteKeyDigest32]``.
The reply is the existing mode2 readiness array14, whose challenge equals the
phone nonce. Existing R2 Arm/Signature/task/terminal bodies do not change.

Owner evidence is closed array7
``[1,b"issuer-site-current-owner-evidence-v1",fullSignedIADM,fullJointOriginal4,
fullScope16,actualIssuerRevocationRevision,keyState1or2or3]``. These are complete
comparison originals, not a portable owner. The server may emit them only from
the actual independently current Site permission, admitted W/native operation
and current issuer revocation/state selection. Issuer revision is not a Core
binding/session counter. A private producer must freshly recheck all owners at
Arm, PRE, protected read and POST; parsed evidence alone never appoints them.

The phone checks both installation and own AUTHN signatures of the full joint
approval at its actual signed attendance time, including its exact closed
joint-only descriptor. It then checks current grant expiry, own current native
session policy/revocation coordinates and independently retained enrolment.
The Site public key must match the current convergence ACK target digest, and
the complete IADM must verify under that Site key. Full Scope16 and readiness
Site/installation/authority/epoch/W identities must agree. The current initial
W generation is supported; a later generation requires its genuine transition
history rather than relabeling initial IADM.

The private handoff is created only by the fixed actual native authentication
and proof-verification pipeline. Its lifecycle fence starts before preparation
and covers display, FaceID and delivery, with nondecreasing wall observations
and current enrolment/ACK checks. Cancel/background is terminal. After
FaceID the existing SiteRoot signer, with no key creation, emits PRE and POST
under one original two-second end. Signed envelopes remain DATA. The actual
Thes native read owns the protected read between them.

No owner, query, permission lease or two-second server budget is retained across
phone display. The server PUBLIC-DATA mailbox is outside the Controller lock
so an actual J read can wait for the phone without blocking HTTP delivery.
The native thread retains the genuine owners and validates all expected facts
before using the mailbox. This protocol does not bootstrap expired HTTPS or
authorise certificate maintenance, and provides no TLS exception.
