# Attended Mac connection approval

This screen consumes the existing adopted INT-07 Mac Pending contract. It adds
no URL-derived trust, new signing purpose or replacement enrolment. The current
app identity is Pistis iOS 0.28.0, build 75; allocation is Kanon PR801.

Use the retained trusted installation in Installations, choose Approve pending
Mac connection, and open the exact Pending record produced by the native Mac
client. Review its installation, stream and expiry, then perform the separate
Face ID approval. Keep the app in the foreground. The original short deadline
is inherited; do not renew it by reconnecting, replacing the record or retrying
an uncertain bind. Cancellation or any mismatch denies completion.

The app submits through the enrolled pinned SiteRoot endpoint and held native
session. Main must independently match the same Root, Mac stream and complete
Pending bytes and consume the binding once. A matching receipt is a comparison
result, not a substitute for server authority or installed package admission.

Simulator tests use synthetic records and cannot establish physical Face ID,
device enrolment, production release signing or actual installed full-flow
acceptance. Preserve existing keys and enrolments; never reset them to qualify
this screen.
