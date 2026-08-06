# Monas-owned Pistis provider Debian package

The Pistis-to-Monas integration does **not** supply an independently runnable
Pistis provider daemon or a second browser-session authority.  `pistis-monas`
is a framework-neutral contract.  Monas owns the Linux service account,
configuration, service lifecycle, browser session, and the sole Jenkins
authority endpoint:

```text
/run/mnemosyne-pistis/jenkins-authority.sock
```

This ownership preserves ADR 0010: a Pistis package must not start a competing
service, create a socket, issue a host session, or substitute a local
credential.  The endpoint appears only after the reviewed Monas provider has
validated its protected configuration, Site Trust, custody and Pistis evidence.

## Required Monas package boundary

The `monas` Debian archive is the smallest provider lifecycle artifact.  It
must contain:

- `lib/systemd/system/monas-pistis.service`, running as
  `mnemosyne-monas`, with `mnemosyne-pistis-jenkins` as its supplementary peer
  group, `UMask=0007`, and a narrow runtime write path;
- `usr/lib/tmpfiles.d/monas-pistis-runtime.conf`, which declares
  `/run/mnemosyne-pistis` as mode `2770` owned by
  `mnemosyne-monas:mnemosyne-pistis-jenkins`; and
- a non-activating maintainer script.

The archive must not contain `jenkins-authority.sock`.  Package installation
must not enable, start, restart, or hand-create the provider.  Until an
attended Monas activation validates every accepted runtime prerequisite, the
socket remains absent and Jenkins remains disabled.  There is no fallback
socket, local password, PAM path, or Pistis-owned substitute service.

The contract does not grant authority merely because a service account or
runtime directory exists.  The service must still verify peer credentials for
every authority request, and Monas/Prosopikon remains responsible for the
durable completion transaction and browser session.

## Packaging validation

Run the credential-free content gate against a prospective Monas archive:

```sh
./deploy/deb/validate-monas-pistis-provider-deb.sh monas_VERSION_ARCH.deb
```

It validates only package contents and refuses activation.  The fixture suite
is run with:

```sh
./deploy/deb/test-monas-pistis-provider-deb-contract.sh
```

Passing this gate is necessary but insufficient for production readiness.  It
does not establish Site Trust, Thesaurophylax custody, iPhone attestation,
Pistis verification, a Monas session, or Jenkins execution.
