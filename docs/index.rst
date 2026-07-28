Pistis documentation
====================

Pistis is a local-first cryptographic identity, authentication, approval, and
portable-evidence system. These pages are the rendered documentation authority
for the project.

Project and delivery
--------------------

.. toctree::
   :maxdepth: 2

   README
   PROJECT_CHARTER
   MVP_RELEASE_CANDIDATE
   MILESTONE
   TODO
   BOOTSTRAP
   BOOTSTRAP_STATUS

Development
-----------

.. toctree::
   :maxdepth: 2

   development/README
   development/code-structure
   development/fuzzing
   development/provider-conformance
   development/ios
   development/android
   development/synoptikon
   development/monas
   development/cli-authentication
   development/local-agent
   development/discovery
   development/discovery-implementation-evaluation
   development/device-lifecycle
   development/security-hardening
   development/release-packaging
   development/issue-model
   development/jenkins-ci
   development/documentation

Architecture and operations
---------------------------

.. toctree::
   :maxdepth: 2

   adr/README
   adr/0000-template
   adr/0001-canonical-encoding
   adr/0002-signature-suites
   adr/0003-github-trust-enrolment
   adr/0004-google-trust-enrolment
   adr/0005-device-registry-storage
   adr/0006-qr-authentication-reference-flow
   adr/0007-ios-reference-application
   adr/0008-android-reference-application
   adr/0009-synoptikon-integration-boundary
   adr/0010-monas-standalone-integration-boundary
   adr/0011-local-discovery-and-direct-exchange
   adr/0012-recovery-revocation-and-multi-device-lifecycle
   adr/0013-security-assurance-and-independent-review
   adr/0014-release-packaging-and-provenance
   adr/0015-cli-native-authentication
   adr/0016-exact-action-approval-protocol
   adr/0017-local-authentication-agent
   adr/0018-production-cose-sign1-profile
   adr/0019-mvp-signed-message-schemas
   adr/0020-prosopikon-pistis-authority-transaction
   adr/0021-production-qr-envelope-and-installation-trust
   adr/0022-host-owned-cli-agent-authority-port
   adr/0023-authenticated-mobile-enrolment-exchange
   protocol/README
   protocol/domain-model
   protocol/action-approval
   protocol
   crypto
   encoding
   assurance
   security/README
   operations/README
   operations/device-registry
   operations/github-enrolment
   operations/google-enrolment
   operations/mobile-enrolment
   operations/qr-authentication
   operations/ios
   operations/android
   operations/synoptikon
   operations/monas
   operations/discovery
   operations/device-lifecycle
   operations/security-hardening
   operations/release-packaging
   operations/cli-authentication
   operations/local-agent
