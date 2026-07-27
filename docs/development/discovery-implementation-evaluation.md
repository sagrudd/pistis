# Discovery implementation evaluation

This report closes the implementation-selection outcome of PIS-E11-F01-T01.
It selects platform adapters without changing the untrusted-discovery boundary
in ADR 0011.

## MVP product decision

The MVP requires no QR scan for a previously paired installation when the user
opens Pistis and visits nearby pending requests. Browsing is foreground,
explicit, bounded, and cancelled on dismissal, backgrounding, network change,
or deadline. Closed-app notification is deferred. No dedicated notification
server, cloud relay, public DNS publication, or continuous background scan is
introduced.

## Selected adapters

| Surface | Selection | Rationale |
| --- | --- | --- |
| iOS | Network.framework/Bonjour | Native permission and lifecycle behavior; declares the exact Bonjour service and local-network purpose. |
| Android | `NsdManager` | Native DNS-SD/mDNS discovery, network association, callbacks, and evolving local-network permission behavior. |
| Rust host | pinned `mdns-sd` behind a Pistis port | Safe Rust, no imposed async runtime, publication and browse support, conflict handling, and monitorable daemon lifecycle. |

The Rust dependency is linked only into `pistis-discovery`, not protocol,
authentication, or mobile core crates. Version `0.20.2` is pinned exactly and
locked. The crate is dual MIT/Apache-2.0 licensed, declares MSRV 1.71, forbids
unsafe code in its library, and supplies probing, announcements, goodbye
records, conflict events, and daemon shutdown. Its transitive graph is retained
by Jenkins dependency evidence and remains subject to the repository advisory,
license, and source gates.

The portable `WireAdvertisement` projection is implemented independently of
the selected library. It emits the exact service type, random instance name,
closed TXT set, and bounded publication lifetime accepted by ADR 0011. This removes raw string
construction from future platform adapters but is not itself network
publication. PIS-E11-F01-T02 adds the host publication owner: it accepts only
explicit private, link-local, or IPv6 unique-local addresses; uses an opaque
random hostname rather than the machine hostname; and unregisters at expiry,
conflict, backend failure, or owner cancellation.

The negative prototype found that `mdns-sd` does not expose per-service DNS
record TTL setters. Pistis therefore treats the 30-second value as the
authoritative publication lifetime and performs a graceful unregister at that
deadline. Normal unregister sends goodbye records. If the process crashes,
peer DNS caches can retain an opaque instance/endpoint record for the library's
RFC-default cache TTL; that stale record has no authority and the endpoint
ceremony rejects it after expiry. This residual availability/privacy behavior
must be included in physical-network acceptance and must not be represented as
a 30-second DNS cache TTL.

## Alternatives

`simple-mdns` is not selected because its one-shot/responder-oriented surface
does not reduce native mobile lifecycle work. `agnostic-mdns` is not selected
because its runtime abstraction and larger integration surface are unnecessary
for the small host advertiser. Raw UDP/DNS implementation is rejected because
Pistis must not invent a network protocol parser. Phone advertisement is
rejected because it exposes device presence and reverses the privacy model.

## Platform findings

Apple Bonjour provides local service publication and discovery. The app must
declare the browsed Bonjour service and local-network usage explanation.
Android NSD is asynchronous and based on DNS-SD over mDNS; discovery must be
stopped when no longer required. Android permission and multicast behavior
varies by platform and SDK-extension level, so capability checks belong in the
native adapter rather than shared protocol code.

Primary references:

- [Apple Bonjour](https://developer.apple.com/documentation/foundation/bonjour/)
- [Apple Bonjour overview](https://developer.apple.com/bonjour/)
- [Android NsdManager](https://developer.android.com/reference/android/net/nsd/NsdManager)
- [Android NSD guide](https://developer.android.com/develop/connectivity/wifi/use-nsd)
- [`mdns-sd` 0.20.2 documentation](https://docs.rs/mdns-sd/0.20.2/mdns_sd/)
- [`simple-mdns` documentation](https://docs.rs/simple-mdns/)
- [`agnostic-mdns` documentation](https://docs.rs/agnostic-mdns/)

## Acceptance and remaining work

Evaluation plus the bounded Rust advertiser and strict Rust browser are
complete. This does not claim native mobile browse, authenticated channel, or
physical-device interoperability. PIS-E11-F01-T04 and T05 remain open until
their code, negative cases, operations documentation, and native/network
evidence pass.
