#!/bin/sh
# Production iOS source must not contain deployment-specific operator or host
# identity. Test fixtures may use concrete hosts; the shipped app sources may
# not.

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sources="$root/ios/PistisApp/Sources"

if rg -n --glob '*.swift' \
    '192\.168\.(0\.193|1\.192)|sagrudd|stephen|Synoptikon Berlin|Provider user 184203|7A31 9C42 0F88 1B6D' \
    "$sources" >/dev/null; then
    echo 'host-agnostic app contract: deployment-specific identity found in production sources' >&2
    exit 1
fi

rg -F 'ProductionMonasSiteRootTransportFactory.make()' \
    "$sources/App/PistisApp.swift" >/dev/null
rg -F 'MonasSiteRootGenesisBrokerTransport' \
    "$sources/Platform/MonasSiteRootDelegationTransport.swift" >/dev/null

echo 'host-agnostic app contract: OK'
