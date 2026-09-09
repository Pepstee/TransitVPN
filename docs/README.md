# TransitVPN

## ArtVault installation

The working source is `/srv/artvault/projects/transitvpn/workspace`; from the workspace run
`../.venv/bin/transitvpn --help`. All 670 tests passed on Mac and Linux. The pinned Xray loopback
certificate passed on both systems, but public REALITY deployment and recovery remain unprovisioned.

TransitVPN generates a matched Xray server/client pair for VLESS over REALITY RAW. It pins
Xray **26.7.11** and refuses to write either configuration unless that exact executable accepts
both with its native config test. The non-secret identity record contains only the version and
SHA-256 digest of the executable.

## Generate a deployment

First verify a suitable target from the eventual server network: it must be reachable, negotiate
TLS 1.3 for the chosen SNI, and be deliberately assessed for the deployment. Arbitrary popular
sites, Microsoft, and CDNs are not safe defaults. Then install the pinned Xray release and run:

```console
transitvpn bootstrap \
  --host vpn.example.net \
  --target verified-target.example:443 \
  --server-name verified-target.example \
  --target-verified \
  --xray-binary /usr/local/bin/xray
```

This creates `state/xray-server.json`, `state/xray-client.json`, and
`state/xray-identity.json` with mode 0600. Each run creates a new UUID, X25519 key pair, and
non-empty 16-hex-character short ID. `state/` is ignored by Git. Use `--dry-run` to perform the
same generation and real-binary validation without persisting secrets.

The client exposes a SOCKS proxy only on `127.0.0.1:10808`; it does not silently route around a
failed proxy. Configure application DNS and routing through that proxy according to the client
platform before treating it as leak-resistant.

## Limits and recovery

REALITY can make classification harder in some conditions; it does not make traffic
indistinguishable and cannot guarantee availability on any network. This configuration is locally
valid, not proof of external reachability or operation in Beijing. Those claims require endpoint
and field tests.

No automatic Shadowsocks fallback is implemented. Standalone Shadowsocks and WireGuard have
classifiable traffic patterns and are not represented as censorship-resistance recovery. Until an
independent endpoint is provisioned and tested, the recovery path is **unprovisioned**. Prepare and
test independent connectivity before travel rather than treating the same endpoint as redundant.

Never publish, log, commit, or reuse files in `state/`; they contain long-term credentials. Rotate
by generating a new deployment, validating both peers, distributing the new client file through a
secure channel, and then removing the old UUID/short ID from the live server.

## Migration reconciliation

The mapped Mac checkout at `86d19f2` is the canonical source. Its untracked temporary
files contain test/runtime artefacts and no source candidates; they remain on the Mac
and are excluded from migration. The standalone Shadowsocks configuration export
helper is retained alongside the existing URI helper. It does not enable automatic
fallback or claim censorship resistance. CGNAT detection and key generation remain
library capabilities; automatic CGNAT bootstrap integration and a keygen CLI are
not implemented. Old tests that relied on an implicit target
and empty short ID must use the explicit validated deployment contract.

The local tunnel certificate exercises plain VLESS RAW on loopback, not REALITY.
Real-binary configuration validation and a loopback pass do not establish a working
public REALITY deployment, DNS-leak protection or Beijing reachability. The current
status command checks process existence only. Persistent service installation,
upgrade/rollback, recovery endpoint provisioning and complete client setup remain
unimplemented. Runtime `up` starts a server and is not used as a migration smoke test.

The deterministic code index under `graphify-out` has a distinct machine-readable
navigation role; this document remains the owner of human-readable migration scope.

The pinned Xray release blocks private destinations by default. The temporary
loopback certificate grants TCP access only to its own `127.0.0.1/32` responder
and exact ephemeral port, resolving `localhost` to IPv4. Production deployment
configuration receives no such exception. Real application bytes passed this
certificate on both macOS ARM64 and ArtVault Linux x86-64.

For migration, certification runs on a tracked-source export so local runtime
artefacts are neither scanned nor transferred. Its child commands inherit that
source path even when their working directory changes. Historical assertions
about shell grep ordering are retired: the acceptance launcher now delegates to
Python, and retained subprocess tests verify the actual down/status behaviour.
