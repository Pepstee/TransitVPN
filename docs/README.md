# TransitVPN

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
