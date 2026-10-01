# TransitVPN

## Local use

The registered development source is on ArtVault at
`/srv/artvault/projects/transitvpn/workspace`. In an environment where the package is installed,
run `transitvpn --help` for the available commands. No public TransitVPN endpoint is currently
provisioned.

TransitVPN generates a matched Xray client/server pair for VLESS over REALITY RAW. It pins Xray
**26.7.11** and refuses to write either configuration unless that exact executable accepts both
with its native config test. The non-secret identity record contains only the version and
SHA-256 digest of the executable.

## Generate a deployment

Choose and verify a suitable REALITY target from the eventual server network: it must be reachable,
negotiate TLS 1.3 for the chosen SNI, and be deliberately assessed for the deployment. Arbitrary
popular sites, Microsoft, and CDNs are not safe defaults. Then install the pinned Xray release and
run:

```console
transitvpn bootstrap \
  --host vpn.example.net \
  --target verified-target.example:443 \
  --server-name verified-target.example \
  --target-verified \
  --xray-binary /usr/local/bin/xray
```

This creates `state/xray-server.json`, `state/xray-client.json`, and `state/xray-identity.json`
with mode 0600. Each run creates a new UUID, X25519 key pair, and non-empty 16-hex-character short
ID. `state/` is ignored by Git. Use `--dry-run` to perform the same generation and real-binary
validation without persisting secrets.

## Export an offline client profile

After `bootstrap` has created `state/xray-client.json`, run the export command from that same
workspace. Choose a new private destination directory:

```console
umask 077
mkdir -m 700 "$HOME/transitvpn-export"
transitvpn export-profile --output "$HOME/transitvpn-export/client.vless"
```

Export is offline: it reads the generated client configuration and does not contact a provider or
remote service. The output file is created exclusively with mode 0600; a new immediate parent
directory is created with mode 0700 when needed. Existing output files, symlinks, non-private
parents, and unsupported configurations are refused. The command prints only a generic success or
error message.

The share URI represents one VLESS peer using RAW/TCP over REALITY, including the UUID, server,
port, REALITY public key, SNI, fingerprint, short ID, and supported flow. Treat the exported file as
a credential. Transfer it only through a trusted private channel and remove it securely when no
longer needed. The URI does not encode custom DNS, routing, or application policy. Configure those
in the receiving client; this export does not establish DNS leak protection or prove that a Mac or
phone application imported the profile successfully.

## Local checks and limits

`status` reports whether the managed process appears live; it does not verify HTTP tunnel health.
`health --url http://...` sends an HTTP request through the configured local SOCKS client and
reports the observed response. It does not check process liveness or fall back to a direct request.

`certify-local-tunnel` validates the pinned Xray binary and exercises a local plain VLESS RAW
loopback HTTP path. The exported-profile acceptance also reconstructs the URI into an Xray client
configuration and exercises a local REALITY loopback HTTP path with a wrong-key negative control.
These local fixtures do not demonstrate a public endpoint, remote DNS behavior, phone/Mac app
import, or reachability in Beijing.

REALITY can make classification harder in some conditions; it does not make traffic
indistinguishable or guarantee availability on any network. No automatic Shadowsocks fallback is
implemented. Standalone Shadowsocks and WireGuard have classifiable traffic patterns and are not
represented as censorship-resistant recovery. Until an independent endpoint is provisioned and
tested, recovery remains unprovisioned.

Never publish, log, commit, or reuse files in `state/`; they contain long-term credentials. Rotate
by generating a new deployment, validating both peers, distributing the new client file through a
secure channel, and then removing the old UUID/short ID from the live server.
