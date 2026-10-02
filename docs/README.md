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

For a local-only deployment, bootstrap can bind the server and choose the peer and client SOCKS
ports explicitly. These values are also written into the matching client configuration:

```console
transitvpn bootstrap \
  --host 127.0.0.1 \
  --listen 127.0.0.1 \
  --port 18443 \
  --socks-port 18080 \
  --target verified-target.example:443 \
  --server-name verified-target.example \
  --target-verified \
  --xray-binary /usr/local/bin/xray
```

`--listen` accepts an IPv4 or IPv6 literal. When omitted, the server listener behavior remains
unchanged. Ports must be in the range 1–65535; the client SOCKS listener remains loopback-only.

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

## Import a client profile

On the machine that should run the tunnel client, import an exported profile through the
product's own user-facing route:

```console
umask 077
mkdir -m 700 client-work
cd client-work
transitvpn import-profile --input /secure/channel/client.vless --socks-port 10808
```

Import reads one regular profile file (`--input`, mode 0600, no final-component symlink). The
implementation does not enforce private permissions on the input's parent directory. It
strictly accepts only the exact VLESS RAW/TCP REALITY share format produced by
`export-profile`: the fixed `security=reality`, `encryption=none`, `type=tcp` transport plus the
UUID, REALITY public key, SNI, fingerprint, short ID and the supported flow. Duplicate, unknown
or malformed fields, any unsupported transport, and arbitrary third-party share formats are
refused with a fixed generic error. The credential-bearing URI is never accepted on the command
line and never printed or logged.

The command reconstructs the client configuration, validates it with the pinned Xray binary
(`--xray-binary`, default `TRANSITVPN_XRAY_BIN` or `xray`), and writes it privately as
`state/xray-client.json` (mode 0600) with a loopback-only SOCKS listener on `--socks-port`
(default 10808) and exactly one proxy outbound; there is no direct fallback outbound. An
existing `state/xray-client.json` is never overwritten by default. The input profile file
is not modified.

To deliberately refresh a stopped client, first run transitvpn down --client, then import the new
profile with --replace. Replacement is permitted only for an existing private regular single-link
config inside a private state directory, and refuses if any state/tunnel-client.pid filesystem
entry remains (including a dangling symlink). It validates the new profile with pinned Xray
before staging a private same-directory file and atomically replacing the old config. Validation
and pre-commit write failures preserve the previous config. If the lifecycle record remains, run
down --client successfully before retrying; status alone does not authorize replacement.

## Managed client lifecycle

The server and the imported client are two managed roles with separate state:

```console
transitvpn up              # start the server tunnel from state/xray-server.json
transitvpn up --client     # start the client tunnel from state/xray-client.json
transitvpn status          # server process status
transitvpn status --client # client process status
transitvpn down            # stop the server tunnel (record: state/tunnel.pid)
transitvpn down --client   # stop the client tunnel (record: state/tunnel-client.pid)
```

Both roles use the same pidfd-bound ownership checks and never overwrite each other's process
records. Starting a role whose config file is missing or invalid fails safely without touching
the other role. `health --url http://...` sends its request through the imported client's
configured loopback SOCKS listener. To stop everything, run `down --client` and then `down`.
Recovery after a crash is `down --client` (or `down`) followed by `up --client` (or `up`).

## Foreground Linux service

`serve` validates the selected config with pinned Xray, starts one verified tunnel process, and
stays in the foreground. Run it under a Linux user service manager with restart-on-failure; the
foreground command exits unsuccessfully if its tunnel child exits unexpectedly and stops only its
verified child when the manager requests a stop. This local transient service procedure does not
install a persistent unit or enable boot/login startup:

```console
set -eu
TRANSITVPN_SOURCE=/absolute/path/to/TransitVPN
TRANSITVPN_WORKDIR=/absolute/path/to/private/server-workdir
TRANSITVPN_PYTHON=/absolute/path/to/python
PINNED_XRAY=/absolute/path/to/pinned/xray
systemd-run --user --unit=transitvpn-local --collect \
  --property=WorkingDirectory="$TRANSITVPN_WORKDIR" \
  --property=Restart=on-failure --property=RestartSec=1s \
  --property=RuntimeMaxSec=1h \
  --property=StartLimitIntervalSec=30s --property=StartLimitBurst=5 \
  --property=StandardOutput=null --property=StandardError=null \
  --setenv=PYTHONPATH="$TRANSITVPN_SOURCE" \
  --setenv=TRANSITVPN_PROXY_BIN="$PINNED_XRAY" \
  --setenv=TRANSITVPN_XRAY_BIN="$PINNED_XRAY" \
  "$TRANSITVPN_PYTHON" -m transitvpn serve
systemctl --user stop transitvpn-local.service
```

The bounded transient service canary exercises local crash recovery only. Boot/login persistence
and the complete installation, upgrade, and rollback route remain unfinished.

## Private configuration backup and restore

The primary deployment's `state/` contains long-term credentials. Use only the explicit
private two-file workflow below; do not copy the repository, runtime, PID files, logs or
other state. Choose a new backup directory under an existing private parent. The product
requires the parent and backup directory to be owned by the current user with mode 0700,
creates backup files with mode 0600, refuses symlinks or an existing destination, and
copies only `xray-server.json` and `xray-client.json`.

Create the private parent once. For each backup, use a new absolute destination path, stop the
imported client in its existing client work directory, then stop and back up the primary server
from its server work directory:

```console
set -eu
umask 077
# One-time setup for this private backup parent:
mkdir -m 700 "$HOME/transitvpn-backups"
# If it already exists, verify owner and mode 0700; do not rerun mkdir.
SERVER_WORKDIR=/absolute/path/to/server-deployment
CLIENT_WORKDIR=/absolute/path/to/existing-imported-client
BACKUP="$HOME/transitvpn-backups/$(date -u +%Y%m%dT%H%M%SZ)"
( cd "$CLIENT_WORKDIR" && transitvpn down --client )
( cd "$SERVER_WORKDIR" && transitvpn down && transitvpn config-backup --destination "$BACKUP" )
```

For recovery after both server configuration files are absent, explicitly choose the absolute
path of a trusted private backup in this recovery shell. Stop the existing imported client and
server through their respective product work directories. Restore and start the server there;
then start and check the unchanged imported client profile in its existing client work directory:

```console
set -eu
SERVER_WORKDIR=/absolute/path/to/server-deployment
CLIENT_WORKDIR=/absolute/path/to/existing-imported-client
BACKUP=/absolute/path/to/trusted/private/backup
PINNED_XRAY=/absolute/path/to/pinned/xray
( cd "$CLIENT_WORKDIR" && transitvpn down --client )
( cd "$SERVER_WORKDIR" && transitvpn down && transitvpn config-restore --source "$BACKUP" --xray-binary "$PINNED_XRAY" && transitvpn up )
( cd "$CLIENT_WORKDIR" && transitvpn up --client && transitvpn health --url http://127.0.0.1:PORT/health )
```

Restore does not import a new client profile or alter the existing imported-client directory.

Restore refuses any `tunnel.pid` or `tunnel-client.pid` filesystem entry and refuses to
overwrite either existing config. It accepts exactly the two private regular single-link
files, validates both with the byte-pinned Xray executable before writing, restores mode
0600, and compares the restored bytes with the backup. The two-file restore is not an
atomic transaction: an interruption between file writes can leave one config restored;
inspect `state/` before retrying. The command prints only a generic result.

The directory is trusted storage for reusable long-term credentials. In-process SHA-256
comparisons detect copy changes; they do not authenticate an untrusted backup. Protect the
backup location and restore only a backup whose provenance you trust. Restoration reuses
the credentials in that backup; an older backup can re-enable revoked client identities.
If credentials may be compromised or revoked, generate a new deployment, distribute its
client profile through a secure channel, and retire the old UUID/short ID instead of
restoring those credentials. Never publish, log, commit or make ad hoc backups of `state/`;
this explicit private workflow is the supported backup/restore exception.

## Current evidence scope

The pinned-Xray acceptance test exercises the whole local workflow through product entrypoints:
server `up`, `export-profile`, `import-profile` into a private client state directory, client
`up --client`, a real HTTP request through the client's SOCKS listener via the `health` CLI with
responder evidence, private two-file config backup, simulated config loss, refusal to start
with missing state, pinned-Xray validation and restoration, continued HTTP with the unchanged
imported client config, and final `down` of both roles. All listeners are on 127.0.0.1 and the
REALITY target is a locally generated TLS 1.3 fixture, so this is a loopback proof only.
External endpoint reachability, phone or Mac app import, DNS leak guarantees, and reachability
from Beijing are unverified. The profile carries the supported peer settings only, not
arbitrary DNS or routing policy.

## Opt-in Internet egress canary

`tests/test_internet_egress_canary.py` is skipped by default so offline test runs stay
offline; a skipped canary is never treated as passed. To authorise its bounded remote
requests, set `TRANSITVPN_EGRESS_CANARY=1` and run the test with the pinned Xray binary:

```console
TRANSITVPN_EGRESS_CANARY=1 pytest tests/test_internet_egress_canary.py
```

The opted-in canary keeps the managed server inbound, the imported client SOCKS listener
and the fresh TLS 1.3 REALITY cover fixture on IPv4 127.0.0.1. It sends two bounded,
unauthenticated `GET https://example.com/` requests on TCP 443 through the imported
client's loopback SOCKS listener with an ordinary `curl` client, using `socks5h` and
certificate verification, with no redirects or POSTs. The first and the post-restart
request must both return HTTPS 200; an intervening request while the server is down must
fail while the client remains live. Fixture routing sends only `full:example.com` TCP
443 to a uniquely tagged IPv4 freedom outbound and sends all other routed traffic to a
blackhole outbound. No public or LAN listener is opened. It does not demonstrate remote
VPN ingress, phone or Mac import, DNS leak guarantees, or reachability from Beijing.

## Local checks and limits

`status` (server) and `status --client` (imported client) report whether the managed process appears live; they do not verify HTTP tunnel health.
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

Never publish, log, commit, or make ad hoc backups of files in `state/`; they contain long-term
credentials. The private `config-backup` and `config-restore` procedure above is the only supported
backup/restore path. Restoration reuses credentials from a trusted backup. To rotate, create a
new deployment, validate both peers, distribute the new client file through a
secure channel, and remove the old UUID/short ID from the live server.
