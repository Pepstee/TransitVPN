# transitvpn

A self-hosted VPN manager built around **VLESS+REALITY** (primary) and **Shadowsocks-2022** (fallback), with automatic CGNAT detection and a documented VPS/relay escape path.

---

## One-command setup

```bash
pip install transitvpn && transitvpn bootstrap
```

`bootstrap` generates all key material, detects CGNAT, writes Xray and Shadowsocks server configs to `state/`, and prints connection URIs with QR codes.  Use `--dry-run` to preview without touching the network or writing any files:

```bash
transitvpn bootstrap --dry-run
```

---

## VLESS + REALITY (primary protocol)

[REALITY](https://github.com/XTLS/REALITY) is a TLS-masquerading transport used by VLESS that makes the VPN connection indistinguishable from ordinary HTTPS traffic to a chosen SNI target (e.g. `www.example.com`).

`bootstrap` generates a `state/xray-server.json` ready for [Xray-core](https://github.com/XTLS/Xray-core):

```json
{
  "inbounds": [{
    "protocol": "vless",
    "port": 443,
    "settings": { "clients": [{ "id": "<uuid>", "flow": "xtls-rprx-vision" }] },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "privateKey": "<reality_private_key>",
        "shortIds": ["<short_id>"],
        "serverNames": ["www.example.com"]
      }
    }
  }]
}
```

The matching client URI is printed after bootstrap:

```
vless://<uuid>@<server>:443?security=reality&pbk=<public_key>&sid=<short_id>&sni=www.example.com&fp=chrome&flow=xtls-rprx-vision#transitvpn
```

To regenerate key material without running a full bootstrap:

```bash
transitvpn keygen
```

---

## Shadowsocks-2022 fallback

When REALITY is blocked or the host is unreachable, clients fall back to **Shadowsocks** using the AEAD-2022 cipher suite (`2022-blake3-aes-256-gcm`), which offers authenticated encryption and replay protection without any TLS fingerprint.

`bootstrap` writes `state/ss-server.json` alongside the Xray config.  The Shadowsocks URI is also printed:

```
ss://2022-blake3-aes-256-gcm:<base64-password>@<server>:8388#transitvpn-ss
```

Run [sing-box](https://github.com/SagerNet/sing-box) or [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) against `state/ss-server.json` to activate the fallback listener.

Client-side: configure your client app with both the VLESS and Shadowsocks URIs; it will try VLESS first and fall back to Shadowsocks automatically.

---

## CGNAT self-check

Carrier-Grade NAT (CGNAT, RFC 6598 `100.64.0.0/10`) prevents inbound connections to your host, making direct VPN hosting impossible.  `bootstrap` runs this check automatically and warns you if it detects CGNAT:

```
cgnat: behind_cgnat
  local IP: 100.96.x.x
  public IP: unreachable
warning: host appears to be behind CGNAT — direct port forwarding may not work
```

The check works by:

1. Resolving the host's default-route local IP.
2. Fetching the public IP the internet actually sees, from `api.ipify.org` / `checkip.amazonaws.com` / `ifconfig.me`.
3. Asking the local router for its own WAN address over UPnP IGD (`GetExternalIPAddress`).
4. Deciding from the router's WAN address — the authoritative signal:
   - if the router's WAN IP is itself non-routable (RFC 1918 or `100.64.0.0/10`), **or**
   - if it differs from the public IP the internet sees,

   then a carrier NAT sits upstream of the router and **CGNAT is confirmed**. This catches the common case a naïve local-vs-public comparison misses: a CGNAT'd host still sees the carrier's *routable* egress IP, so only the router's WAN address reveals the upstream NAT. When the router will not report its WAN IP, the check falls back to inspecting the local and public addresses directly.

---

## VPS / relay fallback path

If CGNAT is detected (or the server is a home machine without a public IP), route traffic through a cheap VPS or relay node.

### Architecture

```
Client → VPS (public IP, port 443) → relay tunnel → Home server (CGNAT)
```

The relay hop is modelled by `RelayConfig` in `transitvpn/config.py`.  A relay listens locally (default `127.0.0.1:10808`) and forwards to the upstream `VlessConfig` or `ShadowsocksConfig`.

### Minimal relay setup on VPS

1. **Install Xray on the VPS** and configure an inbound on port 443 (VLESS+REALITY).
2. **Add an outbound** pointing at your home server's relay port (e.g. Shadowsocks-2022 on port 8388 via a persistent tunnel such as `autossh` or WireGuard).
3. **On the home server**, `bootstrap` generated `state/ss-server.json`; run the Shadowsocks daemon against it.

```
VPS inbound (VLESS:443) → VPS outbound (SS-2022:tunnel) → Home SS daemon (port 8388)
```

The relay configuration object:

```python
from transitvpn.config import RelayConfig, ShadowsocksConfig

relay = RelayConfig(
    name="vps-relay",
    listen_address="127.0.0.1",
    listen_port=10808,
    upstream=ShadowsocksConfig(
        server="<home-server-or-tunnel-ip>",
        port=8388,
        password="<ss_password>",
        method="2022-blake3-aes-256-gcm",
    ),
    tags=["cgnat-bypass"],
)
```

### Choosing a VPS

Any VPS with a publicly routable IPv4 address works.  Requirements: root/sudo, open TCP port 443, ~512 MB RAM.  Providers with monthly billing under USD 5 are sufficient.

---

## CLI reference

| Command | Description |
|---------|-------------|
| `transitvpn bootstrap` | Generate keys, detect CGNAT, write configs, print URIs |
| `transitvpn bootstrap --dry-run` | Same but skip network and skip writing state files |
| `transitvpn keygen` | Print new UUID, REALITY key-pair, and Shadowsocks password |
| `transitvpn up` | Start the Xray tunnel process from `state/xray-server.json` |
| `transitvpn down` | Stop the running tunnel process |
| `transitvpn status` | Report whether the tunnel process is running |

---

## Security notes

- REALITY private key and Shadowsocks password are generated with a CSPRNG and stored only in `state/` (gitignored).
- `2022-blake3-aes-256-gcm` provides AEAD encryption; the 2022 epoch prevents replay attacks older than the bootstrap timestamp.
- Never share `state/xray-server.json` or `state/ss-server.json`; they contain long-term secrets.
