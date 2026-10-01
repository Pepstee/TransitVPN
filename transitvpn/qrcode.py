"""URI generation helpers for explicitly supplied protocol configurations."""

import base64
import io
from urllib.parse import urlencode

import segno

from transitvpn.keygen import Keys

DEFAULT_FINGERPRINT = "chrome"
DEFAULT_FLOW = "xtls-rprx-vision"
DEFAULT_SS_METHOD = "2022-blake3-aes-256-gcm"


def make_vless_uri(
    keys: Keys,
    host: str,
    port: int,
    *,
    sni: str,
    short_id: str,
    fingerprint: str = DEFAULT_FINGERPRINT,
    flow: str = DEFAULT_FLOW,
) -> str:
    """Build a VLESS+REALITY share URI.

    Carries every parameter a client needs to complete a REALITY handshake:
    ``pbk`` (server public key), ``sni`` (serverName), ``sid`` (shortId),
    ``fp`` (TLS fingerprint) and ``flow``. Without these the link cannot
    establish a connection.
    """
    return make_vless_uri_from_fields(
        keys.vless_uuid,
        keys.reality_public_key,
        host,
        port,
        sni=sni,
        short_id=short_id,
        fingerprint=fingerprint,
        flow=flow,
    )


def make_vless_uri_from_fields(
    user_id: str,
    public_key: str,
    host: str,
    port: int,
    *,
    sni: str,
    short_id: str,
    fingerprint: str = DEFAULT_FINGERPRINT,
    flow: str | None = None,
) -> str:
    """Build a VLESS+REALITY URI from already validated peer fields."""
    if not sni or not short_id:
        raise ValueError("sni and short_id must not be empty")
    params = {
        "security": "reality",
        "encryption": "none",
        "type": "tcp",
        "pbk": public_key,
        "sni": sni,
        "sid": short_id,
        "fp": fingerprint,
    }
    if flow is not None:
        params["flow"] = flow
    uri_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"vless://{user_id}@{uri_host}:{port}?{urlencode(params)}"


def make_ss_uri(
    keys: Keys,
    host: str,
    port: int,
    *,
    method: str = DEFAULT_SS_METHOD,
) -> str:
    """Build a standalone SIP002 Shadowsocks share URI."""
    userinfo = base64.urlsafe_b64encode(
        f"{method}:{keys.ss_password}".encode()
    ).decode().rstrip("=")
    return f"ss://{userinfo}@{host}:{port}"


def render_qr(uri: str, *, border: int = 2) -> str:
    """Render ``uri`` as a scannable QR code for the terminal.

    Uses segno's ANSI reverse-video rendering (dark modules drawn as the
    terminal's inverted background). Returns a multi-line string suitable for
    printing directly to a terminal;
    a phone camera can scan it to import the connection. This is what makes the
    documented "prints connection URIs with QR codes" behaviour real rather
    than printing a bare link.
    """
    qr = segno.make(uri, error="m")
    buf = io.StringIO()
    qr.terminal(buf, border=border)
    return buf.getvalue().rstrip("\n")


def write_qr_png(uri: str, path: str, *, scale: int = 6, border: int = 2) -> None:
    """Write ``uri`` as a PNG QR code to ``path`` (e.g. ``client.qr.png``)."""
    segno.make(uri, error="m").save(path, scale=scale, border=border)
