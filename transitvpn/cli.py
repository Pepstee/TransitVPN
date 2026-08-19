"""Command-line interface for transitvpn."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=path.parent, delete=False, suffix=".tmp"
    ) as fh:
        json.dump(data, fh, indent=2)
        tmp = fh.name
    os.replace(tmp, path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="transitvpn",
        description="Transit VPN management tool",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    subparsers.add_parser("up", help="Bring up the VPN tunnel")
    subparsers.add_parser("down", help="Tear down the VPN tunnel")
    subparsers.add_parser("status", help="Show tunnel status")

    bootstrap_p = subparsers.add_parser("bootstrap", help="Generate keys and write server configs")
    bootstrap_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip network probes and do not write state files",
    )
    bootstrap_p.add_argument(
        "--host",
        metavar="HOST",
        default=None,
        help="Override the public IP/hostname used in generated URIs",
    )

    subparsers.add_parser("keygen", help="Generate and print new key material")

    return parser


def _cmd_bootstrap(args: argparse.Namespace) -> int:
    from transitvpn.cgnat import detect_cgnat
    from transitvpn.keygen import generate_keys
    from transitvpn.qrcode import make_ss_uri, make_vless_uri, render_qr
    from transitvpn.server import build_ss_config, build_xray_config

    cgnat = detect_cgnat(dry_run=args.dry_run)
    print(f"cgnat: {cgnat.status.value}")
    for detail in cgnat.details:
        print(f"  {detail}")
    if cgnat.is_behind_cgnat:
        print("warning: host appears to be behind CGNAT — direct port forwarding may not work")

    keys = generate_keys()
    xray_cfg = build_xray_config(keys)
    ss_cfg = build_ss_config(keys)

    host = args.host or cgnat.public_ip or "0.0.0.0"
    vless_uri = make_vless_uri(keys, host, port=443)
    ss_uri = make_ss_uri(keys, host, port=8388)

    if host == "0.0.0.0":
        print(
            "\nwarning: public IP unknown — pass --host <IP> or replace 0.0.0.0 in the URIs below"
        )

    print(f"\nvless_uri: {vless_uri}")
    print(render_qr(vless_uri))
    print(f"\nss_uri:    {ss_uri}")
    print(render_qr(ss_uri))

    if not args.dry_run:
        _atomic_write(Path("state") / "xray-server.json", xray_cfg)
        _atomic_write(Path("state") / "ss-server.json", ss_cfg)
        print("\nwrote state/xray-server.json and state/ss-server.json")

    return 0


def _cmd_up(_args: argparse.Namespace) -> int:
    from transitvpn.tunnel import start_tunnel

    config_path = str(Path("state") / "xray-server.json")
    pid, err = start_tunnel(config_path, "state")
    if err is not None:
        print(f"up: error: {err}")
        return 1
    print(f"up: tunnel started (pid={pid})")
    return 0


def _cmd_down(_args: argparse.Namespace) -> int:
    from transitvpn.tunnel import stop_tunnel

    stop_tunnel("state")
    print("down: tunnel stopped")
    return 0


def _cmd_status(_args: argparse.Namespace) -> int:
    from transitvpn.tunnel import get_status

    running, pid = get_status("state")
    if running:
        print(f"status: running (pid={pid})")
    else:
        print("status: not running")
    return 0


def _cmd_keygen(_args: argparse.Namespace) -> int:
    from transitvpn.keygen import generate_keys

    keys = generate_keys()
    print(f"vless_uuid:          {keys.vless_uuid}")
    print(f"reality_private_key: {keys.reality_private_key}")
    print(f"reality_public_key:  {keys.reality_public_key}")
    print(f"ss_password:         {keys.ss_password}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "up":
        return _cmd_up(args)

    if args.command == "down":
        return _cmd_down(args)

    if args.command == "status":
        return _cmd_status(args)

    if args.command == "bootstrap":
        return _cmd_bootstrap(args)

    if args.command == "keygen":
        return _cmd_keygen(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
