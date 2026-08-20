"""Command-line interface for transitvpn."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=path.parent, delete=False, suffix=".tmp"
    ) as fh:
        json.dump(data, fh, indent=2)
        tmp = fh.name
    os.chmod(tmp, 0o600)
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

    bootstrap_p = subparsers.add_parser(
        "bootstrap", help="Generate and validate matching Xray server/client configs"
    )
    bootstrap_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate with Xray but do not write state files",
    )
    bootstrap_p.add_argument(
        "--host",
        metavar="HOST",
        required=True,
        help="Public IP/hostname clients use to reach this deployment",
    )
    bootstrap_p.add_argument("--target", required=True, metavar="HOST:PORT",
                             help="Deliberately selected REALITY target")
    bootstrap_p.add_argument("--server-name", required=True, metavar="SNI",
                             help="SNI accepted by the verified target")
    bootstrap_p.add_argument(
        "--target-verified", action="store_true", required=True,
        help="Attest that target reachability, TLS 1.3 and SNI were checked from the server",
    )
    bootstrap_p.add_argument("--xray-binary", default=os.environ.get("TRANSITVPN_XRAY_BIN", "xray"),
                             help="Path to the pinned Xray executable")

    return parser


def _cmd_bootstrap(args: argparse.Namespace) -> int:
    from transitvpn.config import XrayDeployment
    from transitvpn.keygen import generate_keys, generate_short_id
    from transitvpn.server import build_client_config, build_server_config
    from transitvpn.xray import validate_configs

    deployment = XrayDeployment(
        keys=generate_keys(), server=args.host, target=args.target,
        server_name=args.server_name, short_id=generate_short_id(),
        target_verified=args.target_verified,
    )
    server_cfg = build_server_config(deployment)
    client_cfg = build_client_config(deployment)
    try:
        identity = validate_configs(
            {"server": server_cfg, "client": client_cfg}, args.xray_binary
        )
    except RuntimeError as exc:
        print(f"bootstrap: error: {exc}", file=sys.stderr)
        return 1
    print(f"validated server and client with Xray {identity['version']} ({identity['sha256']})")

    if not args.dry_run:
        _atomic_write(Path("state") / "xray-server.json", server_cfg)
        _atomic_write(Path("state") / "xray-client.json", client_cfg)
        _atomic_write(Path("state") / "xray-identity.json", identity)
        print("wrote permission-restricted server/client configs and binary identity to state/")

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

    return 0


if __name__ == "__main__":
    sys.exit(main())
