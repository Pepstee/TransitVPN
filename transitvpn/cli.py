"""Command-line interface for transitvpn."""

import argparse
import ipaddress
import json
import math
import os
import sys
import tempfile
from pathlib import Path


def _port_number(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "port must be an integer between 1 and 65535"
        ) from None
    if not 0 < port < 65536:
        raise argparse.ArgumentTypeError(
            "port must be an integer between 1 and 65535"
        )
    return port


def _listen_address(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise argparse.ArgumentTypeError(
            "listen must be a literal IPv4 or IPv6 address"
        ) from None


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


_SERVER_PID_NAME = "tunnel.pid"
_CLIENT_PID_NAME = "tunnel-client.pid"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="transitvpn",
        description="Transit VPN management tool",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    certify_p = subparsers.add_parser(
        "certify-local-tunnel",
        help="Certify the pinned Xray loopback VLESS RAW data path",
    )
    certify_p.add_argument(
        "--xray-binary",
        default=os.environ.get("TRANSITVPN_XRAY_BIN", "xray"),
        help="Path to the pinned Xray executable",
    )
    certify_p.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="Timeout in seconds for the local certification run (default: 10)",
    )

    up_p = subparsers.add_parser("up", help="Bring up the VPN tunnel")
    up_p.add_argument(
        "--client", action="store_true",
        help="Manage the imported client tunnel instead of the server",
    )
    down_p = subparsers.add_parser("down", help="Tear down the VPN tunnel")
    down_p.add_argument(
        "--client", action="store_true",
        help="Manage the imported client tunnel instead of the server",
    )
    status_p = subparsers.add_parser("status", help="Show tunnel status")
    status_p.add_argument(
        "--client", action="store_true",
        help="Manage the imported client tunnel instead of the server",
    )

    health_p = subparsers.add_parser(
        "health", help="Request HTTP health through the configured local SOCKS tunnel"
    )
    health_p.add_argument("--url", required=True, help="Plain HTTP health URL to request through Xray")
    health_p.add_argument(
        "--timeout", type=float, default=5.0, metavar="SECONDS",
        help="Request timeout in seconds (default: 5; maximum: 30)",
    )

    export_p = subparsers.add_parser(
        "export-profile", help="Export the configured VLESS+REALITY client profile privately"
    )
    export_p.add_argument(
        "--output", type=Path, required=True,
        help="New profile file under an existing private directory",
    )

    import_p = subparsers.add_parser(
        "import-profile",
        help="Import an exported VLESS+REALITY profile as the managed client config",
    )
    import_p.add_argument(
        "--input", type=Path, required=True,
        help="Private profile file produced by export-profile",
    )
    import_p.add_argument(
        "--socks-port", type=int, default=10808, metavar="PORT",
        help="Loopback SOCKS listener port for the imported client (default: 10808)",
    )
    import_p.add_argument(
        "--xray-binary", default=os.environ.get("TRANSITVPN_XRAY_BIN", "xray"),
        help="Path to the pinned Xray executable",
    )

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
    bootstrap_p.add_argument(
        "--listen", metavar="ADDRESS", type=_listen_address, default=None,
        help="Literal IPv4/IPv6 server bind address (default: Xray behavior)",
    )
    bootstrap_p.add_argument(
        "--port", metavar="PORT", type=_port_number, default=443,
        help="VLESS peer port (default: 443)",
    )
    bootstrap_p.add_argument(
        "--socks-port", metavar="PORT", type=_port_number, default=10808,
        help="Local client SOCKS port (default: 10808)",
    )
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
        target_verified=args.target_verified, listen=args.listen,
        port=args.port, socks_port=args.socks_port,
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
        operator_identity = {
            **identity,
            "local_evidence": {
                "scope": "configuration-validation",
                "xray_configuration": "observed",
            },
            "external_recovery": {"status": "unprovisioned", "observed": False},
        }
        _atomic_write(Path("state") / "xray-identity.json", operator_identity)
        print("wrote permission-restricted server/client configs and binary identity to state/")

    return 0


def _cmd_certify_local_tunnel(args: argparse.Namespace) -> int:
    from transitvpn.xray import certify_local_tunnel

    if not (args.timeout > 0.0) or args.timeout == float("inf"):
        print("certify-local-tunnel: error: --timeout must be a positive finite number",
              file=sys.stderr)
        return 2

    try:
        result = certify_local_tunnel(args.xray_binary, timeout=args.timeout)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"certify-local-tunnel: error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result.operator_record(), indent=2))
    return 0


def _cmd_up(args: argparse.Namespace) -> int:
    from transitvpn.tunnel import start_tunnel

    client = bool(getattr(args, "client", False))
    config_path = str(
        Path("state") / ("xray-client.json" if client else "xray-server.json")
    )
    if client:
        pid, err = start_tunnel(
            config_path, "state", pid_name=_CLIENT_PID_NAME
        )
    else:
        pid, err = start_tunnel(config_path, "state")
    if err is not None:
        print(f"up: error: {err}")
        return 1
    print(f"up: tunnel started (pid={pid})")
    return 0


def _cmd_down(args: argparse.Namespace) -> int:
    from transitvpn.tunnel import stop_tunnel

    client = bool(getattr(args, "client", False))
    if client:
        error = stop_tunnel("state", pid_name=_CLIENT_PID_NAME)
    else:
        error = stop_tunnel("state")
    if error is not None:
        print(f"down: error: {error}")
        return 1
    print("down: tunnel stopped")
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    from transitvpn.tunnel import get_status, lifecycle_support_error

    support_error = lifecycle_support_error()
    if support_error:
        print(f"status: unavailable; {support_error}")
        return 2
    client = bool(getattr(args, "client", False))
    if client:
        running, pid = get_status("state", pid_name=_CLIENT_PID_NAME)
    else:
        running, pid = get_status("state")
    if running:
        print(f"status: live process (pid={pid}); tunnel health unverified")
    else:
        print("status: not running; tunnel health unavailable")
    return 0


def _cmd_health(args: argparse.Namespace) -> int:
    from transitvpn.xray_certification import (
        XrayCertificationError,
        probe_configured_socks_http,
    )

    if not math.isfinite(args.timeout) or not 0.0 < args.timeout <= 30.0:
        print("health: error: --timeout must be positive, finite, and at most 30 seconds",
              file=sys.stderr)
        return 2

    try:
        observation = probe_configured_socks_http(
            Path("state") / "xray-client.json", args.url, timeout=args.timeout
        )
    except ValueError as exc:
        print(f"health: error: {exc}", file=sys.stderr)
        return 2
    except XrayCertificationError as exc:
        record: dict[str, object] = {
            "health": "unhealthy",
            "http_observed": hasattr(exc, "status_code"),
            "route": "configured_socks",
            "process_liveness": "not_checked",
            "error": str(exc),
        }
        if hasattr(exc, "status_code"):
            record["http_status"] = exc.status_code
            record["response_bytes"] = exc.response_bytes
        print(json.dumps(record, indent=2))
        return 1

    record = observation.operator_record()
    print(json.dumps(record, indent=2))
    return 0 if record["health"] == "healthy" else 1


def _cmd_export_profile(args: argparse.Namespace) -> int:
    from transitvpn.export_profile import ProfileExportError, export_profile

    try:
        export_profile(Path("state") / "xray-client.json", args.output)
    except ProfileExportError:
        print("export-profile: error: client profile could not be exported", file=sys.stderr)
        return 1
    print("export-profile: profile exported")
    return 0


def _cmd_import_profile(args: argparse.Namespace) -> int:
    from transitvpn.import_profile import ProfileImportError, import_profile

    if (
        isinstance(args.socks_port, bool)
        or not isinstance(args.socks_port, int)
        or not 1 <= args.socks_port <= 65535
    ):
        print(
            "import-profile: error: --socks-port must be between 1 and 65535",
            file=sys.stderr,
        )
        return 2

    try:
        import_profile(
            args.input,
            Path("state") / "xray-client.json",
            socks_port=args.socks_port,
            xray_binary=args.xray_binary,
        )
    except ProfileImportError:
        print(
            "import-profile: error: client profile could not be imported",
            file=sys.stderr,
        )
        return 1
    print("import-profile: client profile imported and validated")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "certify-local-tunnel":
        return _cmd_certify_local_tunnel(args)

    if args.command == "up":
        return _cmd_up(args)

    if args.command == "down":
        return _cmd_down(args)

    if args.command == "status":
        return _cmd_status(args)

    if args.command == "health":
        return _cmd_health(args)

    if args.command == "export-profile":
        return _cmd_export_profile(args)

    if args.command == "import-profile":
        return _cmd_import_profile(args)

    if args.command == "bootstrap":
        return _cmd_bootstrap(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
