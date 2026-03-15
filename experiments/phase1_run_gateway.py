"""Phase 1 gateway runner for phone-based IoT experiments."""

from __future__ import annotations

import argparse
import pathlib
import socket
import sys
import time

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from lightweight_secure_channel.network.server import GatewayServer


def _detect_local_ip() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run gateway for Phase 1 phone experiments.")
    parser.add_argument("--host", default="0.0.0.0", help="Gateway bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9010, help="Gateway bind port (default: 9010)")
    parser.add_argument(
        "--session-timeout",
        type=int,
        default=300,
        help="Session timeout in seconds (default: 300)",
    )
    args = parser.parse_args()

    local_ip = _detect_local_ip()
    print("Starting proposed Phase 1 gateway (ECC + ASCON + sponge-KDF)...")
    if args.port == 9020:
        print("Warning: port 9020 is reserved for baseline gateway in this project.")
        print("If you are testing baseline client, run experiments/phase1_run_baseline_gateway.py instead.")
    print(f"Bind: {args.host}:{args.port}")
    print(f"LAN IP hint for phone client: {local_ip}:{args.port}")
    print("Press Ctrl+C to stop.")

    server = GatewayServer(host=args.host, port=args.port, session_timeout=args.session_timeout)
    thread = server.start_in_thread()

    try:
        while thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Stopping gateway...")
    finally:
        server.stop()
        thread.join(timeout=2)
        print("Gateway stopped.")


if __name__ == "__main__":
    main()
