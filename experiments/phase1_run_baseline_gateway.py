"""Phase 1 baseline gateway runner (ECDH + HKDF + AES-GCM)."""

from __future__ import annotations

import argparse
import json
import pathlib
import socket
import sys
import time
from io import BufferedRWPair
from typing import Any

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from experiments.baseline_protocol import (
    BaselinePacket,
    BaselineSecureChannel,
    perform_baseline_server_handshake,
)


def _send_json(stream: BufferedRWPair, payload: dict[str, Any]) -> None:
    stream.write(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
    stream.flush()


def _recv_json(stream: BufferedRWPair) -> dict[str, Any]:
    line = stream.readline()
    if not line:
        raise EOFError("Connection closed while waiting for packet.")
    return json.loads(line.decode("utf-8"))


def _detect_local_ip() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 80))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def _handle_connection(connection: socket.socket) -> None:
    with connection:
        stream = connection.makefile("rwb")
        try:
            handshake = perform_baseline_server_handshake(stream)
            channel = BaselineSecureChannel(
                session_id=handshake.session_id,
                key_material=handshake.key_material,
            )

            while True:
                envelope = _recv_json(stream)
                if envelope.get("type") != "SecurePacket":
                    raise ValueError("Unexpected packet type.")

                packet = BaselinePacket.from_dict(envelope["packet"])
                plaintext = channel.decrypt_packet(packet)
                if plaintext == b"__close__":
                    break

                ack_packet = channel.encrypt_packet(b"ACK:" + plaintext)
                _send_json(stream, {"type": "SecurePacket", "packet": ack_packet.to_dict()})
        except EOFError:
            pass
        finally:
            stream.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run baseline gateway for Phase 1 phone experiments.")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9020, help="Bind port (default: 9020)")
    args = parser.parse_args()

    local_ip = _detect_local_ip()
    print("Starting baseline Phase 1 gateway...")
    print(f"Bind: {args.host}:{args.port}")
    print(f"LAN IP hint for phone client: {local_ip}:{args.port}")
    print("Press Ctrl+C to stop.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((args.host, args.port))
        server_socket.listen()
        server_socket.settimeout(1.0)

        try:
            while True:
                try:
                    connection, _ = server_socket.accept()
                except socket.timeout:
                    continue
                _handle_connection(connection)
        except KeyboardInterrupt:
            print("Stopping baseline gateway...")

    time.sleep(0.1)
    print("Baseline gateway stopped.")


if __name__ == "__main__":
    main()
