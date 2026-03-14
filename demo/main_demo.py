"""Demonstration script for handshake, encrypted messaging, and session resumption."""

from __future__ import annotations

import pathlib
import sys
import time

# Allow direct execution: `python demo/main_demo.py`
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from lightweight_secure_channel.network.client import IoTClient
from lightweight_secure_channel.network.server import GatewayServer


def main() -> None:
    server = GatewayServer(host="127.0.0.1", port=9010, session_timeout=300)
    server_thread = server.start_in_thread()
    time.sleep(0.2)

    client = IoTClient(host="127.0.0.1", port=9010, session_timeout=300)

    client.connect()
    t0 = time.perf_counter()
    first = client.perform_handshake()
    first_handshake_ms = (time.perf_counter() - t0) * 1000.0
    print(f"Handshake complete: resumed={first.resumed}, latency={first_handshake_ms:.2f} ms")

    messages = ["temperature=24.5", "humidity=58", "pressure=1008"]
    responses = client.send_encrypted_messages(messages)
    for msg, rsp in zip(messages, responses):
        print(f"{msg} -> {rsp}")

    # Explicit packet encryption/decryption demonstration on active secure channel.
    assert client.channel is not None
    demo_packet = client.channel.encrypt_packet(b"packet-demo")
    recovered = client.channel.decrypt_packet(demo_packet)
    print(f"Packet demo plaintext recovered: {recovered.decode('utf-8')}")

    client.close()
    time.sleep(0.2)

    # Reconnect and resume lightweight session using connection ID.
    client.connect()
    t1 = time.perf_counter()
    resumed = client.perform_handshake()
    resumed_handshake_ms = (time.perf_counter() - t1) * 1000.0
    print(f"Resumed handshake: resumed={resumed.resumed}, latency={resumed_handshake_ms:.2f} ms")

    resumed_responses = client.send_encrypted_messages(["reconnect=ok"])
    print(f"resume message -> {resumed_responses[0]}")

    client.close()
    server.stop()
    server_thread.join(timeout=2)


if __name__ == "__main__":
    main()
