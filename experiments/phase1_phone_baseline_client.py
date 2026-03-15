"""Phase 1 phone baseline client runner with CSV metrics logging."""

from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import statistics
import sys
import time
from datetime import datetime, timezone
from io import BufferedRWPair
from typing import Any

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import psutil  # type: ignore
except Exception:
    psutil = None

from experiments.baseline_protocol import (
    BaselinePacket,
    BaselineSecureChannel,
    perform_baseline_client_handshake,
)

DEFAULT_OUTPUT = PROJECT_ROOT / "results" / "tables" / "phase1_phone_metrics.csv"
DEFAULT_POWER_PROFILE_W = {
    "phone_midrange": 2.5,
    "phone_flagship": 3.5,
    "iot_mcu_wifi": 0.35,
    "iot_mcu_ble": 0.12,
    "unknown": 2.0,
}


def _normalize_host_port(host_arg: str, port_arg: int) -> tuple[str, int]:
    """Accept either host or host:port and normalize to tuple."""
    host = host_arg.strip()
    if host.count(":") == 1 and not host.startswith("["):
        maybe_host, maybe_port = host.rsplit(":", 1)
        if maybe_port.isdigit():
            return maybe_host, int(maybe_port)
    return host, port_arg


def _send_json(stream: BufferedRWPair, payload: dict[str, Any]) -> None:
    stream.write(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
    stream.flush()


def _recv_json(stream: BufferedRWPair) -> dict[str, Any]:
    line = stream.readline()
    if not line:
        raise EOFError("Connection closed while waiting for response packet.")
    return json.loads(line.decode("utf-8"))


def _build_payload(device_id: str, scenario: str, cycle: int, seq: int, payload_size: int) -> bytes:
    prefix = f"{device_id}|{scenario}|cycle={cycle}|seq={seq}|".encode("utf-8")
    if len(prefix) >= payload_size:
        return prefix[:payload_size]
    return prefix + os.urandom(payload_size - len(prefix))


def _ensure_csv_header(path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > 0:
        return

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "timestamp_utc",
                "protocol",
                "device_class",
                "avg_power_w_assumed",
                "device_id",
                "scenario",
                "cycle",
                "messages",
                "payload_size_bytes",
                "handshake_latency_ms",
                "resumed",
                "resume_expected",
                "resume_success",
                "reconnect_success",
                "avg_encrypt_ms",
                "avg_roundtrip_ms",
                "throughput_mbps",
                "cpu_utilization_pct",
                "memory_delta_mb",
                "cycle_duration_s",
                "cpu_time_s",
                "estimated_energy_j",
                "energy_per_message_mj",
                "session_id",
                "connection_id",
            ]
        )


def _append_row(path: pathlib.Path, row: list[str | int | float | bool]) -> None:
    with path.open("a", encoding="utf-8", newline="") as handle:
        csv.writer(handle).writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Phase 1 baseline phone client experiment cycles.")
    parser.add_argument("--host", required=True, help="Gateway host/IP address")
    parser.add_argument("--port", type=int, default=9020, help="Gateway port (default: 9020)")
    parser.add_argument("--device-id", default="phone-1", help="Logical device id for logs")
    parser.add_argument(
        "--device-class",
        default="phone_midrange",
        help="Device class label (e.g., phone_midrange, phone_flagship, iot_mcu_wifi)",
    )
    parser.add_argument(
        "--power-w",
        type=float,
        default=None,
        help="Optional average power override in Watts for energy estimation",
    )
    parser.add_argument(
        "--scenario",
        default="stable_wifi",
        choices=["stable_wifi", "wifi_to_mobile", "airplane_toggle", "app_restart"],
        help="Scenario label for this run",
    )
    parser.add_argument("--cycles", type=int, default=3, help="Number of reconnect cycles (default: 3)")
    parser.add_argument("--messages", type=int, default=100, help="Messages per cycle (default: 100)")
    parser.add_argument(
        "--payload-size",
        type=int,
        default=128,
        help="Payload size in bytes (default: 128)",
    )
    parser.add_argument(
        "--reconnect-delay",
        type=float,
        default=1.0,
        help="Delay in seconds between cycles (default: 1.0)",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help=f"Output CSV path (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()
    host, port = _normalize_host_port(args.host, args.port)
    if host != args.host or port != args.port:
        print(f"Normalized endpoint -> host={host}, port={port}")

    power_w_assumed = (
        args.power_w
        if args.power_w is not None
        else DEFAULT_POWER_PROFILE_W.get(args.device_class, DEFAULT_POWER_PROFILE_W["unknown"])
    )

    output_path = pathlib.Path(args.output)
    _ensure_csv_header(output_path)

    if psutil is not None:
        process = psutil.Process(os.getpid())
    else:
        process = None

    print(f"Starting baseline Phase 1 run -> host={host}:{port}, scenario={args.scenario}")

    total_reconnect_success = 0

    for cycle in range(1, args.cycles + 1):
        print(f"Cycle {cycle}/{args.cycles}: connecting...")
        reconnect_success = True
        resumed = False
        session_id = ""
        connection_id = ""

        memory_before = process.memory_info().rss if process is not None else 0
        cpu_before = time.process_time()
        cycle_wall_start = time.perf_counter()

        encrypt_latencies: list[float] = []
        roundtrip_latencies: list[float] = []
        sent_bytes = 0

        sock = None
        stream = None
        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            stream = sock.makefile("rwb")

            handshake_start = time.perf_counter()
            handshake_result = perform_baseline_client_handshake(stream)
            handshake_latency_ms = (time.perf_counter() - handshake_start) * 1000.0

            session_id = handshake_result.session_id
            connection_id = "baseline-no-cid"
            resumed = False

            channel = BaselineSecureChannel(
                session_id=handshake_result.session_id,
                key_material=handshake_result.key_material,
            )

            for seq in range(args.messages):
                payload = _build_payload(
                    device_id=args.device_id,
                    scenario=args.scenario,
                    cycle=cycle,
                    seq=seq,
                    payload_size=args.payload_size,
                )

                encrypt_start = time.perf_counter()
                packet = channel.encrypt_packet(payload)
                encrypt_latencies.append((time.perf_counter() - encrypt_start) * 1000.0)

                send_start = time.perf_counter()
                _send_json(stream, {"type": "SecurePacket", "packet": packet.to_dict()})
                envelope = _recv_json(stream)
                if envelope.get("type") != "SecurePacket":
                    raise ValueError("Unexpected envelope type from baseline gateway.")

                ack_packet = BaselinePacket.from_dict(envelope["packet"])
                plaintext = channel.decrypt_packet(ack_packet)
                roundtrip_latencies.append((time.perf_counter() - send_start) * 1000.0)

                expected = b"ACK:" + payload
                if plaintext != expected:
                    raise ValueError("ACK payload mismatch.")

                sent_bytes += len(payload)

            _send_json(stream, {"type": "SecurePacket", "packet": channel.encrypt_packet(b"__close__").to_dict()})
        except Exception as error:
            reconnect_success = False
            handshake_latency_ms = 0.0
            print(f"Cycle {cycle} failed: {error}")
        finally:
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass
            try:
                if sock is not None:
                    sock.close()
            except Exception:
                pass

        cycle_wall_end = time.perf_counter()
        cpu_after = time.process_time()
        memory_after = process.memory_info().rss if process is not None else 0

        wall_delta = max(cycle_wall_end - cycle_wall_start, 1e-9)
        cpu_time_s = max(cpu_after - cpu_before, 0.0)
        cpu_pct = ((cpu_after - cpu_before) / wall_delta) * 100.0
        memory_delta_mb = ((memory_after - memory_before) / (1024 * 1024)) if process is not None else 0.0
        avg_encrypt_ms = statistics.mean(encrypt_latencies) if encrypt_latencies else 0.0
        avg_roundtrip_ms = statistics.mean(roundtrip_latencies) if roundtrip_latencies else 0.0
        throughput_mbps = (sent_bytes / wall_delta) / (1024 * 1024)
        estimated_energy_j = power_w_assumed * wall_delta
        energy_per_message_mj = (estimated_energy_j * 1000.0 / args.messages) if args.messages > 0 else 0.0

        if reconnect_success:
            total_reconnect_success += 1

        _append_row(
            output_path,
            [
                datetime.now(timezone.utc).isoformat(),
                "baseline",
                args.device_class,
                f"{power_w_assumed:.6f}",
                args.device_id,
                args.scenario,
                cycle,
                args.messages,
                args.payload_size,
                f"{handshake_latency_ms:.6f}",
                int(resumed),
                0,
                0,
                int(reconnect_success),
                f"{avg_encrypt_ms:.6f}",
                f"{avg_roundtrip_ms:.6f}",
                f"{throughput_mbps:.6f}",
                f"{cpu_pct:.6f}",
                f"{memory_delta_mb:.6f}",
                f"{wall_delta:.6f}",
                f"{cpu_time_s:.6f}",
                f"{estimated_energy_j:.6f}",
                f"{energy_per_message_mj:.6f}",
                session_id,
                connection_id,
            ],
        )

        print(
            "Cycle complete: "
            f"reconnect_success={reconnect_success}, handshake_ms={handshake_latency_ms:.2f}, "
            f"avg_rtt_ms={avg_roundtrip_ms:.2f}, throughput={throughput_mbps:.3f} MB/s"
        )

        if cycle < args.cycles:
            time.sleep(max(args.reconnect_delay, 0.0))

    reconnect_success_rate = (total_reconnect_success / max(args.cycles, 1)) * 100.0

    print("Baseline Phase 1 run finished.")
    print(f"Output CSV: {output_path}")
    print(f"Reconnect success rate: {reconnect_success_rate:.2f}% ({total_reconnect_success}/{args.cycles})")


if __name__ == "__main__":
    main()
