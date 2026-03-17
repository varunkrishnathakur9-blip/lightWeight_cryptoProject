"""Phase 2 edge bridge: Mega2560+R307 sensor events to secure gateway protocols.

Hardware-in-the-loop topology:
R307 -> Mega2560 (UART) -> USB Serial -> this edge bridge -> gateway
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import socket
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BufferedRWPair
from pathlib import Path
from typing import Any, Protocol

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional at runtime
    psutil = None

try:
    import serial  # type: ignore
except Exception:  # pragma: no cover - optional at runtime
    serial = None

from experiments.baseline_protocol import (
    BaselinePacket,
    BaselineSecureChannel,
    perform_baseline_client_handshake,
)
from lightweight_secure_channel.network.client import IoTClient
from lightweight_secure_channel.protocol.packet import SecurePacket

DEFAULT_OUTPUT = PROJECT_ROOT / "results" / "tables" / "phase2_edge_metrics.csv"

DEFAULT_POWER_PROFILE_W = {
    "mega2560_r307s": 0.8,
    "mega2560_sim": 0.6,
    "unknown": 1.0,
}


@dataclass(frozen=True)
class SensorEvent:
    seq: int
    status: str
    finger_id: int
    confidence: int
    sensor_ts_ms: int
    raw_line: str


@dataclass(frozen=True)
class HandshakeSnapshot:
    latency_ms: float
    resumed: bool
    session_id: str
    connection_id: str


@dataclass(frozen=True)
class SendResult:
    encrypt_latency_ms: float
    roundtrip_latency_ms: float
    ack_valid: bool
    ack_rx_epoch_ms: int
    session_id: str
    connection_id: str


class SensorSource(Protocol):
    latest_free_ram_bytes: int

    def next_event(self) -> SensorEvent:
        raise NotImplementedError

    def send_bridge_ack(self, seq: int, ok: bool, message: str = "") -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class SerialSensorSource:
    """Reads newline-delimited JSON sensor events from Mega USB serial."""

    def __init__(self, port: str, baudrate: int, read_timeout_s: float, event_timeout_s: float) -> None:
        if serial is None:
            raise RuntimeError("pyserial is required for serial mode. Install `pyserial`.")
        self._serial = serial.Serial(port=port, baudrate=baudrate, timeout=read_timeout_s)
        self._event_timeout_s = event_timeout_s
        self.latest_free_ram_bytes = 0

    def _parse_event(self, line: str) -> SensorEvent | None:
        payload = json.loads(line)
        msg_type = payload.get("type")
        if msg_type == "heartbeat":
            free_ram = payload.get("free_ram_bytes")
            if isinstance(free_ram, int):
                self.latest_free_ram_bytes = free_ram
            return None

        if msg_type != "sensor_event":
            return None

        seq = int(payload.get("seq", 0))
        status = str(payload.get("status", "unknown"))
        finger_id = int(payload.get("finger_id", -1))
        confidence = int(payload.get("confidence", 0))
        sensor_ts_ms = int(payload.get("sensor_ts_ms", int(time.time() * 1000)))
        return SensorEvent(
            seq=seq,
            status=status,
            finger_id=finger_id,
            confidence=confidence,
            sensor_ts_ms=sensor_ts_ms,
            raw_line=line,
        )

    def next_event(self) -> SensorEvent:
        deadline = time.time() + self._event_timeout_s
        while time.time() < deadline:
            raw = self._serial.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                event = self._parse_event(line)
                if event is not None:
                    return event
            except Exception:
                continue
        raise TimeoutError("Timed out waiting for sensor event from serial source.")

    def send_bridge_ack(self, seq: int, ok: bool, message: str = "") -> None:
        safe_message = message.replace("\n", " ").replace(",", ";")[:120]
        line = f"ACK,{seq},{1 if ok else 0},{safe_message}\n"
        self._serial.write(line.encode("utf-8"))

    def close(self) -> None:
        self._serial.close()


class SimulatedSensorSource:
    """Generates synthetic events for dry-runs without hardware connected."""

    def __init__(self, interval_ms: int) -> None:
        self._interval_s = max(interval_ms, 1) / 1000.0
        self._seq = 0
        self.latest_free_ram_bytes = 4096

    def next_event(self) -> SensorEvent:
        time.sleep(self._interval_s)
        now_ms = int(time.time() * 1000)
        event = SensorEvent(
            seq=self._seq,
            status="simulated_match",
            finger_id=1,
            confidence=80,
            sensor_ts_ms=now_ms,
            raw_line="simulated",
        )
        self._seq += 1
        return event

    def send_bridge_ack(self, seq: int, ok: bool, message: str = "") -> None:
        _ = (seq, ok, message)

    def close(self) -> None:
        return


class ProtocolHandler(Protocol):
    def open_session(self) -> HandshakeSnapshot:
        raise NotImplementedError

    def send_payload(self, payload: bytes) -> SendResult:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class ProposedProtocolHandler:
    def __init__(self, host: str, port: int, session_timeout: int) -> None:
        self._client = IoTClient(host=host, port=port, session_timeout=session_timeout)

    @staticmethod
    def _send_json(stream: BufferedRWPair, payload: dict[str, Any]) -> None:
        stream.write(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
        stream.flush()

    @staticmethod
    def _recv_json(stream: BufferedRWPair) -> dict[str, Any]:
        line = stream.readline()
        if not line:
            raise EOFError("Connection closed while waiting for response packet.")
        return json.loads(line.decode("utf-8"))

    def open_session(self) -> HandshakeSnapshot:
        self._client.connect()
        t0 = time.perf_counter()
        result = self._client.perform_handshake()
        latency_ms = (time.perf_counter() - t0) * 1000.0
        return HandshakeSnapshot(
            latency_ms=latency_ms,
            resumed=result.resumed,
            session_id=result.session_id,
            connection_id=result.connection_id,
        )

    def send_payload(self, payload: bytes) -> SendResult:
        if self._client.stream is None or self._client.channel is None:
            raise RuntimeError("Proposed session not ready. Call open_session first.")

        encrypt_start = time.perf_counter()
        packet = self._client.channel.encrypt_packet(payload)
        encrypt_latency_ms = (time.perf_counter() - encrypt_start) * 1000.0

        roundtrip_start = time.perf_counter()
        self._send_json(self._client.stream, {"type": "SecurePacket", "packet": packet.to_dict()})
        envelope = self._recv_json(self._client.stream)
        if envelope.get("type") != "SecurePacket":
            raise ValueError("Unexpected envelope type from proposed gateway.")

        ack_packet = SecurePacket.from_dict(envelope["packet"])
        ack_plaintext = self._client.channel.decrypt_packet(ack_packet)
        roundtrip_latency_ms = (time.perf_counter() - roundtrip_start) * 1000.0

        ack_valid = ack_plaintext == (b"ACK:" + payload)
        ack_rx_epoch_ms = int(time.time() * 1000)

        session_id = self._client.channel.session_id
        connection_id = self._client._last_connection_id or ""
        self._client.session_manager.advance_nonce_counter(session_id, self._client.channel.nonce_counter)
        return SendResult(
            encrypt_latency_ms=encrypt_latency_ms,
            roundtrip_latency_ms=roundtrip_latency_ms,
            ack_valid=ack_valid,
            ack_rx_epoch_ms=ack_rx_epoch_ms,
            session_id=session_id,
            connection_id=connection_id,
        )

    def close(self) -> None:
        self._client.close()


class BaselineProtocolHandler:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.socket: socket.socket | None = None
        self.stream: BufferedRWPair | None = None
        self.channel: BaselineSecureChannel | None = None
        self.session_id: str = ""

    @staticmethod
    def _send_json(stream: BufferedRWPair, payload: dict[str, Any]) -> None:
        stream.write(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
        stream.flush()

    @staticmethod
    def _recv_json(stream: BufferedRWPair) -> dict[str, Any]:
        line = stream.readline()
        if not line:
            raise EOFError("Connection closed while waiting for baseline response packet.")
        return json.loads(line.decode("utf-8"))

    def open_session(self) -> HandshakeSnapshot:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self.stream = self.socket.makefile("rwb")

        t0 = time.perf_counter()
        result = perform_baseline_client_handshake(self.stream)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        self.session_id = result.session_id
        self.channel = BaselineSecureChannel(session_id=result.session_id, key_material=result.key_material)
        return HandshakeSnapshot(
            latency_ms=latency_ms,
            resumed=False,
            session_id=result.session_id,
            connection_id="baseline-no-cid",
        )

    def send_payload(self, payload: bytes) -> SendResult:
        if self.stream is None or self.channel is None:
            raise RuntimeError("Baseline session not ready. Call open_session first.")

        encrypt_start = time.perf_counter()
        packet = self.channel.encrypt_packet(payload)
        encrypt_latency_ms = (time.perf_counter() - encrypt_start) * 1000.0

        roundtrip_start = time.perf_counter()
        self._send_json(self.stream, {"type": "SecurePacket", "packet": packet.to_dict()})
        envelope = self._recv_json(self.stream)
        if envelope.get("type") != "SecurePacket":
            raise ValueError("Unexpected envelope type from baseline gateway.")

        ack_packet = BaselinePacket.from_dict(envelope["packet"])
        ack_plaintext = self.channel.decrypt_packet(ack_packet)
        roundtrip_latency_ms = (time.perf_counter() - roundtrip_start) * 1000.0

        ack_valid = ack_plaintext == (b"ACK:" + payload)
        ack_rx_epoch_ms = int(time.time() * 1000)
        return SendResult(
            encrypt_latency_ms=encrypt_latency_ms,
            roundtrip_latency_ms=roundtrip_latency_ms,
            ack_valid=ack_valid,
            ack_rx_epoch_ms=ack_rx_epoch_ms,
            session_id=self.session_id,
            connection_id="baseline-no-cid",
        )

    def close(self) -> None:
        try:
            if self.stream is not None and self.channel is not None:
                close_packet = self.channel.encrypt_packet(b"__close__")
                self._send_json(self.stream, {"type": "SecurePacket", "packet": close_packet.to_dict()})
        except Exception:
            pass

        try:
            if self.stream is not None:
                self.stream.close()
        except Exception:
            pass
        try:
            if self.socket is not None:
                self.socket.close()
        except Exception:
            pass

        self.stream = None
        self.socket = None
        self.channel = None


def _normalize_host_port(host_arg: str, port_arg: int) -> tuple[str, int]:
    host = host_arg.strip()
    if host.count(":") == 1 and not host.startswith("["):
        maybe_host, maybe_port = host.rsplit(":", 1)
        if maybe_port.isdigit():
            return maybe_host, int(maybe_port)
    return host, port_arg


def _ensure_csv_header(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > 0:
        return

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "run_id",
                "timestamp_utc",
                "protocol",
                "device_id",
                "device_class",
                "scenario",
                "event_index",
                "sensor_seq",
                "sensor_status",
                "finger_id",
                "confidence",
                "sensor_ts_raw_ms",
                "sensor_ts_ms",
                "edge_rx_ts_ms",
                "ack_rx_ts_ms",
                "handshake_latency_ms",
                "resumed",
                "resume_expected",
                "reconnect_index",
                "encrypt_latency_ms",
                "roundtrip_latency_ms",
                "sensor_to_ack_latency_ms",
                "retry_count",
                "send_success",
                "ack_valid",
                "free_ram_bytes",
                "cpu_utilization_pct",
                "memory_delta_mb",
                "event_duration_s",
                "estimated_energy_j",
                "energy_per_message_mj",
                "payload_size_bytes",
                "session_id",
                "connection_id",
                "error",
            ]
        )


def _append_row(path: Path, row: list[str | int | float]) -> None:
    with path.open("a", encoding="utf-8", newline="") as handle:
        csv.writer(handle).writerow(row)


def _normalize_sensor_timestamp(
    sensor_ts_ms: int,
    edge_rx_ts_ms: int,
    current_offset_ms: int | None,
) -> tuple[int, int | None]:
    """Normalize sensor timestamp to epoch ms when MCU emits uptime millis()."""
    if sensor_ts_ms >= 1_000_000_000_000:
        return sensor_ts_ms, current_offset_ms

    offset = current_offset_ms
    if offset is None:
        offset = edge_rx_ts_ms - sensor_ts_ms
    return sensor_ts_ms + offset, offset


def _build_payload(event: SensorEvent, scenario: str, device_id: str) -> bytes:
    payload = {
        "device_id": device_id,
        "scenario": scenario,
        "seq": event.seq,
        "status": event.status,
        "finger_id": event.finger_id,
        "confidence": event.confidence,
        "sensor_ts_ms": event.sensor_ts_ms,
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 2 edge bridge for Mega2560 + R307 hardware runs.")
    parser.add_argument("--protocol", choices=["proposed", "baseline"], required=True)
    parser.add_argument("--host", required=True, help="Gateway host/IP or host:port")
    parser.add_argument("--port", type=int, default=9010)
    parser.add_argument("--device-id", default="mega-r307s-1")
    parser.add_argument("--device-class", default="mega2560_r307s")
    parser.add_argument("--scenario", default="periodic")
    parser.add_argument("--events", type=int, default=300)
    parser.add_argument("--reconnect-every", type=int, default=0, help="Force reconnect every N events (0 disables)")
    parser.add_argument("--max-retries", type=int, default=1)
    parser.add_argument("--retry-backoff-ms", type=int, default=120)
    parser.add_argument("--session-timeout", type=int, default=300)
    parser.add_argument("--power-w", type=float, default=None)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))

    parser.add_argument("--serial-port", default="", help="Serial port for Mega (e.g., COM5 or /dev/ttyACM0)")
    parser.add_argument("--baudrate", type=int, default=115200)
    parser.add_argument("--serial-read-timeout", type=float, default=0.4)
    parser.add_argument("--event-timeout", type=float, default=60.0)
    parser.add_argument("--simulate", action="store_true", help="Use synthetic events instead of serial input")
    parser.add_argument("--simulate-interval-ms", type=int, default=2000)
    args = parser.parse_args()

    host, port = _normalize_host_port(args.host, args.port)
    power_w = args.power_w if args.power_w is not None else DEFAULT_POWER_PROFILE_W.get(args.device_class, DEFAULT_POWER_PROFILE_W["unknown"])

    output_path = Path(args.output)
    _ensure_csv_header(output_path)

    if args.protocol == "proposed":
        if port == 9020:
            print("Warning: proposed protocol typically uses port 9010.")
        protocol_handler: ProtocolHandler = ProposedProtocolHandler(host=host, port=port, session_timeout=args.session_timeout)
    else:
        if port == 9010:
            print("Warning: baseline protocol typically uses port 9020.")
        protocol_handler = BaselineProtocolHandler(host=host, port=port)

    if args.simulate:
        source: SensorSource = SimulatedSensorSource(interval_ms=args.simulate_interval_ms)
    else:
        if not args.serial_port:
            raise ValueError("--serial-port is required unless --simulate is used.")
        source = SerialSensorSource(
            port=args.serial_port,
            baudrate=args.baudrate,
            read_timeout_s=args.serial_read_timeout,
            event_timeout_s=args.event_timeout,
        )

    run_id = uuid.uuid4().hex[:12]
    reconnect_index = 0
    process = psutil.Process(os.getpid()) if psutil is not None else None

    print(f"Phase2 bridge run_id={run_id}")
    print(f"Protocol={args.protocol}, gateway={host}:{port}, scenario={args.scenario}, events={args.events}")

    pending_handshake = protocol_handler.open_session()
    delivered = 0
    sensor_epoch_offset_ms: int | None = None

    try:
        for event_index in range(1, args.events + 1):
            if args.reconnect_every > 0 and event_index > 1 and (event_index - 1) % args.reconnect_every == 0:
                protocol_handler.close()
                reconnect_index += 1
                pending_handshake = protocol_handler.open_session()

            event = source.next_event()
            edge_rx_ts_ms = int(time.time() * 1000)
            normalized_sensor_ts_ms, sensor_epoch_offset_ms = _normalize_sensor_timestamp(
                sensor_ts_ms=event.sensor_ts_ms,
                edge_rx_ts_ms=edge_rx_ts_ms,
                current_offset_ms=sensor_epoch_offset_ms,
            )
            payload = _build_payload(event=event, scenario=args.scenario, device_id=args.device_id)

            mem_before = process.memory_info().rss if process is not None else 0
            cpu_before = time.process_time()
            wall_before = time.perf_counter()

            retry_count = 0
            send_success = False
            ack_valid = False
            encrypt_latency_ms = 0.0
            roundtrip_latency_ms = 0.0
            ack_rx_ts_ms = 0
            session_id = ""
            connection_id = ""
            error_text = ""

            used_handshake = pending_handshake

            while retry_count <= args.max_retries and not send_success:
                try:
                    sent = protocol_handler.send_payload(payload)
                    encrypt_latency_ms = sent.encrypt_latency_ms
                    roundtrip_latency_ms = sent.roundtrip_latency_ms
                    ack_valid = sent.ack_valid
                    ack_rx_ts_ms = sent.ack_rx_epoch_ms
                    session_id = sent.session_id
                    connection_id = sent.connection_id
                    send_success = ack_valid
                    if not ack_valid:
                        error_text = "ACK validation failed"
                        raise ValueError(error_text)
                except Exception as error:
                    error_text = str(error)
                    if retry_count >= args.max_retries:
                        break
                    retry_count += 1
                    try:
                        protocol_handler.close()
                    except Exception:
                        pass
                    reconnect_index += 1
                    pending_handshake = protocol_handler.open_session()
                    used_handshake = pending_handshake
                    time.sleep(max(args.retry_backoff_ms, 0) / 1000.0)

            wall_after = time.perf_counter()
            cpu_after = time.process_time()
            mem_after = process.memory_info().rss if process is not None else 0

            wall_delta = max(wall_after - wall_before, 1e-9)
            cpu_pct = ((cpu_after - cpu_before) / wall_delta) * 100.0
            memory_delta_mb = ((mem_after - mem_before) / (1024 * 1024)) if process is not None else 0.0
            estimated_energy_j = power_w * wall_delta
            energy_per_message_mj = estimated_energy_j * 1000.0

            handshake_latency_ms = used_handshake.latency_ms if used_handshake is not None else 0.0
            resumed = int(used_handshake.resumed) if used_handshake is not None else 0
            resume_expected = 0
            if used_handshake is not None and args.protocol == "proposed":
                resume_expected = 1 if reconnect_index > 0 else 0

            if send_success:
                delivered += 1
                pending_handshake = None
            else:
                try:
                    protocol_handler.close()
                    reconnect_index += 1
                    pending_handshake = protocol_handler.open_session()
                except Exception:
                    pass

            sensor_to_ack_latency_ms = (ack_rx_ts_ms - normalized_sensor_ts_ms) if ack_rx_ts_ms > 0 else 0

            _append_row(
                output_path,
                [
                    run_id,
                    datetime.now(timezone.utc).isoformat(),
                    args.protocol,
                    args.device_id,
                    args.device_class,
                    args.scenario,
                    event_index,
                    event.seq,
                    event.status,
                    event.finger_id,
                    event.confidence,
                    event.sensor_ts_ms,
                    normalized_sensor_ts_ms,
                    edge_rx_ts_ms,
                    ack_rx_ts_ms,
                    f"{handshake_latency_ms:.6f}",
                    resumed,
                    resume_expected,
                    reconnect_index,
                    f"{encrypt_latency_ms:.6f}",
                    f"{roundtrip_latency_ms:.6f}",
                    f"{float(sensor_to_ack_latency_ms):.6f}",
                    retry_count,
                    int(send_success),
                    int(ack_valid),
                    source.latest_free_ram_bytes,
                    f"{cpu_pct:.6f}",
                    f"{memory_delta_mb:.6f}",
                    f"{wall_delta:.6f}",
                    f"{estimated_energy_j:.6f}",
                    f"{energy_per_message_mj:.6f}",
                    len(payload),
                    session_id,
                    connection_id,
                    error_text,
                ],
            )

            source.send_bridge_ack(event.seq, send_success, error_text)

            print(
                f"event={event_index}/{args.events} seq={event.seq} success={send_success} "
                f"enc_ms={encrypt_latency_ms:.3f} rtt_ms={roundtrip_latency_ms:.3f} "
                f"resume={resumed} retries={retry_count}"
            )

    finally:
        try:
            protocol_handler.close()
        except Exception:
            pass
        source.close()

    delivery_rate = (delivered / max(args.events, 1)) * 100.0
    print("Phase2 edge bridge finished.")
    print(f"Output CSV: {output_path}")
    print(f"Delivered events: {delivered}/{args.events} ({delivery_rate:.2f}%)")


if __name__ == "__main__":
    main()
