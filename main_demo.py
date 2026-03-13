"""End-to-end demo for the lightweight secure communication protocol."""

from __future__ import annotations

import json
import time

from lightweight_secure_channel.network.client import IoTClient
from lightweight_secure_channel.network.server import GatewayServer
from lightweight_secure_channel.utils.benchmark import BenchmarkRunner
from lightweight_secure_channel.utils.logger import configure_logger


def run_demo() -> None:
    logger = configure_logger("lscp.demo")
    server = GatewayServer(host="127.0.0.1", port=9009, kdf_mode="ascon", session_timeout=300)
    server_thread = server.start_in_thread()
    time.sleep(0.4)

    client = IoTClient(host="127.0.0.1", port=9009, kdf_mode="ascon", session_timeout=300)

    t0 = time.perf_counter()
    first_handshake = client.connect()
    handshake_ms = (time.perf_counter() - t0) * 1000.0
    print(f"Handshake time: {handshake_ms:.2f} ms")
    print(f"Session resumed: {first_handshake.resumed}")

    messages = ["temperature=23.1", "humidity=61", "status=nominal"]
    for message in messages:
        response = client.send_message(message)
        print(f"Client sent: {message} | Server replied: {response}")
    client.close()

    time.sleep(0.2)

    t1 = time.perf_counter()
    second_handshake = client.connect()
    resumed_ms = (time.perf_counter() - t1) * 1000.0
    print(f"Resumed handshake time: {resumed_ms:.2f} ms")
    print(f"Session resumed: {second_handshake.resumed}")

    resumed_response = client.send_message("reconnect-check")
    print(f"Client sent: reconnect-check | Server replied: {resumed_response}")
    client.close()

    benchmark_runner = BenchmarkRunner(output_dir="benchmark_results")
    benchmark_report = benchmark_runner.run_experiments(num_messages=100, payload_size=128)

    print(f"Encryption time (ASCON mean): {benchmark_report.ascon_encrypt.mean_ms:.3f} ms")
    print(f"Decryption time (ASCON mean): {benchmark_report.ascon_decrypt.mean_ms:.3f} ms")
    print(f"AES-GCM encryption mean: {benchmark_report.aes_encrypt.mean_ms:.3f} ms")
    print(f"Memory delta: {benchmark_report.memory_delta_mb:.3f} MB")
    print(f"CPU utilization (process): {benchmark_report.cpu_utilization_pct:.2f}%")
    print("Plots:")
    for name, path in benchmark_report.plot_files.items():
        print(f"  {name}: {path}")

    logger.info("Benchmark summary:\n%s", json.dumps(benchmark_report.to_dict(), indent=2))

    server.stop()
    server_thread.join(timeout=2)


if __name__ == "__main__":
    run_demo()

