"""Benchmarking for handshake and ASCON vs AES-GCM encryption performance."""

from __future__ import annotations

import os
import socket
import threading
import time
from dataclasses import dataclass

import matplotlib
import psutil
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lightweight_secure_channel.crypto.ascon_cipher import ascon_decrypt, ascon_encrypt
from lightweight_secure_channel.protocol.handshake import perform_client_handshake, perform_server_handshake
from lightweight_secure_channel.protocol.session_manager import SessionManager
from lightweight_secure_channel.utils.logger import configure_logger
from lightweight_secure_channel.utils.metrics import BenchmarkReport, LatencyMetrics

matplotlib.use("Agg")
import matplotlib.pyplot as plt


@dataclass(frozen=True)
class _HandshakeMetrics:
    full_ms: float
    resumed_ms: float


class BenchmarkRunner:
    """Runs reproducible performance experiments for the prototype."""

    def __init__(self, output_dir: str = "benchmark_results") -> None:
        self.output_dir = output_dir
        self.logger = configure_logger("lscp.benchmark")
        os.makedirs(self.output_dir, exist_ok=True)

    def _run_handshake_pair(
        self,
        client_manager: SessionManager,
        server_manager: SessionManager,
        resume_token: dict | None = None,
    ) -> tuple[float, dict]:
        client_sock, server_sock = socket.socketpair()
        server_result: dict = {}

        def _server_worker() -> None:
            with server_sock:
                stream = server_sock.makefile("rwb")
                try:
                    server_result["handshake"] = perform_server_handshake(
                        stream=stream,
                        session_manager=server_manager,
                        kdf_mode="ascon",
                    )
                finally:
                    stream.close()

        server_thread = threading.Thread(target=_server_worker, daemon=True)
        server_thread.start()

        start = time.perf_counter()
        with client_sock:
            stream = client_sock.makefile("rwb")
            try:
                client_result = perform_client_handshake(
                    stream=stream,
                    session_manager=client_manager,
                    resume_token=resume_token,
                    kdf_mode="ascon",
                )
            finally:
                stream.close()
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        server_thread.join(timeout=5)
        if "handshake" not in server_result:
            raise RuntimeError("Server handshake thread did not complete.")
        return elapsed_ms, client_result.session_token

    def _measure_handshake(self) -> _HandshakeMetrics:
        client_manager = SessionManager(session_timeout=300)
        server_manager = SessionManager(session_timeout=300)

        full_ms, token = self._run_handshake_pair(
            client_manager=client_manager,
            server_manager=server_manager,
            resume_token=None,
        )
        resumed_ms, _ = self._run_handshake_pair(
            client_manager=client_manager,
            server_manager=server_manager,
            resume_token=token,
        )
        return _HandshakeMetrics(full_ms=full_ms, resumed_ms=resumed_ms)

    def run_experiments(
        self,
        num_messages: int = 100,
        payload_size: int = 128,
    ) -> BenchmarkReport:
        """Run complete benchmark suite and persist plots."""
        handshake_metrics = self._measure_handshake()

        process = psutil.Process(os.getpid())
        memory_before = process.memory_info().rss
        cpu_time_before = time.process_time()
        wall_before = time.perf_counter()

        ascon_encrypt_latencies: list[float] = []
        ascon_decrypt_latencies: list[float] = []
        aes_encrypt_latencies: list[float] = []
        aes_decrypt_latencies: list[float] = []

        ascon_key = os.urandom(16)
        aes_key = os.urandom(16)
        aesgcm = AESGCM(aes_key)

        total_bytes = 0
        total_ascon_encrypt_time = 0.0
        total_aes_encrypt_time = 0.0

        for index in range(num_messages):
            payload = os.urandom(payload_size)
            associated_data = f"bench|seq={index}|v=LSCP-1.0".encode("utf-8")
            total_bytes += len(payload)

            nonce_ascon = os.urandom(16)
            start = time.perf_counter()
            ascon_ciphertext, ascon_tag = ascon_encrypt(
                key=ascon_key,
                nonce=nonce_ascon,
                ad=associated_data,
                plaintext=payload,
            )
            elapsed = (time.perf_counter() - start) * 1000.0
            ascon_encrypt_latencies.append(elapsed)
            total_ascon_encrypt_time += elapsed / 1000.0

            start = time.perf_counter()
            _ = ascon_decrypt(
                key=ascon_key,
                nonce=nonce_ascon,
                ad=associated_data,
                ciphertext=ascon_ciphertext,
                tag=ascon_tag,
            )
            ascon_decrypt_latencies.append((time.perf_counter() - start) * 1000.0)

            nonce_aes = os.urandom(12)
            start = time.perf_counter()
            aes_ciphertext = aesgcm.encrypt(nonce_aes, payload, associated_data)
            elapsed = (time.perf_counter() - start) * 1000.0
            aes_encrypt_latencies.append(elapsed)
            total_aes_encrypt_time += elapsed / 1000.0

            start = time.perf_counter()
            _ = aesgcm.decrypt(nonce_aes, aes_ciphertext, associated_data)
            aes_decrypt_latencies.append((time.perf_counter() - start) * 1000.0)

        wall_after = time.perf_counter()
        cpu_time_after = time.process_time()
        memory_after = process.memory_info().rss

        memory_delta_mb = (memory_after - memory_before) / (1024 * 1024)
        wall_delta = max(wall_after - wall_before, 1e-9)
        cpu_utilization = ((cpu_time_after - cpu_time_before) / wall_delta) * 100.0
        ascon_throughput_mbps = (total_bytes / max(total_ascon_encrypt_time, 1e-9)) / (1024 * 1024)
        aes_throughput_mbps = (total_bytes / max(total_aes_encrypt_time, 1e-9)) / (1024 * 1024)

        report = BenchmarkReport(
            handshake_time_ms=handshake_metrics.full_ms,
            resumed_handshake_time_ms=handshake_metrics.resumed_ms,
            ascon_encrypt=LatencyMetrics(ascon_encrypt_latencies),
            ascon_decrypt=LatencyMetrics(ascon_decrypt_latencies),
            aes_encrypt=LatencyMetrics(aes_encrypt_latencies),
            aes_decrypt=LatencyMetrics(aes_decrypt_latencies),
            memory_delta_mb=memory_delta_mb,
            cpu_utilization_pct=cpu_utilization,
            ascon_throughput_mbps=ascon_throughput_mbps,
            aes_throughput_mbps=aes_throughput_mbps,
            plot_files={},
        )

        plot_files = self._save_plots(report)
        return BenchmarkReport(
            handshake_time_ms=report.handshake_time_ms,
            resumed_handshake_time_ms=report.resumed_handshake_time_ms,
            ascon_encrypt=report.ascon_encrypt,
            ascon_decrypt=report.ascon_decrypt,
            aes_encrypt=report.aes_encrypt,
            aes_decrypt=report.aes_decrypt,
            memory_delta_mb=report.memory_delta_mb,
            cpu_utilization_pct=report.cpu_utilization_pct,
            ascon_throughput_mbps=report.ascon_throughput_mbps,
            aes_throughput_mbps=report.aes_throughput_mbps,
            plot_files=plot_files,
        )

    def _save_plots(self, report: BenchmarkReport) -> dict[str, str]:
        plot_files: dict[str, str] = {}

        encryption_plot = os.path.join(self.output_dir, "encryption_latency.png")
        plt.figure(figsize=(9, 4))
        plt.plot(report.ascon_encrypt.samples_ms, label="ASCON Encrypt", linewidth=1.2)
        plt.plot(report.aes_encrypt.samples_ms, label="AES-GCM Encrypt", linewidth=1.2)
        plt.xlabel("Message Index")
        plt.ylabel("Latency (ms)")
        plt.title("Encryption Latency Comparison")
        plt.legend()
        plt.tight_layout()
        plt.savefig(encryption_plot, dpi=160)
        plt.close()
        plot_files["encryption_latency"] = encryption_plot

        handshake_plot = os.path.join(self.output_dir, "handshake_latency.png")
        plt.figure(figsize=(6, 4))
        plt.bar(
            ["Full Handshake", "Resumed Handshake"],
            [report.handshake_time_ms, report.resumed_handshake_time_ms],
            color=["#2c7fb8", "#41ab5d"],
        )
        plt.ylabel("Latency (ms)")
        plt.title("Handshake Latency")
        plt.tight_layout()
        plt.savefig(handshake_plot, dpi=160)
        plt.close()
        plot_files["handshake_latency"] = handshake_plot

        memory_plot = os.path.join(self.output_dir, "memory_usage.png")
        plt.figure(figsize=(6, 4))
        plt.bar(["Memory Delta"], [report.memory_delta_mb], color="#636363")
        plt.ylabel("MB")
        plt.title("Memory Usage Delta During Benchmark")
        plt.tight_layout()
        plt.savefig(memory_plot, dpi=160)
        plt.close()
        plot_files["memory_usage"] = memory_plot

        throughput_plot = os.path.join(self.output_dir, "throughput.png")
        plt.figure(figsize=(6, 4))
        plt.bar(
            ["ASCON", "AES-GCM"],
            [report.ascon_throughput_mbps, report.aes_throughput_mbps],
            color=["#756bb1", "#e34a33"],
        )
        plt.ylabel("MB/s")
        plt.title("Encryption Throughput Comparison")
        plt.tight_layout()
        plt.savefig(throughput_plot, dpi=160)
        plt.close()
        plot_files["throughput"] = throughput_plot

        self.logger.info("Saved benchmark plots: %s", plot_files)
        return plot_files
