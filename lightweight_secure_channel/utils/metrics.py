"""Metrics dataclasses used by benchmark experiments."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from statistics import mean


@dataclass(frozen=True)
class LatencyMetrics:
    """Latency samples in milliseconds."""

    samples_ms: list[float]

    @property
    def mean_ms(self) -> float:
        return mean(self.samples_ms) if self.samples_ms else 0.0


@dataclass(frozen=True)
class BenchmarkReport:
    """Consolidated benchmark results."""

    handshake_time_ms: float
    resumed_handshake_time_ms: float
    ascon_encrypt: LatencyMetrics
    ascon_decrypt: LatencyMetrics
    aes_encrypt: LatencyMetrics
    aes_decrypt: LatencyMetrics
    memory_delta_mb: float
    cpu_utilization_pct: float
    ascon_throughput_mbps: float
    aes_throughput_mbps: float
    plot_files: dict[str, str]

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["ascon_encrypt"]["mean_ms"] = self.ascon_encrypt.mean_ms
        payload["ascon_decrypt"]["mean_ms"] = self.ascon_decrypt.mean_ms
        payload["aes_encrypt"]["mean_ms"] = self.aes_encrypt.mean_ms
        payload["aes_decrypt"]["mean_ms"] = self.aes_decrypt.mean_ms
        return payload

