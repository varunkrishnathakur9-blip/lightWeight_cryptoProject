# Phase 2 Hardware-in-the-Loop Summary

| Protocol | Device | Scenario | Runs | Delivered | Delivery % | Handshake (ms) | Resume Hit % | Sensor->ACK p50 (ms) | Sensor->ACK p95 (ms) | Throughput (events/s) | Retry Avg | Free RAM Min (bytes) | Energy/msg (mJ) |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | mega2560_r307s | periodic | 3 | 30/80 | 37.50 | 1739847564834.403 | 0.00 | 224.033 | 417.000 | 214.496 | 0.000 | 1 | 0.305 |
| baseline | mega2560_sim | periodic | 1 | 5/5 | 100.00 | 4.442 | 0.00 | 1.000 | 1.000 | 2008.032 | 0.000 | 4096 | 0.299 |
| proposed | mega2560_r307s | periodic | 6 | 115/198 | 58.08 | 1713262585587.981 | 25.00 | 25687.713 | 116922.000 | 60.409 | 0.000 | 1 | 5.597 |
| proposed | mega2560_sim | periodic | 1 | 5/5 | 100.00 | 37.815 | 100.00 | 7.800 | 9.000 | 127.600 | 0.000 | 4096 | 4.702 |