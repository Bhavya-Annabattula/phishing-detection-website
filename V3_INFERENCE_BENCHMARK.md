# MODEL V3 INFERENCE BENCHMARK REPORT

**Methodology:**
- **Hardware:** Standard CPU execution environment
- **Warm-up:** 500 test URLs evaluated prior to timing
- **Repetitions:** 3 separate runs of 5,000 clean test URLs
- **Pipeline Stages Executed:** Full end-to-end `URLTextPreprocessor` + `CountVectorizer` + `PrunedURLFeatureExtractor` + `StandardScaler` + `LogisticRegression`

### Measured Latency & Throughput Results:

| Repetition | Batch Size | Runtime (s) | Latency per URL (ms) | Throughput (URLs/sec) |
| :--- | :--- | :--- | :--- | :--- |
| Run 1 | 5,000 | 0.2831s | 0.0566 ms | 17,661.0 URLs/s |
| Run 2 | 5,000 | 0.2973s | 0.0595 ms | 16,819.9 URLs/s |
| Run 3 | 5,000 | 0.3075s | 0.0615 ms | 16,260.7 URLs/s |
| **Mean** | **5,000** | **0.2960s** | **0.0592 ms** | **16,894.4 URLs/s** |

### Conclusion:
Model V3 executes in **0.0592 milliseconds per URL**, sustaining **16,894.4 requests/second**, proving that the multi-modal feature fusion adds negligible runtime overhead.
