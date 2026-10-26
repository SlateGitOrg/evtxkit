# Throughput benchmark results

Command: `./scripts/bench.sh --copies 16 --runs 7 --threads 1,2,4,8` (runs `cargo bench --bench throughput`)

- Date: 2026-10-26
- Machine: Apple M5 Pro (Darwin arm64)
- Load average when started: 7.41 10.13 11.04
- Input: synthetic file stitched from the committed samples' chunks (see DATA.md)

input: 944 chunks, 59.0 MiB (16 copies of 59 sample chunks); 15 logical cores; median of 7 runs

| workload | threads | median s | MiB/s | records/s | speedup |
|----------|--------:|---------:|------:|----------:|--------:|
| parse | 1 | 0.236 | 249.9 | 327737 | 1.00x |
| parse | 2 | 0.159 | 370.2 | 485421 | 1.48x |
| parse | 4 | 0.096 | 614.4 | 805659 | 2.46x |
| parse | 8 | 0.075 | 789.6 | 1035485 | 3.16x |
| dump | 1 | 0.412 | 143.4 | 188026 | 1.00x |
| dump | 2 | 0.243 | 242.7 | 318211 | 1.69x |
| dump | 4 | 0.135 | 436.3 | 572108 | 3.04x |
| dump | 8 | 0.089 | 663.5 | 870082 | 4.63x |
