# Throughput benchmark results

Command: `./scripts/bench.sh --copies 16 --runs 7 --threads 1,2,4,8` (runs `cargo bench --bench throughput`)

- Date: 2026-10-24
- Machine: Apple M1 Pro (Darwin arm64)
- Load average when started: 4.78 8.20 9.76
- Input: synthetic file stitched from the committed samples' chunks (see DATA.md)

input: 944 chunks, 59.0 MiB (16 copies of 59 sample chunks); 8 logical cores; median of 7 runs

| workload | threads | median s | MiB/s | records/s | speedup |
|----------|--------:|---------:|------:|----------:|--------:|
| parse | 1 | 0.349 | 168.8 | 221402 | 1.00x |
| parse | 2 | 0.214 | 276.1 | 362051 | 1.64x |
| parse | 4 | 0.126 | 468.1 | 613812 | 2.77x |
| parse | 8 | 0.084 | 698.8 | 916369 | 4.14x |
| dump | 1 | 0.590 | 100.0 | 131122 | 1.00x |
| dump | 2 | 0.368 | 160.3 | 210186 | 1.60x |
| dump | 4 | 0.220 | 268.0 | 351394 | 2.68x |
| dump | 8 | 0.220 | 267.9 | 351273 | 2.68x |
