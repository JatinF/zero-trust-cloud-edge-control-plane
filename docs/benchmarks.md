# Benchmarks

The proposed engineering targets are 3 edge sites, 300 endpoints, local authorization P95 at or below 20 ms, and online policy sync P95 at or below 5 s. They are targets. The numbers below are one in-process run on the authoring workstation. They are not a network deployment and they are not a pass gate.

## Workstation

- Processor: 11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz
- Cores: 4
- Logical processors: 8
- Go: go1.26.4
- OS and architecture: windows/amd64
- `runtime.NumCPU` in the report: 8

The processor name came from `Win32_Processor` on this machine. The other fields came from `go run ./cmd/control-plane bench`.

## Command

```text
go run ./cmd/control-plane bench
```

The report is `reports/bench_results.json`.

| Field | Measured |
| --- | --- |
| Authorization samples | 2000 |
| Authorization P50 | 998 µs |
| Authorization P95 | 2049 µs |
| Authorization max | 10231 µs |
| Sync samples | 8 |
| Sync P50 | 29.492 ms |
| Sync P95 | 32.199 ms |
| Endpoint records | 300 |
| Price | none |

The percentile is the sample at index `int((n-1)*p)` after the durations are sorted. Authorization time is an in-process `Authorize` call on `SYN-EDGE-BRANCH` for a permitted application read. Sync time is one publish, one dispatch, and `SyncAll` across the three edges, including the in-process mTLS fetch. Microseconds are integer `Duration.Microseconds` values.

On this run, 2049 µs is below the 20 ms authorization target and 32.199 ms is below the 5 s sync target. Both comparisons are for this in-process lab only.

`go test ./benchmarks/...` compiles the benchmark programs and does not run them. `go test -bench . -benchtime=1x ./benchmarks/...` runs them. Those programs are separate from the JSON report. Their output was not recorded here.

No price was applied.
