# Correctness and performance investigation — 2026-09-06

The optimized relay improved the paired loopback TCP download ceiling by
**73.4%** and upload throughput by
**53.5%**. Correctness fixes preceded the performance work;
their source snapshot was retained as the control. The implementation is
`2a58844` plus the follow-up that limits WebSocket batching to unpaced mode.
The [machine-readable results](results/2026-09-06.json) include every selected
sample, workload options, variation, loss counters, and source hashes.

## Correctness findings and fixes

- Valid TCP payloads consisting of six zero bytes or six spaces were discarded
  in both relay directions. They are now forwarded unchanged.
- Outbound handshake completion discarded piggybacked data. The final handshake
  ACK now continues through normal data/FIN processing.
- A window-only ACK could leave queued data stalled when nothing was outstanding.
  Valid window updates now resume output; future/stale ACKs cannot alter the
  window. Window advertisements are ordered by sequence and ACK number.
- The relay applied peer window scaling without offering the option itself.
  Windows now remain unscaled, consistent with the negotiation requirements in
  [RFC 7323](https://datatracker.ietf.org/doc/html/rfc7323#section-2.2).
- Data-bearing ACKs and window updates could count toward fast retransmit.
  They no longer trigger false duplicate-ACK loss detection.

Five newly added wire-level regression cases were run against the original code
and failed before the fixes. Additional tests cover scaling, future ACKs,
bidirectional ACK classification, write batching/backpressure, checksum accuracy
against an independent byte-wise oracle, and exact rate-limit expiration.
The final checks passed **74 unit tests and 18 real-socket tests**. This is a
focused correctness pass, not a complete TCP conformance audit.

## Measurement method

Linux x86-64, Ryzen 7 5800H, Node v26.8.1, shared `ws` v8.21.3. Five samples per
candidate, two seconds each, alternating candidate order. Benchmark drivers and
dependencies were shared; only the relay source directory changed. Older branches
therefore did not need to contain tests or benchmarks. Branch names refer to the
local refs resolved to the hashes above; local `main` was three commits ahead of
the `origin/main` tracking ref.

Download ceiling: MSS 1460, window 65535, immediate ACK per segment, no fake-NIC
queue limit or service delay, pacing off, 1 GiB finite source. Upload: MSS 1460,
window 65535, cumulative ACK every two segments or 10 ms, unpaused loopback sink.
Rate limiting was raised to 1 GiB/s and logging disabled to expose CPU/I/O costs.
These are loopback **WS** measurements, not browser-VM or WSS results. Default
rate limits and pacing still constrain real transfers.

A benchmark bug initially obscured the download ceiling: `--ack-delay-ms=0`
still used `setTimeout(0)`. It now sends ACKs synchronously, with a regression
test. All selected TCP comparisons were rerun with the corrected shared harness.
Earlier nominal-zero-delay results are excluded from this report.

## TCP results

Median application goodput, MiB/s:

| Candidate | Download ceiling | Upload |
| --- | ---: | ---: |
| `origin/main` · `71a9ffb` | 5.40 | 40.10 |
| local `main` · `28feb31` | 17.97 | 43.00 |
| starting `develop` · `0ab2b5e` | 44.25 | 53.13 |
| correctness snapshot (paired control) | 41.77 | 50.87 |
| optimized implementation | 72.44 | 78.08 |

Use the paired control for the optimization percentages. Absolute control rates
varied across the longer investigation, so the branch rows are not simultaneous
measurements. In the final paired comparison, download coefficients of variation
were 1.2% / 2.1% (control / optimized), and upload
coefficients were 2.4% / 0.6%.
There were no reported invalid payloads, dropped/retransmitted download segments,
or exhausted sources in these ceiling comparisons. Upload's benchmark does not
simulate loss or retransmission; its zero loss counters are not a TCP loss audit.

The constrained workload uses 20 ms ACK delay, ACK every two segments, an
eight-packet fake NIC serviced every 5 ms, and adaptive pacing where supported.
Older revisions ignore the newer pacing controls. This compares their behavior
under the same receiver workload, rather than assuming identical algorithms.

| Candidate | 10,240-byte window MiB/s | 65,535-byte window MiB/s | Large-window CV | Drops / retransmissions, five large-window runs |
| --- | ---: | ---: | ---: | ---: |
| origin/main | 0.474 | 0.007 | 0.0% | 130 / 39 |
| local main | 0.474 | 0.008 | 0.0% | 114 / 54 |
| develop before this work | 0.446 | 1.505 | 5.9% | 8 / 8 |
| correctness snapshot | 0.461 | 1.522 | 0.6% | 0 / 0 |
| optimized implementation | 0.467 | 1.542 | 22.4% | 2 / 1 |

The old main implementations nearly stall with a large window on this simulated
NIC. The recent performance commits substantially improved that behavior.
Adaptive pacing still has scheduler-sensitive loss: one earlier control group
ranged from 0.474 to 1.501 MiB/s (44% CV). The CPU-ceiling gain should not be
interpreted as a comparable improvement for a constrained VM.
The final optimized large-window group included a 0.841 MiB/s outlier after
two dropped segments; its median alone does not establish a reliable gain.

## Profile-guided changes

Ten-second Node CPU profiles were collected separately from timing runs, inside
the relay child. The profile source cap was 8 GiB and was not exhausted.
Before optimization, socket writes accounted for approximately 33% of active
self samples on downloads and 50% on uploads. Repeated IP/MAC conversion,
buffer allocation, and rate-limit accounting were also visible.
In the final profiles, writes still consumed about 26% of active download
samples and 47% of upload samples. Download allocation and rate-limit accounting
accounted for roughly 14% and 10%; WebSocket unmasking was about 9% on uploads.
These percentages describe sampled active time, not measured syscall counts.

The implementation:

- Batches real TCP socket writes within an event-loop turn. WebSocket writes are
  batched only when pacing is disabled. An earlier experiment batching paced
  output produced extra fake-NIC loss and was narrowed before the final run.
- Resumes queued TCP output from WebSocket send completions instead of polling
  transport backpressure every 20 ms.
- Retains MAC bytes per session, reuses parsed IPv4 metadata, and prepares TCP
  endpoint address bytes once per connection.
- Calculates transport checksums without allocating/copying a pseudo-packet.
- Aggregates rate-limit entries sharing the same millisecond. Those bytes expire
  together, preserving the sliding-window limit exactly.

The batching uses Node's documented
[cork/nextTick/uncork pattern](https://nodejs.org/api/stream.html#writableuncork).
Final profiles and raw samples are preserved locally under
[performance-results/2026-09-06](../performance-results/2026-09-06/), an ignored
generated-artifact directory. The source snapshot used as the correctness
baseline is included there. The standalone packet microbenchmark showed roughly
7–9% higher TCP packet construction/checksum rates; these were separate,
unpaired samples and are secondary to the interleaved socket measurements.

## Reproduce

Compare the current relay against an exact branch revision using the current
benchmark harness:

```bash
npm run bench:tcp-ceiling -- --baseline-ref=71a9ffb --runs=5 --duration-ms=2000 --source-bytes=1073741824
npm run bench:tcp-ingress-compare -- --baseline-ref=71a9ffb --runs=5 --duration-ms=2000
npm run bench:tcp-compare -- --baseline-ref=71a9ffb --runs=5 --duration-ms=2000
```

Use `28feb31` for local main or `0ab2b5e` for the starting develop revision.
Add `--json` to retain full samples. The README documents
`--relay-cpu-prof-dir` for separate relay-only profiles.

The strict zero-loss network test now uses fixed three-segment bursts, providing
headroom below the fake NIC's eight-packet capacity. Adaptive loss recovery is
covered separately. Network tests run serially to reduce workload interference.
The slow-sink test now pauses three times, then resumes fully, and requires both
window closure and reopening; it no longer assumes a perpetually pausing sink
must drain within an arbitrary measurement interval.

## Remaining correctness work

The September 26 follow-up fixes overlapping/resegmented receive tails,
zero-window recovery, and missing/small MSS handling. It also removes the
outbound short-write ACK dependency to favor interactive latency. These changes
have unit and wire-level regression coverage in both relay directions; the
throughput figures above describe the September 6 implementation, not these
later changes. MSS handling follows
[RFC 9293 section 3.7.1](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.7.1).

Receive-sequence/RST validation remains incomplete. Incoming checksums are not
comprehensively validated.

WSS, actual browser VMs, multiple competing sessions, and higher-latency real
networks were not benchmarked in this pass. The remaining profile hotspots are
socket writes, buffer allocation, rate-limit accounting, and WebSocket unmasking;
these are candidates for the next measured pass.
