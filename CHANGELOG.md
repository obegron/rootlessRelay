# Changelog

## Unreleased

### Fixed

- Deduplicate overlapping out-of-order TCP receive ranges and deliver their
  remaining tails, including across sequence-number wraparound.
- Recover lost zero-window reopening updates with backed-off probes in both TCP
  directions, preserving byte accounting and cleaning up probe timers on close.
- Honor small nonzero peer MSS values and use the 536-byte IPv4 default when no
  MSS is advertised, as specified by RFC 9293 section 3.7.1.

### Changed

- Forward small outbound TCP writes without waiting for earlier ACKs, matching
  reverse TCP behavior and avoiding delayed-ACK stalls for interactive traffic.
  Pacing, congestion control, and flow control remain in effect.

## 0.6.0 — 2026-09-12

### Added

- Published `rootlessrelay` command for global installs and `npx`, with all runtime modules and the admin page included in the npm package.
- TCP retransmission timeouts with exponential backoff for handshakes, data, and connection teardown in both relay directions.
- Configurable adaptive, fixed, and disabled TCP pacing, with ACK-driven congestion control and loss recovery.
- Optional jumbo VM MTUs advertised through DHCP and TCP MSS negotiation.
- TCP input backpressure, bounded send queues, and delayed cumulative ACKs for VM uploads.
- Repeatable IP-stack, WebSocket/UDP, and TCP throughput benchmarks, Git revision comparisons, and relay CPU profiling.
- Regression tests for TCP stream integrity, flow control, retransmission, packet checksums, and UDP flow isolation.

### Changed

- Reduce forwarding overhead by reusing parsed addresses, avoiding transport-checksum copies, and batching socket writes.
- Restrict WebSocket write batching to unpaced mode to preserve the timing of paced bursts.
- Resume TCP output when WebSocket writes complete instead of polling transport backpressure on a timer.
- Aggregate rate-limit accounting within each millisecond while preserving exact expiration boundaries.
- Reuse UDP sockets per flow, with idle expiry and per-session flow limits.
- Update the locked `ws` dependency to 8.21.3.

### Fixed

- Load the admin page from the installed package directory when launched from another working directory.
- Preserve valid six-byte TCP payloads containing only spaces or zero bytes.
- Deliver data carried on the final outbound TCP handshake ACK.
- Resume queued TCP data on valid window-only ACKs and reject window changes from invalid ACKs.
- Ignore unnegotiated TCP window scaling and avoid counting data-bearing ACKs or window updates as duplicate ACKs.
- Isolate UDP flows that share a VM source port but use different remote endpoints.
- Handle IPv4 header lengths, packet padding, and transport checksum boundaries consistently.
- Make zero-delay benchmark ACKs immediate, and make backpressure tests explicitly exercise sink recovery.

See the [performance investigation](https://github.com/obegron/rootlessRelay/blob/v0.6.0/benchmarks/PERFORMANCE.md) for measurements,
reproduction commands, and remaining correctness limitations.
