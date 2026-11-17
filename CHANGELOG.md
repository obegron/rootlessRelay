# Changelog

## Unreleased

### Fixed

- A malformed admin API request body no longer crashes the relay. Rule and
  nickname requests are validated, limited to 64 KiB, and must use
  `Content-Type: application/json`, so other web pages cannot create port
  forwards through a browser. Removing a session nickname now works.
- UDP port forwarding keeps one NAT mapping per external client, refreshed on
  use and expired when idle, instead of one per datagram. A burst of about
  10,000 datagrams no longer hangs the relay in an endless port search.
- VM UDP traffic to Internet hosts is no longer diverted to port-forward
  clients when its destination port happens to match a NAT mapping.
- `TCP_WINDOW_SIZE` above 65535 is rejected at startup instead of failing on
  the first connection.
- A SYN on an established outbound connection (e.g. after a VM reboot reuses a
  port) gets a challenge ACK (RFC 5961) so the VM can reset the stale
  connection, instead of being ignored. Ports of just-closed connections can
  be reused immediately.
- The relay no longer answers the VM's handshake-completing ACK with an extra
  ACK.
- Sessions that share a MAC address (cloned VMs, emulator defaults) get
  distinct IPs, and closing one no longer unregisters the other. DHCP
  requests always receive the session's own IP, so a VM cannot drain the pool
  by varying its client hardware address.
- `GATEWAY_IP` now determines the VM subnet; it was previously hard-coded to
  `10.0.2.0/24` in several places.
- HTTP proxy rules with a target path keep the query string and the client's
  path unchanged instead of normalizing them with `path.join`.
- Generated UDP datagrams with a computed checksum of zero now carry `0xffff`
  (RFC 768).
- The number of buffered out-of-order TCP ranges is bounded, so tiny segments
  cannot make each packet sort tens of thousands of ranges.

### Changed

- `LOG_LEVEL` defaults to `0`. Debug logging writes several lines per packet
  and cost about 8% of loopback throughput even with output discarded.
- The TCP retransmission timeout adapts to measured round-trip time (RFC 6298,
  with Karn's algorithm), bounded below by `TCP_RTO_MIN_MS`. Connections are
  aborted only after both `TCP_RTO_MAX_RETRANSMISSIONS` and
  `TCP_RTO_GIVE_UP_MS` are exhausted.

### Performance

- Outgoing frames are built in a single buffer instead of three, with one
  payload copy per segment.
- Internet checksums are computed with 32-bit reads, about 2.4x faster for
  full-size segments. Building and checksumming a 1460-byte TCP packet is
  about 3x faster overall.
- Clock reads are shared within each synchronous batch of work, and ACKs no
  longer cancel and re-create the retransmission timer. Both matter on hosts
  where reading the clock is a system call (HPET or ACPI PM clocksource).

## 0.6.1 — 2026-10-18

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
- Use slow start below ssthresh (RFC 5681, with RFC 3465 byte counting) instead
  of always growing the congestion window by one segment per round trip.

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
