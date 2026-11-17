# Formal verification

Run everything with `npm run verify` (`verification/run_all.sh`). The model
checkers need only Node; `proofs.py` needs `pip install z3-solver`.

**Scope:** the relay data path: `tcp_utils.js`, `tcp_retransmission.js`,
`tcp_pacer.js`, `udp_flow_manager.js`, `rate_limiter.js`, `packet_utils.js`,
and the sequence arithmetic used by the TCP receive path in `relay.js`.
**Excluded, as requested:** the admin server, admin API, rule validation and
`admin.html`. The HTTP reverse proxy and the TCP state machine inside
`relay.js` are also not modelled (see *Not covered*).

## Method

Two complementary techniques, both run against the **real production code**
(not a re-implementation):

1. **SMT proofs (`proofs.py`, Z3)**: 36 lemmas, proved for *all* inputs by
   showing the negation unsatisfiable. 32-bit sequence arithmetic is modelled as
   BV32; checksum sums (JS doubles below 2^53) as unbounded integers.
2. **Bounded-exhaustive model checking + refinement**: the production classes
   are driven by every action sequence up to a depth (and by seeded random
   walks to much greater depth) on a virtual clock (`sim.js`) and compared after
   every step with an independent abstract model, plus structural invariants.

| Artifact | What is established |
| --- | --- |
| `proofs.py` | `seqLessThan` is irreflexive, antisymmetric except at exactly 2^31, total otherwise, and correct across wrap. `acknowledge` classification is exact: "advanced" iff ack in (sndUna, sndNxt], never misclassified (given in-flight < 2^31). Out-of-order sort comparators and offsets are correct across wrap for offsets up to 2^20. Checksum: fold terminates (5 steps), preserves value mod 65535, never yields 0 for positive input; byte-swap/32-bit-word fast path is exact; stored-checksum cancellation is exact; no accumulator overflow. Pacer burst invariant `initial <= burst <= max` is inductive. `parseTCPOptions` reads stay in `[start,end)` and the loop terminates. RTO is always within `[min,max]`; backoff is bounded and monotone. |
| `check_retransmission.js` | 6.9M sequences (exhaustive to depth 5 over 20 actions, 2 ISNs incl. wrap, + 150k random walks of length 10-50). Refines the abstract sequence-space model (SYN/data/FIN cells, partial ACKs, ACK status, bytes acked, in-flight bytes). Segments stay contiguous from `sndUna` to `sndNxt`; at most one live timer; a timer is armed iff data is outstanding or persist is on; RTO in range; `onExhausted` fires at most once and is terminal; `track` throws exactly when closed/exhausted; injected callback failures are handled. **Liveness:** a stalled queue is always eventually exhausted. |
| `check_ooo.js` | 14.5M receive sequences with the relay's in-order/old/future classification, 3 ISNs incl. wrap. Exact refinement of "first copy wins" buffering and in-order delivery; ranges disjoint, in `(0, capacity)`, `<= maxRanges`, byte accounting exact; delivered bytes are always a genuine contiguous prefix of the stream; nothing left undrained at `RCV.NXT`. Also under tight capacity/range caps. |
| `check_rate_limiter.js` | 11.1M sequences vs a naive sliding-window reference: accept/reject and `usage` identical, limit never exceeded. Safe under a backwards-stepping clock and drains afterwards. |
| `check_pacer.js` | 7.2M sequences (depth 7) x 3 modes: burst bounds, `blocked <=> timer`, one timer, `off` never paces, every block released exactly once. |
| `check_udp.js` | 400k sequences vs a reference: flow cap, idle expiry, spoofed-source filtering, no socket leak or double close, `lastFlow` never dangles, error paths. |
| `check_tcp_utils.js` | `parseTCPOptions` exhaustive for every string of length <= 8 over a 6-symbol alphabet (2M) vs an independent parser, with poisoned bytes outside the window; `takeQueuedBytes` exhaustive over small queues. |
| `check_packet.js` | Checksum exhaustive for 0-2 byte inputs, then vs an RFC 1071 reference across lengths, alignments, extremes and 64 KiB; TCP/UDP checksums vs pseudo-header reference; parser fuzz (400k) never throws and never escapes the buffer; build/parse round trips. |

## Findings (both fixed, with regression tests)

- **F1: `TCPRetransmissionQueue.acknowledge()` threw after `close()`.**
  `close()` empties the segment list but keeps `sndNxt`, so a late ACK looked
  "advanced" and hit `ACK advanced beyond tracked TCP segments`. Now returns
  `{status: "stale"}`. Found by `check_retransmission.js` (trace:
  `trackD1 trackD1 trackD1 close ack1`). The relay's state guards appear to keep
  this unreachable today; the fix removes the dependence on them.
- **F2: `SlidingWindowRateLimiter` accumulated floating-point drift.** With
  fractional byte counts, `usage` was e.g. `-1.07e-14` after the window fully
  emptied. The total is now reset to exactly 0 when no entries remain. The relay
  uses integer byte counts, so this was latent.

## Observations (no change made)

- `seqLessThan(a, b)` and `seqLessThan(b, a)` are both true when the values are
  exactly 2^31 apart. Standard for modular comparison; never reached because
  in-flight data is bounded by a 16-bit window.
- Lemmas about `acknowledge` assume **A1**: bytes in flight < 2^31.
  `track()` does not enforce this itself; the relay does via the <= 65535
  window and congestion window.
- `takeQueuedBytes` is not failure-atomic: asking for more bytes than are
  queued consumes the queue before throwing. The relay guards with
  `sendQueueBytes`; callers must keep that precondition.
- After `TCPPacer.noteLoss`, `segmentsInBurst` can transiently exceed the
  reduced burst, so one extra segment may go out before pacing blocks.
- `ipv4Bytes` accepts leading zeros (`"010.0.0.1"` parses as 10.0.0.1).

## Not covered (honest limits)

- Bounded checking proves absence of violations *up to the explored depth*;
  random walks extend this probabilistically. The Z3 lemmas are unbounded.
- The TCP connection state machine and congestion control (NewReno, slow
  start, dup-ACK handling) inside the 3,000-line `relay.js`, the DHCP/ARP
  handling, WebSocket framing and the HTTP reverse proxy are **not** formally
  modelled; they are only exercised by the existing tests. Verifying them
  would first need that logic extracted into pure modules like the ones above.
- Assumptions: Node's `Buffer`, timers and `Date.now` behave as documented;
  the abstract models were written independently but by the same author as
  this check, so they encode the same reading of the RFCs.
