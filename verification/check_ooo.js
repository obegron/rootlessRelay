"use strict";
// Bounded-exhaustive refinement check of bufferTCPOutOfOrder/drainTCPOutOfOrder.
// The receive step mirrors the in-order/old/future classification in relay.js
// (handleTCP receive path), so the check covers the real call protocol,
// including 32-bit sequence wrap-around.
const { bufferTCPOutOfOrder, drainTCPOutOfOrder } = require("../tcp_utils");
const { Violation, check, enumerate, rng } = require("./sim");

const lt = (a, b) => ((a - b) >>> 0) > 0x7fffffff;
const ISNS = [0, 0xfffffffd, 0xffffffff];
const STREAM = 8;
const ACTIONS = [];
for (let start = 0; start <= 6; start++) for (let len = 1; len <= 3; len++) ACTIONS.push({ start, len });

function receive(w, a, idx) {
  const { conn, cap, maxRanges } = w;
  let seq = (w.isn + a.start) >>> 0;
  let payload = Buffer.alloc(a.len, idx + 1); // tag = arrival index + 1
  if (lt(seq, conn.vmSeq)) {
    const have = (conn.vmSeq - seq) >>> 0;
    if (have >= payload.length) return;
    payload = payload.subarray(have);
    seq = conn.vmSeq;
  }
  if (lt(conn.vmSeq, seq)) {
    bufferTCPOutOfOrder(conn, seq, payload, cap, maxRanges);
    return;
  }
  w.delivered.push(...payload);
  conn.vmSeq = (conn.vmSeq + payload.length) >>> 0;
  drainTCPOutOfOrder(conn, (b) => w.delivered.push(...b));
}

// Abstract model (exact when nothing is ever dropped).
function refReceive(w, a, idx) {
  const rcv = w.refDelivered.length;
  const end = a.start + a.len;
  if (end <= rcv) return;
  if (a.start > rcv) {
    for (let p = a.start; p < end; p++) {
      if (p - rcv >= w.cap) break;
      if (!w.refBuf.has(p)) w.refBuf.set(p, idx + 1);
    }
    return;
  }
  for (let p = rcv; p < end; p++) w.refDelivered.push(idx + 1);
  while (w.refBuf.has(w.refDelivered.length)) w.refDelivered.push(w.refBuf.get(w.refDelivered.length));
  for (const p of [...w.refBuf.keys()]) if (p < w.refDelivered.length) w.refBuf.delete(p);
}

function invariants(w, ctx, exact, seq) {
  const { conn, cap, maxRanges } = w;
  const rcv = (conn.vmSeq - w.isn) >>> 0;
  check(rcv === w.delivered.length, "vmSeq does not equal bytes delivered", ctx);
  // Delivered bytes are a genuine prefix of the stream: each came from a segment covering that position.
  w.delivered.forEach((tag, pos) => {
    const s = seq[tag - 1];
    check(s && pos >= s.start && pos < s.start + s.len, `delivered fabricated byte at ${pos}`, ctx);
  });
  check(conn.vmOutOfOrder.size <= maxRanges, "range count exceeds maxRanges", ctx);
  let bytes = 0;
  const seen = new Map();
  for (const [key, buf] of conn.vmOutOfOrder) {
    check(buf.length > 0, "empty buffered range", ctx);
    const off = (key - conn.vmSeq) >>> 0;
    check(off > 0 && off < cap, `buffered range offset ${off} outside (0,cap)`, ctx);
    check(off + buf.length <= cap, "buffered range exceeds capacity", ctx);
    bytes += buf.length;
    for (let i = 0; i < buf.length; i++) {
      const pos = rcv + off + i;
      check(!seen.has(pos), "overlapping buffered ranges", ctx);
      seen.set(pos, buf[i]);
      const s = seq[buf[i] - 1];
      check(s && pos >= s.start && pos < s.start + s.len, "buffered byte fabricated", ctx);
    }
  }
  check(bytes === conn.vmOutOfOrderBytes, `vmOutOfOrderBytes ${conn.vmOutOfOrderBytes} != ${bytes}`, ctx);
  check(!seen.has(rcv), "buffered data begins at rcv.nxt but was not drained", ctx);
  if (exact) {
    check(w.delivered.join() === w.refDelivered.join(), `delivered ${w.delivered} != ref ${w.refDelivered}`, ctx);
    check([...seen].sort((x, y) => x[0] - y[0]).join(";") === [...w.refBuf].sort((x, y) => x[0] - y[0]).join(";"), "buffer content differs from reference (first-copy-wins)", ctx);
  }
}

function run(seq, isn, cap, maxRanges, exact) {
  const w = {
    isn, cap, maxRanges, delivered: [], refDelivered: [], refBuf: new Map(),
    conn: { vmSeq: isn >>> 0, vmOutOfOrder: new Map(), vmOutOfOrderBytes: 0 },
  };
  const ctx = () => `isn=${isn} cap=${cap} max=${maxRanges} ${seq.map((a) => `${a.start}+${a.len}`).join(" ")}`;
  seq.forEach((a, i) => {
    receive(w, a, i);
    if (exact) refReceive(w, a, i);
    invariants(w, ctx, exact, seq);
  });
}

const t0 = Date.now();
let n = 0;
for (const isn of ISNS) {
  n += enumerate(ACTIONS, 5, (s) => run(s.slice(), isn, 1000, 1000, true));       // exact refinement
  n += enumerate(ACTIONS, 4, (s) => run(s.slice(), isn, 5, 2, false));            // tight capacity & range cap
  n += enumerate(ACTIONS, 4, (s) => run(s.slice(), isn, 4, 1000, false));
}
const rand = rng(777);
for (let i = 0; i < 200000; i++) {
  const s = Array.from({ length: 12 }, () => ACTIONS[Math.floor(rand() * ACTIONS.length)]);
  const isn = ISNS[i % 3];
  run(s, isn, 1000, 1000, true);
  run(s, isn, 6, 3, false);
  n += 2;
}
console.log(`out-of-order buffer: ${n} receive sequences (exact refinement + capacity/range-cap safety, wrap-around ISNs) OK in ${Date.now() - t0} ms`);
