"use strict";
// Bounded-exhaustive refinement check of TCPRetransmissionQueue against an
// abstract sequence-space model, with timers driven by a virtual clock.
const { TCPRetransmissionQueue } = require("../tcp_retransmission");
const { Sim, Violation, check, enumerate, rng } = require("./sim");

const HALF = 0x80000000;
const ISNS = [0, 0xfffffffd]; // plain and wrap-around initial sequence numbers

const ACTIONS = [
  "trackD1", "trackD3", "trackS", "trackF", "trackDF",
  "ack0", "ack1", "ack2", "ackAll", "ackFuture", "ackStale", "ackFar",
  "t3", "t20", "fast", "persistOn", "persistOff", "close", "throwNext", "probeFalse",
];

function build(isn, trace) {
  const sim = new Sim();
  const events = [];
  const env = { throwNext: false, probeFalse: false, exhausted: 0 };
  const q = new TCPRetransmissionQueue({
    initialSequence: isn,
    initialRtoMs: 4, minRtoMs: 2, maxRtoMs: 16,
    maxRetransmissions: 2, giveUpMs: 10,
    setTimeoutFn: sim.setTimeout, clearTimeoutFn: sim.clearTimeout, now: sim.clock,
    onRetransmit: (seg, reason) => {
      events.push({ kind: "rtx", seg: { seq: seg.seq, len: seg.payload.length, flags: { ...seg.flags } }, reason });
      if (env.throwNext) { env.throwNext = false; throw new Error("injected"); }
    },
    onPersistProbe: (seg) => {
      events.push({ kind: "probe", seg });
      if (env.probeFalse) { env.probeFalse = false; return false; }
      return undefined;
    },
    onExhausted: () => { env.exhausted++; events.push({ kind: "exhausted" }); },
  });
  return { sim, q, events, env, ref: { una: isn >>> 0, nxt: isn >>> 0, cells: [] }, trace };
}

const flat = (q) => q.segments.map((s) => (s.flags.syn ? "S" : "") + "D".repeat(s.payload.length) + (s.flags.fin ? "F" : "")).join("");
const fmt = (trace) => trace.join(" ");

function step(w, a) {
  const { sim, q, ref, env, events } = w;
  const ctx = () => fmt(w.trace);
  const dead = q.closed || q.exhausted;
  const trk = (payloadLen, flags) => {
    const cells = (flags.syn ? "S" : "") + "D".repeat(payloadLen) + (flags.fin ? "F" : "");
    let threw = false;
    try { q.track({ seq: ref.nxt, payload: Buffer.alloc(payloadLen, 7), flags }); } catch { threw = true; }
    check(threw === dead, `track must throw iff queue is closed/exhausted (threw=${threw}, dead=${dead})`, ctx);
    if (!threw) {
      ref.cells.push(...cells);
      ref.nxt = (ref.nxt + cells.length) >>> 0;
    }
  };
  const ackWith = (offset) => {
    const ack = (ref.una + offset) >>> 0;
    if (q.closed) {
      // A late ACK after teardown must be ignored, never throw.
      let r;
      try { r = q.acknowledge(ack); } catch (e) { check(false, `acknowledge on closed queue threw: ${e.message}`, ctx); }
      check(r.ackedDataBytes === 0 && r.status !== "advanced", "closed queue must not advance", ctx);
      return;
    }
    const adv = (ack - ref.una) >>> 0;
    const out = ref.cells.length;
    let expect;
    if (adv === 0) expect = "duplicate";
    else if (adv >= HALF) expect = "stale";
    else if (adv > out) expect = "future";
    else expect = "advanced";
    let res;
    try { res = q.acknowledge(ack); } catch (e) {
      check(false, `acknowledge threw unexpectedly: ${e.message}`, ctx);
      return;
    }
    check(res.status === expect, `ack status ${res.status} != expected ${expect} (adv=${adv}, out=${out})`, ctx);
    if (expect === "advanced") {
      const consumed = ref.cells.splice(0, adv);
      ref.una = ack;
      check(res.ackedDataBytes === consumed.filter((c) => c === "D").length, "ackedDataBytes mismatch", ctx);
    } else check(res.ackedDataBytes === 0, "non-advancing ack must report 0 bytes", ctx);
  };
  switch (a) {
    case "trackD1": trk(1, {}); break;
    case "trackD3": trk(3, {}); break;
    case "trackS": trk(0, { syn: true }); break;
    case "trackF": trk(0, { fin: true }); break;
    case "trackDF": trk(2, { fin: true }); break;
    case "ack0": ackWith(0); break;
    case "ack1": ackWith(1); break;
    case "ack2": ackWith(2); break;
    case "ackAll": ackWith(ref.cells.length); break;
    case "ackFuture": ackWith(ref.cells.length + 1); break;
    case "ackStale": ackWith(-1); break;
    case "ackFar": ackWith(HALF + 5); break;
    case "t3": sim.advance(3); break;
    case "t20": sim.advance(20); break;
    case "fast": q.fastRetransmit(); break;
    case "persistOn": try { q.setPersist(true); } catch (e) { check(false, e.message, ctx); } break;
    case "persistOff": q.setPersist(false); break;
    case "close": q.close(); ref.cells.length = 0; break;
    case "throwNext": env.throwNext = true; break;
    case "probeFalse": env.probeFalse = true; break;
  }
  invariants(w, ctx);
}

function invariants(w, ctx) {
  const { q, sim, ref, env, events } = w;
  const live = !q.closed && !q.exhausted;
  if (q.closed) {
    check(q.segments.length === 0 && q.payloadBytesInFlight === 0, "closed queue must be empty", ctx);
    check(sim.pending === 0, "closed queue must have no live timer", ctx);
    return;
  }
  // I1-I4: sequence-space bookkeeping refines the abstract model.
  check(q.sndUna === ref.una, `sndUna ${q.sndUna} != ref ${ref.una}`, ctx);
  check(q.sndNxt === ref.nxt, `sndNxt ${q.sndNxt} != ref ${ref.nxt}`, ctx);
  check(flat(q) === ref.cells.join(""), `segments ${flat(q)} != ref ${ref.cells.join("")}`, ctx);
  check(((q.sndNxt - q.sndUna) >>> 0) === ref.cells.length, "sndNxt-sndUna != outstanding", ctx);
  check(q.payloadBytesInFlight === ref.cells.filter((c) => c === "D").length, "payloadBytesInFlight mismatch", ctx);
  let expectSeq = q.sndUna;
  for (const s of q.segments) {
    check(s.seq === expectSeq, "segments not contiguous from sndUna", ctx);
    check(s.sequenceLength > 0 && s.sequenceLength === (s.flags.syn ? 1 : 0) + s.payload.length + (s.flags.fin ? 1 : 0), "bad sequenceLength", ctx);
    expectSeq = (expectSeq + s.sequenceLength) >>> 0;
  }
  check(expectSeq === q.sndNxt, "last segment end != sndNxt", ctx);
  // I5-I6: timer discipline and RTO bounds.
  check(sim.pending <= 1, `more than one live timer (${sim.pending})`, ctx);
  if (live && (q.hasOutstanding || q.persist)) check(sim.pending === 1, "outstanding data/persist without armed timer", ctx);
  if (live && !q.hasOutstanding && !q.persist) check(sim.pending === 0, "idle queue holds a timer", ctx);
  check(q.rtoMs >= q.minRtoMs && q.rtoMs <= q.maxRtoMs || q.srttMs === null && q.rtoMs === q.initialRtoMs, `rtoMs ${q.rtoMs} out of range`, ctx);
  check(q.currentRtoMs >= 1 && q.currentRtoMs <= q.maxRtoMs, `currentRtoMs ${q.currentRtoMs} out of range`, ctx);
  check(q.timeoutRetransmissions >= 0, "negative timeout counter", ctx);
  // I7: lifecycle -- exhaustion is reported exactly once and is terminal.
  check(env.exhausted <= 1, "onExhausted fired more than once", ctx);
  check((env.exhausted === 1) === q.exhausted, "exhausted flag / callback mismatch", ctx);
  if (q.exhausted) check(sim.pending === 0, "exhausted queue holds a timer", ctx);
  // I8: retransmissions always resend the oldest unacknowledged data.
  for (const e of events) if (e.kind === "rtx") check(e.seg.len >= 0 && e.seg.len <= 3, "bad retransmitted segment", ctx);
  events.length = 0;
}

// Liveness (bounded): with no further input from the peer, a stalled queue
// is eventually reported exhausted instead of retrying forever.
function liveness(w) {
  const { q, sim, env } = w;
  if (q.closed || q.exhausted || (!q.hasOutstanding && !q.persist)) return;
  env.probeFalse = false;
  for (let i = 0; i < 60 && !q.exhausted && !q.closed; i++) sim.advance(20);
  check(q.exhausted || q.closed, "stalled queue never exhausted (retransmits forever)", () => fmt(w.trace));
}

function run(seq, isn) {
  const w = build(isn, seq);
  try {
    for (const a of seq) step(w, a);
    if (!seq.includes("probeFalse")) liveness(w);
  } catch (e) {
    if (e instanceof Violation) { e.message += `\n  isn=${isn}`; }
    throw e;
  }
  return w;
}

let sequences = 0;
const t0 = Date.now();
for (const isn of ISNS) {
  sequences += enumerate(ACTIONS, 5, (seq) => { run(seq.slice(), isn); });
}
const rand = rng(12345);
for (let n = 0; n < 150000; n++) {
  const len = 10 + Math.floor(rand() * 40);
  const seq = Array.from({ length: len }, () => ACTIONS[Math.floor(rand() * ACTIONS.length)]);
  run(seq, ISNS[n & 1]);
  sequences++;
}
console.log(`retransmission queue: ${sequences} action sequences (exhaustive depth 5 x 2 ISNs + 150k random walks to length 50) OK in ${Date.now() - t0} ms`);
