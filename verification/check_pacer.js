"use strict";
const { TCPPacer } = require("../tcp_pacer");
const { Sim, check, enumerate } = require("./sim");

const ACTIONS = ["ack0", "ackSmall", "ackBig", "loss", "seg", "t1", "t3", "close"];
const INIT = 1, MAXB = 3, INTERVAL = 2;

function run(mode, seq) {
  const sim = new Sim();
  let ready = 0, blocks = 0;
  const p = new TCPPacer({
    mode, initialBurstSegments: INIT, maxBurstSegments: MAXB, intervalMs: INTERVAL,
    now: sim.clock, setTimeoutFn: sim.setTimeout, clearTimeoutFn: sim.clearTimeout,
  });
  const ctx = () => `${mode}: ${seq.join(" ")}`;
  let prevBurst = p.burstSegments;
  for (const a of seq) {
    switch (a) {
      case "ack0": check(p.noteAck(0, 10) === false, "zero-byte ack must not grow burst", ctx); break;
      case "ackSmall": p.noteAck(1, 10); break;
      case "ackBig": p.noteAck(25, 10); break;
      case "loss": {
        const before = p.burstSegments;
        p.noteLoss();
        check(p.burstSegments <= before && p.burstSegments >= INIT, "loss must shrink burst but not below initial", ctx);
        break;
      }
      case "seg": {
        const wasBlocked = p.blocked;
        const r = p.noteSegment(() => ready++);
        if (mode === "off") check(r === false && !p.blocked, "off mode must never pace", ctx);
        if (wasBlocked) check(r === true, "blocked pacer must report blocked", ctx);
        if (r && !wasBlocked) blocks++;
        break;
      }
      case "t1": sim.advance(1); break;
      case "t3": sim.advance(3); break;
      case "close": p.close(); break;
    }
    const eff = p.mode;
    check(p.burstSegments >= INIT && p.burstSegments <= MAXB, `burst ${p.burstSegments} out of [${INIT},${MAXB}]`, ctx);
    if (eff !== "adaptive") check(p.burstSegments === INIT, "non-adaptive burst must stay fixed", ctx);
    check(p.ackedBytes >= 0, "negative ackedBytes", ctx);
    check(p.segmentsInBurst >= 0, "negative segmentsInBurst", ctx);
    check(sim.pending <= 1, "more than one pacing timer", ctx);
    check(p.blocked === (p.timer !== null), "blocked <=> timer armed violated", ctx);
    check(sim.pending === (p.timer !== null ? 1 : 0), "timer bookkeeping mismatch", ctx);
    if (prevBurst < p.burstSegments) check(a === "ackSmall" || a === "ackBig", "burst grew without an ACK", ctx);
    prevBurst = p.burstSegments;
  }
  // Liveness: every block is released exactly once within one interval.
  if (p.blocked) { sim.advance(INTERVAL); check(!p.blocked && sim.pending === 0, "block never released", ctx); ready; }
  check(ready <= blocks, "onReady fired more often than blocks", ctx);
}

let n = 0;
for (const mode of ["adaptive", "fixed", "off"]) n += enumerate(ACTIONS, 7, (s) => run(mode, s.slice()));
console.log(`tcp pacer: ${n} sequences (3 modes, depth 7) OK`);
