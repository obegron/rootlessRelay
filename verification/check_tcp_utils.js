"use strict";
const { parseTCPOptions, takeQueuedBytes } = require("../tcp_utils");
const { check } = require("./sim");

// --- parseTCPOptions: exhaustive over a small alphabet, against an independent reference.
function refParse(bytes) {
  const out = {};
  let i = 0;
  while (i < bytes.length) {
    const kind = bytes[i];
    if (kind === 0) break;
    if (kind === 1) { i++; continue; }
    if (i + 1 >= bytes.length) break;
    const len = bytes[i + 1];
    if (len < 2 || i + len > bytes.length) break;
    if (kind === 2 && len === 4) { const v = bytes[i + 2] * 256 + bytes[i + 3]; if (v > 0) out.mss = v; }
    if (kind === 3 && len === 3) out.windowScale = bytes[i + 2];
    i += len;
  }
  return out;
}
const ALPHA = [0, 1, 2, 3, 4, 5];
let parsed = 0;
(function gen(prefix, left) {
  const opts = Buffer.from(prefix);
  // Poison bytes outside the option area: a valid MSS and window-scale option on each side.
  const poison = Buffer.from([2, 4, 0x27, 0x0f, 3, 3, 9]);
  const buf = Buffer.concat([poison, opts, poison]);
  const got = parseTCPOptions(buf, poison.length, poison.length + opts.length);
  check(JSON.stringify(got) === JSON.stringify(refParse(prefix)), `options ${prefix} => ${JSON.stringify(got)}, ref ${JSON.stringify(refParse(prefix))}`);
  parsed++;
  if (left === 0) return;
  for (const b of ALPHA) gen([...prefix, b], left - 1);
})([], 8);
// MSS/window-scale values across the full value range
for (let hi = 0; hi < 256; hi += 5) for (let lo = 0; lo < 256; lo += 5) {
  const b = [2, 4, hi, lo, 3, 3, lo];
  check(JSON.stringify(parseTCPOptions(Buffer.from(b), 0, b.length)) === JSON.stringify(refParse(b)), "value mismatch");
}
for (const bad of [[-1, 4], [0, -1], [5, 3], [2, 99]]) {
  let threw = false; try { parseTCPOptions(Buffer.alloc(4), bad[0], bad[1]); } catch (e) { threw = e instanceof RangeError; }
  check(threw, `bad bounds ${bad} must throw RangeError`);
}

// --- takeQueuedBytes: exhaustive over queues of up to 3 buffers (lengths 1..3).
let takes = 0;
function* queues() {
  for (let n = 1; n <= 3; n++) {
    const rec = function* (lens) {
      if (lens.length === n) { yield lens; return; }
      for (let l = 1; l <= 3; l++) yield* rec([...lens, l]);
    };
    yield* rec([]);
  }
}
for (const lens of queues()) {
  let c = 1;
  const make = () => { c = 1; return lens.map((l) => Buffer.from(Array.from({ length: l }, () => c++))); };
  const total = lens.reduce((a, b) => a + b, 0);
  for (let want = 1; want <= total + 1; want++) {
    const q = make();
    const flatBefore = Buffer.concat(q);
    if (want > total) {
      let threw = false; try { takeQueuedBytes(q, want); } catch (e) { threw = e instanceof RangeError; }
      check(threw, `over-request ${want}/${total} must throw RangeError`);
      continue;
    }
    const out = takeQueuedBytes(q, want);
    check(out.length === want && out.equals(flatBefore.subarray(0, want)), "taken bytes are not the queue prefix");
    check(Buffer.concat(q).equals(flatBefore.subarray(want)), "queue remainder is not the suffix");
    check(q.every((b) => b.length > 0), "empty buffer left in queue");
    takes++;
  }
}
console.log(`tcp utils: ${parsed} option strings (exhaustive, len<=8) and ${takes} queue takes (exhaustive) OK`);
