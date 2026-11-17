"use strict";
const { SlidingWindowRateLimiter } = require("../rate_limiter");
const { Violation, check, enumerate, rng } = require("./sim");

const MAX = 4, WIN = 3;
const ACTIONS = ["c0", "c1", "c2", "c3", "c5", "t0", "t1", "t2", "t3", "t5"];

function run(seq) {
  let now = 1000;
  const lim = new SlidingWindowRateLimiter(MAX, WIN, () => now);
  const log = []; // accepted (timestamp, bytes)
  const ctx = () => seq.join(" ");
  for (const a of seq) {
    if (a[0] === "t") now += Number(a.slice(1));
    else {
      const b = Number(a.slice(1));
      const ref = log.filter((e) => e.t > now - WIN).reduce((s, e) => s + e.b, 0);
      const ok = lim.tryConsume(b);
      check(ok === (ref + b <= MAX), `tryConsume(${b}) = ${ok}, reference usage ${ref}`, ctx);
      if (ok) log.push({ t: now, b });
    }
    const usage = log.filter((e) => e.t > now - WIN).reduce((s, e) => s + e.b, 0);
    check(lim.usage === usage, `usage ${lim.usage} != ${usage}`, ctx);
    check(lim.usage <= MAX, "limit exceeded", ctx);
    check(lim.entries.length - lim.head >= 0, "head beyond entries", ctx);
  }
}

// Safety under an adversarial clock (wall clock may step backwards, e.g. NTP),
// and exactness of the empty state with fractional byte counts.
function clockWalk(seed) {
  const r = rng(seed);
  let now = 5000;
  const lim = new SlidingWindowRateLimiter(100, 50, () => now);
  const accepted = [];
  for (let i = 0; i < 400; i++) {
    now += Math.floor(r() * 30) - 8; // mostly forward, sometimes backward
    const b = Math.floor(r() * 40);
    if (lim.tryConsume(b)) accepted.push({ t: now, b });
    check(lim.usage >= 0 && lim.usage <= 100, `usage ${lim.usage} out of [0,100] with non-monotonic clock`);
  }
  now += 10_000;
  check(lim.usage === 0, "limiter does not drain after the clock moves past the window");
}
function fractional(seed) {
  const r = rng(seed);
  let now = 0;
  const lim = new SlidingWindowRateLimiter(10, 5, () => now);
  for (let i = 0; i < 2000; i++) { now += Math.floor(r() * 3); lim.tryConsume(Math.floor(r() * 300) / 100 + 0.1); }
  now += 100;
  check(lim.usage === 0, `usage ${lim.usage} != 0 after full expiry (floating-point drift)`);
}

const t0 = Date.now();
const n = enumerate(ACTIONS, 7, (s) => run(s.slice()));
for (let s = 1; s <= 300; s++) { clockWalk(s); fractional(s); }
console.log(`rate limiter: ${n} sequences exhaustive vs sliding-window reference; 300 non-monotonic-clock and 300 fractional-byte walks OK in ${Date.now() - t0} ms`);
