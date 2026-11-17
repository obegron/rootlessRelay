"use strict";
// Deterministic virtual clock + timer queue. Lets the checkers drive the real
// production classes through every timer interleaving without real time.
class Sim {
  constructor() { this.now = 0; this.nextId = 1; this.timers = new Map(); }
  clock = () => this.now;
  setTimeout = (fn, delay) => {
    const id = this.nextId++;
    this.timers.set(id, { at: this.now + Math.max(0, delay), fn, id });
    return id;
  };
  clearTimeout = (id) => { this.timers.delete(id); };
  get pending() { return this.timers.size; }
  advance(ms) {
    const target = this.now + ms;
    for (;;) {
      let next = null;
      for (const t of this.timers.values()) {
        if (t.at <= target && (!next || t.at < next.at || (t.at === next.at && t.id < next.id))) next = t;
      }
      if (!next) break;
      this.timers.delete(next.id);
      this.now = Math.max(this.now, next.at);
      next.fn();
    }
    this.now = target;
  }
}

class Violation extends Error {}
function check(cond, msg, ctx) {
  if (!cond) throw new Violation(`${msg}${ctx ? `\n  trace: ${ctx()}` : ""}`);
}

// Enumerate every action sequence up to `depth`, calling run(seq) on each.
function enumerate(alphabet, depth, run) {
  let count = 0;
  const seq = [];
  (function rec(d) {
    if (d > 0) { run(seq); count++; }
    if (d === depth) return;
    for (const a of alphabet) { seq.push(a); rec(d + 1); seq.pop(); }
  })(0);
  return count;
}

// Small deterministic PRNG so random walks are reproducible.
function rng(seed) {
  let s = seed >>> 0;
  return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 4294967296; };
}

module.exports = { Sim, Violation, check, enumerate, rng };
