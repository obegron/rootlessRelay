"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { TCPPacer } = require("../tcp_pacer");

function fakeTimers() {
  let now = 0;
  let nextId = 1;
  const timers = new Map();
  return {
    now: () => now,
    setTimeoutFn(callback, delay) {
      const id = nextId++;
      timers.set(id, { callback, dueAt: now + delay });
      return id;
    },
    clearTimeoutFn(id) {
      timers.delete(id);
    },
    advance(ms) {
      now += ms;
      for (const [id, timer] of [...timers]) {
        if (timer.dueAt <= now) {
          timers.delete(id);
          timer.callback();
        }
      }
    },
    get pending() {
      return timers.size;
    },
  };
}

function createPacer(options = {}) {
  const clock = fakeTimers();
  return {
    clock,
    pacer: new TCPPacer({
      initialBurstSegments: 3,
      maxBurstSegments: 8,
      intervalMs: 6,
      ...clock,
      ...options,
    }),
  };
}

test("adaptive pacer blocks once per configured burst", () => {
  const { clock, pacer } = createPacer();
  let resumed = 0;
  assert.equal(pacer.noteSegment(() => resumed++), false);
  assert.equal(pacer.noteSegment(() => resumed++), false);
  assert.equal(pacer.noteSegment(() => resumed++), true);
  assert.equal(pacer.blocked, true);
  assert.equal(clock.pending, 1);
  clock.advance(6);
  assert.equal(pacer.blocked, false);
  assert.equal(resumed, 1);
});

test("adaptive pacer grows once per clean congestion-window of ACKs", () => {
  const { pacer } = createPacer();
  assert.equal(pacer.noteAck(6000, 10000), false);
  assert.equal(pacer.noteAck(4000, 10000), true);
  assert.equal(pacer.burstSegments, 4);
  for (let index = 0; index < 10; index++) pacer.noteAck(10000, 10000);
  assert.equal(pacer.burstSegments, 8);
});

test("adaptive pacer halves on loss without dropping below its initial burst", () => {
  const { pacer } = createPacer();
  for (let index = 0; index < 5; index++) pacer.noteAck(10000, 10000);
  assert.equal(pacer.burstSegments, 8);
  assert.equal(pacer.noteLoss(), true);
  assert.equal(pacer.burstSegments, 4);
  assert.equal(pacer.noteLoss(), true);
  assert.equal(pacer.burstSegments, 3);
  assert.equal(pacer.noteLoss(), false);
});

test("fixed pacing never changes its burst", () => {
  const { pacer } = createPacer({ mode: "fixed" });
  assert.equal(pacer.noteAck(100000, 1000), false);
  assert.equal(pacer.noteLoss(), false);
  assert.equal(pacer.burstSegments, 3);
});

test("off and zero-interval pacing never create timers", () => {
  for (const options of [{ mode: "off" }, { intervalMs: 0 }]) {
    const { clock, pacer } = createPacer(options);
    assert.equal(pacer.noteSegment(() => assert.fail("unexpected callback")), false);
    assert.equal(clock.pending, 0);
  }
});

test("closing a pacer cancels its pending resume", () => {
  const { clock, pacer } = createPacer();
  let resumed = false;
  for (let index = 0; index < 3; index++) {
    pacer.noteSegment(() => {
      resumed = true;
    });
  }
  pacer.close();
  clock.advance(6);
  assert.equal(resumed, false);
  assert.equal(clock.pending, 0);
});

test("pacer rejects invalid configuration", () => {
  assert.throws(() => new TCPPacer({ mode: "other" }), /adaptive, fixed, or off/);
  assert.throws(() => new TCPPacer({ initialBurstSegments: 0 }), /positive integer/);
  assert.throws(
    () => new TCPPacer({ initialBurstSegments: 4, maxBurstSegments: 3 }),
    /at least the initial burst/,
  );
  assert.throws(() => new TCPPacer({ intervalMs: -1 }), /non-negative/);
});
