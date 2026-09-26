"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { TCPRetransmissionQueue } = require("../tcp_retransmission");

class FakeTimers {
  constructor() {
    this.now = 0;
    this.nextId = 1;
    this.timers = new Map();
  }

  setTimeout = (callback, delay) => {
    const id = this.nextId++;
    this.timers.set(id, { callback, at: this.now + delay });
    return id;
  };

  clearTimeout = (id) => {
    this.timers.delete(id);
  };

  advance(ms) {
    const target = this.now + ms;
    while (true) {
      let nextId = null;
      let nextTimer = null;
      for (const [id, timer] of this.timers) {
        if (timer.at <= target && (!nextTimer || timer.at < nextTimer.at)) {
          nextId = id;
          nextTimer = timer;
        }
      }
      if (!nextTimer) break;
      this.now = nextTimer.at;
      this.timers.delete(nextId);
      nextTimer.callback();
    }
    this.now = target;
  }
}

function makeQueue(options = {}) {
  const timers = new FakeTimers();
  const retransmissions = [];
  const failures = [];
  const queue = new TCPRetransmissionQueue({
    initialSequence: 100,
    onRetransmit: (segment, reason) => {
      retransmissions.push({
        seq: segment.seq,
        payload: Buffer.from(segment.payload),
        flags: { ...segment.flags },
        reason,
      });
    },
    onExhausted: (error, segment) => failures.push({ error, segment }),
    setTimeoutFn: timers.setTimeout,
    clearTimeoutFn: timers.clearTimeout,
    ...options,
  });
  return { queue, timers, retransmissions, failures };
}

test("RTO retransmits a lost final segment with the original sequence", () => {
  const { queue, timers, retransmissions } = makeQueue();
  queue.track({ seq: 100, payload: Buffer.from("final"), flags: { ack: true } });

  timers.advance(999);
  assert.equal(retransmissions.length, 0);
  timers.advance(1);
  assert.deepEqual(retransmissions, [{
    seq: 100,
    payload: Buffer.from("final"),
    flags: { ack: true },
    reason: "timeout",
  }]);
  assert.equal(queue.sndNxt, 105);
});

test("zero-window probes back off with one timer and survive responsive closed windows", () => {
  const probes = [];
  const { queue, timers, failures } = makeQueue({
    onPersistProbe: (segment) => {
      probes.push(timers.now);
      if (!segment) queue.track({ seq: 100, payload: Buffer.from("a") });
    },
    initialRtoMs: 100,
    maxRtoMs: 400,
    maxRetransmissions: 2,
  });
  queue.setPersist(true);
  timers.advance(99);
  assert.equal(probes.length, 0);
  timers.advance(1);
  assert.equal(queue.sndNxt, 101);
  assert.equal(queue.payloadBytesInFlight, 1);
  assert.equal(timers.timers.size, 1);
  queue.acknowledge(100);
  for (const interval of [200, 400, 400, 400]) {
    timers.advance(interval);
    queue.acknowledge(100);
    assert.equal(timers.timers.size, 1);
  }
  assert.deepEqual(probes, [100, 300, 700, 1100, 1500]);
  assert.equal(failures.length, 0);
  assert.equal(queue.fastRetransmit(), false);
  queue.close();
  timers.advance(5000);
  assert.equal(probes.length, 5);
  assert.equal(timers.timers.size, 0);
});

test("reopening a window immediately repairs its rejected probe then restores normal RTO", () => {
  const { queue, timers, retransmissions } = makeQueue({ onPersistProbe() {} });
  queue.track({ seq: 100, payload: Buffer.from("x") });
  queue.setPersist(true);
  timers.advance(1000);
  queue.setPersist(false);
  assert.equal(retransmissions.length, 1);
  assert.equal(retransmissions[0].reason, "window-open");
  assert.equal(queue.sndNxt, 101);
  assert.equal(timers.timers.size, 1);
  timers.advance(1000);
  assert.equal(retransmissions[1].reason, "timeout");
  queue.acknowledge(101);
  assert.equal(timers.timers.size, 0);
});

test("unanswered zero-window probes exhaust but stale or future ACKs cannot keep them alive", () => {
  const { queue, timers, failures } = makeQueue({
    onPersistProbe() {}, initialRtoMs: 100, maxRtoMs: 100, maxRetransmissions: 2,
  });
  queue.setPersist(true);
  timers.advance(100);
  queue.acknowledge(99);
  queue.acknowledge(101);
  timers.advance(200);
  assert.equal(failures.length, 1);
  assert.match(failures[0].error.message, /probe limit/);
  assert.equal(timers.timers.size, 0);
});

test("accepting a probe byte preserves the backed-off probe interval", () => {
  const { queue, timers } = makeQueue({
    onPersistProbe: () => {
      if (!queue.hasOutstanding) queue.track({ seq: queue.sndNxt, payload: Buffer.from("x") });
    },
    initialRtoMs: 100, maxRtoMs: 400,
  });
  queue.setPersist(true);
  timers.advance(100);
  queue.acknowledge(101);
  assert.equal(queue.currentRtoMs, 200);
  assert.equal(queue.hasOutstanding, false);
  assert.equal(timers.timers.size, 1);
  queue.setPersist(false);
  assert.equal(timers.timers.size, 0);
});

test("transport backpressure does not consume the unanswered probe budget", () => {
  const { queue, timers, failures } = makeQueue({
    onPersistProbe: () => false,
    initialRtoMs: 100, maxRtoMs: 100, maxRetransmissions: 2,
  });
  queue.setPersist(true);
  timers.advance(1000);
  assert.equal(queue.timeoutRetransmissions, 0);
  assert.equal(failures.length, 0);
  assert.equal(timers.timers.size, 1);
  queue.close();
});

test("ACK progress cancels the RTO and later time cannot retransmit", () => {
  const { queue, timers, retransmissions } = makeQueue();
  queue.track({ seq: 100, payload: Buffer.from("data"), flags: {} });
  assert.equal(queue.acknowledge(104).status, "advanced");

  timers.advance(10000);
  assert.equal(retransmissions.length, 0);
  assert.equal(queue.hasOutstanding, false);
});

test("adding a later segment does not postpone the oldest deadline", () => {
  const { queue, timers, retransmissions } = makeQueue();
  queue.track({ seq: 100, payload: Buffer.alloc(10), flags: {} });
  timers.advance(500);
  queue.track({ seq: 110, payload: Buffer.alloc(10), flags: {} });
  timers.advance(500);

  assert.equal(retransmissions.length, 1);
  assert.equal(retransmissions[0].seq, 100);
});

test("cumulative and partial ACKs advance and rearm for the new oldest", () => {
  const { queue, timers, retransmissions } = makeQueue();
  queue.track({ seq: 100, payload: Buffer.from("abcdef"), flags: {} });
  queue.track({ seq: 106, payload: Buffer.from("ghij"), flags: {} });

  timers.advance(500);
  const partial = queue.acknowledge(103);
  assert.equal(partial.ackedDataBytes, 3);
  assert.equal(queue.oldest.seq, 103);
  assert.equal(queue.oldest.payload.toString(), "def");
  assert.equal(queue.payloadBytesInFlight, 7);

  timers.advance(999);
  assert.equal(retransmissions.length, 0);
  timers.advance(1);
  assert.equal(retransmissions[0].seq, 103);

  const cumulative = queue.acknowledge(110);
  assert.equal(cumulative.ackedDataBytes, 7);
  assert.equal(queue.hasOutstanding, false);
});

test("ACK processing handles sequence number wraparound", () => {
  const { queue } = makeQueue({ initialSequence: 0xfffffffc });
  queue.track({ seq: 0xfffffffc, payload: Buffer.from("abcdef"), flags: {} });

  assert.equal(queue.sndNxt, 2);
  assert.equal(queue.acknowledge(0xffffffff).status, "advanced");
  assert.equal(queue.oldest.seq, 0xffffffff);
  assert.equal(queue.oldest.payload.toString(), "def");
  assert.equal(queue.acknowledge(2).status, "advanced");
  assert.equal(queue.hasOutstanding, false);
});

test("future and stale ACKs cannot discard outstanding data", () => {
  const { queue } = makeQueue();
  queue.track({ seq: 100, payload: Buffer.alloc(10), flags: {} });

  assert.equal(queue.acknowledge(111).status, "future");
  assert.equal(queue.acknowledge(99).status, "stale");
  assert.equal(queue.payloadBytesInFlight, 10);
  assert.equal(queue.sndUna, 100);
});

test("SYN and FIN consume sequence space and are retransmitted", () => {
  const { queue, timers, retransmissions } = makeQueue();
  queue.track({ seq: 100, payload: Buffer.alloc(0), flags: { syn: true } });
  assert.equal(queue.sndNxt, 101);
  timers.advance(1000);
  assert.equal(retransmissions[0].flags.syn, true);
  queue.acknowledge(101);

  queue.track({ seq: 101, payload: Buffer.alloc(0), flags: { fin: true, ack: true } });
  assert.equal(queue.sndNxt, 102);
  timers.advance(1000);
  assert.equal(retransmissions[1].seq, 101);
  assert.equal(retransmissions[1].flags.fin, true);
});

test("fast retransmit does not advance sequence state or duplicate tracking", () => {
  const { queue, retransmissions } = makeQueue();
  queue.track({ seq: 100, payload: Buffer.from("data"), flags: {} });
  assert.equal(queue.fastRetransmit(), true);

  assert.equal(retransmissions[0].reason, "fast");
  assert.equal(queue.sndNxt, 104);
  assert.equal(queue.segments.length, 1);
});

test("RTO backs off and exhausts exactly once", () => {
  const { queue, timers, retransmissions, failures } = makeQueue({
    initialRtoMs: 100,
    maxRtoMs: 250,
    maxRetransmissions: 3,
  });
  queue.track({ seq: 100, payload: Buffer.from("x"), flags: {} });

  timers.advance(100); // retry 1, next 200
  timers.advance(200); // retry 2, next 250
  timers.advance(250); // retry 3, next 250
  timers.advance(250); // exhausted
  timers.advance(1000);

  assert.equal(retransmissions.length, 3);
  assert.equal(failures.length, 1);
  assert.match(failures[0].error.message, /limit exceeded/);
});

test("closing invalidates pending timer callbacks", () => {
  const { queue, timers, retransmissions, failures } = makeQueue();
  queue.track({ seq: 100, payload: Buffer.from("x"), flags: {} });
  queue.close();
  timers.advance(100000);

  assert.equal(retransmissions.length, 0);
  assert.equal(failures.length, 0);
});
