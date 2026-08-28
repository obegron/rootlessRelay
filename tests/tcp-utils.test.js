"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { parseTCPOptions, takeQueuedBytes } = require("../tcp_utils");

test("takeQueuedBytes coalesces adjacent buffers into one segment", () => {
  const queue = [
    Buffer.from("abc"),
    Buffer.from("defg"),
    Buffer.from("hijkl"),
  ];

  assert.equal(takeQueuedBytes(queue, 8).toString(), "abcdefgh");
  assert.equal(queue.length, 1);
  assert.equal(queue[0].toString(), "ijkl");
});

test("takeQueuedBytes returns a zero-copy prefix from one buffer", () => {
  const source = Buffer.from("abcdef");
  const queue = [source];
  const chunk = takeQueuedBytes(queue, 4);

  assert.equal(chunk.toString(), "abcd");
  assert.equal(queue[0].toString(), "ef");
  source[0] = 0x7a;
  assert.equal(chunk[0], 0x7a);
});

test("takeQueuedBytes validates the requested queue length", () => {
  assert.throws(() => takeQueuedBytes([], 1), /queue is empty/);
  assert.throws(
    () => takeQueuedBytes([Buffer.from("a")], 2),
    /fewer bytes than requested/,
  );
  assert.throws(() => takeQueuedBytes([Buffer.from("a")], 0), /positive/);
});

test("parseTCPOptions reads MSS and window scaling", () => {
  const packet = Buffer.from([
    0xaa,
    2, 4, 0x23, 0x00,
    1,
    3, 3, 7,
    0,
    0xbb,
  ]);

  assert.deepEqual(parseTCPOptions(packet, 1, 10), {
    mss: 8960,
    windowScale: 7,
  });
});

test("parseTCPOptions ignores undersized MSS and malformed tails", () => {
  const packet = Buffer.from([2, 4, 0, 100, 3, 4, 7]);
  assert.deepEqual(parseTCPOptions(packet, 0, packet.length), {});
  assert.throws(
    () => parseTCPOptions(packet, 0, packet.length + 1),
    /invalid TCP option bounds/,
  );
});
