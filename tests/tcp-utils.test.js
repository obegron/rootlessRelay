"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  bufferTCPOutOfOrder, drainTCPOutOfOrder, parseTCPOptions, takeQueuedBytes,
} = require("../tcp_utils");

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

test("parseTCPOptions accepts small MSS and ignores malformed tails and zero MSS", () => {
  const packet = Buffer.from([2, 4, 0, 100, 3, 4, 7]);
  assert.deepEqual(parseTCPOptions(packet, 0, packet.length), { mss: 100 });
  assert.deepEqual(parseTCPOptions(Buffer.from([2, 4, 0, 0]), 0, 4), {});
  assert.throws(
    () => parseTCPOptions(packet, 0, packet.length + 1),
    /invalid TCP option bounds/,
  );
});

for (const initial of [1000, 0xfffffffc]) {
  test(`TCP reassembly deduplicates and drains overlapping tails at sequence ${initial}`, () => {
    const conn = { vmSeq: initial, vmOutOfOrder: new Map(), vmOutOfOrderBytes: 0 };
    const at = (offset) => (initial + offset) >>> 0;
    bufferTCPOutOfOrder(conn, at(4), Buffer.from("efgh"), 32);
    bufferTCPOutOfOrder(conn, at(4), Buffer.from("efghijkl"), 32);
    bufferTCPOutOfOrder(conn, at(6), Buffer.from("ghijklmn"), 32);
    assert.equal(conn.vmOutOfOrderBytes, 10, "duplicates do not consume window space");
    conn.vmSeq = at(6); // A differently segmented packet filled the initial gap.
    const received = [Buffer.from("abcdef")];
    drainTCPOutOfOrder(conn, (tail) => received.push(tail));
    assert.equal(Buffer.concat(received).toString(), "abcdefghijklmn");
    assert.equal(conn.vmSeq, at(14));
    assert.equal(conn.vmOutOfOrder.size, 0);
    assert.equal(conn.vmOutOfOrderBytes, 0);
  });
}

test("TCP reassembly clips to the receive window and frees fully covered ranges", () => {
  const conn = { vmSeq: 100, vmOutOfOrder: new Map(), vmOutOfOrderBytes: 0 };
  bufferTCPOutOfOrder(conn, 109, Buffer.alloc(20), 10);
  bufferTCPOutOfOrder(conn, 110, Buffer.alloc(1), 10);
  bufferTCPOutOfOrder(conn, 99, Buffer.alloc(2), 10);
  assert.equal(conn.vmOutOfOrderBytes, 1);
  conn.vmSeq = 111;
  assert.equal(drainTCPOutOfOrder(conn, () => assert.fail("already delivered")), 0);
  assert.equal(conn.vmOutOfOrderBytes, 0);
  assert.equal(conn.vmOutOfOrder.size, 0);
});

test("corkForTurn batches ordered writes and preserves backpressure", async () => {
  const { Writable } = require("node:stream");
  const { once } = require("node:events");
  const { corkForTurn } = require("../tcp_utils");
  const batches = [];
  const stream = new Writable({
    highWaterMark: 4,
    write(chunk, encoding, callback) { batches.push([chunk]); callback(); },
    writev(chunks, callback) { batches.push(chunks.map(({ chunk }) => chunk)); callback(); },
  });
  corkForTurn(stream);
  assert.equal(stream.write(Buffer.from("abc")), true);
  corkForTurn(stream);
  assert.equal(stream.write(Buffer.from("def")), false);
  const drained = once(stream, "drain");
  assert.equal(batches.length, 0);
  await drained;
  assert.equal(batches.length, 1);
  assert.equal(Buffer.concat(batches[0]).toString(), "abcdef");
  assert.equal(stream.writableCorked, 0);
  stream.end();
});

test("corkForTurn does not release a caller's cork or lose data on end", async () => {
  const { Writable } = require("node:stream");
  const { once } = require("node:events");
  const { corkForTurn } = require("../tcp_utils");
  const chunks = [];
  const stream = new Writable({
    write(chunk, encoding, callback) { chunks.push(chunk); callback(); },
  });
  stream.cork();
  corkForTurn(stream);
  stream.write("first");
  await new Promise((resolve) => process.nextTick(resolve));
  assert.equal(stream.writableCorked, 1);
  assert.equal(chunks.length, 0);
  stream.uncork();
  corkForTurn(stream);
  const finished = once(stream, "finish");
  stream.end("last");
  await finished;
  assert.equal(Buffer.concat(chunks).toString(), "firstlast");
});
