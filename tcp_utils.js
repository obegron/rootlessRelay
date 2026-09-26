"use strict";

function corkForTurn(stream) {
  if (!stream || stream.writableCorked > 0 || !stream.writable) return;
  stream.cork();
  process.nextTick(() => stream.uncork());
}

function getReverseFlow(srcIP, dstIP, srcPort, dstPort) {
  return {
    relaySrcIP: dstIP,
    relayDstIP: srcIP,
    relaySrcPort: dstPort,
    relayDstPort: srcPort,
  };
}

// Keep disjoint ranges, retaining the first copy of each byte. Sequence offsets
// are relative to RCV.NXT so sorting also works across the 32-bit wrap boundary.
function bufferTCPOutOfOrder(conn, sequence, payload, capacity) {
  const start = (sequence - conn.vmSeq) >>> 0;
  if (start === 0 || start >= capacity) return;
  const end = Math.min(start + payload.length, capacity);
  let cursor = start;
  const ranges = [...conn.vmOutOfOrder].sort((a, b) =>
    ((a[0] - conn.vmSeq) >>> 0) - ((b[0] - conn.vmSeq) >>> 0)
  );
  const add = (from, to) => {
    if (to <= from) return;
    // Copy only retained bytes; a small range must not pin a large WS buffer.
    const chunk = Buffer.from(payload.subarray(from - start, to - start));
    conn.vmOutOfOrder.set((conn.vmSeq + from) >>> 0, chunk);
    conn.vmOutOfOrderBytes += chunk.length;
  };
  for (const [seq, buffered] of ranges) {
    const offset = (seq - conn.vmSeq) >>> 0;
    if (offset >= end) break;
    if (offset + buffered.length <= cursor) continue;
    add(cursor, Math.min(offset, end));
    cursor = Math.max(cursor, offset + buffered.length);
    if (cursor >= end) return;
  }
  add(cursor, end);
}

function drainTCPOutOfOrder(conn, write) {
  if (conn.vmOutOfOrder.size === 0) return 0;
  const expected = conn.vmSeq;
  const ranges = [...conn.vmOutOfOrder].sort((a, b) =>
    ((a[0] - expected) | 0) - ((b[0] - expected) | 0)
  );
  let delivered = 0;
  for (const [seq, buffered] of ranges) {
    if (((seq - conn.vmSeq) | 0) > 0) break;
    conn.vmOutOfOrder.delete(seq);
    conn.vmOutOfOrderBytes -= buffered.length;
    const consumed = (conn.vmSeq - seq) >>> 0;
    if (consumed >= buffered.length) continue;
    const tail = buffered.subarray(consumed);
    write(tail);
    conn.vmSeq = (conn.vmSeq + tail.length) >>> 0;
    delivered++;
  }
  return delivered;
}

function takeQueuedBytes(queue, length) {
  if (!Array.isArray(queue)) throw new TypeError("queue must be an array");
  if (!Number.isSafeInteger(length) || length <= 0) {
    throw new TypeError("length must be a positive integer");
  }
  if (queue.length === 0) throw new RangeError("queue is empty");

  const first = queue[0];
  if (!Buffer.isBuffer(first)) throw new TypeError("queue entries must be buffers");
  if (first.length >= length) {
    const chunk = first.subarray(0, length);
    if (first.length === length) queue.shift();
    else queue[0] = first.subarray(length);
    return chunk;
  }

  const chunk = Buffer.allocUnsafe(length);
  let offset = 0;
  while (offset < length) {
    const current = queue[0];
    if (!Buffer.isBuffer(current)) {
      throw new TypeError("queue entries must be buffers");
    }
    const bytes = Math.min(current.length, length - offset);
    current.copy(chunk, offset, 0, bytes);
    offset += bytes;
    if (bytes === current.length) queue.shift();
    else queue[0] = current.subarray(bytes);
    if (queue.length === 0 && offset < length) {
      throw new RangeError("queue contains fewer bytes than requested");
    }
  }
  return chunk;
}

function parseTCPOptions(packet, start, end) {
  if (!Buffer.isBuffer(packet)) throw new TypeError("packet must be a Buffer");
  if (
    !Number.isSafeInteger(start) ||
    !Number.isSafeInteger(end) ||
    start < 0 ||
    end < start ||
    end > packet.length
  ) {
    throw new RangeError("invalid TCP option bounds");
  }

  const options = {};
  let offset = start;
  while (offset < end) {
    const kind = packet[offset];
    if (kind === 0) break;
    if (kind === 1) {
      offset++;
      continue;
    }
    if (offset + 1 >= end) break;
    const length = packet[offset + 1];
    if (length < 2 || offset + length > end) break;

    if (kind === 2 && length === 4) {
      const mss = packet.readUInt16BE(offset + 2);
      if (mss > 0) options.mss = mss;
    } else if (kind === 3 && length === 3) {
      options.windowScale = packet[offset + 2];
    }
    offset += length;
  }
  return options;
}

module.exports = {
  bufferTCPOutOfOrder,
  corkForTurn,
  drainTCPOutOfOrder,
  getReverseFlow,
  parseTCPOptions,
  takeQueuedBytes,
};
