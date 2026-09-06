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
      if (mss >= 536) options.mss = mss;
    } else if (kind === 3 && length === 3) {
      options.windowScale = packet[offset + 2];
    }
    offset += length;
  }
  return options;
}

module.exports = {
  corkForTurn,
  getReverseFlow,
  parseTCPOptions,
  takeQueuedBytes,
};
