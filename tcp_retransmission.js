"use strict";

const HALF_SEQUENCE_SPACE = 0x80000000;

function sequenceDistance(later, earlier) {
  return (later - earlier) >>> 0;
}

function sequenceLength(payload, flags) {
  return payload.length + (flags.syn ? 1 : 0) + (flags.fin ? 1 : 0);
}

class TCPRetransmissionQueue {
  constructor({
    initialSequence,
    onRetransmit,
    onExhausted,
    initialRtoMs = 1000,
    maxRtoMs = 60000,
    maxRetransmissions = 4,
    setTimeoutFn = setTimeout,
    clearTimeoutFn = clearTimeout,
  }) {
    if (!Number.isInteger(initialSequence)) {
      throw new TypeError("initialSequence must be an integer");
    }
    if (typeof onRetransmit !== "function" || typeof onExhausted !== "function") {
      throw new TypeError("retransmission callbacks are required");
    }
    if (initialRtoMs <= 0 || maxRtoMs < initialRtoMs) {
      throw new TypeError("invalid RTO range");
    }
    if (!Number.isInteger(maxRetransmissions) || maxRetransmissions < 1) {
      throw new TypeError("maxRetransmissions must be a positive integer");
    }

    this.sndUna = initialSequence >>> 0;
    this.sndNxt = initialSequence >>> 0;
    this.onRetransmit = onRetransmit;
    this.onExhausted = onExhausted;
    this.initialRtoMs = initialRtoMs;
    this.maxRtoMs = maxRtoMs;
    this.maxRetransmissions = maxRetransmissions;
    this.setTimeoutFn = setTimeoutFn;
    this.clearTimeoutFn = clearTimeoutFn;
    this.currentRtoMs = initialRtoMs;
    this.timeoutRetransmissions = 0;
    this.segments = [];
    this.payloadBytesInFlight = 0;
    this.timer = null;
    this.timerGeneration = 0;
    this.closed = false;
    this.exhausted = false;
  }

  get hasOutstanding() {
    return this.segments.length > 0;
  }

  get oldest() {
    return this.segments[0] || null;
  }

  track({ seq, payload, flags = {} }) {
    if (this.closed || this.exhausted) {
      throw new Error("cannot track data on a closed retransmission queue");
    }
    if (!Buffer.isBuffer(payload)) {
      throw new TypeError("tracked payload must be a Buffer");
    }

    const length = sequenceLength(payload, flags);
    if (length === 0) return false;
    const normalizedSeq = seq >>> 0;
    if (normalizedSeq !== this.sndNxt) {
      throw new RangeError(
        `non-contiguous TCP segment: expected ${this.sndNxt}, got ${normalizedSeq}`,
      );
    }

    const segment = {
      seq: normalizedSeq,
      payload,
      flags: { ...flags },
      sequenceLength: length,
      retransmissions: 0,
    };
    this.segments.push(segment);
    this.payloadBytesInFlight += payload.length;
    this.sndNxt = (this.sndNxt + length) >>> 0;
    if (this.segments.length === 1) this.armTimer();
    return true;
  }

  acknowledge(ackNumber) {
    const ack = ackNumber >>> 0;
    const advance = sequenceDistance(ack, this.sndUna);
    const outstanding = sequenceDistance(this.sndNxt, this.sndUna);

    if (advance === 0) return { status: "duplicate", ackedDataBytes: 0 };
    if (advance >= HALF_SEQUENCE_SPACE) {
      return { status: "stale", ackedDataBytes: 0 };
    }
    if (advance > outstanding) {
      return { status: "future", ackedDataBytes: 0 };
    }

    let remaining = advance;
    let ackedDataBytes = 0;
    while (remaining > 0) {
      const segment = this.segments[0];
      if (!segment) throw new Error("ACK advanced beyond tracked TCP segments");

      if (remaining >= segment.sequenceLength) {
        remaining -= segment.sequenceLength;
        ackedDataBytes += segment.payload.length;
        this.payloadBytesInFlight -= segment.payload.length;
        this.segments.shift();
        continue;
      }

      const consumed = this.consumeSegmentPrefix(segment, remaining);
      ackedDataBytes += consumed;
      this.payloadBytesInFlight -= consumed;
      remaining = 0;
    }

    this.sndUna = ack;
    this.timeoutRetransmissions = 0;
    this.currentRtoMs = this.initialRtoMs;
    this.clearTimer();
    if (this.hasOutstanding) this.armTimer();
    return { status: "advanced", ackedDataBytes };
  }

  consumeSegmentPrefix(segment, count) {
    let remaining = count;
    let consumedData = 0;

    if (segment.flags.syn && remaining > 0) {
      segment.flags.syn = false;
      segment.sequenceLength--;
      remaining--;
    }

    if (remaining > 0 && segment.payload.length > 0) {
      const bytes = Math.min(remaining, segment.payload.length);
      segment.payload = segment.payload.subarray(bytes);
      segment.sequenceLength -= bytes;
      remaining -= bytes;
      consumedData += bytes;
    }

    if (segment.flags.fin && remaining > 0) {
      segment.flags.fin = false;
      segment.sequenceLength--;
      remaining--;
    }

    if (remaining !== 0 || segment.sequenceLength <= 0) {
      throw new Error("invalid partial TCP acknowledgement");
    }
    segment.seq = (segment.seq + count) >>> 0;
    return consumedData;
  }

  fastRetransmit() {
    if (!this.hasOutstanding || this.closed || this.exhausted) return false;
    this.currentRtoMs = this.initialRtoMs;
    this.clearTimer();
    if (!this.emitRetransmission("fast")) return false;
    this.armTimer();
    return true;
  }

  armTimer() {
    if (!this.hasOutstanding || this.closed || this.exhausted) return;
    const generation = ++this.timerGeneration;
    this.timer = this.setTimeoutFn(() => {
      if (generation !== this.timerGeneration || this.closed || this.exhausted) {
        return;
      }
      this.timer = null;
      this.handleTimeout();
    }, this.currentRtoMs);
  }

  clearTimer() {
    this.timerGeneration++;
    if (this.timer !== null) {
      this.clearTimeoutFn(this.timer);
      this.timer = null;
    }
  }

  handleTimeout() {
    if (!this.hasOutstanding || this.closed || this.exhausted) return;
    if (this.timeoutRetransmissions >= this.maxRetransmissions) {
      this.exhausted = true;
      this.clearTimer();
      this.onExhausted(new Error("TCP retransmission limit exceeded"), this.oldest);
      return;
    }

    this.timeoutRetransmissions++;
    this.oldest.retransmissions++;
    if (!this.emitRetransmission("timeout")) return;
    this.currentRtoMs = Math.min(this.currentRtoMs * 2, this.maxRtoMs);
    this.armTimer();
  }

  emitRetransmission(reason) {
    try {
      this.onRetransmit(this.oldest, reason);
      return true;
    } catch (error) {
      this.exhausted = true;
      this.clearTimer();
      this.onExhausted(error, this.oldest);
      return false;
    }
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.clearTimer();
    this.segments.length = 0;
    this.payloadBytesInFlight = 0;
  }
}

module.exports = {
  TCPRetransmissionQueue,
  sequenceDistance,
  sequenceLength,
};
