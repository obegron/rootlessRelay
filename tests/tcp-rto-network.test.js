"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const WebSocket = require("ws");
const {
  buildIPv4Packet,
  parseIPv4Packet,
  tcpChecksum,
} = require("../packet_utils");

const ROOT = path.resolve(__dirname, "..");
const VM_IP = "10.0.2.15";
const GATEWAY_IP = "10.0.2.2";
const VM_MAC = Buffer.from([0x52, 0x54, 0x00, 0xab, 0xcd, 0xef]);
const GATEWAY_MAC = Buffer.from([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function freeTcpPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function buildTCPFrame({
  srcIP,
  dstIP,
  srcPort,
  dstPort,
  seq,
  ack = 0,
  flags = {},
  payload = Buffer.alloc(0),
  window = 65535,
  windowScale,
  mss,
}) {
  const headerLength = 20 + (windowScale === undefined ? 0 : 4) + (mss === undefined ? 0 : 4);
  const tcp = Buffer.alloc(headerLength + payload.length);
  tcp.writeUInt16BE(srcPort, 0);
  tcp.writeUInt16BE(dstPort, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp.writeUInt32BE(ack >>> 0, 8);
  tcp[12] = (headerLength / 4) << 4;
  if (windowScale !== undefined) Buffer.from([3, 3, windowScale, 1]).copy(tcp, 20);
  if (mss !== undefined) {
    Buffer.from([2, 4, mss >>> 8, mss & 255]).copy(tcp, headerLength - 4);
  }
  tcp[13] = (flags.fin ? 0x01 : 0) |
    (flags.syn ? 0x02 : 0) |
    (flags.rst ? 0x04 : 0) |
    (flags.psh ? 0x08 : 0) |
    (flags.ack ? 0x10 : 0);
  tcp.writeUInt16BE(window, 14);
  payload.copy(tcp, headerLength);

  const ip = buildIPv4Packet(tcp, srcIP, dstIP, 6, 1);
  ip.writeUInt16BE(tcpChecksum(ip), 36);
  const frame = Buffer.alloc(14 + ip.length);
  GATEWAY_MAC.copy(frame, 0);
  VM_MAC.copy(frame, 6);
  frame.writeUInt16BE(0x0800, 12);
  ip.copy(frame, 14);
  return frame;
}

function buildARPRequest() {
  const frame = Buffer.alloc(42);
  frame.fill(0xff, 0, 6);
  VM_MAC.copy(frame, 6);
  frame.writeUInt16BE(0x0806, 12);
  frame.writeUInt16BE(1, 14);
  frame.writeUInt16BE(0x0800, 16);
  frame[18] = 6;
  frame[19] = 4;
  frame.writeUInt16BE(1, 20);
  VM_MAC.copy(frame, 22);
  Buffer.from(VM_IP.split(".").map(Number)).copy(frame, 28);
  Buffer.alloc(6).copy(frame, 32);
  Buffer.from(GATEWAY_IP.split(".").map(Number)).copy(frame, 38);
  return frame;
}

function parseTCPFrame(frame) {
  if (!Buffer.isBuffer(frame) || frame.length < 54) return null;
  if (frame.readUInt16BE(12) !== 0x0800) return null;
  const parsed = parseIPv4Packet(frame.subarray(14));
  if (!parsed || parsed.protocol !== 6) return null;
  const offset = parsed.headerLength;
  if (parsed.packet.length < offset + 20) return null;
  const dataOffset = (parsed.packet[offset + 12] >>> 4) * 4;
  const flags = parsed.packet[offset + 13];
  return {
    srcIP: parsed.srcIP,
    dstIP: parsed.dstIP,
    srcPort: parsed.packet.readUInt16BE(offset),
    dstPort: parsed.packet.readUInt16BE(offset + 2),
    seq: parsed.packet.readUInt32BE(offset + 4),
    ack: parsed.packet.readUInt32BE(offset + 8),
    syn: (flags & 0x02) !== 0,
    ackFlag: (flags & 0x10) !== 0,
    fin: (flags & 0x01) !== 0,
    rst: (flags & 0x04) !== 0,
    window: parsed.packet.readUInt16BE(offset + 14),
    payload: parsed.packet.subarray(offset + dataOffset),
  };
}

class FrameQueue {
  constructor(ws) {
    this.frames = [];
    ws.on("message", (data, isBinary) => {
      if (!isBinary) return;
      const parsed = parseTCPFrame(data);
      if (parsed) this.frames.push(parsed);
    });
  }

  async waitFor(predicate, timeoutMs = 1500) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const index = this.frames.findIndex(predicate);
      if (index !== -1) return this.frames.splice(index, 1)[0];
      await delay(5);
    }
    throw new Error("Timed out waiting for TCP frame");
  }

  async expectNone(predicate, durationMs) {
    const deadline = Date.now() + durationMs;
    while (Date.now() < deadline) {
      if (this.frames.some(predicate)) {
        assert.fail("Unexpected TCP retransmission after acknowledgement");
      }
      await delay(5);
    }
  }
}

async function connectWebSocket(port, child) {
  const deadline = Date.now() + 5000;
  let lastError;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Relay exited (${child.exitCode})`);
    try {
      return await new Promise((resolve, reject) => {
        const ws = new WebSocket(`ws://127.0.0.1:${port}`, {
          perMessageDeflate: false,
        });
        ws.once("open", () => resolve(ws));
        ws.once("error", reject);
      });
    } catch (error) {
      lastError = error;
      await delay(25);
    }
  }
  throw lastError || new Error("Relay did not accept WebSocket");
}

async function startRelay(overrides = {}) {
  const wsPort = await freeTcpPort();
  const adminPort = await freeTcpPort();
  const child = spawn(process.execPath, [path.join(ROOT, "relay.js")], {
    cwd: ROOT,
    env: {
      ...process.env,
      ENABLE_WSS: "false",
      ENABLE_VM_TO_VM: "false",
      LOG_LEVEL: "0",
      WS_BIND_ADDRESS: "127.0.0.1",
      WS_PORT: String(wsPort),
      ADMIN_BIND_ADDRESS: "127.0.0.1",
      ADMIN_PORT: String(adminPort),
      PROXY_BIND_ADDRESS: "127.0.0.1",
      PROXY_PORT: "0",
      TCP_RTO_INITIAL_MS: "50",
      TCP_RTO_MAX_MS: "100",
      TCP_RTO_MAX_RETRANSMISSIONS: "2",
      REVERSE_TCP_IDLE_TIMEOUT_MS: "2000",
      ...overrides,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
  });
  const ws = await connectWebSocket(wsPort, child);
  return {
    ws,
    adminPort,
    stderr: () => stderr,
    async close() {
      ws.close();
      if (child.exitCode !== null) return;
      child.kill("SIGTERM");
      await Promise.race([
        new Promise((resolve) => child.once("exit", resolve)),
        delay(1000).then(() => child.kill("SIGKILL")),
      ]);
    },
  };
}

function listen(server, port = 0) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve(server.address().port);
    });
  });
}

function postJSON(port, pathname, value) {
  const body = JSON.stringify(value);
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: "127.0.0.1",
      port,
      path: pathname,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
    }, (response) => {
      response.resume();
      response.once("end", () => resolve(response.statusCode));
    });
    request.once("error", reject);
    request.end(body);
  });
}

function connectWithRetry(port) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 2000;
    const attempt = () => {
      const socket = net.connect(port, "127.0.0.1");
      socket.once("connect", () => resolve(socket));
      socket.once("error", (error) => {
        socket.destroy();
        if (Date.now() >= deadline) reject(error);
        else setTimeout(attempt, 20);
      });
    };
    attempt();
  });
}

test(
  "outbound TCP RTO recovers a dropped final data segment",
  { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 10000 },
  async () => {
    const payload = Buffer.from("outbound-final");
    let acceptedSocket;
    let resolveAccepted;
    const accepted = new Promise((resolve) => {
      resolveAccepted = resolve;
    });
    const server = net.createServer((socket) => {
      acceptedSocket = socket;
      resolveAccepted(socket);
      // Exercise servers that send a banner before the emulated handshake ACK.
      socket.write(payload);
    });
    const remotePort = await listen(server);
    const relay = await startRelay();
    const frames = new FrameQueue(relay.ws);
    const vmPort = 41000;
    const vmSeq = 1000;

    try {
      relay.ws.send(buildTCPFrame({
        srcIP: VM_IP,
        dstIP: "127.0.0.1",
        srcPort: vmPort,
        dstPort: remotePort,
        seq: vmSeq,
        flags: { syn: true },
      }));
      const synAck = await frames.waitFor((frame) =>
        frame.srcPort === remotePort && frame.dstPort === vmPort && frame.syn
      );
      const repeatedSynAck = await frames.waitFor((frame) =>
        frame.srcPort === remotePort && frame.dstPort === vmPort && frame.syn
      );
      assert.equal(repeatedSynAck.seq, synAck.seq);
      relay.ws.send(buildTCPFrame({
        srcIP: VM_IP,
        dstIP: "127.0.0.1",
        srcPort: vmPort,
        dstPort: remotePort,
        seq: vmSeq + 1,
        ack: (synAck.seq + 1) >>> 0,
        flags: { ack: true },
      }));
      await frames.waitFor((frame) =>
        frame.srcPort === remotePort && frame.dstPort === vmPort &&
        frame.ackFlag && !frame.syn && frame.payload.length === 0
      );

      const socket = await accepted;
      const original = await frames.waitFor((frame) => frame.payload.equals(payload));
      const retransmitted = await frames.waitFor((frame) => frame.payload.equals(payload));
      assert.equal(retransmitted.seq, original.seq);

      relay.ws.send(buildTCPFrame({
        srcIP: VM_IP,
        dstIP: "127.0.0.1",
        srcPort: vmPort,
        dstPort: remotePort,
        seq: vmSeq + 1,
        ack: (original.seq + payload.length) >>> 0,
        flags: { ack: true },
      }));
      await frames.expectNone((frame) => frame.payload.equals(payload), 175);

      socket.end();
      const fin = await frames.waitFor((frame) =>
        frame.srcPort === remotePort && frame.dstPort === vmPort && frame.fin
      );
      const repeatedFin = await frames.waitFor((frame) =>
        frame.srcPort === remotePort && frame.dstPort === vmPort && frame.fin
      );
      assert.equal(repeatedFin.seq, fin.seq);
      relay.ws.send(buildTCPFrame({
        srcIP: VM_IP,
        dstIP: "127.0.0.1",
        srcPort: vmPort,
        dstPort: remotePort,
        seq: vmSeq + 1,
        ack: (fin.seq + 1) >>> 0,
        flags: { ack: true },
      }));
      await frames.expectNone((frame) => frame.fin && frame.seq === fin.seq, 175);
    } finally {
      acceptedSocket?.destroy();
      await relay.close();
      await new Promise((resolve) => server.close(resolve));
    }
  },
);

test(
  "reverse TCP RTO recovers a dropped final port-forward segment",
  { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 10000 },
  async () => {
    const relay = await startRelay();
    const frames = new FrameQueue(relay.ws);
    const hostPort = await freeTcpPort();
    let client;

    try {
      relay.ws.send(buildARPRequest());
      await delay(30);
      assert.equal(await postJSON(relay.adminPort, "/api/rules", {
        type: "port",
        protocols: ["tcp"],
        host_port: hostPort,
        bind_address: "127.0.0.1",
        vm: VM_IP,
        port: 8080,
      }), 201);
      client = await connectWithRetry(hostPort);

      const syn = await frames.waitFor((frame) =>
        frame.srcIP === GATEWAY_IP && frame.dstIP === VM_IP &&
        frame.dstPort === 8080 && frame.syn
      );
      const repeatedSyn = await frames.waitFor((frame) =>
        frame.srcIP === GATEWAY_IP && frame.dstIP === VM_IP &&
        frame.dstPort === 8080 && frame.syn
      );
      assert.equal(repeatedSyn.seq, syn.seq);
      const vmSeq = 5000;
      relay.ws.send(buildTCPFrame({
        srcIP: VM_IP,
        dstIP: GATEWAY_IP,
        srcPort: 8080,
        dstPort: syn.srcPort,
        seq: vmSeq,
        ack: (syn.seq + 1) >>> 0,
        flags: { syn: true, ack: true },
      }));
      await frames.waitFor((frame) =>
        frame.srcPort === syn.srcPort && frame.dstPort === 8080 &&
        frame.ackFlag && !frame.syn && frame.payload.length === 0
      );

      const payload = Buffer.from("reverse-final");
      client.write(payload);
      const original = await frames.waitFor((frame) => frame.payload.equals(payload));
      const retransmitted = await frames.waitFor((frame) => frame.payload.equals(payload));
      assert.equal(retransmitted.seq, original.seq);

      relay.ws.send(buildTCPFrame({
        srcIP: VM_IP,
        dstIP: GATEWAY_IP,
        srcPort: 8080,
        dstPort: syn.srcPort,
        seq: vmSeq + 1,
        ack: (original.seq + payload.length) >>> 0,
        flags: { ack: true },
      }));
      await frames.expectNone((frame) => frame.payload.equals(payload), 175);

      client.end();
      const fin = await frames.waitFor((frame) =>
        frame.srcPort === syn.srcPort && frame.dstPort === 8080 && frame.fin
      );
      const repeatedFin = await frames.waitFor((frame) =>
        frame.srcPort === syn.srcPort && frame.dstPort === 8080 && frame.fin
      );
      assert.equal(repeatedFin.seq, fin.seq);
      relay.ws.send(buildTCPFrame({
        srcIP: VM_IP,
        dstIP: GATEWAY_IP,
        srcPort: 8080,
        dstPort: syn.srcPort,
        seq: vmSeq + 1,
        ack: (fin.seq + 1) >>> 0,
        flags: { ack: true },
      }));
      await frames.expectNone((frame) => frame.fin && frame.seq === fin.seq, 175);
    } catch (error) {
      error.message += `\nRelay stderr:\n${relay.stderr()}`;
      throw error;
    } finally {
      client?.destroy();
      await relay.close();
    }
  },
);

// Keep these at the wire boundary: both handlers must preserve stream bytes and
// respond to window updates even when there is no outstanding retransmission.
async function openTestConnection(reverse, {
  window = 65535, windowScale, handshakePayload, mss, relayOptions = {},
} = {}) {
  const relay = await startRelay({ TCP_RTO_INITIAL_MS: "1000", TCP_RTO_MAX_MS: "2000", ...relayOptions });
  const frames = new FrameQueue(relay.ws);
  let server;
  let socket;
  let vmPort = 41001;
  let remotePort;
  const remoteIP = reverse ? GATEWAY_IP : "127.0.0.1";
  let relaySeq;
  const received = [];
  try {
    if (reverse) {
      relay.ws.send(buildARPRequest());
      await delay(30);
      const hostPort = await freeTcpPort();
      vmPort = 8080;
      assert.equal(await postJSON(relay.adminPort, "/api/rules", {
        type: "port", protocols: ["tcp"], host_port: hostPort,
        bind_address: "127.0.0.1", vm: VM_IP, port: vmPort,
      }), 201);
      socket = await connectWithRetry(hostPort);
      socket.on("data", (data) => received.push(data));
      const syn = await frames.waitFor((frame) => frame.syn);
      remotePort = syn.srcPort;
      relaySeq = (syn.seq + 1) >>> 0;
    } else {
      let accept;
      const accepted = new Promise((resolve) => { accept = resolve; });
      server = net.createServer((peer) => {
        socket = peer;
        socket.on("data", (data) => received.push(data));
        accept();
      });
      remotePort = await listen(server);
      relay.ws.send(buildTCPFrame({
        srcIP: VM_IP, dstIP: remoteIP, srcPort: vmPort, dstPort: remotePort,
        seq: 1000, flags: { syn: true }, window, windowScale, mss,
      }));
      const synAck = await frames.waitFor((frame) => frame.syn);
      relaySeq = (synAck.seq + 1) >>> 0;
      await accepted;
    }
    const send = (overrides = {}) => relay.ws.send(buildTCPFrame({
      srcIP: VM_IP, dstIP: remoteIP, srcPort: vmPort, dstPort: remotePort,
      seq: 1001, ack: relaySeq, flags: { ack: true }, window,
      ...overrides,
    }));
    send({ seq: reverse ? 1000 : 1001,
      flags: { syn: reverse, ack: true }, payload: handshakePayload, windowScale, mss });
    await frames.waitFor((frame) => frame.ackFlag && !frame.syn);
    return {
      frames, socket, send, received, relaySeq,
      async close() {
        socket.destroy();
        await relay.close();
        if (server) await new Promise((resolve) => server.close(resolve));
      },
    };
  } catch (error) {
    socket?.destroy();
    await relay.close();
    if (server) await new Promise((resolve) => server.close(resolve));
    throw error;
  }
}

for (const reverse of [false, true]) {
  const direction = reverse ? "reverse" : "outbound";
  test(`${direction} TCP forwards a second small write without waiting for the first ACK`,
    { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 10000 }, async () => {
      const conn = await openTestConnection(reverse);
      try {
        conn.socket.write(Buffer.from("first"));
        const first = await conn.frames.waitFor((frame) => frame.payload.toString() === "first");
        conn.socket.write(Buffer.from("second"));
        // The receiver deliberately withholds its ACK. Forwarding the next
        // write must not depend on either that ACK or the one-second RTO.
        const second = await conn.frames.waitFor((frame) => frame.payload.toString() === "second", 500);
        assert.equal(second.seq, (first.seq + first.payload.length) >>> 0);
        conn.send({ ack: (second.seq + second.payload.length) >>> 0 });
      } finally { await conn.close(); }
    });

  test(`${direction} TCP drains overlapping out-of-order tails without retransmission`,
    { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 10000 }, async () => {
      const conn = await openTestConnection(reverse);
      try {
        conn.send({ seq: 1005, payload: Buffer.from("efghij") });
        await conn.frames.waitFor((frame) => frame.ack === 1001);
        conn.send({ seq: 1009, payload: Buffer.from("ijkl") });
        await conn.frames.waitFor((frame) => frame.ack === 1001);
        conn.send({ payload: Buffer.from("abcdef") });
        await conn.frames.waitFor((frame) => frame.ack === 1013);
        await delay(20);
        assert.equal(Buffer.concat(conn.received).toString(), "abcdefghijkl");
        conn.send({ seq: 1013, payload: Buffer.from("mn") });
        await conn.frames.waitFor((frame) => frame.ack === 1015);
        await delay(20);
        assert.equal(Buffer.concat(conn.received).toString(), "abcdefghijklmn");
      } finally { await conn.close(); }
    });

  for (const mss of [undefined, 100]) {
    test(`${direction} TCP respects ${mss === undefined ? "the default IPv4 MSS" : "a small peer MSS"}`,
      { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 10000 }, async () => {
        const conn = await openTestConnection(reverse, { mss });
        try {
          const payload = Buffer.alloc(1800, 0x5a);
          const received = [];
          let next = conn.relaySeq;
          conn.socket.write(payload);
          while (received.reduce((sum, part) => sum + part.length, 0) < payload.length) {
            const frame = await conn.frames.waitFor((frame) => frame.payload.length > 0);
            assert.equal(frame.seq, next);
            assert.ok(frame.payload.length <= (mss ?? 536), `oversized segment: ${frame.payload.length}`);
            received.push(frame.payload);
            next = (next + frame.payload.length) >>> 0;
            conn.send({ ack: next });
          }
          assert.deepEqual(Buffer.concat(received), payload);
        } finally { await conn.close(); }
      });
  }

  test(`${direction} TCP probes a closed window and recovers a lost reopen update`,
    { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 10000 }, async () => {
      const conn = await openTestConnection(reverse, {
        window: 0,
        relayOptions: { TCP_RTO_INITIAL_MS: "50", TCP_RTO_MAX_MS: "100" },
      });
      try {
        const payload = Buffer.from("recover without a window update");
        conn.socket.write(payload);
        // A responsive receiver may stay closed beyond the normal retry budget.
        for (let i = 0; i < 5; i++) {
          const probe = await conn.frames.waitFor((frame) => frame.payload.length > 0 || frame.rst);
          assert.equal(probe.rst, false);
          assert.equal(probe.seq, conn.relaySeq);
          assert.deepEqual(probe.payload, payload.subarray(0, 1));
          conn.send({ window: 0 });
        }
        // The reopening advertisement was lost; only a later probe elicits it.
        const probe = await conn.frames.waitFor((frame) => frame.payload.length > 0);
        assert.equal(probe.seq, conn.relaySeq);
        conn.send({ window: 65535 });
        const received = [];
        let next = conn.relaySeq;
        while (received.reduce((sum, part) => sum + part.length, 0) < payload.length) {
          const frame = await conn.frames.waitFor((frame) => frame.payload.length > 0 || frame.rst);
          assert.equal(frame.rst, false);
          assert.equal(frame.seq, next);
          received.push(frame.payload);
          next = (next + frame.payload.length) >>> 0;
          conn.send({ window: 65535, ack: next });
        }
        assert.deepEqual(Buffer.concat(received), payload);
        await conn.frames.expectNone((frame) => frame.payload.length > 0 || frame.rst, 225);
      } finally { await conn.close(); }
    });

  test(`${direction} TCP accounts for an accepted probe byte exactly once`,
    { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 10000 }, async () => {
      const conn = await openTestConnection(reverse, {
        window: 0,
        relayOptions: { TCP_RTO_INITIAL_MS: "50", TCP_RTO_MAX_MS: "100" },
      });
      try {
        const payload = Buffer.from("accepted probe");
        conn.socket.write(payload);
        const first = await conn.frames.waitFor((frame) => frame.payload.length > 0);
        assert.equal(first.seq, conn.relaySeq);
        assert.deepEqual(first.payload, payload.subarray(0, 1));
        conn.send({ ack: (first.seq + 1) >>> 0, window: 65535 });
        const rest = await conn.frames.waitFor((frame) => frame.payload.length > 0);
        assert.equal(rest.seq, (first.seq + 1) >>> 0);
        assert.deepEqual(Buffer.concat([first.payload, rest.payload]), payload);
        conn.send({ ack: (rest.seq + rest.payload.length) >>> 0, window: 65535 });
        await conn.frames.expectNone((frame) => frame.payload.length > 0 || frame.rst, 225);
      } finally { await conn.close(); }
    });

  test(`${direction} TCP handles a window closing with data in flight`,
    { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 10000 }, async () => {
      const conn = await openTestConnection(reverse, {
        relayOptions: { TCP_RTO_INITIAL_MS: "50", TCP_RTO_MAX_MS: "100" },
      });
      try {
        const payload = Buffer.from("already in flight");
        conn.socket.write(payload);
        const data = await conn.frames.waitFor((frame) => frame.payload.equals(payload));
        conn.send({ window: 0 });
        for (let i = 0; i < 3; i++) {
          const probe = await conn.frames.waitFor((frame) => frame.payload.length > 0 || frame.rst);
          assert.equal(probe.rst, false);
          assert.equal(probe.seq, data.seq);
          assert.deepEqual(probe.payload, payload.subarray(0, 1));
          conn.send({ window: 0 });
        }
        conn.send({ window: 65535 });
        const retried = await conn.frames.waitFor((frame) => frame.payload.equals(payload));
        assert.equal(retried.seq, data.seq);
        conn.send({ ack: (data.seq + payload.length) >>> 0 });
        await conn.frames.expectNone((frame) => frame.payload.length > 0 || frame.rst, 225);
      } finally { await conn.close(); }
    });

  test(`${direction} TCP eventually delivers a FIN blocked by a closed window`,
    { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 10000 }, async () => {
      const conn = await openTestConnection(reverse, {
        window: 0,
        relayOptions: { TCP_RTO_INITIAL_MS: "50", TCP_RTO_MAX_MS: "100" },
      });
      try {
        conn.socket.end();
        const fin = await conn.frames.waitFor((frame) => frame.fin);
        assert.equal(fin.seq, conn.relaySeq);
        conn.send({ window: 0 });
        const repeat = await conn.frames.waitFor((frame) => frame.fin);
        assert.equal(repeat.seq, fin.seq);
        conn.send({ ack: (fin.seq + 1) >>> 0, window: 65535 });
        await conn.frames.expectNone((frame) => frame.fin || frame.rst, 225);
      } finally { await conn.close(); }
    });

  test(`${direction} TCP preserves six-byte zero and space payloads`,
    { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 10000 }, async () => {
      const conn = await openTestConnection(reverse);
      try {
        const zeros = Buffer.alloc(6);
        const spaces = Buffer.alloc(6, 0x20);
        conn.send({ payload: zeros });
        await conn.frames.waitFor((frame) => frame.ack === 1007);
        conn.send({ seq: 1007, payload: spaces });
        await conn.frames.waitFor((frame) => frame.ack === 1013);
        await delay(20);
        assert.deepEqual(Buffer.concat(conn.received), Buffer.concat([zeros, spaces]));
      } finally { await conn.close(); }
    });

  test(`${direction} TCP ignores unnegotiated window scaling`,
    { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 10000 }, async () => {
      const conn = await openTestConnection(reverse, { window: 2, windowScale: 7 });
      try {
        conn.socket.write(Buffer.from("abcdefgh"));
        const data = await conn.frames.waitFor((frame) => frame.payload.length > 0);
        assert.equal(data.payload.toString(), "ab");
        await conn.frames.expectNone((frame) => frame.payload.length > 0, 50);
      } finally { await conn.close(); }
    });

  test(`${direction} TCP does not count data-bearing ACKs as duplicate ACKs`,
    { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 10000 }, async () => {
      const conn = await openTestConnection(reverse);
      try {
        conn.socket.write(Buffer.from("unacknowledged"));
        const data = await conn.frames.waitFor((frame) => frame.payload.length > 0);
        for (let i = 0; i < 3; i++) {
          conn.send({ seq: 1001 + i, payload: Buffer.from([i + 1]) });
        }
        await conn.frames.waitFor((frame) => frame.ack === 1004);
        await conn.frames.expectNone((frame) => frame.payload.length > 0, 100);
        conn.send({ seq: 1004, ack: (data.seq + data.payload.length) >>> 0 });
        assert.deepEqual(Buffer.concat(conn.received), Buffer.from([1, 2, 3]));
      } finally { await conn.close(); }
    });

  test(`${direction} TCP resumes on a window-only ACK`,
    { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 10000 }, async () => {
      const conn = await openTestConnection(reverse, { window: 0 });
      try {
        const payload = Buffer.from("resume queued data");
        conn.socket.write(payload);
        await conn.frames.expectNone((frame) => frame.payload.length > 0, 50);
        // An ACK for unsent bytes must not reopen the window.
        conn.send({ window: 65535, ack: (conn.relaySeq + 100) >>> 0 });
        await conn.frames.expectNone((frame) => frame.payload.length > 0, 50);
        conn.send({ window: 65535 });
        const data = await conn.frames.waitFor((frame) => frame.payload.equals(payload));
        conn.send({ window: 65535, ack: (data.seq + payload.length) >>> 0 });
      } finally { await conn.close(); }
    });
}

test("outbound TCP delivers data on the final handshake ACK without retransmission",
  { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 10000 }, async () => {
    const payload = Buffer.from("request on handshake");
    const conn = await openTestConnection(false, { handshakePayload: payload });
    try {
      await conn.frames.waitFor((frame) => frame.ack === 1001 + payload.length);
      await delay(20);
      assert.deepEqual(Buffer.concat(conn.received), payload);
    } finally { await conn.close(); }
  });
