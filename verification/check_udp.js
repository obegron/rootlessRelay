"use strict";
const { UDPFlowManager, flowKey } = require("../udp_flow_manager");
const { check, enumerate } = require("./sim");
const EventEmitter = require("node:events");

const IDLE = 3, MAXF = 2;
const FLOWS = {
  A: { vmIP: "10.0.2.15", vmPort: 1000, remoteIP: "8.8.8.8", remotePort: 53 },
  B: { vmIP: "10.0.2.15", vmPort: 1001, remoteIP: "8.8.8.8", remotePort: 53 },
  C: { vmIP: "10.0.2.16", vmPort: 1000, remoteIP: "1.1.1.1", remotePort: 53 },
};
const ACTIONS = ["sA", "sB", "sC", "t1", "t2", "t4", "cleanup", "rA", "rB", "spoofA", "errA", "sendThrowsA", "createThrowsC"];

class FakeSocket extends EventEmitter {
  constructor(env) { super(); this.env = env; this.closed = 0; this.sent = []; env.sockets.push(this); }
  send(payload, port, ip) {
    if (this.env.sendThrows) { this.env.sendThrows = false; throw new Error("send failed"); }
    this.sent.push({ port, ip });
  }
  close() { this.closed++; this.env.open--; }
}

function run(seq) {
  let now = 100;
  const env = { sockets: [], open: 0, sendThrows: false, createThrows: false };
  const responses = [], errors = [];
  const m = new UDPFlowManager({
    createSocket: () => { if (env.createThrows) { env.createThrows = false; throw new Error("no sockets"); } env.open++; return new FakeSocket(env); },
    idleTimeoutMs: IDLE, maxFlows: MAXF, now: () => now,
    onResponse: (payload, flow) => responses.push(flow.key),
    onError: (e) => errors.push(e),
  });
  const ref = new Map(); // key -> lastSeen
  const sockOf = (n) => env.sockets.filter((s) => !s.closed).find((s) => s.flowName === n);
  const ctx = () => seq.join(" ");
  const refCleanup = () => { for (const [k, ls] of ref) if (now - ls >= IDLE) ref.delete(k); };
  const name = (key) => Object.keys(FLOWS).find((n) => flowKey(FLOWS[n]) === key);
  try {
    for (const a of seq) {
      if (a === "sA" || a === "sB" || a === "sC") {
        const n = a[1], info = FLOWS[n], key = flowKey(info);
        env.sendThrows = false;
        const before = env.sockets.length;
        let expectOk;
        if (ref.has(key)) { ref.set(key, now); expectOk = true; }
        else { refCleanup(); expectOk = ref.size < MAXF; if (expectOk) ref.set(key, now); }
        const ok = m.send(Buffer.from("x"), info);
        check(ok === expectOk, `send(${n}) = ${ok}, expected ${expectOk}`, ctx);
        if (ok && env.sockets.length > before) env.sockets[env.sockets.length - 1].flowName = n;
        if (ok) { const f = m.flows.get(key); check(f.socket.sent.at(-1).ip === info.remoteIP && f.socket.sent.at(-1).port === info.remotePort, "datagram sent to wrong peer", ctx); }
      } else if (a === "t1") now += 1; else if (a === "t2") now += 2; else if (a === "t4") now += 4;
      else if (a === "cleanup") { m.cleanup(); refCleanup(); }
      else if (a === "rA" || a === "rB") {
        const n = a[1], key = flowKey(FLOWS[n]), f = m.flows.get(key);
        if (f) { const c = responses.length; f.socket.emit("message", Buffer.from("r"), { address: FLOWS[n].remoteIP, port: FLOWS[n].remotePort }); check(responses.length === c + 1 && responses.at(-1) === key, "valid response not delivered to its flow", ctx); ref.set(key, now); }
      } else if (a === "spoofA") {
        const f = m.flows.get(flowKey(FLOWS.A));
        if (f) { const c = responses.length; f.socket.emit("message", Buffer.from("evil"), { address: "6.6.6.6", port: 53 }); f.socket.emit("message", Buffer.from("evil"), { address: FLOWS.A.remoteIP, port: 54 }); check(responses.length === c, "spoofed datagram delivered to VM", ctx); }
      } else if (a === "errA") {
        const key = flowKey(FLOWS.A), f = m.flows.get(key);
        if (f) { f.socket.emit("error", new Error("boom")); ref.delete(key); }
      } else if (a === "sendThrowsA") {
        const key = flowKey(FLOWS.A);
        const exists = ref.has(key);
        if (!exists) refCleanup(); // cleanup only runs on a table miss
        if (exists || ref.size < MAXF) { env.sendThrows = true; const ok = m.send(Buffer.from("x"), FLOWS.A); check(ok === false, "send that throws must report failure", ctx); ref.delete(key); if (!exists) { const s = env.sockets.at(-1); s.flowName = "A"; } }
        env.sendThrows = false;
      } else if (a === "createThrowsC") {
        const key = flowKey(FLOWS.C);
        if (!ref.has(key)) { refCleanup(); if (ref.size < MAXF) { const e0 = m.sendErrors; env.createThrows = true; check(m.send(Buffer.from("x"), FLOWS.C) === false && m.sendErrors === e0 + 1, "createSocket failure mishandled", ctx); } }
        env.createThrows = false;
      }
      // Invariants
      check(m.flows.size <= MAXF, "flow table exceeds maxFlows", ctx);
      check(env.open === m.flows.size, `open sockets ${env.open} != flows ${m.flows.size} (socket leak)`, ctx);
      check(env.sockets.every((s) => s.closed <= 1), "socket closed twice", ctx);
      check([...m.flows.keys()].sort().join() === [...ref.keys()].sort().join(), `flow set ${[...m.flows.keys()]} != ref ${[...ref.keys()]}`, ctx);
      for (const [k, f] of m.flows) check(k === f.key && k === flowKey(f), "flow stored under wrong key", ctx);
      check(m.lastFlow === null || m.flows.get(m.lastFlow.key) === m.lastFlow, "lastFlow dangling", ctx);
    }
  } finally { m.close(); }
  check(env.open === 0, "close() leaked sockets", ctx);
}

let n = enumerate(ACTIONS, 5, (s) => run(s.slice()));
console.log(`udp flow manager: ${n} sequences vs reference (cap, idle expiry, spoof filter, socket accounting) OK`);
