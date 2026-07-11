"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { UDPFlowManager } = require("../udp_flow_manager");

class FakeSocket extends EventEmitter {
  constructor() {
    super();
    this.sent = [];
    this.closed = false;
  }

  send(payload, port, address) {
    this.sent.push({ payload: Buffer.from(payload), port, address });
  }

  close() {
    this.closed = true;
  }
}

function makeManager(options = {}) {
  const sockets = [];
  const responses = [];
  const errors = [];
  const manager = new UDPFlowManager({
    createSocket: () => {
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket;
    },
    idleTimeoutMs: 1000,
    maxFlows: 8,
    onResponse: (payload, flow) => responses.push({ payload, flow }),
    onError: (error, flow) => errors.push({ error, flow }),
    ...options,
  });
  return { manager, sockets, responses, errors };
}

test("UDP flow manager reuses a socket for the same VM four-tuple", (t) => {
  const { manager, sockets } = makeManager();
  t.after(() => manager.close());
  const flow = {
    vmPort: 40000,
    vmIP: "10.0.2.15",
    remotePort: 53,
    remoteIP: "8.8.8.8",
  };

  assert.equal(manager.send(Buffer.from("one"), flow), true);
  assert.equal(manager.send(Buffer.from("two"), flow), true);
  assert.equal(sockets.length, 1);
  assert.deepEqual(
    sockets[0].sent.map(({ payload }) => payload.toString()),
    ["one", "two"],
  );
});

test("UDP flow manager isolates colliding VM ports and remote endpoints", (t) => {
  const { manager, sockets, responses } = makeManager();
  t.after(() => manager.close());

  manager.send(Buffer.from("a"), {
    vmPort: 40000,
    vmIP: "10.0.2.15",
    remotePort: 9000,
    remoteIP: "192.0.2.1",
  });
  manager.send(Buffer.from("b"), {
    vmPort: 40000,
    vmIP: "10.0.2.15",
    remotePort: 9001,
    remoteIP: "192.0.2.2",
  });
  manager.send(Buffer.from("c"), {
    vmPort: 40001,
    vmIP: "10.0.2.15",
    remotePort: 9000,
    remoteIP: "192.0.2.1",
  });

  assert.equal(sockets.length, 3);
  sockets[0].emit("message", Buffer.from("reply-a"), {
    address: "192.0.2.1",
    port: 9000,
  });
  sockets[1].emit("message", Buffer.from("reply-b"), {
    address: "192.0.2.2",
    port: 9001,
  });
  sockets[2].emit("message", Buffer.from("reply-c"), {
    address: "192.0.2.1",
    port: 9000,
  });

  assert.deepEqual(
    responses.map(({ payload, flow }) => [payload.toString(), flow.vmPort]),
    [["reply-a", 40000], ["reply-b", 40000], ["reply-c", 40001]],
  );
});

test("UDP flow manager includes the VM address in its flow identity", (t) => {
  const { manager, sockets } = makeManager();
  t.after(() => manager.close());
  const flow = {
    vmPort: 40000,
    vmIP: "10.0.2.15",
    remotePort: 9000,
    remoteIP: "192.0.2.1",
  };

  manager.send(Buffer.from("first"), flow);
  manager.send(Buffer.from("second"), { ...flow, vmIP: "10.0.2.16" });
  assert.equal(sockets.length, 2);
});

test("UDP flow manager ignores packets from an unexpected remote", (t) => {
  const { manager, sockets, responses } = makeManager();
  t.after(() => manager.close());
  manager.send(Buffer.from("request"), {
    vmPort: 40000,
    vmIP: "10.0.2.15",
    remotePort: 53,
    remoteIP: "8.8.8.8",
  });

  sockets[0].emit("message", Buffer.from("wrong"), {
    address: "1.1.1.1",
    port: 53,
  });
  assert.equal(responses.length, 0);
});

test("UDP flow manager bounds flows and expires idle sockets", (t) => {
  let now = 100;
  const { manager, sockets } = makeManager({ maxFlows: 1, now: () => now });
  t.after(() => manager.close());
  const first = {
    vmPort: 40000,
    vmIP: "10.0.2.15",
    remotePort: 53,
    remoteIP: "8.8.8.8",
  };
  const second = { ...first, remoteIP: "1.1.1.1" };

  assert.equal(manager.send(Buffer.alloc(1), first), true);
  assert.equal(manager.send(Buffer.alloc(1), second), false);
  assert.equal(manager.droppedPackets, 1);

  now = 1100;
  manager.cleanup();
  assert.equal(sockets[0].closed, true);
  assert.equal(manager.send(Buffer.alloc(1), second), true);
});

test("UDP flow manager contains socket errors and removes failed flows", (t) => {
  const { manager, sockets, errors } = makeManager();
  t.after(() => manager.close());
  manager.send(Buffer.alloc(1), {
    vmPort: 40000,
    vmIP: "10.0.2.15",
    remotePort: 53,
    remoteIP: "8.8.8.8",
  });

  sockets[0].emit("error", new Error("network down"));
  assert.equal(manager.size, 0);
  assert.equal(sockets[0].closed, true);
  assert.equal(errors[0].error.message, "network down");
  assert.equal(manager.sendErrors, 1);
});

test("UDP flow manager reports socket creation failure without throwing", (t) => {
  const errors = [];
  const { manager } = makeManager({
    createSocket: () => {
      throw new Error("descriptor limit");
    },
    onError: (error, flow) => errors.push({ error, flow }),
  });
  t.after(() => manager.close());

  const accepted = manager.send(Buffer.alloc(1), {
    vmPort: 40000,
    vmIP: "10.0.2.15",
    remotePort: 53,
    remoteIP: "8.8.8.8",
  });
  assert.equal(accepted, false);
  assert.equal(manager.size, 0);
  assert.equal(errors[0].error.message, "descriptor limit");
  assert.equal(manager.sendErrors, 1);
});
