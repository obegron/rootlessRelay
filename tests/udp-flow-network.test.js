"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const dgram = require("node:dgram");
const { UDPFlowManager } = require("../udp_flow_manager");

function bind(socket) {
  return new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(0, "127.0.0.1", () => {
      socket.removeListener("error", reject);
      resolve(socket.address().port);
    });
  });
}

function close(socket) {
  return new Promise((resolve) => socket.close(resolve));
}

test(
  "UDP flow manager routes colliding real socket replies to the correct VM flow",
  { skip: process.env.RUN_NETWORK_TESTS !== "1", timeout: 5000 },
  async () => {
    const firstRemote = dgram.createSocket("udp4");
    const secondRemote = dgram.createSocket("udp4");
    const firstPort = await bind(firstRemote);
    const secondPort = await bind(secondRemote);
    firstRemote.on("message", (payload, rinfo) => {
      firstRemote.send(Buffer.concat([Buffer.from("first:"), payload]), rinfo.port, rinfo.address);
    });
    secondRemote.on("message", (payload, rinfo) => {
      secondRemote.send(Buffer.concat([Buffer.from("second:"), payload]), rinfo.port, rinfo.address);
    });

    const responses = [];
    let resolveResponses;
    const allResponses = new Promise((resolve) => {
      resolveResponses = resolve;
    });
    const manager = new UDPFlowManager({
      onResponse: (payload, flow) => {
        responses.push([payload.toString(), flow.vmPort, flow.remotePort]);
        if (responses.length === 3) resolveResponses();
      },
      onError: (error) => assert.fail(error),
    });

    try {
      manager.send(Buffer.from("a"), {
        vmIP: "10.0.2.15",
        vmPort: 40000,
        remoteIP: "127.0.0.1",
        remotePort: firstPort,
      });
      manager.send(Buffer.from("b"), {
        vmIP: "10.0.2.15",
        vmPort: 40000,
        remoteIP: "127.0.0.1",
        remotePort: secondPort,
      });
      manager.send(Buffer.from("c"), {
        vmIP: "10.0.2.15",
        vmPort: 40001,
        remoteIP: "127.0.0.1",
        remotePort: firstPort,
      });
      await allResponses;

      responses.sort(([left], [right]) => left.localeCompare(right));
      assert.deepEqual(responses, [
        ["first:a", 40000, firstPort],
        ["first:c", 40001, firstPort],
        ["second:b", 40000, secondPort],
      ]);
    } finally {
      manager.close();
      await Promise.all([close(firstRemote), close(secondRemote)]);
    }
  },
);
