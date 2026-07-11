"use strict";

const dgram = require("node:dgram");
const { performance } = require("node:perf_hooks");
const { parentPort, workerData } = require("node:worker_threads");

const socket = dgram.createSocket("udp4");
let payloadSize = 0;
let marker = 0;
let measuring = false;
let receivedPackets = 0;
let receivedBytes = 0;
let lastReceivedAt = 0;
let totalReceivedPackets = 0;
let totalLastReceivedAt = 0;

function sendResponse(id, result) {
  parentPort.postMessage({ id, result });
}

socket.on("message", (message) => {
  totalReceivedPackets++;
  totalLastReceivedAt = performance.now();
  if (
    !measuring ||
    message.length !== payloadSize ||
    message[0] !== marker
  ) return;
  receivedPackets++;
  receivedBytes += message.length;
  lastReceivedAt = totalLastReceivedAt;
});

socket.on("error", (error) => {
  parentPort.postMessage({ error: error.message });
});

parentPort.on("message", ({ id, command, size, phaseMarker }) => {
  if (command === "reset") {
    payloadSize = size;
    marker = phaseMarker;
    receivedPackets = 0;
    receivedBytes = 0;
    lastReceivedAt = 0;
    measuring = true;
    sendResponse(id, true);
  } else if (command === "stats") {
    sendResponse(id, {
      receivedPackets,
      receivedBytes,
      lastReceivedAt,
      totalReceivedPackets,
      totalLastReceivedAt,
    });
  } else if (command === "stop") {
    measuring = false;
    sendResponse(id, {
      receivedPackets,
      receivedBytes,
      lastReceivedAt,
      totalReceivedPackets,
      totalLastReceivedAt,
    });
  } else if (command === "close") {
    measuring = false;
    socket.close(() => sendResponse(id, true));
  }
});

socket.bind(0, "127.0.0.1", () => {
  try {
    socket.setRecvBufferSize(workerData.receiveBufferBytes);
  } catch {
    // Some platforms cap or do not expose socket buffer tuning.
  }

  let receiveBufferBytes = null;
  try {
    receiveBufferBytes = socket.getRecvBufferSize();
  } catch {
    // Keep reporting portable when the platform does not expose this value.
  }

  parentPort.postMessage({
    ready: {
      port: socket.address().port,
      receiveBufferBytes,
    },
  });
});
