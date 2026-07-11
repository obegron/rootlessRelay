"use strict";

const dgram = require("node:dgram");

function flowKey({ vmIP, vmPort, remoteIP, remotePort }) {
  return `${vmIP}|${vmPort}|${remoteIP}|${remotePort}`;
}

class UDPFlowManager {
  constructor({
    createSocket = () => dgram.createSocket("udp4"),
    idleTimeoutMs = 30000,
    maxFlows = 256,
    onResponse,
    onError = () => {},
    now = Date.now,
  }) {
    if (!Number.isInteger(maxFlows) || maxFlows < 1) {
      throw new TypeError("maxFlows must be a positive integer");
    }
    if (!Number.isFinite(idleTimeoutMs) || idleTimeoutMs <= 0) {
      throw new TypeError("idleTimeoutMs must be positive");
    }
    if (typeof onResponse !== "function") {
      throw new TypeError("onResponse must be a function");
    }

    this.createSocket = createSocket;
    this.idleTimeoutMs = idleTimeoutMs;
    this.maxFlows = maxFlows;
    this.onResponse = onResponse;
    this.onError = onError;
    this.now = now;
    this.flows = new Map();
    this.lastFlow = null;
    this.droppedPackets = 0;
    this.sendErrors = 0;

    this.cleanupInterval = setInterval(
      () => this.cleanup(),
      Math.min(1000, idleTimeoutMs),
    );
    this.cleanupInterval.unref?.();
  }

  get size() {
    return this.flows.size;
  }

  send(payload, flowInfo) {
    let key;
    let flow = this.lastFlow;
    if (
      !flow ||
      flow.vmIP !== flowInfo.vmIP ||
      flow.vmPort !== flowInfo.vmPort ||
      flow.remotePort !== flowInfo.remotePort ||
      flow.remoteIP !== flowInfo.remoteIP
    ) {
      key = flowKey(flowInfo);
      flow = this.flows.get(key);
    } else {
      key = flow.key;
    }

    if (!flow) {
      this.cleanup();
      if (this.flows.size >= this.maxFlows) {
        this.droppedPackets++;
        return false;
      }
      try {
        flow = this.createFlow(key, flowInfo);
      } catch (error) {
        this.sendErrors++;
        this.onError(error, flowInfo);
        return false;
      }
    }
    this.lastFlow = flow;

    flow.lastSeen = this.now();
    try {
      flow.socket.send(payload, flow.remotePort, flow.remoteIP);
      return true;
    } catch (error) {
      this.handleFlowError(key, error);
      return false;
    }
  }

  createFlow(key, flowInfo) {
    const socket = this.createSocket();
    const flow = {
      ...flowInfo,
      key,
      socket,
      lastSeen: this.now(),
    };
    this.flows.set(key, flow);

    socket.on("message", (payload, rinfo) => {
      if (
        rinfo.address !== flow.remoteIP ||
        rinfo.port !== flow.remotePort
      ) return;

      flow.lastSeen = this.now();
      try {
        this.onResponse(payload, flow);
      } catch (error) {
        this.onError(error, flow);
      }
    });
    socket.on("error", (error) => this.handleFlowError(key, error));

    return flow;
  }

  handleFlowError(key, error) {
    const flow = this.flows.get(key);
    if (!flow) return;
    this.sendErrors++;
    this.onError(error, flow);
    this.removeFlow(key);
  }

  cleanup(now = this.now()) {
    for (const [key, flow] of this.flows) {
      if (now - flow.lastSeen >= this.idleTimeoutMs) {
        this.removeFlow(key);
      }
    }
  }

  removeFlow(key) {
    const flow = this.flows.get(key);
    if (!flow) return;
    this.flows.delete(key);
    if (this.lastFlow === flow) this.lastFlow = null;
    try {
      flow.socket.close();
    } catch {
      // The socket may already be closed after an asynchronous error.
    }
  }

  close() {
    clearInterval(this.cleanupInterval);
    for (const key of [...this.flows.keys()]) this.removeFlow(key);
  }
}

module.exports = {
  UDPFlowManager,
  flowKey,
};
