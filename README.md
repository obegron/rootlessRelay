# RootlessRelay

A WebSocket based VPN/proxy relay for virtual machines.

## Features

- **Secure Communication:** Supports secure WebSockets (WSS) for encrypted data transfer.
- **Dynamic IP Allocation:** Built-in DHCP-like server to automatically assign IP
  addresses to virtual machines.
- **VM-to-VM Networking:** Allows virtual machines on the same relay to communicate
  communicate with each other (configurable).
- **Admin Interface:** A web-based UI to monitor active sessions and manage
  proxy rules.
- **HTTP Proxying:** Reverse proxy functionality to expose services from VMs to
  the host network.
- **Rate Limiting:** Configurable bandwidth limits for each connected VM.
- **TCP Loss Recovery:** Fast retransmit plus backed-off retransmission timeouts
  for handshakes, data, and connection teardown in both relay directions.

## Configuration

These default values can be overridden by setting corresponding environment variables.

### General Settings

| Setting                  | Purpose                                                                | Default     |
| ------------------------ | ---------------------------------------------------------------------- | ----------- |
| `RATE_LIMIT_KBPS`        | Maximum upload/download bandwidth for each VM in kilobytes per second. | `1024`      |
| `MAX_CONNECTIONS_PER_IP` | Maximum number of concurrent WebSocket connections from a single IP.   | `4`         |
| `ENABLE_WSS`             | Use Secure WebSockets (WSS). Requires `cert.pem` and `key.pem`.        | `true`      |
| `ENABLE_VM_TO_VM`        | Allow VMs on the same relay to communicate with each other.            | `true`      |
| `LOG_LEVEL`              | Controls logging verbosity. `0` (Disabled), `1` (Debug), `2` (Trace).  | `1` (Debug) |

### Network & Port Settings

| Setting              | Purpose                                                    | Default                    |
| -------------------- | ---------------------------------------------------------- | -------------------------- |
| `GATEWAY_IP`         | IP address of the virtual gateway within the VM's network. | `10.0.2.2`                 |
| `DHCP_START`         | The starting IP address for the DHCP pool (last octet).    | `15`                       |
| `DHCP_END`           | The ending IP address for the DHCP pool (last octet).      | `254`                      |
| `DNS_SERVER_IP`      | DNS server provided to VMs via DHCP.                       | `8.8.8.8`                  |
| `VM_MTU`             | VM-to-relay link MTU; also controls the negotiated TCP MSS. | `1500`                    |
| `TCP_WINDOW_SIZE`    | TCP window size for connections to/from the VM.            | `10240`                    |
| `TCP_SEND_BURST_SEGMENTS` | Maximum TCP segments sent to a VM per paced burst.    | `3`                        |
| `TCP_SEND_BURST_INTERVAL_MS` | Delay between paced TCP bursts sent to a VM.        | `6`                        |
| `TCP_INITIAL_CWND_BYTES` | Initial ACK-driven TCP congestion window.                | `10240`                    |
| `TCP_SEND_QUEUE_HIGH_WATER_BYTES` | Pause the real input stream at this queued size. | `1048576`                  |
| `UDP_FLOW_IDLE_TIMEOUT_MS` | Idle lifetime of a UDP flow mapping.                  | `30000`                    |
| `MAX_UDP_FLOWS_PER_SESSION` | Maximum concurrent UDP flows per VM session.          | `256`                      |
| `TCP_RTO_INITIAL_MS` | Initial TCP retransmission timeout.                            | `1000`                     |
| `TCP_RTO_MAX_MS` | Maximum backed-off TCP retransmission timeout.                      | `60000`                    |
| `TCP_RTO_MAX_RETRANSMISSIONS` | Retransmissions before a TCP connection is aborted.   | `4`                        |
| `WS_PORT`            | Port for the WebSocket server.                             | `8443` (WSS) / `8086` (WS) |
| `WS_BIND_ADDRESS`    | IP address for the WebSocket server to bind to.            | `0.0.0.0`                  |
| `ADMIN_PORT`         | Port for the web-based admin interface.                    | `8001`                     |
| `ADMIN_BIND_ADDRESS` | IP address for the admin interface to bind to.             | `127.0.0.1`                |
| `PROXY_PORT`         | Port for the HTTP reverse proxy server.                    | `8080`                     |
| `PROXY_BIND_ADDRESS` | IP address for the reverse proxy to bind to.               | `127.0.0.1`                |

## How to use

### 1. Installation

This project requires Node.js. You can install the dependencies using npm:

```bash
npm install
```

### 2. Generating SSL/TLS key pair (for WSS)

For secure WebSockets (WSS), you need to generate a private key and a certificate.
You can generate a self-signed pair using the following npm script:

```bash
npm run keygen
```

This will create `key.pem` and `cert.pem` in your project directory. When prompted,
you can leave the fields for distinguished name blank.

Alternatively, you can run the `openssl` command directly.
This is useful if you want to use different settings:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 3. Running the relay

Once the dependencies are installed and you have your key pair (if using WSS),
you can start the relay server:

```bash
npm start

```

| In the browser you will use the relay first visit <https://127.0.0.1:8443> and
| trust the certificate you created.

The server will start, and you can see log output in your console.

### 4. Admin UI

The project includes a simple web-based admin UI. By default, it's available at `http://localhost:8001`.

## IP-stack choke test

Run the single-process packet construction and checksum benchmark with:

```bash
npm run bench:ip-stack
```

The benchmark reports packets per second, application-payload throughput, and
IPv4 throughput for TCP and UDP across several payload sizes. It measures the
CPU ceiling of the relay's packet-building hot path; it does not include
WebSocket, kernel socket, rate limiting, or network I/O. TCP packets larger than
the relay's 1460-byte MSS are synthetic stress cases; the separately reported
`Production TCP MSS ceiling` is the relevant packet-building limit for TCP.
Use longer samples or select cases with:

```bash
npm run bench:ip-stack -- --duration-ms=3000 --protocol=tcp --sizes=1460,8192,32768
```

Use `--json` to capture comparable results before and after an optimization.

To include the real WebSocket ingress and relay UDP forwarding path, run:

```bash
npm run bench:ws
```

This starts a temporary loopback relay, sends Ethernet/IPv4/UDP frames through
WebSocket, and reports the payload received by an isolated-worker UDP socket.
Separating the sender and receiver event loops prevents the load generator from
creating its own receive loss. Packet loss is still reported when strict
sent/relayed/received accounting detects it. Payloads above 1400 bytes are
synthetic jumbo-frame stress cases; use the reported standard-MTU reference for
ordinary Ethernet. Customize it with `--duration-ms`, `--buffer-bytes`,
`--sizes`, or `--json`.

To measure the opposite, TCP-download direction without requiring a browser or
VM image, run:

```bash
npm run bench:tcp-egress
```

This starts a real loopback TCP source and relay, then connects a fake VM over
WebSocket. The fake VM completes the TCP handshake, validates received payload,
and sends delayed cumulative ACKs. Its bounded fake NIC queue makes burst loss
and retransmission visible. The defaults compare the relay's `10240`- and
`65535`-byte TCP windows with a 20 ms ACK delay and an eight-packet receive
queue. Use `--rx-queue-packets=0` to remove the artificial NIC queue limit, or
customize the workload with `--duration-ms`, `--ack-delay-ms`, `--ack-every`,
`--rx-service-ms`, `--send-burst-segments`, `--send-burst-interval-ms`,
`--initial-cwnd-bytes`, `--tcp-mss`, `--windows`, or `--json`.

### Experimental jumbo VM link

The relay terminates TCP instead of forwarding Internet IP packets directly.
That means only the private VM-to-relay link needs to support a larger MTU. To
reduce WebSocket messages and virtual-NIC packets per byte, start the relay with
an opt-in jumbo MTU, for example:

```bash
VM_MTU=9000 \
TCP_WINDOW_SIZE=65535 \
TCP_INITIAL_CWND_BYTES=17920 \
TCP_SEND_BURST_SEGMENTS=3 \
TCP_SEND_BURST_INTERVAL_MS=5 \
node relay.js
```

`VM_MTU` is advertised with DHCP option 26 and as a TCP MSS option. Confirm the
guest interface reports the requested MTU before testing a new TCP connection:

```bash
ip link show
```

If the DHCP client ignores the MTU option, set it explicitly inside the guest:

```bash
ip link set dev eth0 mtu 9000
```

Jumbo support depends on the browser VM's virtual NIC. If connectivity stalls,
return to `VM_MTU=1500`. The default remains 1500, and the relay limits outbound
segments to the MSS advertised by the guest, so a guest that advertises 1460
will not receive jumbo TCP segments.

The real-socket UDP flow collision test is opt-in:

```bash
npm run test:network
```
