# ADR 0003 — TCP Transport for Workflow Engine

## Status

Accepted for engine-daemon transport.

The trigger-service details in this ADR belong to the v1 prototype and are
superseded by ADR 0004. TCP remains the intended transport for the engine and
step execution APIs.

## Context

The workflow engine needs to communicate with the App Mesh daemon for app execution, output retrieval, and event subscriptions. Three transport options exist in the Go SDK:

- **HTTP**: Stateless, no event subscription capability. Would require polling for stdout and exit status.
- **WSS (WebSocket Secure)**: Supports subscriptions but adds WebSocket protocol overhead.
- **TCP**: Binary msgpack protocol, persistent connection, native event subscription via message demuxer. Lowest latency and overhead.

The engine needs event subscriptions for:
1. **Trigger service**: subscribe to App EXIT/START events to fire workflows.

## Decision

The workflow engine uses **TCP transport exclusively** for all daemon communication. Both `run` and `serve` modes create a `NewTCPClient` (default `127.0.0.1:6059`). For cross-node execution, per-job TCP clients are created with `ForwardTo` set to the target node.

## Consequences

### Benefits

- **Step stdout archival**: after step completion, `GetAppOutput` fetches full stdout and writes to `{workdir}/steps/{job}.{step}.log`. Real-time output during execution is available directly via `appc app output -n wf-cmd-<id> -f` on the daemon.
- **Efficient exit detection**: subscribe to EXIT event instead of polling `GetAppOutput` in a loop.
- **Single protocol**: no mixed HTTP+TCP client management. One connection type, one set of abstractions.
- **Lower overhead**: binary msgpack is more compact than HTTP+JSON for high-frequency stdout chunks.

### Trade-offs

- **Persistent connection required**: TCP client needs a live connection to the daemon. If the connection drops, subscriptions are lost (reconnect logic needed).
- **Cross-node connections**: each remote node needs its own TCP connection (vs HTTP which is stateless per-request). Acceptable because the number of distinct target nodes in a workflow is typically small.
- **Port dependency**: requires TCP port 6059 open, in addition to HTTPS 6060. Both are standard App Mesh ports.
