# Port Specification

This document is the single specification for the App Mesh product listening ports. The main and legacy branches, the UI, compose files, CI workflows and SDK default values must agree with it.

## 1. Allocation rules

- All listening ports are in one continuous range: `6060-6079`. No port is below 6060.
- The REST entry keeps its published port, 6060.
- Port numbers increase as exposure decreases: entry, engine transports, identity, integrations.
- Each component owns a fixed slot. A gap separates the groups.
- `0` disables a listener.
- A parallel sandbox shifts all ports by `+1000` (`60xx` to `70xx`).

This specification applies to product listening ports only. Ports used only for local debugging or testing (for example the UI development server `9528` and the IM mock `7070`) are out of scope.

## 2. Listening ports

| Port | Process | Protocol | Default bind | Purpose | Previous | Legacy |
|---|---|---|---|---|---|---|
| 6060 | Go agent | HTTPS | `127.0.0.1` | Single REST entry; proxies to 6062 and 6063 | 6060 | Same |
| 6061 | Go agent | HTTP | `127.0.0.1` | Prometheus metrics export; disabled (`0`) by default | 6061 | Same |
| 6062 | daemon | TCP (msgpack) | `RestListenAddress` | Engine TCP API; TCP transport, event subscriptions and workers for the SDKs | 6059 | Same |
| 6063 | daemon | HTTPS, WSS | `RestListenAddress` | Engine-native REST and WebSocket; WSS transport for the CLI and the SDKs | 6058 | Same |
| 6064 | reserved | — | — | Next engine transport | — | — |
| 6065 | identity | HTTP | `127.0.0.1` | OIDC issuer and token endpoint (`/auth`) | 6062 | Same |
| 6066 | identity | HTTP | `127.0.0.1` | Health check (`/healthz`) | 6063 | Same |
| 6067 | identity | gRPC | `127.0.0.1` | Dex gRPC | 5557 | Same |
| 6068 | dexuser | HTTP | `127.0.0.1` | User administration UI | 6064 | Same |
| 6069 | reserved | — | — | Next identity listener | — | — |
| 6070 | mcp-server | HTTP, HTTPS | `0.0.0.0` | MCP Streamable HTTP | 6071 | Same |
| 443 | UI (nginx) | HTTPS | `0.0.0.0` | Production entry | 443 | Same |

The UI forwards to fixed targets: `/appmesh/` to 6060, `/auth/` to 6065 and `/dexuser/` to 6068.

Configuration keys: `REST.RestListenPort` (6060), `REST.TcpApiPort` (6062), `REST.WebSocketPort` (6063) and `REST.PrometheusExporterListenPort` (6061).

## 3. Client default ports

| Client | HTTP | TCP | WSS |
|---|---|---|---|
| CLI `appm` | — | — | 6063 |
| Go, Python, Rust, Java and JavaScript SDKs | 6060 | 6062 | 6063 |

The SSE side channel of a TCP client always uses 6063. When ports are shifted, all clients must pass the port explicitly.

## 4. Migration

The port change is breaking. A deployment and its clients must move to the new ports together; there is no transition period. The default issuer follows the Dex port, so every principal ID changes. The Previous column shows the old port of each listener.

## 5. Security baseline

- 6060, 6061, 6065, 6066, 6067 and 6068 bind to `127.0.0.1` by default.
- Publish only 443, 6060, 6062, 6063 and 6070 externally.
- When 6061 is enabled, the metrics endpoints require a token, unless `REST.MetricsRequireAuth` is `false`.
