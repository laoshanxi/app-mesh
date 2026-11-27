# ADR 0014: Allocate listening ports from 6060

- Status: Accepted
- Date: 2026-11-27

## Context

Listening ports were added one at a time, without an allocation rule. The engine listeners (6058, 6059) sat below the main client entry (6060). The Dex gRPC listener (5557) sat outside the `60xx` block. No rule said where the next listener goes.

## Decision

[Ports.md](../source/Ports.md) is the specification:

1. All listening ports are in `6060-6079`.
2. The REST entry keeps port 6060.
3. Port numbers increase as exposure decreases: entry, engine transports, identity, integrations.
4. Each component owns a fixed slot, and a gap separates the groups.

| Port | Process | Previous |
| --- | --- | --- |
| 6060 | Go agent | 6060 |
| 6061 | Go agent | 6061 |
| 6062 | daemon (TCP) | 6059 |
| 6063 | daemon (HTTPS, WSS) | 6058 |
| 6065 | identity (issuer) | 6062 |
| 6066 | identity (health) | 6063 |
| 6067 | identity (gRPC) | 5557 |
| 6068 | dexuser | 6064 |
| 6070 | mcp-server | 6071 |

This decision supersedes the port numbers quoted in ADR 0003. Its transport decision does not change.

## Consequences

- The change is breaking. A deployment and its clients move to the new ports together; there is no transition period.
- The default issuer follows the Dex port, so every principal ID changes.
- The five SDKs and the CLI change their default ports in the same release.
