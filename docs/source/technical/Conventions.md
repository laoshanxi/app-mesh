# Data Conventions

This document specifies the cross-cutting data conventions of the App Mesh interfaces: time representation, text encoding, identifiers, and control-flow rules. Clients and integrations follow these rules on every transport.

## 1. Time

| Value | Representation |
| --- | --- |
| Absolute instants (`start_time`, `end_time`, response timestamps) | Unix epoch seconds; other formats are rejected at the API |
| Intervals (`interval`) | Integer seconds, numeric text, or an ISO-8601 duration |
| Daily windows (`daily_limitation`) | UTC seconds since midnight; the server normalizes epoch-seconds values from SDKs to the same form |
| Log and display output | ISO 8601 |

- The daily window is a UTC time-of-day rule with no calendar meaning. Convert local time at the client boundary before sending the value.
- Scheduling boundaries are half-open: `start_time` is a valid instant, `end_time` is not; the daily window is `[daily_start, daily_end)`, with equal endpoints meaning the full day. See [Application Management](../engine/AppManagement.md).

## 2. Text and encoding

- All interfaces and SDKs use UTF-8 on every platform; user data passes through in its original language.
- Fixed interface strings are English. Clients use status codes and protocol fields for control flow, never message text.
- `X-File-Path` values are percent-encoded UTF-8; the daemon and the agent are the only decode points.
- Nothing depends on a process locale; clients must not call `setlocale` with a non-C locale.

## 3. Identifiers

| Identifier | Rule |
| --- | --- |
| Application name | `[A-Za-z0-9_-]`, at most 128 characters; Docker applications must start with a letter or digit (container-name rules) |
| Principal ID | Derived from the immutable issuer and subject of a token; display names never authorize |
| Workflow run ID | An xid assigned at run creation |
| `process_uuid` | Identifies one async run for output queries and START events |

## 4. JSON robustness

- Invalid duration syntax and malformed schedule values are rejected while parsing the application, not at run time.
- The daemon validates JSON structure at the boundaries where it consumes external documents (Docker API responses, workflow payloads); a parse failure is an error value, not an exception path in the control flow.
- MCP application views omit empty values.

## 5. Related

- [Application Management](../engine/AppManagement.md) — the scheduling semantics these time forms feed
- [REST API](../interfaces/RESTAPI.md) — the field-level reference
