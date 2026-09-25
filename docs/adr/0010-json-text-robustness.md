# ADR 0010: JSON and text robustness decisions

- Status: Accepted
- Date: 2026-09-19
- Updated: 2026-09-26

## Context

An audit checked the I18N handling and the JSON handling across the daemon, the agent, the CLI, the SDKs, and the MCP components. It found no need for a translation framework. It found JSON defects. The defect fixes are complete.

## Decisions

- Fixed interface strings are English today. Do not link ICU or other large Unicode libraries. A light embedded message table is allowed. User data passes through in its original language.
- All clients use status codes and protocol fields for control flow, never message text.
- Application names stay limited to `[A-Za-z0-9_-]`, maximum 128 characters.
- SDKs return UTF-8 text on all platforms.
- The `X-File-Path` value is percent-encoded UTF-8; the daemon and the agent are the only decode points.
- MCP application views omit empty values.
- Review rule: reject code or dependencies that call `setlocale` with a non-C locale.

## Open item

Add an optional machine-readable `code` field to the REST error body. Deferred.
