# Changelog

## 4.0.0

**Breaking:** the deprecated snake_case method aliases (`list_apps`,
`set_bearer_token`, `add_app`, `run_app_sync`, `fetch_task`, ...) were
removed. Public methods are camelCase only — migrate callers to the canonical
names (`listApps`, `setBearerToken`, `addApp`, `runAppSync`, `fetchTask`, ...).

Subscription and transport fixes included in this release:

- TCP read side rewritten as a persistent read pump, fixing the
  pause/resume deadlock on large file transfers.
- Zero-length frames are skipped instead of being treated as EOF.
- Concurrent demuxer startup is serialized (`_enableDemuxer` promise chain),
  preventing double read loops.
- `waitForAsyncRun` clears its timeout timer, no longer pinning the event loop.
- A 401 triggers one token refresh + retry and respects caller-managed
  Authorization headers.
- Frame length validation on the TCP read path.
- Subscribe conformance suite (`test/subscribe_test.js`, 22 cases) joined to
  `npm test`.
