# Troubleshooting

Read this reference after a remote connection, synchronization, execution,
deployment, output, or cleanup failure.

## Configuration and connection

- `APPMESH_WORKSPACE not set`: configure the remote source directory before
  `sync`, `sync-exec`, or `deploy`.
- `Failed to connect`: verify `APPMESH_HOST`, network reachability, daemon status,
  username, and password.
- TLS verification failure: provide the correct CA file through
  `APPMESH_SSL_VERIFY`. Use `false` only for an explicitly trusted development
  node.
- `No module named appmesh`: install the Python SDK in the interpreter used to
  invoke `scripts/remote.py`.

## Synchronization

- Use `sync --force` when a previous successful-sync marker is stale.
- Add build products or large generated directories to
  `APPMESH_SYNC_EXCLUDE` as comma-separated tar patterns.
- A remote extraction failure should leave the local tree untouched. Inspect the
  reported output, remote disk space, and `APPMESH_WORKSPACE` permissions.

## Execution and deployment

- A nonzero exit code is a command failure; report the relevant output rather
  than treating transport success as task success.
- Increase `--timeout` only when the workload is expected to run longer. Do not
  retry indefinitely.
- After interruption, use the application name printed by the tool with
  `cleanup <app-name>` if automatic cleanup did not finish.
- If `output` or `cleanup` cannot find an application, verify the name printed by
  `deploy` or `exec` and confirm that the same App Mesh node is configured.
