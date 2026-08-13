---
name: appmesh-remote
description: Sync local source and build, test, run, diagnose, or deploy it on a remote App Mesh node. Use for remote execution sandbox requests when APPMESH_WORKSPACE is configured; keep file editing, source search, and Git operations local.
---

# App Mesh Remote Execution

Edit source locally and execute operating-system workloads on a remote App Mesh
node. Use the coding agent's native file tools for local work and the bundled
script only for remote work.

## Resolve the bundled tool

Resolve `<skill-dir>` as the directory containing this `SKILL.md`, following its
project discovery link when necessary. Invoke the tool as:

```bash
python3 <skill-dir>/scripts/remote.py <command> [arguments]
```

In this repository the canonical path is
`.agents/skills/appmesh-remote/scripts/remote.py`. Claude Code reaches the same file
through the repository-level `.claude` link to `.agents`.

## Load supporting guidance when needed

- Read `references/configuration.md` when setting up the skill, configuring
  authentication or TLS, changing synchronization excludes, or installing it in
  another repository.
- Read `references/troubleshooting.md` after a connection, synchronization,
  execution, deployment, output, or cleanup failure.

Before remote execution, confirm that the App Mesh Python SDK is installed, a
daemon is reachable, and `APPMESH_WORKSPACE` identifies the remote source tree.

Treat credentials and TLS settings as user-provided configuration. Never invent
or print secret values.

## Route work

- Keep reading, editing, creating, and searching source files local.
- Keep Git status, diff, commit, and push operations local.
- Use `sync-exec` for builds, tests, and programs that need current local source.
- Use `exec` for remote diagnostics or system commands that do not need a sync.
- Use `sync` when the user requests file synchronization only.
- Use `run-script` for a standalone local script that should be uploaded, run,
  and removed.
- Use `deploy` to register a long-running remote application.
- Use `output` to inspect a deployed application's output.
- Use `cleanup` to stop and remove a remote application.

## Commands

Synchronize source, then build or test:

```bash
python3 <skill-dir>/scripts/remote.py sync-exec "<command>" --timeout <seconds>
```

Execute without synchronization:

```bash
python3 <skill-dir>/scripts/remote.py exec "<command>" --timeout <seconds>
```

Run the other workflows:

```bash
python3 <skill-dir>/scripts/remote.py sync [--force]
python3 <skill-dir>/scripts/remote.py run-script <file> --timeout <seconds>
python3 <skill-dir>/scripts/remote.py deploy <name> "<command>"
python3 <skill-dir>/scripts/remote.py output <app-name>
python3 <skill-dir>/scripts/remote.py cleanup <app-name>
```

## Typical examples

Build and test the synchronized source tree:

```bash
python3 <skill-dir>/scripts/remote.py sync-exec "cmake -S . -B build && cmake --build build -j\$(nproc)" --timeout 600
python3 <skill-dir>/scripts/remote.py sync-exec "ctest --test-dir build --output-on-failure" --timeout 600
```

Inspect the remote environment without synchronizing source:

```bash
python3 <skill-dir>/scripts/remote.py exec "uname -a && python3 --version" --timeout 60
```

Deploy a service, inspect its output, then remove it:

```bash
python3 <skill-dir>/scripts/remote.py deploy my-api "python3 service.py"
python3 <skill-dir>/scripts/remote.py output my-api
python3 <skill-dir>/scripts/remote.py cleanup my-api
```

## Execution rules

1. Confirm `APPMESH_WORKSPACE` is set before synchronization or deployment.
2. Preserve the user's command and choose a timeout appropriate to the workload.
3. Report the remote exit code and relevant output.
4. Treat a nonzero remote exit code as a failed build, test, or run.
5. On interruption, clean up the temporary App Mesh application when the tool
   reports its name.
