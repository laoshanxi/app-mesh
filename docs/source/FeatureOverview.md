# User-Value Feature Overview

This document groups App Mesh features by the value they provide to SDK users.
It describes what users can accomplish, independent of SDK method names,
programming languages, transports, command-line behavior, operating systems, and
internal implementation details.

## Feature Map

```text
SDK User Capabilities
├── Workloads
│   ├── Application Hosting
│   ├── Scheduling and Lifecycle Automation
│   ├── On-Demand Remote Execution
│   └── Resident Application Task Invocation
├── Runtime Assurance
│   ├── Runtime Observation and Events
│   └── Resource Governance and Isolation
└── Platform Capabilities
    ├── Secure Access and Multi-Tenancy
    └── Node Operations and Data Exchange
```

## 1. Application Hosting

App Mesh lets users delegate the continuous management of an application to a
remote node.

- Host native processes.
- Host Docker applications.
- Adopt an existing process.
- Configure commands, working directories, and runtime environments.
- Manage ordinary and sensitive environment variables.
- Enable, disable, update, and remove applications.
- Select the operating-system user that runs an application.
- Control access to an application.
- Persist application definitions and recover their management after a daemon
  restart.

**User value:** applications do not need to implement their own supervision,
recovery, and process-management logic.

## 2. Scheduling and Lifecycle Automation

App Mesh lets users declare when an application should run and how the platform
should react when a run ends.

- Define application start and end dates.
- Restrict execution to a daily time window.
- Run applications at fixed intervals.
- Run applications according to cron schedules.
- Leave an application on standby after exit.
- Restart an application after exit.
- Apply different actions for different exit codes.
- Keep an application continuously available.
- Remove an application automatically after exit.
- Limit restart frequency to contain crash loops.
- Control the handoff and delayed cleanup between recurring runs.

**User value:** timing and exit handling become declarative policies instead of
custom control code.

## 3. On-Demand Remote Execution

App Mesh lets users submit a single unit of work to a remote execution
environment.

- Execute an ad hoc command or script.
- Execute once using an existing application definition.
- Wait synchronously for a complete result.
- Submit work asynchronously and continue with other operations.
- Consume execution output as it is produced.
- Obtain the final process exit result.
- Bound the maximum execution lifetime.
- Bound how long the caller waits.
- Direct execution to a selected remote node.

**User value:** remote nodes become programmable execution environments without
requiring a permanently registered service for every command.

## 4. Resident Application Task Invocation

App Mesh lets users invoke work inside an application that is already running.

- Send a task payload to a resident application.
- Wait for the application to return a result.
- Queue tasks from multiple callers.
- Cancel a task or bound it with a timeout.
- Let an application continuously fetch pending tasks.
- Return text or binary task results.
- Isolate an old application instance after it has been replaced.
- Build resident workers, compute services, and lightweight RPC-style services.

**User value:** callers reuse a warm process and avoid process startup for every
request.

## 5. Runtime Observation and Events

App Mesh lets users inspect current runtime state and react to changes in real
time.

- Inspect application availability and health.
- Inspect process identifiers, exit codes, and start counts.
- Inspect recent start, exit, and error information.
- Inspect the next planned start time.
- Read current and retained output.
- Consume standard output as it is produced.
- Observe application start, output, exit, and removal events.
- Trigger application logic in response to runtime events.
- Wait for asynchronous execution to complete.

**User value:** integrations can combine state queries with event-driven
reactions instead of relying only on polling.

## 6. Resource Governance and Isolation

App Mesh lets users bound application resource consumption and separate
workloads from one another.

- Limit physical memory usage.
- Limit combined memory and swap usage.
- Assign relative CPU weight.
- Inspect application resource consumption.
- Inspect the managed process tree.
- Control retained output history.
- Run an application as a selected operating-system user.
- Isolate applications owned by different App Mesh users.

**User value:** one application or tenant is less likely to exhaust a node or
interfere with other workloads.

## 7. Secure Access and Multi-Tenancy

App Mesh lets programs access remote capabilities with an explicit identity and
bounded authority.

- Authenticate users and establish renewable sessions.
- Use token-based or OAuth-based authentication.
- Require multi-factor authentication.
- Manage users, roles, groups, and permissions.
- Associate applications with owners.
- Apply application-level read and write permissions.
- Protect sensitive runtime configuration.
- Check whether the current identity has a required permission.
- Separate resources belonging to different users.

**User value:** long-running automation clients can operate with least privilege
while tenant resources remain isolated.

## 8. Node Operations and Data Exchange

App Mesh lets users prepare remote nodes, inspect them, and retrieve the results
of remote work.

- Inspect host CPU, memory, storage, and network resources.
- Collect monitoring metrics.
- Describe node capabilities with labels.
- Direct an operation to another node.
- Upload input files and artifacts.
- Download logs, artifacts, and result files.
- Preserve supported file attributes during transfer.
- Inspect and adjust daemon configuration.
- Adjust daemon logging verbosity.

**User value:** applications can automate the setup, execution, observation, and
result-retrieval cycle through one platform.

## Scope Notes

- Application Hosting describes a persisted desired application definition;
  On-Demand Remote Execution describes one execution instance.
- Resident Application Task Invocation reuses an existing process, whereas
  On-Demand Remote Execution starts a new process.
- SDK languages and HTTP, TCP, or WebSocket transports are delivery mechanisms,
  not user-value feature groups.
- Generic raw-request escape hatches are not treated as product features.
- Workflow orchestration is not listed as a first-class SDK feature because the
  current SDKs do not expose a dedicated workflow client contract. It is an
  upper-layer capability built from application hosting, task invocation, and
  remote execution.
