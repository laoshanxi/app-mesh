# Task Run

This document specifies the two execution models that send work to a node on demand: one-shot runs (a process per request) and the task RPC (a request into an already-running application). Endpoint lists live in [REST API](../interfaces/RESTAPI.md); the streaming variant lives in [Streaming interfaces](../interfaces/Streaming.md).

## 1. One-shot runs

`POST /appmesh/app/run` starts a command asynchronously; `POST /appmesh/app/syncrun` waits for it. Both create a `OneShot` application (see [Application Management](AppManagement.md)):

- an anonymous run takes the command from the request body;
- a run naming a registered application uses a temporary copy of that definition (a managed application's normal launches stay with the scheduler);
- the async reply carries `process_uuid`; follow the run with the output API or events;
- on-demand Docker runs start the container, stream its output, and report the container exit code; the image must exist locally — an on-demand run never pulls (register the application to pull first).

### 1.1 Sync output paging

`syncrun` returns at most 5 MiB of output in one response. When more output may follow:

| Header | Meaning |
| --- | --- |
| `X-Output-Truncated: 1` | The response is incomplete |
| `X-Output-Position` | The position that follows the returned output |
| `X-App-Name` | The run's application name |

Read the rest with `GET /appmesh/app/{X-App-Name}/output?stdout_position={X-Output-Position}` and repeat until a response is shorter than 5 MiB. A multi-page run stays registered for 10 minutes after the reply; delete it or let retention remove it. A run whose output fits one page is removed when the reply is sent.

### 1.2 Client disconnect

`syncrun` stops the on-demand run when the waiting client disconnects. This cleanup needs a direct connection to the REST listener: the agent port and the CLI/WebSocket transports multiplex requests over one connection, so the engine cannot observe the disconnect there and the run continues until it finishes or times out.

## 2. Task RPC

The task RPC sends a payload to a running application process and waits for the result — an in-memory call with no process startup cost. The same mechanism drives the workflow engine and the LLM agent.

### 2.1 Model

```text
client                                App Mesh daemon                worker application
  run_task(app, payload, timeout)  →    queue (FIFO, max 512)   →    fetch_task()
  result                           ←    route by process key    ←    send_task_result(output)
```

- Client calls: `run_task` (send and wait) and `cancel_task` (cancel the pending request).
- Worker calls: `fetch_task` (block for the next payload) and `send_task_result` (return the output).
- Use the HTTP client for short-lived requests and the TCP client for long-running workloads (see [SDK Behavioral Contract](../interfaces/SDKContract.md) for the per-language names and the loop contract).
- A worker that produces output continuously (model token streams, progress) pushes partial results on the same call through [streaming task RPC](../interfaces/Streaming.md); a plain task answers one final result.

### 2.2 Worker example

```python
from appmesh import AppMeshWorkerTCP

context = AppMeshWorkerTCP()
while True:
    payload = context.fetch_task()      # block until a task arrives
    output = do_the_work(payload)       # application code
    context.send_task_result(output)    # return the result to the caller
```

The Python SDK ships a ready task application (`py-exec`) that evaluates the payload as Python code:

```python
from appmesh import AppMeshClient
client = AppMeshClient(bearer_token=token)
print(client.run_task(app_name="py-exec", data="print(sum(range(100)))"))   # 4950
```

### 2.3 Rules

- Requests queue FIFO per application; the queue holds at most 512 pending requests and answers `503` when full.
- A worker restart re-dispatches the active task first; replies from an old worker process cannot pollute a new run.
- Task status is visible on the application: `idle` (worker blocked in `fetch_task`), `busy` (task dispatched or queued), empty (no task service).
- With request forwarding, a task reaches an application on another node (see [Cluster](Cluster.md)).

## 3. Related

- [Application Management](AppManagement.md) — lifecycle and scheduling of the target applications
- [Streaming interfaces](../interfaces/Streaming.md) — partial-result task RPC, output streams, stdin injection
- [SDK Behavioral Contract](../interfaces/SDKContract.md) — worker loop contract across SDKs
- [Cluster](Cluster.md) — `-F` forwarding for cluster-wide execution
