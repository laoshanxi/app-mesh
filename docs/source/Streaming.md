# Streaming interfaces

Large-model services produce output continuously and often accept input
continuously. App Mesh serves those workloads with three streaming
primitives on the plain HTTPS REST listener, so any HTTP client — `curl`,
a browser `fetch`, an OpenAI-style consumer — receives tokens as they are
produced:

| Primitive | Route | Purpose |
|---|---|---|
| Output stream | `GET /appmesh/app/{name}/output/stream` | Server-sent stdout follow (replay + live) |
| Streaming task RPC | `POST /appmesh/app/{name}/task/stream` | Worker partials + final result over one call |
| stdin injection | `POST /appmesh/app/{name}/input` | Drive a running process turn by turn |

All three answer on the same listener as the REST API (default port 6058)
and use the standard bearer authentication and the application permission
model. The server pushes frames as `text/event-stream` (SSE); a comment
line (`: ping`) arrives every 15 seconds as a keep-alive and disconnect
probe.

## Event contract

Every stream emits zero or more data events and exactly one terminal
`end` event, then closes:

```
event: stdout   data: {"position": <byte offset>, "raw_size"?: <int>, "output": "<text>"}
event: partial  data: {"data": "<text>"}
event: final    data: {"result": "<payload string>"}
event: end      data: {"reason": "...", "exit_code"?, "position"?, "status"?, "message"?}
```

`stdout` positions are raw stdout byte offsets; `output` is the UTF-8
sanitized text, and `raw_size` (present when the sanitation changed the
length) keeps a cursor consumer on raw offsets.

| `end.reason` | Meaning |
|---|---|
| `exit` | The process exited; `exit_code` and the final `position` are set |
| `removed` | The application was removed while the stream was open |
| `timeout` | The stream's overall `timeout` elapsed |
| `eof` | Replay finished on a `follow=false` stream |
| `final` | The streaming task delivered its final result |
| `disconnected` | The keep-alive heartbeat detected the peer is gone |
| `error` | The call failed; `status` and `message` carry the equivalent HTTP answer |

## Output stream

```
GET /appmesh/app/{name}/output/stream?stdout_position=0&process_uuid=&follow=true&timeout=3600
```

- `stdout_position`: byte cursor to start from; `0` replays from the beginning.
- `process_uuid`: pin the stream to one run; empty follows the current run.
- `follow`: `true` (default) keeps streaming until the run exits; `false`
  replays to the current end of output and stops with `end{eof}`.
- `timeout`: overall stream lifetime in seconds (default 3600, maximum 86400).

The server subscribes before it replays and reconciles both by the byte
cursor, so a client never sees a gap or a duplicate between the replay and
the live frames.

```
$ curl -N -H "Authorization: Bearer $TOKEN" \
    "https://127.0.0.1:6058/appmesh/app/inference/output/stream?follow=true"
event: stdout
data: {"position":0,"output":"token1 token2 "}

event: stdout
data: {"position":14,"output":"token3"}

event: end
data: {"reason":"exit","exit_code":0,"position":21}
```

Permission: `app-output-view` plus read access to the application.

## Streaming task RPC

```
POST /appmesh/app/{name}/task/stream?timeout=300
<body: the task payload, same contract as POST /appmesh/app/{name}/task>
```

The call parks like a normal task RPC. A worker (see the Worker API below)
may push any number of `partial` events while it works; its final reply
arrives as `final` and the stream ends with `end{final}`. A one-shot
`run_task` caller receives no partials; a streaming caller that never gets
a worker reply ends with `end{timeout}` or `end{error}`.

Permission: `app-run-task` plus write access to the application. Framed
transports (TCP 6059, WSS control channel) answer this route with 405:
streams belong to plain HTTP.

### Worker side

A managed process pushes partials through its worker helper. The daemon
authenticates the call with the process pre-shared key, exactly like the
final task reply:

```python
from appmesh import AppMeshWorker

worker = AppMeshWorker()          # inside a managed App
worker.send_task_partial("token ")   # -> SSE "partial" event
worker.send_task_result(...)         # -> SSE "final" event
```

## stdin injection

```
POST /appmesh/app/{name}/input
Content-Type: application/octet-stream
X-Input-Close: true          (optional: close the pipe after this write)

<body: raw bytes for the process stdin>
```

The application must be registered with `"stdin": "pipe"`. The daemon keeps
the pipe's write end open; each call writes the body to the running process,
and `X-Input-Close: true` sends EOF. Read the echo or the produced output
with the output stream. This turns an interactive CLI (a model chat binary,
an agent REPL) into a conversational resource:

```python
from appmesh import App, AppMeshClient

client = AppMeshClient(bearer_token=TOKEN)
client.add_app(App({"name": "chat", "command": "my-model-cli", "stdin": "pipe"}))
for turn in ["Hello!", "What did I say?"]:
    client.send_input("chat", turn + "\n")
    for token in client.follow_output("chat"):
        print(token, end="")
client.send_input("chat", b"", close=True)   # EOF: the process exits
```

Rules:

- `"stdin": "pipe"` cannot be combined with launch `metadata` (metadata
  feeds the process stdin once at start), and container applications do not
  support it.
- A full pipe answers 412 with the number of bytes already written; retry
  with the remainder.
- No running process answers 409.

Permission: `app-control` plus write access to the application.

## Python SDK

The SDK (>= 3.0.20) wraps all three primitives as generators; the
generator's return value is an `SseEnd` marker:

```python
from appmesh import AppMeshClient

client = AppMeshClient(bearer_token=TOKEN)

# 1) stream a one-shot run
for chunk in client.stream_run("python3 infer.py --prompt '...'"):
    print(chunk, end="")

# 2) streaming task RPC (LLM agent token stream)
end = None
for token in client.run_task_stream("llm-agent",
        '{"action":"session_send","session_id":"s1","input":"hi","stream":true}',
        timeout=180):
    print(token, end="")
# end.result carries the final envelope

# 3) follow an application's output
for chunk in client.follow_output("inference", follow=True, timeout=600):
    print(chunk, end="")

# 4) stdin injection (see above)
client.send_input("chat", "Hello!\n")
```

TCP and WebSocket clients use a direct HTTPS connection for these methods
(the same side-channel shape as file transfers) — a framed transport cannot
carry a chunked event stream. The other SDKs keep their callback-based
wait/subscribe APIs for now.

## Limits and scope

- Streams do not traverse node forwarding (`X-Target-Host`) or the agent
  proxy (6060); connect to the target node's REST listener directly.
- Browser `EventSource` cannot set an `Authorization` header; use `fetch`
  with a ReadableStream reader for bearer-authenticated streams.
- An SSE replay covers the current run only; rotated stdout files keep
  their `GET /appmesh/app/{name}/output?stdout_index=N` interface.
- Request-signature hardening covers the streamed endpoints with the
  empty-body hash exemption, like the streamed file endpoints.
