# Remote Task (in-memory compute)

App Mesh supports both process-level and code/task-level remote calls without injecting user code. Task-level remote execution provides in-memory compute capability, delivering extreme performance for high-throughput workloads.

## Overview

Remote tasks allow a client to send a payload to App Mesh. App Mesh dispatches the payload to a running application process, which processes it and returns the result.

With request forwarding, you can achieve cluster-level task execution.

### Client

The client sends a payload (task data) to App Mesh and waits for the response.

The client needs a bearer token. Run `appm logon` once first — it enrolls the first administrator — then mint a token with the built-in password grant (`sudo` is needed on a native install):

```shell
export APPMESH_BEARER_TOKEN=$(curl -s -u "appmesh-cli:" -X POST http://127.0.0.1:6062/auth/token \
    --data-urlencode grant_type=password \
    --data-urlencode "username=admin@appmesh.local" \
    --data-urlencode "password=$(sudo /opt/appmesh/script/appmesh-auth.sh print-initial-password)" \
    --data-urlencode "scope=openid audience:server:client_id:appmesh-api" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
```

```python
import os
from appmesh import AppMeshClient
# Initialize the App Mesh Client
client = AppMeshClient(bearer_token=os.environ["APPMESH_BEARER_TOKEN"])
count_in_server = "0"
for i in range(10):
    # task data
    task_data = f"print({count_in_server}+{i}, end='')"
    # remote invoke and get result
    count_in_server = client.run_task(app_name="py-task", data=task_data)
    # print
    print(count_in_server)
```

### Server

The worker is the application process managed by App Mesh. It receives the payload, processes it, and returns the result.

```python
from appmesh import AppMeshWorkerTCP
from py_task import exec_with_output   # local helper; see src/sdk/python/py_task.py

if __name__ == "__main__":
    # Minimal server loop: fetch a payload, execute it, return the output.
    context = AppMeshWorkerTCP()
    while True:
        # Block fetch invocation payload.
        payload = context.fetch_task()
        # Execute with payload and capture prints.
        output = exec_with_output(payload)
        # Return the result to the client
        context.send_task_result(output)

```

### Demo

```shell
$ appm ls
ID  NAME    OWNER  ENABLED   HEALTH  PID    USER  MEMORY    %CPU  RETURN  AGE  DURATION  STARTS  COMMAND
1   py-task  system  Yes      OK      16412        32.7Mi    0     1       8h             2       "python.exe ../../bi*"
2   py-exec  system  -         -       -      -     -         -     -       8h   -         0       "python.exe ../../bi*"
3   ping    system  Yes       OK      -      -     -         -     0       8h   -         1       "ping github.com"

$ python3 sample.py
Start sample...
... (application add, view, enable, output, and delete output)
0
1
3
6
10
15
21
28
36
45
Completed sample

$ appm ls -a py-task | grep task_
task_id: 23
task_status: idle
```

`sample.py` also runs the application-management demo, which needs `app-reg`,
`app-view`, `app-control`, `app-output-view`, and `app-delete` in addition to
`app-run-task`.

### Task status

The task status is represented by application runtime attributes. Possible values include:

- `idle`: the service is ready and waiting for a task
- `busy`: a task has been dispatched or queued and is currently processing
- empty string: the application has no task service

A worker that has returned the last result and blocked in `fetch_task()` reports `idle`.

### API

Client:

- run_task(): send an invocation message to a running App Mesh application and wait for result
- cancel_task(): cancel a running task to a App Mesh application

Note: Use AppMeshClient (HTTP) for short-lived requests and AppMeshClientTCP (TCP) for long-running workloads.

Server:

- fetch_task(): retrieve a task data in the currently running App Mesh application process
- send_task_result(): send the result of a server-side invocation back to the original client.
