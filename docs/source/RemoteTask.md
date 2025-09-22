# Remote Task (in-memory compute)

App Mesh supports both process-level and code/task-level remote calls without injecting user code. Task-level remote execution provides in-memory compute capability, delivering extreme performance for high-throughput workloads.

## Overview

Remote tasks allow a client to send a payload to App Mesh. App Mesh dispatches the payload to a running application process, which processes it and returns the result.

With request forwarding, you can achieve cluster-level task execution.

### Client

The client sends a payload (task data) to App Mesh and waits for the response.

```python
from appmesh import AppMeshClient
# Initialize the App Mesh Client
client = AppMeshClient()
if client.login("admin", "admin123"):
    count_in_server = "0"
    for i in range(10):
        # task data
        task_data = f"print({count_in_server}+{i}, end='')"
        # remote invoke and get result
        count_in_server = client.run_task(app_name="pytask", data=task_data)
        # print
        print(count_in_server)
```

### Server

The server is the application process managed by App Mesh. It receives the payload, processes it, and returns the result.

```python
from appmesh import AppMeshServer
if __name__ == "__main__":
    # Minimal server loop: fetch a payload, execute it, return the output.
    context = AppMeshServer()
    while True:
        # Block fetch invocation payload.
        payload = context.task_fetch()
        # Execute with payload and capture prints.
        output = exec_with_output(payload)
        # Return the result to the client
        context.task_return(output)

```

### Demo

```shell
$ appc ls
ID  NAME    OWNER  STATUS    HEALTH  PID    USER  MEMORY    %CPU  RETURN  AGE  DURATION  STARTS  COMMAND
1   pytask  mesh   enabled   OK      16412        32.7 MiB  0     1       8h             2       "python.exe ../../bi*"
2   pyexec  mesh   disabled  -       -      -     -         -     -       8h   -         0       "python.exe ../../bi*"
3   ping    mesh   enabled   OK      -      -     -         -     0       8h   -         1       "ping github.com"

$ python3 sample.py
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

$ appc ls -a pytask | grep task_
task_id: 23
task_status: busy
```

### Task status

The task status is represented by application runtime attributes. Possible values include:

- `idle`: the service is ready and waiting for a task
- `busy`: a task has been dispatched and is currently processing

### API

Client:

- run_task(): send an invocation message to a running App Mesh application and wait for result
- cancle_task(): cancle a running task to a App Mesh application

Note: Use AppMeshClient (HTTP) for short-lived requests and AppMeshClientTCP (TCP) for long-running workloads.

Server:

- task_fetch(): retrieve a task data in the currently running App Mesh application process
- task_return(): response the result of a server-side invocation back to the original client.
