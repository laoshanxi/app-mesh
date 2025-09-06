# Remote Task

App Mesh supports both process-level remote calls and code/task-level remote calls without injecting user code.

## Overview

Remote tasks allow a client send a payload to App Mesh. App Mesh dispatches the payload to a running application process, which processes it and returns the result.

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
    mesh = AppMeshServer()
    while True:
        # Block fetch invocation payload.
        payload = mesh.task_fetch()
        # Execute with payload and capture prints.
        output = exec_with_output(payload)
        # Return the result to the client
        mesh.task_return(output)

```

### Demo

```shell
$ appc ls
ID  NAME    OWNER  STATUS   HEALTH  PID   USER  MEMORY    %CPU  RETURN  AGE  DURATION  STARTS  COMMAND
1   pyrun   mesh   enabled  OK      2833  root  29.1 MiB  0     -       44s  44s       1       "python3 ../../bin/py_t*"
2   ping    mesh   enabled  OK      2834  root  3.3 MiB   0     -       44s  44s       1       "ping github.com"

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
```