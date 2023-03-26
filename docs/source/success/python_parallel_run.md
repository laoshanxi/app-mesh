# Python parallel run
Python does not support real threads to run something parallel, with App Mesh, Python could do this.

## Solution
Use SDK AppMeshClient.run_async() to run process or Python code segment by App Mesh.

### 1. Install App Mesh
[Installation Guide](https://app-mesh.readthedocs.io/en/latest/Install.html#native-installation)

### 2. Python sample
```python
#!/usr/bin/python3
from datetime import datetime
# python3 -m pip install --upgrade appmesh
from appmesh import appmesh_client

# login
client = appmesh_client.AppMeshClient()
client.login("admin", "admin123")

start_time = datetime.now()
# create async run
runs = []
for i in range(100):
    # example: 100 run shell command:
    runs.append(client.run_async(appmesh_client.App({"command": "ping www.baidu.com -w {0}".format(i), "shell": True}), max_time_seconds=8))
    # example: 100 run python code segment:
    runs.append(client.run_async(appmesh_client.App({"name": "pyrun", "metadata": "import time;print({0});time.sleep({0})".format(i)}), max_time_seconds=10))

# wait all async runs to be finished
for run in runs:
    # wait each run flexible
    exit_code = run.wait(stdout_print=False)
    print(exit_code)

print(datetime.now() - start_time)
```
