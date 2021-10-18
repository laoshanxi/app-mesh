# Remote run
App Mesh support remote run a command, a script, and even a section of Python script

## Run commands
```
# appc run -c whoami
root
```


## Run Python script
Use metadata to input python script which would be executed on remote side:
```
# appc run -n  run_python -g "print(99); print(2+9)" -t -1
99
11
```
