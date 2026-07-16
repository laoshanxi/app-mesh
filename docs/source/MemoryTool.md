# C++ memory tools

## libasan memory test

### build with libasan

```shell
cmake -DENABLE_ASAN=ON ..
```

### run appmesh with asan

```shell
cd /opt/appmesh
ASAN_OPTIONS=verbosity=1 bin/appmesh 2> output.txt

```

more asan options can be found from [wiki](https://github.com/google/sanitizers/wiki/AddressSanitizerFlags).

### check report

the asan output (stderr) was redirected to local file `output.txt`

## valgrind memory check

### enable valgrind attach for appmesh daemon

```shell
sudo touch /opt/appmesh/bin/appmesh.valgrind
sudo systemctl restart appmesh
```

### run test as much as possible

### stop valgrind test and generate report

```shell
touch /opt/appmesh/bin/appmesh.valgrind.stop
```

the valgrind report can be found from `/opt/appmesh/bin/appmesh.valgrind.$pid.log`
