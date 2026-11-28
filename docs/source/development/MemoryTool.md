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

The daemon has a built-in valgrind control. You do not start valgrind by hand.

### build precondition

The control is compiled only when `NDEBUG` is not defined
(`main.cpp`: `#if !defined(NDEBUG) && !defined(_WIN32)`). A release build has no
valgrind code at all, and the control files have no effect. Build with
`-DCMAKE_BUILD_TYPE=Debug` for a valgrind test.

```shell
nm -C bin/appmesh | grep valgrind_main   # no output = compiled out
```

Do not search for the text `appmesh.valgrind`. The daemon builds the log file
name at run time from the binary name.

### start the daemon under valgrind

```shell
sudo touch /opt/appmesh/bin/appmesh.valgrind
sudo systemctl restart appmesh
```

The options come from `src/common/Valgrind.h`:

```
valgrind --tool=memcheck --trace-children=no --leak-check=full \
         --show-reachable=yes --error-limit=no --log-file=appmesh.valgrind.%p.log
```

### how to test: live heap A/B with vgdb

`vgdb` reads the live heap of the running daemon. The daemon keeps running, and
one process gives the before and the after report.

```shell
PID=$(pgrep -f '/usr/bin/valgrind.bin' | head -1)
sudo vgdb --pid=$PID leak_check full reachable any > before.txt
# run the test
sudo vgdb --pid=$PID leak_check full reachable any > after.txt
sleep 240
sudo vgdb --pid=$PID leak_check full reachable any > late.txt
```

Aggregate each file by allocation stack, then subtract. Any small script that
parses `--alloc-fn` stack blocks and computes the per-stack difference does this
calculation.

| Compare | Meaning of a positive value |
|---------|-----------------------------|
| before -> after | Memory that the test left in the heap. |
| before -> late | Memory that a timer released. Not a leak. |

Use 240 s before the `late` report. Two timers can hold a closed connection for
that long: the idle-connection timeout, 120 s (`Adaptor.cpp`), and the WebSocket
ping timer, 30 s (drogon default).

The daemon also stops itself on this file, and then valgrind writes a report:

```shell
sudo touch /opt/appmesh/bin/appmesh.valgrind.stop
```

The report goes to `/opt/appmesh/appmesh.valgrind.<pid>.log`. **In a container
test this stop file had no effect.** Use `vgdb`.

Do not stop with `service appmesh stop`. The shutdown releases the long-lived
containers of the daemon, and valgrind reports no leak.

### how to read the report

| Kind | Meaning |
|------|---------|
| definitely lost | No reference points to the block. A real leak. |
| indirectly lost | A child of a "definitely lost" block. |
| possibly lost | A reference points to the middle of the block. |
| still reachable | A live container holds the block. |

Memory that is released at shutdown shows up as **still reachable**, not as
"definitely lost". Look at `still reachable` first.

### points that cause wrong results

- **Do not use `SIGKILL`.** Valgrind writes no report for a killed process.
- **Wait longer than every timer.** A settle time of 30 s tells you nothing.
- **Take the `before` report after the daemon is idle.** Startup allocations are
  not part of the test.
- **Count connections, not only requests.** The same total of requests over many
  connections and over few connections separates a per-connection cost from a
  per-request cost.
- **Do not trust RSS.** The allocator keeps freed pages. A clean live heap can
  come with a rising RSS.
