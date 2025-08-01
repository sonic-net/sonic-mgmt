# Dependencies:
- Linux (tested on ubuntu)
- Go (https://go.dev/doc/install)
- Bazel-5.4.0+ (https://bazel.build/install)
- Rest of the dependencies should be auto-installed on bazel run.

# Compilation:
```
bazel build ...
```

# Compile and Run Test:
```
bazel run //tests:test_name --test_strategy=exclusive --test_timeout=3600
```


# Debug code:
- Install Delve (https://github.com/go-delve/delve/tree/master/Documentation/installation)
- Compile repo in debug mode:
```
bazel build ... --strip=never --compilation_mode=dbg
```
- Run the test with dlv debugger:
```
dlv --wd=$PWD/tests/ exec bazel-bin/tests/test_name_/test_name -- --testbed=$PWD/testbeds/testbed.textproto
// inside dlv; map path for debugging:
config substitute-path external bazel-pins_ondatra/external
```
