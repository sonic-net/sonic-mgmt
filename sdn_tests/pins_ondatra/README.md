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

#Running All Tests
- To run all registered test targets at once, use the all_tests filegroup defined in the root BUILD.bazel file.

```
bazel test //:all_tests
```
- Ensure all relevant test targets are added to the all_tests group like below:

filegroup(
    name = "all_tests",
    srcs = [
        "//infrastructure/thinkit:ondatra_generic_testbed_fixture_test",
        "//tests:ethcounter_sw_dual_switch_test",
        "//tests:gnmi_long_stress_test",
        "//tests:gnoi_file_test",
        "//tests/thinkit:arbitration_test",
        "//tests/thinkit:arriba_test",
        # Add new test target here
   ],
)

#Guidelines for Developers

When adding new test targets:

- Define your test target in the appropriate BUILD.bazel file.

- Register it in the tests list inside the filegroup(name = "all_tests", ...) in the root BUILD.bazel

Example:

Add this in your test package's BUILD.bazel

go_test(
    name = "my_new_test",
    srcs = ["my_new_test.go"],
    deps = [...],
)

Now register the test in root BUILD.bazel

filegroup(
    name = "all_tests",
    srcs = [
        "//tests:my_new_test",
        #Other test targets...
    ],
)

- This ensures bazel test //:all_tests includes your test.

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
