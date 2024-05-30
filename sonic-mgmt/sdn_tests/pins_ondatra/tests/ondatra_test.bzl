"""Generate Ondatra test definitions."""

load("@io_bazel_rules_go//go:def.bzl", "go_test")

def ondatra_test(
        name,
        srcs,
        testbed = "",
        run_timeout = "30m",
        args = None,
        deps = None,
        data = None,
        tags = None,
        visibility = None):
    """Compiles and runs an Ondatra test written in Go.

    Args:
      name: Name; required
      srcs: List of labels; required
      testbed: Label of testbed file; required
      run_timeout: Timeout on the test run, excluding the wait time for the
        testbed to become available, specified as a duration string
        (see http://godoc/pkg/time#ParseDuration); default is 30 minutes
      args: List of args: optional
      tags: List of arbitrary text tags; optional
      deps: List of labels; optional
      data: List of labels; optional
      visibility: List of visibility labels; optional
    """
    data = (data or []) + ["//infrastructure/data"]
    testbed = testbed or "infrastructure/data/testbeds.textproto"
    testbed_arg = "--testbed=%s" % testbed

    args = (args or []) + [
        testbed_arg,
        "--run_time=%s" % run_timeout,
        "--wait_time=0",
    ]
    go_test(
        name = name,
        srcs = srcs,
        deps = deps,
        data = data,
        args = args,
        tags = (tags or []) + ["manual", "exclusive", "external"],
        rundir = ".",
        visibility = visibility,
        size = "enormous",  # Reservation is highly variable.
        local = True,  # Tests cannot run on Forge.
    )

def ondatra_test_suite(
        name,
        srcs,
        testbeds = {},
        per_test_run_timeout = "30m",
        args = None,
        deps = None,
        data = None,
        tags = None,
        visibility = None):
    """Defines a suite of Ondatra tests written in Go.

    For every (testbed-name, testbed-file) entry in the provided testbeds map,
    this rule creates an ondatra_test with the name "[name]_[testbed-name]" and
    the testbed equal to testbed-file.

    Args:
      name: Name; required
      srcs: List of labels; required
      testbeds: Map of custom testbed name to testbed label; required
      per_test_run_timeout: Timeout on each test run in the suite, excluding the
        wait time for the testbed to become available, specified as a duration
        string (see http://godoc/pkg/time#ParseDuration); default is 30 minutes
      args: List of args: optional
      deps: List of labels; optional
      data: List of labels; optional
      tags: List of arbitrary text tags; optional
      visibility: List of visibility labels; optional
    """
    if len(testbeds) == 0:
        testbeds = {"dualnode" : "infrastructure/data/testbeds.textproto"}

    tests = []
    for testbed_name, testbed_src in testbeds.items():
        test_name = "%s_%s" % (name, testbed_name)
        tests.append(test_name)
        go_test_tags = (tags or []) + [testbed_name]
        ondatra_test(
            name = test_name,
            srcs = srcs,
            testbed = testbed_src,
            run_timeout = per_test_run_timeout,
            args = args,
            deps = deps,
            data = data,
            tags = go_test_tags,
            visibility = visibility,
        )

    # Unlike other tags, "manual" on a test_suite means the suite itself is manual.
    native.test_suite(name = name, tests = tests, visibility = visibility, tags = ["manual"])
