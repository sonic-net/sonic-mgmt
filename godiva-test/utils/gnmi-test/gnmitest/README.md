# gnmitest - A Test Framework for gNMI

The gnmitest framework contains a test runner, and a set of tests to validate
an implementation of the gNMI protocol. The tests are schema-aware, such that
they can also validate the payload carried by gNMI - particularly, this allows
compliance tests against the OpenConfig schema to be implemented.

The framework is intended to:

1. Perform compliance tests for gNMI against the specification.
1. Validate compliance with the OpenConfig schema.
1. Allow augmentation to qualify a specific implementation against a set of
   operational requirements, such as a mandatory set of paths.

The gnmitest framework can be used as part of a wider test framework, to perform
device interactions such as setting configuration, or as a validator that
particular telemetry values are sent by a device in response to a particular
stimulus. Currently, gnmitest does not validate the correctness of data that is
returned by telemetry, or the behaviour of the device once a configuration has
been applied.

**Note**: This is not an official Google product.

## Tests in gnmitest

The tests that the framework can run are specified under the `tests` directory,
and are organised according to the gNMI RPC that they test.

Tests that validate the behaviour of streaming telemetry implementations can be
found in the `subscribe` directory -- for example, providing schema compliance
tests for paths in received `Notifications`, and checks for data completeness -
such as all expected entries being present in a list. As the framework is
extended, additional subscription tests (value compliance with the schema, path
set completeness) will be implemented within this directory.

The `getsetv` directory contains tests that relate to the Get and Set RPCs.
Particularly, these tests allow the retrieval and manipulation of configuration
on a device.

You can also learn about [executing gnmitest `Suite`](https://github.com/openconfig/gnmitest/tree/master/docs/running_gnmitest.md)
and [extending gnmitest `Subscribe` tests](https://github.com/openconfig/gnmitest/tree/master/docs/extending_gnmitest_subscribe_tests.md).
