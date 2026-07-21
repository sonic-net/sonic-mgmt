"""Pytest composition for native gRPC clients."""

import pytest

from tests.common.grpc_test_environment import (
    DEFAULT_GRPC_TEST_SPEC,
    GrpcTestEnvironment,
)


@pytest.fixture(
    scope="module",
    params=[DEFAULT_GRPC_TEST_SPEC],
    ids=["mtls-standard"],
)
def grpc_spec(request):
    """Return the module's complete gRPC environment selection."""
    return request.param


@pytest.fixture(scope="module")
def _grpc_environment(duthosts, enum_rand_one_per_hwsku_frontend_hostname, grpc_spec):
    """Own managed gRPC server state for native protocol fixtures."""
    environment = GrpcTestEnvironment(
        duthosts[enum_rand_one_per_hwsku_frontend_hostname],
        grpc_spec,
    )
    try:
        yield environment.start()
    finally:
        environment.stop()


@pytest.fixture(scope="function")
def gnmi_client(_grpc_environment):
    """Yield a complete native gNMI client with transport details hidden."""
    client = _grpc_environment.gnmi_client()
    try:
        yield client
    finally:
        client.close()
