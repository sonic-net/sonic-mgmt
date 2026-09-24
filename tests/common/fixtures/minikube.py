"""Fixtures for the disposable Minikube profile reserved for this test suite."""

import os
from contextlib import contextmanager

import pytest

from tests.common.minikube import DEFAULT_PROFILE
from tests.common.minikube import MinikubeCluster
from tests.common.minikube import MinikubeError
from tests.common.minikube import MinikubeSpec
from tests.common.minikube import select_minikube_duthost
from tests.common.minikube import select_minikube_vmhost


def _option(request, name, default):
    try:
        return request.config.getoption(name)
    except ValueError:
        return default


def _vmhost_user(host_vars):
    secret_group_vars = host_vars.get("secret_group_vars")
    secret_vmhost = secret_group_vars.get("vm_host", {}) if isinstance(secret_group_vars, dict) else {}
    candidates = (
        os.environ.get("SONIC_MGMT_VM_HOST_USER"),
        host_vars.get("ansible_user"),
        host_vars.get("vm_host_user"),
        secret_vmhost.get("ansible_user") if isinstance(secret_vmhost, dict) else None,
    )
    for value in candidates:
        if isinstance(value, str) and value and "{{" not in value and "}}" not in value:
            return value
    return None


@pytest.fixture(scope="module")
def minikube_duthost(request, duthosts):
    try:
        return select_minikube_duthost(duthosts, _option(request, "--minikube-dut", None))
    except MinikubeError as error:
        pytest.fail(str(error))


@pytest.fixture(scope="module")
def minikube_cluster(request, vmhosts):
    vmhost = select_minikube_vmhost(vmhosts, _option(request, "--minikube-vmhost", None))
    spec = MinikubeSpec(profile=_option(request, "--minikube-profile", DEFAULT_PROFILE))
    inventory_host = vmhost.host.options["inventory_manager"].get_host(vmhost.hostname)
    host_vars = vmhost.host.options["variable_manager"].get_vars(host=inventory_host)
    vmhost_user = _vmhost_user(host_vars)
    if not vmhost_user:
        pytest.fail("Minikube VM host inventory must define vm_host_user or ansible_user")
    proxy_environment = host_vars.get("proxy_env", {})
    with MinikubeCluster(
        vmhost,
        spec=spec,
        proxy_environment=proxy_environment,
        vmhost_user=str(vmhost_user),
    ) as cluster:
        yield cluster


@pytest.fixture
def minikube_dut_factory(minikube_cluster):
    """Join the explicit DUT supplied by the caller; CLI DUT selection is not used."""

    @contextmanager
    def join(duthost):
        with minikube_cluster.joined_dut(duthost) as joined:
            yield joined

    return join


@pytest.fixture
def joined_minikube_dut(minikube_dut_factory, minikube_duthost):
    with minikube_dut_factory(minikube_duthost) as joined:
        yield joined
