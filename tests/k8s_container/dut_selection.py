"""Fail-closed DUT selection for KubeSonic qualification tests."""

import pytest

from tests.common.minikube import MinikubeError
from tests.common.minikube import select_minikube_duthost


def select_kubesonic_duthost(request, duthosts):
    try:
        explicit_name = request.config.getoption("--minikube-dut")
    except ValueError:
        explicit_name = None
    try:
        return select_minikube_duthost(duthosts, explicit_name)
    except MinikubeError as error:
        pytest.fail(str(error))
