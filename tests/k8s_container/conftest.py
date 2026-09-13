"""Collection controls for explicitly selected Kubernetes container tests."""

from pathlib import Path

import pytest


_SUITE_DIRECTORY = Path(__file__).resolve().parent


def _is_suite_test(path):
    path = Path(str(path)).resolve()
    try:
        path.relative_to(_SUITE_DIRECTORY)
    except ValueError:
        return False
    return path.name.startswith("test_")


def pytest_addoption(parser):
    group = parser.getgroup("Kubernetes gNMI provider")
    group.addoption(
        "--k8s-container-test",
        action="store_true",
        default=False,
        help="Run explicitly selected Kubernetes container infrastructure tests",
    )
    group.addoption("--minikube-profile", default="sonic-mgmt-k8s", help="Explicit Minikube profile")
    group.addoption("--minikube-vmhost", default=None, help="Exact associated server hostname")
    group.addoption("--minikube-dut", default=None, help="Exact DUT hostname")
    group.addoption(
        "--minikube-allow-shared-profile",
        action="store_true",
        default=False,
        help="Allow compatible profile reuse without a framework ownership contract",
    )
    group.addoption(
        "--k8s-gnmi-image",
        default=None,
        help="Version-pinned candidate image already present on the selected DUT",
    )
    group.addoption(
        "--k8s-gnmi-role",
        choices=("golden", "candidate"),
        default="golden",
        help="Evidence role for the deployed image",
    )


def pytest_ignore_collect(collection_path, config):
    if _is_suite_test(collection_path) and not config.getoption("--k8s-container-test"):
        return True
    return None


def pytest_collection_modifyitems(config, items):
    if config.getoption("--k8s-container-test"):
        return
    # Explicit file selections bypass pytest_ignore_collect; keep a skipped result
    # instead of an empty session with exit code 5.
    for item in items:
        if _is_suite_test(item.path):
            item.add_marker(pytest.mark.skip(reason="Requires explicit --k8s-container-test opt-in"))
