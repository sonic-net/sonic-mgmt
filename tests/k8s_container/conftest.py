"""Collection controls for explicitly selected infrastructure tests."""


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
    if not collection_path.name.startswith("test_"):
        return False
    try:
        return not config.getoption("--k8s-container-test")
    except ValueError:
        return True
