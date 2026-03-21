"""Kubesonic test utilities.

Helper functions for DUT operations in kubesonic tests.
Similar pattern to tests/k8s/k8s_test_utilities.py.
"""

import logging
import time

logger = logging.getLogger(__name__)

MINIKUBE_VIP_HOSTNAME = "control-plane.minikube.internal"
DUT_CERT_DIR = "/etc/sonic/credentials"
DUT_CERT_BAK = f"{DUT_CERT_DIR}.bak"


def setup_dut(duthost, vmhost):
    """Setup DUT for joining K8s cluster.

    Configures:
    - DNS entry for minikube VIP
    - Certificates from minikube
    - State DB initialization
    - Cgroup driver fix (for Debian 13+)

    Args:
        duthost: DUT host fixture
        vmhost: VM host fixture (where minikube runs)
    """
    _setup_dns(duthost, vmhost)
    _install_certs(duthost, vmhost)
    _check_state_db(duthost)
    _fix_cgroup_driver(duthost)


def join_cluster(duthost, vip, vmhost=None, timeout=120):
    """Join DUT to K8s cluster.

    Args:
        duthost: DUT host fixture
        vip: API server VIP (usually vmhost.mgmt_ip)
        vmhost: VM host fixture (for kubectl verification, optional)
        timeout: Max seconds to wait for join

    Raises:
        RuntimeError: If join fails within timeout
    """
    logger.info("Joining DUT to K8s cluster at %s", vip)

    # Check API server reachable
    result = duthost.shell(
        f"curl -k -s -o /dev/null -w '%{{http_code}}' https://{vip}:6443/healthz",
        module_ignore_errors=True
    )
    http_code = result.get("stdout", "").strip()
    if http_code not in ("200", "401", "403"):
        raise RuntimeError(f"DUT cannot reach API server at {vip}:6443, got HTTP {http_code}")

    # Configure and enable
    duthost.shell(f"sudo config kube server ip {vip}")
    duthost.shell("sudo config kube server disable off")

    # Wait for join - verify via kubectl on vmhost if available
    start = time.time()
    hostname = duthost.hostname
    while time.time() - start < timeout:
        if vmhost:
            # Check via kubectl
            result = vmhost.shell(
                f"NO_PROXY=192.168.49.2 minikube kubectl -- get nodes {hostname}",
                module_ignore_errors=True
            )
            if hostname in result.get("stdout", "") and "NotReady" not in result.get("stdout", ""):
                logger.info("DUT joined successfully (verified via kubectl)")
                return
        else:
            # Fallback: check via DUT status
            if _check_connected(duthost):
                logger.info("DUT joined successfully (verified via DUT status)")
                return
        time.sleep(10)

    raise RuntimeError("DUT failed to join K8s cluster within timeout")


def disjoin_cluster(duthost):
    """Disjoin DUT from K8s cluster.

    Args:
        duthost: DUT host fixture
    """
    logger.info("Disjoining DUT from K8s cluster")
    duthost.shell("sudo config kube server disable on", module_ignore_errors=True)
    time.sleep(20)


def cleanup_dut(duthost):
    """Clean up DUT K8s configuration.

    Removes:
    - Config DB K8s settings
    - DNS entry for minikube
    - Restores original certificates

    Args:
        duthost: DUT host fixture
    """
    logger.info("Cleaning up DUT K8s configuration")

    # Clean config DB
    duthost.shell(
        "sonic-db-cli CONFIG_DB DEL 'KUBERNETES_MASTER|SERVER'",
        module_ignore_errors=True
    )

    # Remove DNS entry
    duthost.shell(
        f"sudo sed -i '/{MINIKUBE_VIP_HOSTNAME}/d' /etc/hosts",
        module_ignore_errors=True
    )

    # Restore original certs
    duthost.shell(
        f"if [ -d {DUT_CERT_BAK} ]; then rm -rf {DUT_CERT_DIR} && mv {DUT_CERT_BAK} {DUT_CERT_DIR}; fi",
        module_ignore_errors=True
    )


def _setup_dns(duthost, vmhost):
    """Add minikube VIP to /etc/hosts."""
    logger.info("Setting up DNS for minikube VIP")
    vip_entry = f"{vmhost.mgmt_ip} {MINIKUBE_VIP_HOSTNAME}"
    duthost.shell(
        f"grep -q '{vip_entry}' /etc/hosts || echo '{vip_entry}' | sudo tee -a /etc/hosts"
    )


def _install_certs(duthost, vmhost):
    """Extract certs from minikube and install on DUT."""
    logger.info("Installing certificates on DUT")

    # Extract from minikube
    cert = vmhost.shell(
        "docker exec minikube cat /var/lib/minikube/certs/apiserver.crt"
    )["stdout"]
    key = vmhost.shell(
        "docker exec minikube cat /var/lib/minikube/certs/apiserver.key"
    )["stdout"]

    # Backup existing certs
    duthost.shell(
        f"if [ -d {DUT_CERT_DIR} ]; then mv {DUT_CERT_DIR} {DUT_CERT_BAK}; fi"
    )
    duthost.shell(f"mkdir -p {DUT_CERT_DIR}")

    # Install new certs
    duthost.shell(f"echo -n '{cert}' > {DUT_CERT_DIR}/restapiserver.crt")
    duthost.shell(f"echo -n '{key}' > {DUT_CERT_DIR}/restapiserver.key")


def _check_state_db(duthost):
    """Ensure K8s state DB is initialized."""
    logger.info("Checking K8s state DB")
    result = duthost.shell(
        "sonic-db-cli STATE_DB hget 'KUBERNETES_MASTER|SERVER' update_time",
        module_ignore_errors=True
    )
    if not result["stdout"]:
        duthost.shell(
            "sonic-db-cli STATE_DB hset 'KUBERNETES_MASTER|SERVER' update_time '2024-12-24 01:01:01'"
        )
        # Restart ctrmgrd if available
        result = duthost.shell(
            "systemctl list-unit-files ctrmgrd.service",
            module_ignore_errors=True
        )
        if "ctrmgrd.service" in result.get("stdout", ""):
            duthost.shell("systemctl restart ctrmgrd")


def _fix_cgroup_driver(duthost):
    """Fix kubelet cgroup driver to match Docker if needed.

    Newer SONiC images (Debian 13+) use systemd cgroup driver for Docker,
    but kubelet may still be configured with cgroupfs.
    """
    # Check Docker's cgroup driver
    result = duthost.shell(
        "docker info --format '{{.CgroupDriver}}'",
        module_ignore_errors=True
    )
    docker_cgroup = result.get("stdout", "").strip()

    if docker_cgroup != "systemd":
        logger.info("Docker cgroup driver is %s, no fix needed", docker_cgroup)
        return

    # Check if kubelet is configured with cgroupfs
    result = duthost.shell(
        "grep -q 'cgroup-driver=cgroupfs' /etc/default/kubelet",
        module_ignore_errors=True
    )
    if result.get("rc", 1) != 0:
        logger.info("Kubelet not configured with cgroupfs, no fix needed")
        return

    logger.info("Fixing kubelet cgroup driver: cgroupfs -> systemd")
    duthost.shell(
        "sudo sed -i 's/--cgroup-driver=cgroupfs/--cgroup-driver=systemd/' /etc/default/kubelet"
    )
    duthost.shell("sudo systemctl daemon-reload")


def _check_connected(duthost):
    """Check if DUT shows connected status to K8s master."""
    result = duthost.shell("show kube server", module_ignore_errors=True)
    for line in result.get("stdout_lines", []):
        if "connected" in line.lower() and "true" in line.lower():
            return True
    return False
