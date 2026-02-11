"""DUT-side Kubernetes configuration."""

import logging
import time

logger = logging.getLogger(__name__)

MINIKUBE_VIP = "control-plane.minikube.internal"


class DutKubeConfig:
    """Manages DUT-side K8s configuration."""

    def __init__(self, duthost, vmhost):
        self.duthost = duthost
        self.vmhost = vmhost

    def has_kube_support(self):
        """Check if DUT has kubernetes/kubesonic support."""
        result = self.duthost.shell(
            "systemctl list-unit-files ctrmgrd.service",
            module_ignore_errors=True
        )
        return "ctrmgrd.service" in result.get("stdout", "")

    def setup_dns(self):
        """Add minikube VIP to /etc/hosts."""
        logger.info("Setting up DNS for minikube VIP")
        vip_entry = f"{self.vmhost.mgmt_ip} {MINIKUBE_VIP}"
        self.duthost.shell(
            f"grep '{vip_entry}' /etc/hosts || echo '{vip_entry}' | sudo tee -a /etc/hosts"
        )

    def remove_dns(self):
        """Remove minikube VIP from /etc/hosts."""
        logger.info("Removing minikube VIP from DNS")
        self.duthost.shell(f"sudo sed -i '/{MINIKUBE_VIP}/d' /etc/hosts")

    def check_state_db(self):
        """Ensure K8s state DB is initialized."""
        logger.info("Checking K8s state DB")
        result = self.duthost.shell(
            "sonic-db-cli STATE_DB hget 'KUBERNETES_MASTER|SERVER' update_time",
            module_ignore_errors=True
        )
        if not result["stdout"]:
            self.duthost.shell(
                "sonic-db-cli STATE_DB hset 'KUBERNETES_MASTER|SERVER' update_time '2024-12-24 01:01:01'"
            )
            if self.has_kube_support():
                self.duthost.shell("systemctl restart ctrmgrd")
            else:
                logger.warning("ctrmgrd service not found - DUT may not have kubesonic support")

    def join(self, timeout=120):
        """Join DUT to K8s cluster."""
        logger.info("Joining DUT to K8s cluster")
        self.duthost.shell(f"sudo config kube server ip {self.vmhost.mgmt_ip}")
        self.duthost.shell("sudo config kube server disable off")

        # Wait for join
        start = time.time()
        while time.time() - start < timeout:
            result = self.vmhost.shell(
                f"sudo NO_PROXY=192.168.49.2 minikube kubectl -- get nodes {self.duthost.hostname}",
                module_ignore_errors=True
            )
            if self.duthost.hostname in result.get("stdout", "") and "NotReady" not in result.get("stdout", ""):
                logger.info("DUT joined successfully")
                return True
            time.sleep(10)
        raise RuntimeError("DUT failed to join K8s cluster")

    def disjoin(self):
        """Disjoin DUT from K8s cluster."""
        logger.info("Disjoining DUT from K8s cluster")
        self.duthost.shell("sudo config kube server disable on")
        time.sleep(20)

    def clean_config_db(self):
        """Clean K8s config from config DB."""
        logger.info("Cleaning K8s config DB")
        self.duthost.shell("sonic-db-cli CONFIG_DB DEL 'KUBERNETES_MASTER|SERVER'")

    def setup(self):
        """Full DUT setup for K8s."""
        self.setup_dns()
        self.check_state_db()

    def teardown(self):
        """Full DUT teardown."""
        self.clean_config_db()
        self.remove_dns()
