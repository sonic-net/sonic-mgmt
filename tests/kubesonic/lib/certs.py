"""Certificate management for DUT joining K8s cluster."""

import logging

logger = logging.getLogger(__name__)

DUT_CERT_DIR = "/etc/sonic/credentials"
DUT_CERT_BAK = f"{DUT_CERT_DIR}.bak"


class CertManager:
    """Manages certificates for DUT to join K8s cluster."""

    def __init__(self, vmhost, duthost):
        self.vmhost = vmhost
        self.duthost = duthost

    def extract_certs(self):
        """Extract API server certs from minikube."""
        logger.info("Extracting certs from minikube")
        cert = self.vmhost.shell(
            "docker exec minikube cat /var/lib/minikube/certs/apiserver.crt"
        )["stdout"]
        key = self.vmhost.shell(
            "docker exec minikube cat /var/lib/minikube/certs/apiserver.key"
        )["stdout"]
        return cert, key

    def install_on_dut(self, cert, key):
        """Install certs on DUT."""
        logger.info("Installing certs on DUT")
        # Backup existing
        self.duthost.shell(
            f"if [ -d {DUT_CERT_DIR} ]; then mv {DUT_CERT_DIR} {DUT_CERT_BAK}; fi"
        )
        self.duthost.shell(f"mkdir -p {DUT_CERT_DIR}")

        # Write certs - use echo -n to match original test (no trailing newline)
        self.duthost.shell("echo -n '{}' > {}/restapiserver.crt".format(cert, DUT_CERT_DIR))
        self.duthost.shell("echo -n '{}' > {}/restapiserver.key".format(key, DUT_CERT_DIR))

    def setup(self):
        """Extract and install certs."""
        cert, key = self.extract_certs()
        self.install_on_dut(cert, key)

    def teardown(self):
        """Restore original certs."""
        logger.info("Restoring original certs on DUT")
        self.duthost.shell(
            f"if [ -d {DUT_CERT_BAK} ]; then rm -rf {DUT_CERT_DIR} && mv {DUT_CERT_BAK} {DUT_CERT_DIR}; fi"
        )
