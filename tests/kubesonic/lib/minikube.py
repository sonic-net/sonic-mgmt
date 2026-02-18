"""Minikube lifecycle management on vmhost."""

import logging
import time

logger = logging.getLogger(__name__)

MINIKUBE_VERSION = "v1.34.0"
KUBERNETES_VERSION = "v1.22.2"
NO_PROXY = "NO_PROXY=192.168.49.2"


class MinikubeManager:
    """Manages minikube lifecycle on vmhost."""

    def __init__(self, vmhost, creds):
        self.vmhost = vmhost
        self.creds = creds

    @property
    def _proxy_env(self):
        """Build proxy environment string."""
        http_proxy = self.creds.get("proxy_env", {}).get("http_proxy", "")
        https_proxy = self.creds.get("proxy_env", {}).get("https_proxy", "")
        parts = []
        if http_proxy:
            parts.append(f"http_proxy={http_proxy}")
        if https_proxy:
            parts.append(f"https_proxy={https_proxy}")
        return " ".join(parts)

    def install_prerequisites(self):
        """Install prerequisites for minikube."""
        logger.info("Installing minikube prerequisites")
        self.vmhost.shell("sudo apt-get update && sudo apt-get install -y conntrack")

    def download(self):
        """Download minikube binary."""
        logger.info("Downloading minikube %s", MINIKUBE_VERSION)
        url = f"https://github.com/kubernetes/minikube/releases/download/{MINIKUBE_VERSION}/minikube-linux-amd64"
        proxy = self.creds.get("proxy_env", {}).get("http_proxy", "")
        proxy_param = f"-x '{proxy}'" if proxy else ""
        self.vmhost.shell(f"curl -L {url} -o /tmp/minikube {proxy_param} --max-time 360")
        self.vmhost.shell("sudo install /tmp/minikube /usr/local/bin/minikube && rm -f /tmp/minikube")

    def start(self):
        """Start minikube cluster."""
        logger.info("Starting minikube cluster")
        # Match original test - no sudo for minikube itself
        cmd = f"""
            {self._proxy_env} minikube start \
            --listen-address=0.0.0.0 \
            --apiserver-port=6443 \
            --ports=6443:6443 \
            --extra-config=kubeadm.skip-phases=addon/kube-proxy,addon/coredns \
            --install-addons=false \
            --kubernetes-version={KUBERNETES_VERSION} \
            --apiserver-ips={self.vmhost.mgmt_ip} \
            --force
        """
        self.vmhost.shell(cmd)

    def stop(self):
        """Stop and delete minikube cluster."""
        logger.info("Stopping minikube cluster")
        # Clean up root-owned files first
        self.vmhost.shell("sudo rm -rf /root/.minikube", module_ignore_errors=True)
        self.vmhost.shell("sudo rm -f /tmp/juju-mk*", module_ignore_errors=True)
        self.vmhost.shell("sudo rm -f /tmp/minikube*", module_ignore_errors=True)
        # Match original test - no sudo for minikube
        self.vmhost.shell("minikube delete --all --purge", module_ignore_errors=True)
        self.vmhost.shell("docker rm -f minikube", module_ignore_errors=True)

    def is_ready(self):
        """Check if minikube is ready."""
        result = self.vmhost.shell(
            f"{NO_PROXY} minikube kubectl -- get node minikube --no-headers",
            module_ignore_errors=True
        )
        return "Ready" in result.get("stdout", "")

    def wait_ready(self, timeout=120):
        """Wait for minikube to be ready."""
        start = time.time()
        while time.time() - start < timeout:
            if self.is_ready():
                return True
            time.sleep(5)
        return False

    def check_api_server(self):
        """Check if API server is accessible - useful checkpoint for debugging."""
        logger.info("Checking API server accessibility from vmhost")
        result = self.vmhost.shell(
            f"curl -k -s -o /dev/null -w '%{{http_code}}' https://{self.vmhost.mgmt_ip}:6443/healthz",
            module_ignore_errors=True
        )
        http_code = result.get("stdout", "").strip()
        logger.info("API server health check returned HTTP %s", http_code)
        # 401/403 means API is running but auth required - that's fine
        if http_code in ("200", "401", "403"):
            return True
        logger.warning("API server may not be accessible, got HTTP %s", http_code)
        return False

    def update_kubelet_config(self):
        """Update kubelet config for DUT compatibility."""
        logger.info("Updating kubelet config")
        # Must set sysctl right before kubectl to avoid juju lock permission issues
        self.vmhost.shell("sudo sysctl fs.protected_regular=0")
        tmp_file = "/tmp/kubelet-config.yaml"
        get_cmd = f"{NO_PROXY} minikube kubectl -- get cm kubelet-config-1.22 -n kube-system -o yaml"
        self.vmhost.shell(f"{get_cmd} > {tmp_file}")
        self.vmhost.shell(f"sed 's|/var/lib/minikube/certs/ca.crt|/etc/kubernetes/pki/ca.crt|' -i {tmp_file}")
        self.vmhost.shell(f"{NO_PROXY} minikube kubectl -- apply -f {tmp_file}")
        self.vmhost.shell(f"rm -f {tmp_file}")

    def deploy_test_daemonset(self):
        """Deploy test daemonset."""
        logger.info("Deploying test daemonset")
        daemonset_content = """
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: test-daemonset
spec:
  selector:
    matchLabels:
      group: test-ds-pod
  template:
    metadata:
      labels:
        group: test-ds-pod
    spec:
      nodeSelector:
        deployDaemonset: "true"
      hostNetwork: true
      containers:
      - image: k8s.gcr.io/pause:3.5
        name: mock-ds-container
"""
        # Match original test approach
        daemonset_yaml = "/tmp/daemonset.yaml"
        self.vmhost.shell(f"echo -n '{daemonset_content}' > {daemonset_yaml}")
        self.vmhost.shell(f"{NO_PROXY} minikube kubectl -- apply -f {daemonset_yaml}")

    def get_kubeconfig_data(self):
        """Get kubeconfig as dict, built in memory from vmhost certs.

        This returns a dict that can be passed directly to
        kubernetes.config.load_kube_config_from_dict() in the sonic-mgmt container.
        No files are written - certs are fetched via shell and assembled in memory.
        """
        logger.info("Fetching kubeconfig data from minikube")
        ca = self.vmhost.shell(
            "docker exec minikube cat /var/lib/minikube/certs/ca.crt | base64 -w0"
        )["stdout"]
        cert = self.vmhost.shell(
            "docker exec minikube cat /var/lib/minikube/certs/apiserver-kubelet-client.crt | base64 -w0"
        )["stdout"]
        key = self.vmhost.shell(
            "docker exec minikube cat /var/lib/minikube/certs/apiserver-kubelet-client.key | base64 -w0"
        )["stdout"]

        return {
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [{
                "cluster": {
                    "certificate-authority-data": ca,
                    "server": f"https://{self.vmhost.mgmt_ip}:6443"
                },
                "name": "minikube"
            }],
            "contexts": [{
                "context": {"cluster": "minikube", "user": "minikube"},
                "name": "minikube"
            }],
            "current-context": "minikube",
            "users": [{
                "name": "minikube",
                "user": {
                    "client-certificate-data": cert,
                    "client-key-data": key
                }
            }]
        }

    def setup(self):
        """Full setup sequence."""
        self.stop()  # Clean any existing
        self.install_prerequisites()
        self.download()
        self.start()
        self.wait_ready()
        self.update_kubelet_config()
        self.deploy_test_daemonset()

    def teardown(self):
        """Full teardown sequence."""
        self.stop()
        self.vmhost.shell("sudo rm -f /usr/local/bin/minikube")
