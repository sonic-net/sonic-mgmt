import json
import logging
import pytest
import time

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


@pytest.fixture()
def setup_and_teardown(vmhost, duthost, creds):
    logger.info("Start to setup single master k8s cluster on vmhost")
    minikube_address = "https://github.com/kubernetes/minikube/releases/download/v1.34.0/minikube-linux-amd64"
    target_location = "/usr/local/bin/minikube"
    http_proxy = creds.get("proxy_env", {}).get("http_proxy", "")
    proxy_param = f"-x '{http_proxy}'" if http_proxy != "" else ""
    vmhost.shell(f"curl -L {minikube_address} -o {target_location} {proxy_param}")
    k8s_master_setup_cmd = f'''
        minikube start \
        --listen-address=0.0.0.0 \
        --apiserver-port=6443 \
        --ports=6443:6443 \
        --kubernetes-version=v1.22.2 \
        --extra-config=kubeadm.skip-phases=addon/kube-proxy,addon/coredns \
        --install-addons=false \
        --apiserver-ips={vmhost.mgmt_ip} \
        --force \
    '''
    vmhost.shell("minikube delete --all --purge")
    vmhost.shell("rm -f /tmp/juju-mk*")
    vmhost.shell(k8s_master_setup_cmd)
    vmhost.shell("sysctl fs.protected_regular=0")
    tmp_kubelet_config = "/tmp/kubelet-config-1.22.yaml"
    vmhost.shell(f"minikube kubectl -- get cm kubelet-config-1.22 -n kube-system -o yaml > {tmp_kubelet_config}")
    vmhost.shell(f"sed 's|/var/lib/minikube/certs/ca.crt|/etc/kubernetes/pki/ca.crt|' -i {tmp_kubelet_config}")
    vmhost.shell(f"minikube kubectl -- apply -f {tmp_kubelet_config}")
    logger.info("K8s master setup is done")
    
    # Prepare certs for duthost join
    logger.info("Prepare certs for duthost join")
    cert_dir = "/etc/sonic/credentials"
    cert_bak = f"{cert_dir}.bak"
    cert_path = f"{cert_dir}/restapiserver.crt"
    key_path = f"{cert_dir}/restapiserver.key"
    join_cert = vmhost.shell("docker exec minikube cat /var/lib/minikube/certs/apiserver.crt")
    join_key = vmhost.shell("docker exec minikube cat /var/lib/minikube/certs/apiserver.key")
    duthost.shell(f"if [ -d {cert_dir} ]; then mv {cert_dir} {cert_bak}; fi")
    duthost.shell(f"mkdir -p {cert_dir}")
    duthost.shell("echo -n '{}' > {}".format(join_cert["stdout"], cert_path))
    duthost.shell("echo -n '{}' > {}".format(join_key["stdout"], key_path))
    logger.info("Certs are ready")
    
    yield

    logger.info("Start to restore the certs")
    duthost.shell(f"rm -rf {cert_dir}")
    duthost.shell(f"if [ -d {cert_bak} ]; then mv {cert_bak} {cert_dir}; fi")
    logger.info("Certs are restored")

    logger.info("Start to teardown the k8s cluster")
    vmhost.shell("minikube delete --all --purge")
    vmhost.shell("rm -f /tmp/juju-mk*")
    vmhost.shell(f"rm -f {target_location}")
    logger.info("Cleaned up the k8s cluster")


def trigger_join_and_check(duthost, vmhost):
    logger.info("Start to join duthost to k8s cluster and check the status")
    duthost.shell(f"sudo config kube server ip {vmhost.mgmt_ip}")
    duthost.shell("sudo config kube server disable off")
    time.sleep(60)
    nodes = vmhost.shell(f"minikube kubectl -- get nodes {duthost.hostname}")
    pytest_assert(duthost.hostname in nodes["stdout"], "Failed to join duthost to k8s cluster")
    pytest_assert("NotReady" not in nodes["stdout"], "The status of duthost in k8s cluster is not ready")
    logger.info(f"Successfully joined duthost {duthost.hostname} to k8s cluster")


def trigger_disjoin_and_check(duthost, vmhost):
    logger.info("Start to disjoin duthost from k8s cluster and check the status")
    duthost.shell("sudo config kube server disable on")
    time.sleep(20)
    nodes = vmhost.shell("minikube kubectl -- get nodes")
    pytest_assert(duthost.hostname not in nodes["stdout"], "Failed to disjoin duthost from k8s cluster")


def deploy_daemonset_and_check(duthost, vmhost):
    logger.info("Start to deploy daemonset and check the status")
    daemonset_yaml = "/tmp/daemonset.yaml"
    daemonset_content = '''
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
      hostNetwork: true
      containers:
      - image: k8s.gcr.io/pause:3.5
        name: pause35
    '''
    vmhost.shell("minikube kubectl -- taint node minikube node-role.kubernetes.io/master='':NoSchedule")
    vmhost.shell(f"echo -n '{daemonset_content}' > {daemonset_yaml}")
    vmhost.shell(f"minikube kubectl -- apply -f {daemonset_yaml}")
    time.sleep(15)
    ds_status = vmhost.shell("minikube kubectl -- get daemonset test-daemonset -o json")
    ds_status = json.loads(ds_status["stdout"])
    if "status" in ds_status:
        if ("currentNumberScheduled" in ds_status["status"] and
                "desiredNumberScheduled" in ds_status["status"] and
                "numberReady" in ds_status["status"] and
                "numberAvailable" in ds_status["status"] and
                "updatedNumberScheduled" in ds_status["status"]):
            pytest_assert(ds_status["status"]["currentNumberScheduled"] == 1, "currentNumberScheduled is not 1")
            pytest_assert(ds_status["status"]["desiredNumberScheduled"] == 1, "desiredNumberScheduled is not 1")
            pytest_assert(ds_status["status"]["numberReady"] == 1, "numberReady is not 1")
            pytest_assert(ds_status["status"]["numberAvailable"] == 1, "numberAvailable is not 1")
            pytest_assert(ds_status["status"]["updatedNumberScheduled"] == 1, "updatedNumberScheduled is not 1")
        else:
            pytest_assert(False, "Partial status of daemonset is missing")
    else:
        pytest_assert(False, "Status of daemonset is missing")

    ds_pod_status = vmhost.shell("minikube kubectl -- get pods -l group=test-ds-pod")
    pytest_assert("1/1" in ds_pod_status["stdout"], "Failed to deploy daemonset")
    pytest_assert("Running" in ds_pod_status["stdout"], "Failed to deploy daemonset")
    logger.info("Successfully deployed daemonset")


def delete_daemonset_and_check(duthost, vmhost):
    logger.info("Start to delete daemonset and check the status")
    vmhost.shell("minikube kubectl -- delete daemonset test-daemonset")
    time.sleep(15)
    ds_status = vmhost.shell("minikube kubectl -- get daemonset")
    pytest_assert("No resources found" in ds_status["stderr"], "Failed to delete daemonset")
    logger.info("Successfully deleted daemonset")


def test_kubesonic_join_and_disjoin(setup_and_teardown, duthost, vmhost):
    trigger_join_and_check(duthost, vmhost)
    deploy_daemonset_and_check(duthost, vmhost)
    delete_daemonset_and_check(duthost, vmhost)
    trigger_disjoin_and_check(duthost, vmhost)