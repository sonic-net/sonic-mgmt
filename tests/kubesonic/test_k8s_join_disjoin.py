import logging
import pytest
import time

from datetime import datetime
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

MINIKUBE_VERSION = "v1.34.0"
MINIKUBE_PATH = "/usr/local/bin/minikube"
MINIKUBE_VIP = "control-plane.minikube.internal"
MINIKUBE_DEFAULT_IP = "192.168.49.2"
NO_PROXY = f"NO_PROXY={MINIKUBE_DEFAULT_IP}"
MINIKUBE_SETUP_MAX_SECOND = 600
MINIKUBE_DOWNLOAD_TIMEOUT_SECOND = 360
MINIKUBE_SETUP_CHECK_INTERVAL = 10
KUBERNETES_VERSION = "v1.22.2"
KUBELET_CONFIGMAP = "kubelet-config-1.22"
DAEMONSET_NODE_LABEL = "deployDaemonset"
DAEMONSET_POD_LABEL = "test-ds-pod"
DAEMONSET_CONTAINER_NAME = "mock-ds-container"
VMHOST_PARAM_DEFAULT = None
DUT_CERT_DIR = "/etc/sonic/credentials"
DUT_CERT_BAK = f"{DUT_CERT_DIR}.bak"
DUT_HOSTS_FILE = "/etc/hosts"
DUT_PAUSE_IMAGE = "k8s.gcr.io/pause:3.5"


def check_dut_k8s_version_supported(duthost):
    logger.info("Check if the k8s version is supported")
    k8s_version = duthost.shell("kubeadm version -o short")["stdout"]
    if k8s_version != KUBERNETES_VERSION:
        log_msg = f"Need to update this kubesonic test plan, sonic k8s version is upgraded to {k8s_version}"
        pytest.skip(log_msg)
    logger.info(f"K8s version {k8s_version} is supported")


def download_minikube(vmhost, creds):
    logger.info("Start to download minikube")
    minikube_url = f"https://github.com/kubernetes/minikube/releases/download/{MINIKUBE_VERSION}/minikube-linux-amd64"
    tmp_location = "/tmp/minikube-linux-amd64"
    http_proxy = creds.get("proxy_env", {}).get("http_proxy", "")
    proxy_param = f"-x '{http_proxy}'" if http_proxy != "" else ""
    time_out_param = f"--max-time {MINIKUBE_DOWNLOAD_TIMEOUT_SECOND}"
    vmhost.shell(f"curl -L {minikube_url} -o {tmp_location} {proxy_param} {time_out_param}")
    vmhost.shell(f"install {tmp_location} {MINIKUBE_PATH} && rm -f {tmp_location}")
    logger.info("Minikube is downloaded")


def remove_minikube(vmhost):
    logger.info("Start to remove minikube")
    vmhost.shell(f"rm -f {MINIKUBE_PATH}")
    logger.info("Minikube is removed")


def setup_k8s_master(vmhost, creds):
    logger.info("Start to setup k8s master on vmhost")
    http_proxy = creds.get("proxy_env", {}).get("http_proxy", "")
    https_proxy = creds.get("proxy_env", {}).get("https_proxy", "")
    http_proxy_param = f"http_proxy={http_proxy}" if http_proxy else ""
    https_proxy_param = f"https_proxy={https_proxy}" if https_proxy else ""
    k8s_master_setup_cmd = f'''
        {http_proxy_param} {https_proxy_param} \
        minikube start \
        --listen-address=0.0.0.0 \
        --apiserver-port=6443 \
        --ports=6443:6443 \
        --extra-config=kubeadm.skip-phases=addon/kube-proxy,addon/coredns \
        --install-addons=false \
        --kubernetes-version={KUBERNETES_VERSION} \
        --apiserver-ips={vmhost.mgmt_ip} \
        --force \
    '''
    vmhost.shell(k8s_master_setup_cmd)
    logger.info("K8s master setup is done")


def remove_k8s_master(vmhost):
    logger.info("Start to remove k8s master on vmhost")
    vmhost.shell("minikube delete --all --purge")
    vmhost.shell("rm -f /tmp/juju-mk*")
    vmhost.shell("rm -f /tmp/minikube*")
    logger.info("K8s master is removed")


# Minikube's default pki ca path is /var/lib/minikube/certs/ca.crt
# But DUT's default pki ca path is /etc/kubernetes/pki/ca.crt, so need update
def update_kubelet_config(vmhost, creds):
    logger.info("Start to update kubelet config")
    http_proxy = creds.get("proxy_env", {}).get("http_proxy", "")
    https_proxy = creds.get("proxy_env", {}).get("https_proxy", "")
    http_proxy_param = f"http_proxy={http_proxy}" if http_proxy else ""
    https_proxy_param = f"https_proxy={https_proxy}" if https_proxy else ""
    proxy_param = f"{http_proxy_param} {https_proxy_param} {NO_PROXY}"
    tmp_kubelet_config = "/tmp/kubelet-config.yaml"
    get_kubelet_config_cmd = f"{proxy_param} minikube kubectl -- get cm {KUBELET_CONFIGMAP} -n kube-system -o yaml"
    vmhost.shell(f"{get_kubelet_config_cmd} > {tmp_kubelet_config}")
    vmhost.shell(f"sed 's|/var/lib/minikube/certs/ca.crt|/etc/kubernetes/pki/ca.crt|' -i {tmp_kubelet_config}")
    vmhost.shell(f"{NO_PROXY} minikube kubectl -- apply -f {tmp_kubelet_config}")
    vmhost.shell(f"rm -f {tmp_kubelet_config}")
    logger.info("Kubelet config is updated")


# Minikube kubectl needs to update the kernel param
def update_vmhost_param(vmhost):
    logger.info("Start to update vmhost param")
    global VMHOST_PARAM_DEFAULT
    param_default_value = vmhost.shell("sysctl fs.protected_regular", module_ignore_errors=True)["stdout"]
    if param_default_value:
        VMHOST_PARAM_DEFAULT = param_default_value.replace(" ", "")
    vmhost.shell("sysctl fs.protected_regular=0")
    logger.info("Vmhost param are updated")


def restore_vmhost_param(vmhost):
    logger.info("Start to restore vmhost param")
    if VMHOST_PARAM_DEFAULT:
        vmhost.shell(f"sysctl {VMHOST_PARAM_DEFAULT}")
    logger.info("VMhost param are restored")


def check_k8s_state_db(duthost):
    logger.info("Start to check k8s state db")
    get_update_time_cmd = "sonic-db-cli STATE_DB hget 'KUBERNETES_MASTER|SERVER' update_time"
    update_time = duthost.shell(f"{get_update_time_cmd}", module_ignore_errors=True)["stdout"]
    ctrmgrd_status = duthost.shell("systemctl status ctrmgrd", module_ignore_errors=True)["stdout"]
    logger.info(f"Ctrmgrd status: {ctrmgrd_status}")
    if not update_time:
        duthost.shell("sonic-db-cli STATE_DB hset 'KUBERNETES_MASTER|SERVER' update_time '2024-12-24 01:01:01'")
        duthost.shell("systemctl restart ctrmgrd")
        logger.info("Ctrmgrd service is restarted")
    logger.info("Checking k8s state db is done")


def prepare_cert(duthost, vmhost):
    logger.info("Start to prepare cert for duthost join")
    cert_path = f"{DUT_CERT_DIR}/restapiserver.crt"
    key_path = f"{DUT_CERT_DIR}/restapiserver.key"
    join_cert = vmhost.shell("docker exec minikube cat /var/lib/minikube/certs/apiserver.crt")
    join_key = vmhost.shell("docker exec minikube cat /var/lib/minikube/certs/apiserver.key")
    duthost.shell(f"if [ -d {DUT_CERT_DIR} ]; then mv {DUT_CERT_DIR} {DUT_CERT_BAK}; fi")
    duthost.shell(f"mkdir -p {DUT_CERT_DIR}")
    duthost.shell("echo -n '{}' > {}".format(join_cert["stdout"], cert_path))
    duthost.shell("echo -n '{}' > {}".format(join_key["stdout"], key_path))
    logger.info("Cert is ready")


def restore_cert(duthost):
    logger.info("Start to restore the cert")
    duthost.shell(f"if [ -d {DUT_CERT_BAK} ]; then rm -rf {DUT_CERT_DIR} && mv {DUT_CERT_BAK} {DUT_CERT_DIR}; fi")
    logger.info("Cert is restored")


def get_minikube_vip_dns_item(vmhost):
    return f"{vmhost.mgmt_ip} {MINIKUBE_VIP}"


def prepare_minikube_vip_dns(duthost, vmhost):
    logger.info("Start to prepare dns for minikube vip")
    vip_dns_item = get_minikube_vip_dns_item(vmhost)
    duthost.shell(f"grep '{vip_dns_item}' {DUT_HOSTS_FILE} || echo '{vip_dns_item}' |sudo tee -a {DUT_HOSTS_FILE}")
    logger.info("Minikube vip dns is ready")


def remove_minikube_vip_dns(duthost, vmhost):
    logger.info("Start to remove minikube vip dns")
    vip_dns_item = get_minikube_vip_dns_item(vmhost)
    duthost.shell(f"sudo sed -i '/^{vip_dns_item}$/d' {DUT_HOSTS_FILE}")
    logger.info("Minikube vip dns is removed")


def deploy_test_daemonset(vmhost):
    logger.info("Start to deploy daemonset and check the status")
    daemonset_yaml = "/tmp/daemonset.yaml"
    daemonset_content = f'''
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: test-daemonset
spec:
  selector:
    matchLabels:
      group: {DAEMONSET_POD_LABEL}
  template:
    metadata:
      labels:
        group: {DAEMONSET_POD_LABEL}
    spec:
      nodeSelector:
        {DAEMONSET_NODE_LABEL}: "true"
      hostNetwork: true
      containers:
      - image: {DUT_PAUSE_IMAGE}
        name: {DAEMONSET_CONTAINER_NAME}
    '''

    vmhost.shell(f"echo -n '{daemonset_content}' > {daemonset_yaml}")
    vmhost.shell(f"{NO_PROXY} minikube kubectl -- apply -f {daemonset_yaml}")
    logger.info("Daemonset is deployed")


def check_minikube_ready(vmhost):
    logger.info("Check if minikube is ready")
    get_minikube_node_cmd = f"{NO_PROXY} minikube kubectl -- get node minikube --no-headers"
    minikube_status = vmhost.shell(get_minikube_node_cmd, module_ignore_errors=True)
    status_stdout = minikube_status["stdout"]
    status_stdout_list = status_stdout.split()
    if status_stdout != "" and len(status_stdout_list) == 5 and status_stdout_list[1] == "Ready":
        logger.info("Minikube master is ready")
        return True
    else:
        logger.info("Minikube master is not ready")
        return False


def mark_minikube_started(vmhost):
    logger.info("Mark minikube as started")
    vmhost.shell("mkdir -p /run/minikube && touch /run/minikube/started")
    logger.info("Minikube is marked as started")


def mark_minikube_completed(vmhost):
    logger.info("Mark minikube as completed")
    vmhost.shell("rm -f /run/minikube/started")
    logger.info("Minikube is marked as completed")


def check_minikube_setup_started(vmhost):
    logger.info("Check if minikube setup is started")
    # Check the file creation time
    minikube_setup_started = vmhost.shell("stat -c %z /run/minikube/started", module_ignore_errors=True)
    if minikube_setup_started["stdout"] == "":
        logger.info("Minikube setup is not started")
        return False, None
    else:
        time_format = '%Y-%m-%d %H:%M:%S'
        creation_time = datetime.strptime(minikube_setup_started["stdout"].strip().split('.')[0], time_format)
        logger.info(f"Minikube setup is started, creation time is {creation_time}")
        return True, creation_time


def clean_up_and_setup_minikube(vmhost, creds):
    # Mark the minikube as started
    mark_minikube_started(vmhost)
    # Clean up the previous minikube
    remove_minikube(vmhost)
    # Download minikube
    download_minikube(vmhost, creds)
    # Clean up the setup env
    remove_k8s_master(vmhost)
    # Setup k8s master
    setup_k8s_master(vmhost, creds)
    # Mark the minikube as completed
    mark_minikube_completed(vmhost)


def clean_configdb_k8s_table(duthost):
    logger.info("Start to clean k8s table in configdb")
    duthost.shell("sonic-db-cli CONFIG_DB DEL 'KUBERNETES_MASTER|SERVER'")
    logger.info("K8s table in configdb is cleaned")


@pytest.fixture()
def setup_and_teardown(duthost, vmhost, creds):
    check_dut_k8s_version_supported(duthost)
    logger.info("Start to setup test environment")

    # Get duthost asic type
    asic_type = duthost.facts["asic_type"]
    logger.info(f"DUT ASIC type is {asic_type}")

    if asic_type == "vs":
        clean_up_and_setup_minikube(vmhost, creds)
    else:
        while not check_minikube_ready(vmhost):
            setup_started, creation_time = check_minikube_setup_started(vmhost)
            if not setup_started:
                clean_up_and_setup_minikube(vmhost, creds)
                break
            else:
                # Generally, the setup process should be completed within 2 minutes
                time_now = datetime.now()
                logger.info(f"Current time is {time_now}")
                time_diff = time_now - creation_time
                time_diff_seconds = time_diff.total_seconds()
                logger.info(f"Minikube setup has started for {time_diff_seconds} seconds")
                if time_diff_seconds > MINIKUBE_SETUP_MAX_SECOND:
                    logger.info("Minikube setup timeout, need to re-setup")
                    clean_up_and_setup_minikube(vmhost, creds)
                    break
                else:
                    logger.info(f"Minikube setup is progress, wait for {MINIKUBE_SETUP_CHECK_INTERVAL} seconds")
                    time.sleep(MINIKUBE_SETUP_CHECK_INTERVAL)

    # Update vmhost param
    update_vmhost_param(vmhost)

    # Update kubelet config
    update_kubelet_config(vmhost, creds)

    # Deploy test daemonset
    deploy_test_daemonset(vmhost)

    # Check k8s state db
    check_k8s_state_db(duthost)

    # Prepare certs for duthost join
    prepare_cert(duthost, vmhost)

    # Prepare dns for minikube vip
    prepare_minikube_vip_dns(duthost, vmhost)

    yield

    # Clean up the k8s table in configdb
    clean_configdb_k8s_table(duthost)

    # Restore dns for minikube vip
    remove_minikube_vip_dns(duthost, vmhost)

    # Restore certs for duthost join
    restore_cert(duthost)

    if asic_type == "vs":

        # Restore vmhost param
        restore_vmhost_param(vmhost)

        # Clean up the current env
        remove_k8s_master(vmhost)
        remove_minikube(vmhost)


def trigger_join_and_check(duthost, vmhost):
    logger.info("Start to join duthost to k8s cluster and check the status")
    duthost.shell(f"sudo config kube server ip {vmhost.mgmt_ip}")
    duthost.shell("sudo config kube server disable off")
    time.sleep(60)
    nodes = vmhost.shell(f"{NO_PROXY} minikube kubectl -- get nodes {duthost.hostname}", module_ignore_errors=True)
    pytest_assert(duthost.hostname in nodes["stdout"], "Failed to join duthost to k8s cluster")
    pytest_assert("NotReady" not in nodes["stdout"], "The status of duthost in k8s cluster is not ready")
    logger.info(f"Successfully joined duthost {duthost.hostname} to k8s cluster")


def trigger_disjoin_and_check(duthost, vmhost):
    logger.info("Start to disjoin duthost from k8s cluster and check the status")
    duthost.shell("sudo config kube server disable on")
    time.sleep(20)
    nodes = vmhost.shell(f"{NO_PROXY} minikube kubectl -- get nodes {duthost.hostname}", module_ignore_errors=True)
    pytest_assert(duthost.hostname not in nodes["stdout"], "Failed to disjoin duthost from k8s cluster")
    pytest_assert("Error from server (NotFound)" in nodes["stderr"], "Failed to disjoin duthost from k8s cluster")
    logger.info(f"Successfully disjoined duthost {duthost.hostname} from k8s cluster")


def deploy_daemonset_pod_and_check(duthost, vmhost):
    logger.info("Start to label node and check if the daemonset pod is deployed")
    vmhost.shell(f"{NO_PROXY} minikube kubectl -- label node {duthost.hostname} {DAEMONSET_NODE_LABEL}=true")
    time.sleep(15)
    ds_pod_status = vmhost.shell(f"{NO_PROXY} minikube kubectl -- get pods -l group={DAEMONSET_POD_LABEL} \
                                    --field-selector spec.nodeName={duthost.hostname}")
    pytest_assert("1/1" in ds_pod_status["stdout"], "Failed to find daemonset pod from k8s")
    pytest_assert("Running" in ds_pod_status["stdout"], "Failed to find daemonset pod from k8s")
    container_status = duthost.shell(f"docker ps |grep {DAEMONSET_CONTAINER_NAME}", module_ignore_errors=True)
    pytest_assert(container_status["stdout"] != "", "Failed to find daemonset pod from duthost")
    logger.info("Successfully deployed daemonset pod")


def delete_daemonset_pod_and_check(duthost, vmhost):
    logger.info("Start to unlabel node and check if the daemonset pod is deleted")
    vmhost.shell(f"{NO_PROXY} minikube kubectl -- label node {duthost.hostname} {DAEMONSET_NODE_LABEL}-")
    time.sleep(15)
    ds_pod_status = vmhost.shell(f"{NO_PROXY} minikube kubectl -- get pods -l group={DAEMONSET_POD_LABEL} \
                                    --field-selector spec.nodeName={duthost.hostname}")
    pytest_assert("No resources found" in ds_pod_status["stderr"], "Failed to delete daemonset")
    container_status = duthost.shell("docker ps |grep {DAEMONSET_CONTAINER_NAME}", module_ignore_errors=True)
    pytest_assert(container_status["stdout"] == "", "Failed to delete daemonset pod")
    logger.info("Successfully deleted daemonset pod")


def test_kubesonic_join_and_disjoin(setup_and_teardown, duthost, vmhost):
    trigger_join_and_check(duthost, vmhost)
    deploy_daemonset_pod_and_check(duthost, vmhost)
    delete_daemonset_pod_and_check(duthost, vmhost)
    trigger_disjoin_and_check(duthost, vmhost)
