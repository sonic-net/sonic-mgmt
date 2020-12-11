import logging
import time

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)


KUBECONFIG_PATH = '/etc/sonic/kube_admin.conf'


def join_master(duthost, master_vip):
    """
    Joins DUT to Kubernetes master

    Args:
        duthost: DUT host object
        master_vip: VIP of high availability Kubernetes master

    If join fails, test will fail at the assertion to check_connected
    """
    logger.info("Joining DUT to Kubernetes master")
    dut_join_cmds = ['sudo config kube server disable on',
                     'sudo config kube server ip {}'.format(master_vip),
                     'sudo config kube server disable off']
    duthost.shell_cmds(cmds=dut_join_cmds)
    pytest_assert(poll_for_status_change(duthost, 'connected', True),"DUT failed to successfully join Kubernetes master")
    

def make_vip_unreachable(duthost, master_vip):
    """
    Makes Kubernetes master VIP unreachable from SONiC DUT by configuring iptables rules. Cleans preexisting iptables rules for VIP. 

    Args:
        duthost: DUT host object
        master_vip: VIP of high availability Kubernetes master
    """
    logger.info("Making Kubernetes master VIP unreachable from DUT")
    clean_vip_iptables_rules(duthost, master_vip)
    duthost.shell('sudo iptables -A INPUT -s {} -j DROP'.format(master_vip))
    duthost.shell('sudo iptables -A OUTPUT -d {} -j DROP'.format(master_vip))


def make_vip_reachable(duthost, master_vip):
    """
    Makes Kubernetes master VIP reachable from SONiC DUT by removing any iptables rules associated with the VIP. 

    Args:
        duthost: DUT host object
        master_vip: VIP of high availability Kubernetes master
    """
    logger.info("Making Kubernetes master VIP reachable from DUT")
    clean_vip_iptables_rules(duthost, master_vip)


def clean_vip_iptables_rules(duthost, master_vip):
    """
    Removes all iptables rules associated with the VIP.

    Args:
        duthost: DUT host object
        master_vip: VIP of high availability Kubernetes master
    """
    iptables_rules = duthost.shell('sudo iptables -S | grep {} || true'.format(master_vip))["stdout_lines"]
    logger.info('iptables rules: {}'.format(iptables_rules))
    for line in iptables_rules:
        if line: 
            duthost.shell('sudo iptables -D {}'.format(line[2:]))

def is_service_running(duthost, feature):
    service_status = duthost.shell("sudo systemctl status {} | grep 'Active: '".format(feature), module_ignore_errors=True)["stdout"]
    return "(running)" in service_status.split()

def check_running_container_id(duthost, feature):
    """
    Checks currently running container ID for the specified feature

    Args:
        duthost: DUT host object
        feature: SONiC feature for which we aim to retrieve the container ID
    """
    feature_data = duthost.shell('show feature status {} | grep {}'.format(feature, feature))["stdout"]
    container_id = feature_data.split()[6]
    pytest_assert(len(container_id)  == 12, "Found invalid container ID")
    return container_id

def check_connected(duthost):
    """
    Checks if the DUT already shows status 'connected' to Kubernetes master
    
    Args:
        duthost: DUT host object
    
    Returns:
        True if connected, False if not connected
    """
    kube_server_status = duthost.shell('show kube server status')["stdout"]
    logger.info("Kube server status: {}".format(kube_server_status))
    if ("true" in kube_server_status.split()):
        logger.info("CONNECTED")
        return True
    return False

def check_feature_owner(duthost, feature):
    """
    Checks DUT's current owner for specified feature
    
    Args:
        duthost: DUT host object
        feature: SONiC feature for which owner is being checked
    
    Returns:
        local or kube
    """
    kube_owner_status = duthost.shell('show feature status {} | grep {}'.format(feature, feature))["stdout"]
    logger.info("Kube feature {} owner status: {}".format(feature, kube_owner_status))
    return kube_owner_status.split()[-2]


def check_feature_version(duthost, feature):
    """
    Checks currently running version of specified feature
    
    Args:
        duthost: DUT host object
        feature: SONiC feature for which version is being checked
    
    Returns:
        version of currently running container for specified feature
    """
    base_image_version = duthost.os_version.split('.')[0]
    feature_status = duthost.shell('show feature status {} | grep {}'.format(feature, feature))["stdout"].split()
    for value in feature_status:
        if base_image_version in value:
            feature_version = value.split('.')[1]
    return feature_version


def poll_for_status_change(duthost, status_to_check, exp_status, feature=None, poll_wait_secs=5, min_wait_time=20, max_wait_time=180):
    """
    Polls to see if kube server connected status updates as expected

    Args:
        duthost: DUT host object
        status_to_check: identifies which status to check: connected, feature_owner, or feature_version
        exp_status: expected server connected status once processes are synced
        feature: specify feature when checking status related to SONiC feature
        poll_wait_secs: seconds between each server connected status poll. Default: 5 seconds
        min_wait_time: seconds before starting poll of server connected status. Default: 20 seconds
        max_wait_time: maximum amount of time to spend polling for status change. Default: 120 seconds

    Returns: 
        True if server status updates as expected by max_wait_time
        False if server status fails to update as expected by max_wait_time
    """
    time.sleep(min_wait_time)
    time_elapsed = min_wait_time
    while (time_elapsed < max_wait_time):
        if (status_to_check == 'connected'):
            if (check_connected(duthost) == exp_status):
                logging.info("Time taken to update Kube server status: {} seconds".format(time_elapsed))
                return True
        elif (status_to_check == 'feature_owner'):
            if (check_feature_owner(duthost, feature) == exp_status):
                logging.info("Time taken to update feature owner: {} seconds".format(time_elapsed))
                return True
        elif (status_to_check == 'feature_version'):
            if (check_feature_version(duthost, feature) == exp_status):
                logging.info("Time taken to update feature version: {} seconds".format(time_elapsed))
                return True
        time.sleep(poll_wait_secs)
        time_elapsed += poll_wait_secs
    return False


def apply_manifest(duthost, master_vip, feature, version, valid_url):
    """
    Applies manifest for specified SONiC feature and version

    Args:
        duthost: DUT host object
        master_vip: VIP of Kubernetes master, HAProxy VM IP at which the container registry is stored
        feature: SONiC feature for which manifest is being applied
        version: image version feature to simulate
        valid_url: True if manifest should be applied with valid image URL source, False if manifest should be applied with invalid image URL source
    """
    # feature_manifest_path = "{}/{}.yaml".format(MANIFESTS_PATH, feature)
    prepare_registry(duthost, master_vip, feature, version)
    feature_manifest_path = generate_manifest(duthost, master_vip, feature, version, valid_url)
    duthost.shell('kubectl --kubeconfig={} apply -f {}'.format(KUBECONFIG_PATH, feature_manifest_path))


def prepare_registry(duthost, master_vip, feature, version):
    """
    Prepares private registry running on k8s master so that images are available to be downloaded for kube mode features once manifest is properly applied

    Args:
        duthost: DUT host object
        master_vip: VIP of Kubernetes master, HAProxy VM IP at which the container registry is stored
        feature: SONiC feature for which manifest is being applied
        version: image version feature to simulate
    """
    feature_version_env = '{}.{}'.format(duthost.os_version.split('.')[0], version)
    feature_image_id = duthost.shell("docker inspect {} | grep sha256 | sed 's/^.*://' | cut -c1-64".format(feature))["stdout"]
    feature_update_image_path = '{}:5000/{}_{}-v{}'.format(master_vip, duthost.hostname, feature, version)
    duthost.shell('docker commit --change "ENV IMAGE_VERSION={}" {} {}'.format(feature_version_env, feature, feature_update_image_path))
    duthost.shell('docker push {}'.format(feature_update_image_path))
    duthost.shell('docker rmi {}'.format(feature_update_image_path))


def generate_manifest(duthost, master_vip, feature, version, valid_url):
    """
    Generates filled in feature manifest from manifest template stored in feature's docker image label

    Args:
        duthost: DUT host object
        master_vip: VIP of Kubernetes master, HAProxy VM IP at which the container registry is stored
        feature: SONiC feature for which manifest is being applied
        version: image version feature to simulate
        valid_url: True if manifest should be applied with valid image URL source, False if manifest should be applied with invalid image URL source
    
    Returns:
        Path of generated manifest template for specified feature and version
    """
    if (valid_url):
        feature_image_url = '{}:5000/{}_{}-v{}'.format(master_vip, duthost.hostname, feature, version)
    else:
        feature_image_url = '{}:5000/{}_{}-v{}invalid'.format(master_vip, duthost.hostname, feature, version)
    kube_manifests_path = '/home/admin/kube_manifests'
    # duthost.shell('docker inspect {} | grep manifest > /home/admin/{}-template.yaml'.format(feature, feature, version) )
    duthost.shell('mkdir -p {}'.format(kube_manifests_path))
    duthost.shell('sudo chmod -R 777 {}'.format(kube_manifests_path))
    filled_manifest_path = '{}/{}-v{}.yaml'.format(kube_manifests_path, feature, version)
    # duthost.shell('cd /home/admin')
    duthost.shell('sed s#%IMAGE_URL%#{}#g /home/admin/{}-template.yaml > {}/{}-v{}.yaml'.format(feature_image_url, feature, kube_manifests_path, feature, version)) 
    return filled_manifest_path
    # with open(feature_manifest_template) as f:
    #    manifest_data = yaml.safe_load(f)
    # manifest_data['metadata']['name'] = '{}-v{}'.format(feature, version)
    # if valid_url:
    #    manifest_data['spec']['template']['spec']['containers']['image'] = '{}:{}:{}'.format(registry_address, feature, version)
    # else:
    #    manifest_data['spec']['template']['spec']['containers']['image'] = '{}:{}:{}ext'.format(registry_address, feature, version)
    

