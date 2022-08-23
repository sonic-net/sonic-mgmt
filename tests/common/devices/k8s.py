import logging
import time

from tests.common.devices.base import AnsibleHostBase

logger = logging.getLogger(__name__)


class K8sMasterHost(AnsibleHostBase):
    """
    @summary: Class for Ubuntu KVM that hosts Kubernetes master

    For running ansible module on the K8s Ubuntu KVM host
    """

    def __init__(self, ansible_adhoc, hostname, is_haproxy):
        """ Initialize an object for interacting with Ubuntu KVM using ansible modules

        Args:
            ansible_adhoc (): The pytest-ansible fixture
            hostname (string): hostname of the Ubuntu KVM
            is_haproxy (boolean): True if node is haproxy load balancer, False if node is backend master server

        """
        self.hostname = hostname
        self.is_haproxy = is_haproxy
        super(K8sMasterHost, self).__init__(ansible_adhoc, hostname)
        evars = {
            'ansible_become_method': 'enable'
        }
        self.host.options['variable_manager'].extra_vars.update(evars)

    def check_k8s_master_ready(self):
        """
        @summary: check if all Kubernetes master node statuses reflect target state "Ready"

        """
        k8s_nodes_statuses = self.shell('kubectl get nodes | grep master', module_ignore_errors=True)["stdout_lines"]
        logging.info("k8s master node statuses: {}".format(k8s_nodes_statuses))

        for line in k8s_nodes_statuses:
            if "NotReady" in line:
                return False
        return True

    def shutdown_api_server(self):
        """
        @summary: Shuts down API server container on one K8sMasterHost server

        """
        self.shell('sudo systemctl stop kubelet')
        logging.info("Shutting down API server on backend master server hostname: {}".format(self.hostname))
        api_server_container_ids = self.shell('sudo docker ps -qf "name=apiserver"')["stdout_lines"]
        for id in api_server_container_ids:
            self.shell('sudo docker kill {}'.format(id))
        api_server_container_ids = self.shell('sudo docker ps -qf "name=apiserver"')["stdout"]
        assert not api_server_container_ids

    def start_api_server(self):
        """
        @summary: Starts API server container on one K8sMasterHost server

        """
        self.shell('sudo systemctl start kubelet')
        logging.info("Starting API server on backend master server hostname: {}".format(self.hostname))
        timeout_wait_secs = 60
        poll_wait_secs = 5
        api_server_container_ids = self.shell('sudo docker ps -qf "name=apiserver"')["stdout_lines"]
        while ((len(api_server_container_ids) < 2) and (timeout_wait_secs > 0)):
            logging.info("Waiting for Kubernetes API server to start")
            time.sleep(poll_wait_secs)
            timeout_wait_secs -= poll_wait_secs
            api_server_container_ids = self.shell('sudo docker ps -qf "name=apiserver"')["stdout_lines"]
        assert len(api_server_container_ids) > 1

    def ensure_kubelet_running(self):
        """
        @summary: Ensures kubelet is running on one K8sMasterHost server

        """
        logging.info("Ensuring kubelet is started on {}".format(self.hostname))
        kubelet_status = self.shell("sudo systemctl status kubelet | grep 'Active: '", module_ignore_errors=True)
        for line in kubelet_status["stdout_lines"]:
            if not "running" in line:
                self.shell("sudo systemctl start kubelet")


class K8sMasterCluster(object):
    """
    @summary: Class that encapsulates Kubernetes master cluster

    For operating on a group of K8sMasterHost objects that compose one HA Kubernetes master cluster
    """

    def __init__(self, k8smasters):
        """Initialize a list of backend master servers, and identify the HAProxy load balancer node

        Args:
            k8smasters: fixture that allows retrieval of K8sMasterHost objects

        """
        self.backend_masters = []
        for hostname, k8smaster in k8smasters.items():
            if k8smaster['host'].is_haproxy:
                self.haproxy = k8smaster['host']
            else:
                self.backend_masters.append(k8smaster)

    @property
    def vip(self):
        """
        @summary: Retrieve VIP of Kubernetes master cluster

        """
        return self.haproxy.mgmt_ip

    def shutdown_all_api_server(self):
        """
        @summary: shut down API server on all backend master servers

        """
        for k8smaster in self.backend_masters:
            logger.info("Shutting down API Server on master node {}".format(k8smaster['host'].hostname))
            k8smaster['host'].shutdown_api_server()

    def start_all_api_server(self):
        """
        @summary: Start API server on all backend master servers

        """
        for k8smaster in self.backend_masters:
            logger.info("Starting API server on master node {}".format(k8smaster['host'].hostname))
            k8smaster['host'].start_api_server()

    def check_k8s_masters_ready(self):
        """
        @summary: Ensure that Kubernetes master is in healthy state

        """
        for k8smaster in self.backend_masters:
            assert k8smaster['host'].check_k8s_master_ready()

    def ensure_all_kubelet_running(self):
        """
        @summary: Ensures kubelet is started on all backend masters, start kubelet if necessary

        """
        for k8smaster in self.backend_masters:
            k8smaster['host'].ensure_kubelet_running()
