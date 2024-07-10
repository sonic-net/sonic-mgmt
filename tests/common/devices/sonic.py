
import ipaddress
import json
import logging
import os
import re
import socket
import time
import sys

from collections import defaultdict
from datetime import datetime, timedelta

from ansible import constants as ansible_constants
from ansible.plugins.loader import connection_loader

from tests.common.devices.base import AnsibleHostBase
from tests.common.devices.constants import ACL_COUNTERS_UPDATE_INTERVAL_IN_SEC
from tests.common.helpers.dut_utils import is_supervisor_node, is_macsec_capable_node
from tests.common.utilities import get_host_visible_vars
from tests.common.cache import cached
from tests.common.helpers.constants import DEFAULT_ASIC_ID, DEFAULT_NAMESPACE
from tests.common.helpers.platform_api.chassis import is_inband_port
from tests.common.helpers.parallel import parallel_run_threaded
from tests.common.errors import RunAnsibleModuleFail
from tests.common import constants

logger = logging.getLogger(__name__)

PROCESS_TO_CONTAINER_MAP = {
    "orchagent": "swss",
    "syncd": "syncd"
}


class SonicHost(AnsibleHostBase):
    """
    A remote host running SONiC.

    This type of host contains information about the SONiC device (device info, services, etc.),
    and also provides the ability to run Ansible modules on the SONiC device.
    """
    DEFAULT_ASIC_SERVICES = ["bgp", "database", "lldp", "swss", "syncd", "teamd"]

    """
    setting either one of shell_user/shell_pw or ssh_user/ssh_passwd pair should yield the same result.
    """
    def __init__(self, ansible_adhoc, hostname,
                 shell_user=None, shell_passwd=None,
                 ssh_user=None, ssh_passwd=None):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)

        self.DEFAULT_ASIC_SERVICES = ["bgp", "database", "lldp", "swss", "syncd", "teamd"]

        if shell_user and shell_passwd:
            im = self.host.options['inventory_manager']
            vm = self.host.options['variable_manager']
            sonic_conn = vm.get_vars(
                host=im.get_hosts(pattern='sonic')[0]
            )['ansible_connection']
            hostvars = vm.get_vars(host=im.get_host(hostname=self.hostname))
            # parse connection options and reset those options with
            # passed credentials
            connection_loader.get(sonic_conn, class_only=True)
            user_def = ansible_constants.config.get_configuration_definition(
                "remote_user", "connection", sonic_conn
            )
            pass_def = ansible_constants.config.get_configuration_definition(
                "password", "connection", sonic_conn
            )
            for user_var in (_['name'] for _ in user_def['vars']):
                if user_var in hostvars:
                    vm.extra_vars.update({user_var: shell_user})
            for pass_var in (_['name'] for _ in pass_def['vars']):
                if pass_var in hostvars:
                    vm.extra_vars.update({pass_var: shell_passwd})

        if ssh_user and ssh_passwd:
            evars = {
                'ansible_ssh_user': ssh_user,
                'ansible_ssh_pass': ssh_passwd,
            }
            self.host.options['variable_manager'].extra_vars.update(evars)

        self._facts = self._gather_facts()
        self._os_version = self._get_os_version()
        if 'router_type' in self.facts and self.facts['router_type'] == 'spinerouter':
            self.DEFAULT_ASIC_SERVICES.append("macsec")
        feature_status = self.get_feature_status()
        # Append gbsyncd only for non-VS to avoid pretest check for gbsyncd
        # e.g. in test_feature_status, test_disable_rsyslog_rate_limit
        gbsyncd_enabled = 'gbsyncd' in feature_status[0].keys() and feature_status[0]['gbsyncd'] == 'enabled'
        if gbsyncd_enabled and self.facts["asic_type"] != "vs":
            self.DEFAULT_ASIC_SERVICES.append("gbsyncd")
        self._sonic_release = self._get_sonic_release()
        self.is_multi_asic = True if self.facts["num_asic"] > 1 else False
        self._kernel_version = self._get_kernel_version()

    def __str__(self):
        return '<SonicHost {}>'.format(self.hostname)

    def __repr__(self):
        return self.__str__()

    @property
    def facts(self):
        """
        Platform information for this SONiC device.

        Returns:
            dict: A dictionary containing the device platform information.

            For example:
            {
                "platform": "x86_64-arista_7050_qx32s",
                "hwsku": "Arista-7050-QX-32S",
                "asic_type": "broadcom",
                "num_asic": 1,
                "router_mac": "52:54:00:f0:ac:9d",
            }
        """

        return self._facts

    @property
    def os_version(self):
        """
        The OS version running on this SONiC device.

        Returns:
            str: The SONiC OS version (e.g. "20181130.31")
        """

        return self._os_version

    @property
    def sonic_release(self):
        """
        The SONiC release running on this SONiC device.

        Returns:
            str: The SONiC release (e.g. "202012")
        """

        return self._sonic_release

    @property
    def kernel_version(self):
        """
        The kernel version running on this SONiC device.

        Returns:
            str: The SONiC kernel version (e.g. "4.9.0")
        """
        return self._kernel_version

    @property
    def critical_services(self):
        """
        The critical services running on this SONiC device.

        Note:
            This list is used for tracking purposes ONLY. This list does not
            show which critical services are currently running. See the
            critical_services_status method for that info.

        Returns:
            list[str]: A list of the critical services (e.g. ["swss", "syncd"])
        """

        return self._critical_services

    @critical_services.setter
    def critical_services(self, var):
        """
        Updates the list of critical services running on this device.

        Note:
            This list is used for tracking purposes ONLY. Updating the list does
            not actually modify any services running on the device.
        """
        self._critical_services = var

        logging.debug(self._critical_services)

    def reset_critical_services_tracking_list(self, service_list):
        """
        Resets the list of critical services.
        """

        self.critical_services = service_list

    @cached(name='basic_facts')
    def _gather_facts(self):
        """
        Gather facts about the platform for this SONiC device.
        """
        facts = self._get_platform_info()

        results = parallel_run_threaded(
            [
                lambda: self._get_asic_count(facts["platform"]),
                self._get_router_mac,
                self._get_modular_chassis,
                self._get_mgmt_interface,
                self._get_switch_type,
                self._get_router_type,
                self.get_asics_present_from_inventory,
                lambda: self._get_platform_asic(facts["platform"])
            ],
            timeout=120,
            thread_count=5
        )

        facts["num_asic"] = results[0]
        facts["router_mac"] = results[1]
        facts["modular_chassis"] = results[2]
        facts["mgmt_interface"] = results[3]
        facts["switch_type"] = results[4]
        facts["router_type"] = results[5]

        facts["asics_present"] = results[6] if len(results[6]) != 0 else list(range(facts["num_asic"]))

        if results[7]:
            facts["platform_asic"] = results[7]

        logging.debug("Gathered SonicHost facts: %s" % json.dumps(facts))
        return facts

    def _get_mgmt_interface(self):
        """
        Gets the IPs of management interface
        Output example

            admin@ARISTA04T1:~$ show management_interface address
            Management IP address = 10.250.0.54/24
            Management Network Default Gateway = 10.250.0.1
            Management IP address = 10.250.0.59/24
            Management Network Default Gateway = 10.250.0.1

        """
        show_cmd_output = self.shell("show management_interface address", module_ignore_errors=True)
        mgmt_addrs = []
        for line in show_cmd_output["stdout_lines"]:
            addr = re.match(r"Management IP address = (\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3})\/\d+", line)
            if addr:
                mgmt_addrs.append(addr.group(1))
        return mgmt_addrs

    def _get_modular_chassis(self):
        py_res = self.shell("python -c \"import sonic_platform\"", module_ignore_errors=True)
        if py_res["failed"]:
            out = self.shell(
                "python3 -c \"import sonic_platform.platform as P; \
                             print(P.Platform().get_chassis().is_modular_chassis()); exit()\"",
                module_ignore_errors=True)
        else:
            out = self.shell(
                "python -c \"import sonic_platform.platform as P; \
                print(P.Platform().get_chassis().is_modular_chassis()); exit()\"",
                module_ignore_errors=True)
        res = "False" if out["failed"] else out["stdout"]
        return res

    def _get_asic_count(self, platform):
        """
        Gets the number of asics for this device.
        """
        num_asic = 1
        asic_conf_file_path = os.path.join("/usr/share/sonic/device", platform, "asic.conf")
        try:
            output = self.shell("cat {}".format(asic_conf_file_path))["stdout_lines"]
            logging.debug(output)

            for line in output:
                key, value = line.split("=")
                if key.strip().upper() == "NUM_ASIC":
                    num_asic = value.strip()
                    break

            logging.debug("num_asic = %s" % num_asic)

            return int(num_asic)
        except Exception:
            return int(num_asic)

    def _get_router_mac(self):
        return self.command("sonic-cfggen -d -v 'DEVICE_METADATA.localhost.mac'")["stdout_lines"][0].encode().decode(
            "utf-8").lower()

    def _get_switch_type(self):
        try:
            return self.command("sonic-cfggen -d -v 'DEVICE_METADATA.localhost.switch_type'")["stdout_lines"][0]\
                .encode().decode("utf-8").lower()
        except Exception:
            return ''

    def _get_router_type(self):
        try:
            return self.command("sonic-cfggen -d -v 'DEVICE_METADATA.localhost.type'")["stdout_lines"][0] \
                .encode().decode("utf-8").lower()
        except Exception:
            return ''

    def _get_platform_info(self):
        """
        Gets platform information about this SONiC device.
        """

        platform_info = self.command("show platform summary")["stdout_lines"]
        result = {}
        for line in platform_info:
            if line.startswith("Platform:"):
                result["platform"] = line.split(":")[1].strip()
            elif line.startswith("HwSKU:"):
                result["hwsku"] = line.split(":")[1].strip()
            elif line.startswith("ASIC:"):
                result["asic_type"] = line.split(":")[1].strip()

        if result["platform"]:
            platform_file_path = os.path.join("/usr/share/sonic/device", result["platform"], "platform.json")

            try:
                out = self.command("cat {}".format(platform_file_path))
                platform_info = json.loads(out["stdout"])
                for key, value in list(platform_info.items()):
                    result[key] = value

            except Exception:
                # if platform.json does not exist, then it's not added currently for certain platforms
                # eventually all the platforms should have the platform.json
                logging.debug("platform.json is not available for this platform, " +
                              "DUT facts will not contain complete platform information.")

        return result

    def _get_os_version(self):
        """
        Gets the SONiC OS version that is running on this device.
        """

        output = self.command("sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version")
        return output["stdout_lines"][0].strip()

    def _get_sonic_release(self):
        """
        Gets the SONiC Release that is running on this device.
        E.g. 202106, 202012, ...
             if the release is master, then return none
        """

        output = self.command("sonic-cfggen -y /etc/sonic/sonic_version.yml -v release")
        if len(output['stdout_lines']) == 0:
            # get release from OS version
            if self.os_version:
                return self.os_version.split('.')[0][0:6]
            return 'none'
        return output["stdout_lines"][0].strip()

    def _get_kernel_version(self):
        """
        Gets the SONiC kernel version
        :return:
        """
        output = self.command('uname -r')
        return output["stdout"].split('-')[0]

    def get_service_props(self, service, props=["ActiveState", "SubState"]):
        """
        @summary: Use 'systemctl show' command to get detailed properties of a service. By default, only get
            ActiveState and SubState of the service.
        @param service: Service name.
        @param props: Properties of the service to be shown.
        @return: Returns a dictionary containing properties of the specified service, for example:
            {
                "ActivateState": "active",
                "SubState": "running"
            }
        """
        props = " ".join(["-p %s" % prop for prop in props])
        output = self.command("systemctl %s show %s" % (props, service))
        result = {}
        for line in output["stdout_lines"]:
            fields = line.split("=")
            if len(fields) >= 2:
                result[fields[0]] = fields[1]
        return result

    def get_asics_present_from_inventory(self):
        im = self.host.options['inventory_manager']
        inv_files = im._sources
        dut_vars = get_host_visible_vars(inv_files, self.hostname)
        if dut_vars and 'asics_present' in dut_vars:
            return dut_vars['asics_present']
        return []

    def is_supervisor_node(self):
        """Check if the current node is a supervisor node in case of multi-DUT.

        Returns:
            Currently, we are using 'type' in the inventory to make the decision. If 'type' for the node is defined in
            the inventory, and it is 'supervisor', then return True, else return False. In future, we can change this
            logic if possible to derive it from the DUT.
        """
        im = self.host.options['inventory_manager']
        inv_files = im._sources
        return is_supervisor_node(inv_files, self.hostname)

    def is_frontend_node(self):
        """Check if the current node is a frontend node in case of multi-DUT.

        Returns:
            True if it is not any other type of node. Currently, the only other type of node supported is 'supervisor'
            node. If we add more types of nodes, then we need to exclude them from this method as well.
        """
        return not self.is_supervisor_node()

    def is_macsec_capable_node(self):
        im = self.host.options['inventory_manager']
        inv_files = im._sources
        return is_macsec_capable_node(inv_files, self.hostname)

    def is_service_fully_started(self, service):
        """
        @summary: Check whether a SONiC specific service is fully started.

        This function assumes that the final step of all services checked by this function is to spawn a Docker
        container with the same name as the service. We determine that the service has fully started if the
        Docker container is running.

        @param service: Name of the SONiC service
        """
        try:
            output = self.command(r"docker inspect -f \{\{.State.Running\}\} %s" % service)
            if output["stdout"].strip() == "true":
                return True
            else:
                return False
        except Exception:
            return False

    def get_running_containers(self):
        """
        Get the running containers names
        :param duthost:  DUT host object
        :return: Running container name list
        """
        return self.shell(r'docker ps --format \{\{.Names\}\}')['stdout_lines']

    def is_container_running(self, service):
        """
        Checks where a container exits.

        @param service: Container name

        Returns:
            True or False
        """
        status = self.command(
            "docker ps -f name={}".format(service), module_ignore_errors=True
        )

        if len(status["stdout_lines"]) > 1:
            logging.info("container {} status: {}".format(
                service, status["stdout"])
            )
        else:
            logging.info("container {} is not running".format(service))

        return len(status["stdout_lines"]) > 1

    def is_host_service_running(self, service):
        """
        Check if the specified service is running or not
        @param service: Service name
        @return: True if specified service is running, else False
        """
        service_status = self.shell("sudo systemctl status {} | grep 'Active'".format(service))
        return "active (running)" in service_status['stdout']

    def critical_services_status(self):
        # Initialize service status
        services = {}
        for service in self.critical_services:
            services[service] = False

        # Check and update service status
        try:
            results = self.command(r"docker ps --filter status=running --format \{\{.Names\}\}")['stdout_lines']
            for service in self.critical_services:
                if service in results:
                    services[service] = True
        except Exception as e:
            logging.info("Critical service status: {}".format(json.dumps(services)))
            logging.info("Get critical service status failed with error {}".format(repr(e)))

        return services

    def critical_services_fully_started(self):
        """
        @summary: Check whether all the SONiC critical services have started
        """
        result = self.critical_services_status()
        logging.debug("Status of critical services: %s" % str(result))
        return all(result.values())

    def get_monit_services_status(self):
        """
        @summary: Get metadata (service name, service status and service type) of services
                  which were monitored by Monit.
        @return: A dictionary in which key is the service name and values are service status
                 and service type.
        """
        monit_services_status = {}
        services_status_result = self.shell("sudo monit status", module_ignore_errors=True, verbose=True)

        exit_code = services_status_result["rc"]
        if exit_code != 0:
            return monit_services_status

        for index, service_info in enumerate(services_status_result["stdout_lines"]):
            if "status" in service_info and "monitoring status" not in service_info:
                service_type_name = services_status_result["stdout_lines"][index - 1]
                service_type = service_type_name.split("'")[0].strip()
                service_name = service_type_name.split("'")[1].strip()
                service_status = service_info[service_info.find("status") + len("status"):].strip()

                monit_services_status[service_name] = {}
                monit_services_status[service_name]["service_status"] = service_status
                monit_services_status[service_name]["service_type"] = service_type

        return monit_services_status

    def get_critical_group_and_process_lists(self, container_name):
        """
        @summary: Get critical group and process lists by parsing the
                  critical_processes file in the specified container
        @return: Two lists which include the critical groups and critical processes respectively
        """
        critical_group_list = []
        critical_process_list = []
        succeeded = True

        file_content = self.shell("docker exec {} bash -c '[ -f /etc/supervisor/critical_processes ] \
                && cat /etc/supervisor/critical_processes'".format(container_name), module_ignore_errors=True)
        for line in file_content["stdout_lines"]:
            line_info = line.strip().split(':')
            if len(line_info) != 2:
                if '201811' in self._os_version and len(line_info) == 1:
                    identifier_value = line_info[0].strip()
                    critical_process_list.append(identifier_value)
                    continue

                succeeded = False
                break

            identifier_key = line_info[0].strip()
            identifier_value = line_info[1].strip()
            if identifier_key == "group" and identifier_value:
                critical_group_list.append(identifier_value)
            elif identifier_key == "program" and identifier_value:
                critical_process_list.append(identifier_value)
            else:
                succeeded = False
                break

        # For PMon container, since different daemons are enabled in different platforms, we need find common processes
        # which are not only in the critical_processes file and also are configured to run on that platform.
        if succeeded and container_name == "pmon":
            expected_critical_group_list = []
            expected_critical_process_list = []
            process_list = self.shell("docker exec {} supervisorctl status"
                                      .format(container_name), module_ignore_errors=True)
            for process_info in process_list["stdout_lines"]:
                process_name = process_info.split()[0].strip()
                process_status = process_info.split()[1].strip()
                if ":" in process_name:
                    group_name = process_name.split(":")[0]
                    process_name = process_name.split(":")[1]
                    if process_status == "RUNNING" and group_name in critical_group_list:
                        expected_critical_group_list.append(process_name)
                else:
                    if process_status == "RUNNING" and process_name in critical_process_list:
                        expected_critical_process_list.append(process_name)

            critical_group_list = expected_critical_group_list
            critical_process_list = expected_critical_process_list

        return critical_group_list, critical_process_list, succeeded

    def critical_group_process(self):
        # Get critical group and process definitions by running cmds in batch to save overhead
        cmds = []
        for service in self.critical_services:
            cmd = 'docker exec {} bash -c "[ -f /etc/supervisor/critical_processes ]' \
                  ' && cat /etc/supervisor/critical_processes"'.format(service)

            cmds.append(cmd)
        results = self.shell_cmds(cmds=cmds, continue_on_fail=True, module_ignore_errors=True, timeout=30)['results']

        # Extract service name of each command result, transform results list to a dict keyed by service name
        service_results = {}
        for res in results:
            service = res['cmd'].split()[2]
            service_results[service] = res

        # Parse critical group and service definition of all services
        group_process_results = {}
        for service in self.critical_services:
            if service not in service_results or service_results[service]['rc'] != 0:
                continue

            service_group_process = {'groups': [], 'processes': []}

            file_content = service_results[service]['stdout_lines']
            for line in file_content:
                line_info = line.strip().split(':')
                if len(line_info) != 2:
                    if '201811' in self._os_version and len(line_info) == 1:
                        process_name = line_info[0].strip()
                        service_group_process['processes'].append(process_name)
                else:
                    group_or_process = line_info[0].strip()
                    group_process_name = line_info[1].strip()
                    if group_or_process == 'group' and group_process_name:
                        service_group_process['groups'].append(group_process_name)
                    elif group_or_process == 'program' and group_process_name:
                        service_group_process['processes'].append(group_process_name)
            group_process_results[service] = service_group_process

        return group_process_results

    def critical_processes_running(self, service):
        """
        @summary: Check whether critical processes are running for a service

        @param service: Name of the SONiC service
        """
        return self.critical_process_status(service)['status']

    def critical_process_status(self, service):
        """
        @summary: Check whether critical process status of a service.

        @param service: Name of the SONiC service
        """
        result = {
            'status': True,
            'exited_critical_process': [],
            'running_critical_process': []
        }

        # return false if the service is not started
        service_status = self.is_service_fully_started(service)
        if service_status is False:
            result['status'] = False
            return result

        # get critical group and process lists for the service
        critical_group_list, critical_process_list, succeeded = self.get_critical_group_and_process_lists(service)
        if succeeded is False:
            result['status'] = False
            return result

        # get process status for the service
        output = self.command("docker exec {} supervisorctl status".format(service), module_ignore_errors=True)
        logging.info("====== supervisor process status for service {} ======".format(service))

        return self.parse_service_status_and_critical_process(
            service_result=output,
            critical_group_list=critical_group_list,
            critical_process_list=critical_process_list
        )

    def all_critical_process_status(self):
        """
        @summary: Check whether all critical processes status for all critical services
        """
        # Get critical process definition of all services
        group_process_results = self.critical_group_process()

        # Get process status of all services. Run cmds in batch to save overhead
        cmds = []
        for service in self.critical_services:
            cmd = 'docker exec {} supervisorctl status'.format(service)
            cmds.append(cmd)
        results = self.shell_cmds(cmds=cmds, continue_on_fail=True, module_ignore_errors=True, timeout=30)['results']

        # Extract service name of each command result, transform results list to a dict keyed by service name
        service_results = {}
        for res in results:
            service = res['cmd'].split()[2]
            service_results[service] = res

        # Parse critical process status of all services
        all_critical_process = {}
        for service in self.critical_services:
            service_critical_process = {
                'status': True,
                'exited_critical_process': [],
                'running_critical_process': []
            }
            if service not in group_process_results or service not in service_results:
                service_critical_process['status'] = False
                all_critical_process[service] = service_critical_process
                continue

            all_critical_process[service] = self.parse_service_status_and_critical_process(
                service_result=service_results[service],
                critical_group_list=group_process_results[service]['groups'],
                critical_process_list=group_process_results[service]['processes']
            )

        return all_critical_process

    def parse_service_status_and_critical_process(self, service_result, critical_group_list,
                                                  critical_process_list):
        """
        Parse the result of command "docker exec <container_name> supervisorctl status"
        and get service container status and critical processes
        """
        service_critical_process = {
            'status': True,
            'exited_critical_process': [],
            'running_critical_process': []
        }
        # If container is not running, stdout_lines is empty
        # In this situation, service container status should be false
        if not service_result['stdout_lines']:
            service_critical_process['status'] = False
        for line in service_result['stdout_lines']:
            pname, status, _ = re.split('\\s+', line, 2)
            # 1. Check status is valid
            # Sometimes, stdout_lines may be error messages but not emtpy
            # In this situation, service container status should be false
            # We can check status is valid or not
            # You can just add valid status str in this tuple if meet later
            if status not in ('RUNNING', 'EXITED', 'STOPPED', 'FATAL', 'BACKOFF', 'STARTING'):
                service_critical_process['status'] = False
            # 2. Check status is not running
            elif status != 'RUNNING':
                # 3. Check process is critical
                if pname in critical_group_list or pname in critical_process_list:
                    service_critical_process['exited_critical_process'].append(pname)
                    service_critical_process['status'] = False
            else:
                if pname in critical_group_list or pname in critical_process_list:
                    service_critical_process['running_critical_process'].append(pname)

        return service_critical_process

    def control_process(self, process, pause=True, namespace='', signal=''):
        """
        Send a signal to a process on the DUT
        """
        process_control_cmd = "docker exec -i {}{} bash -c 'kill -s {} `pgrep {}`'"
        if signal:
            proc_signal = signal
        elif pause:
            proc_signal = "SIGSTOP"
        elif not pause:
            proc_signal = "SIGCONT"
        else:
            logger.error("Must specify either `pause` or a specific signal")
            return

        container = PROCESS_TO_CONTAINER_MAP.get(process, None)
        if not container:
            logger.error("Unknown process {}".format(process))
            return
        cmd = process_control_cmd.format(container, namespace, proc_signal, process)
        self.shell(cmd)

    def get_crm_resources_for_masic(self, namespace=DEFAULT_NAMESPACE):
        """
        @summary: Run the "crm show resources all" command on multi-asic dut and parse its output
        """
        # Construct mapping of {'ASIC0' : {"main_resources": {}, "acl_resources": [], "table_resources": []}, ...}
        # Here we leave value as empty and overwrite it at the end of each ASIC table
        multi_result = dict()
        for n in range(self.num_asics()):
            ns = "asic" + str(n)
            multi_result[ns] = {"main_resources": {}, "acl_resources": [], "table_resources": []}

        output = self.command("crm show resources all")["stdout_lines"]
        current_table = 0   # Totally 3 tables in the command output
        asic = None
        for line in output:
            if len(line.strip()) == 0 or "---" in line:
                continue
            if "ASIC" in line:
                asic = line.lower()
            # Switch table type when 'ASIC0' comes again
            if "ASIC0" in line:
                current_table += 1
                continue
            if current_table == 1:      # content of first table, main resources
                fields = line.split()
                if len(fields) == 3:
                    multi_result[asic]["main_resources"][fields[0]] = \
                        {"used": int(fields[1]), "available": int(fields[2])}
            if current_table == 2:      # content of the second table, acl resources
                fields = line.split()
                if len(fields) == 5:
                    multi_result[asic]["acl_resources"].append({"stage": fields[0],
                                                                "bind_point": fields[1],
                                                                "resource_name": fields[2],
                                                                "used_count": int(fields[3]),
                                                                "available_count": int(fields[4])})
            if current_table == 3:      # content of the third table, table resources
                fields = line.split()
                if len(fields) == 4:
                    multi_result[asic]["table_resources"].append({"table_id": fields[0],
                                                                  "resource_name": fields[1],
                                                                  "used_count": int(fields[2]),
                                                                  "available_count": int(fields[3])})
        return multi_result[namespace]

    def get_crm_resources(self, namespace=DEFAULT_NAMESPACE):
        """
        @summary: Run the "crm show resources all" command and parse its output
        """
        if self.is_multi_asic:
            return self.get_crm_resources_for_masic(namespace)
        result = {"main_resources": {}, "acl_resources": [], "table_resources": []}
        output = self.command("crm show resources all")["stdout_lines"]
        current_table = 0   # Totally 3 tables in the command output
        for line in output:
            if len(line.strip()) == 0:
                continue
            if "---" in line:
                current_table += 1
                continue
            if current_table == 1:      # content of first table, main resources
                fields = line.split()
                if len(fields) == 3:
                    result["main_resources"][fields[0]] = {"used": int(fields[1]), "available": int(fields[2])}
            if current_table == 2:      # content of the second table, acl resources
                fields = line.split()
                if len(fields) == 5:
                    result["acl_resources"].append({"stage": fields[0],
                                                    "bind_point": fields[1],
                                                    "resource_name": fields[2],
                                                    "used_count": int(fields[3]),
                                                    "available_count": int(fields[4])})
            if current_table == 3:      # content of the third table, table resources
                fields = line.split()
                if len(fields) == 4:
                    result["table_resources"].append({"table_id": fields[0],
                                                      "resource_name": fields[1],
                                                      "used_count": int(fields[2]),
                                                      "available_count": int(fields[3])})

        return result

    def get_pmon_daemon_db_value(self, daemon_db_table_key, field):
        """
        @summary: get db value in state db to check the daemon expected status
        """
        ret_val = None
        get_db_value_cmd = 'redis-cli -n 6 hget "{}" {}'.format(daemon_db_table_key, field)

        cmd_output = self.shell(get_db_value_cmd, module_ignore_errors=True)
        if cmd_output['rc'] == 0:
            ret_val = cmd_output['stdout']

        return ret_val

    def start_pmon_daemon(self, daemon_name):
        """
        @summary: start daemon in pmon docker using supervisorctl start command.
        """
        pmon_daemon_start_cmd = "docker exec pmon supervisorctl start {}".format(daemon_name)

        self.shell(pmon_daemon_start_cmd, module_ignore_errors=True)

    def stop_pmon_daemon_service(self, daemon_name):
        """
        @summary: stop daemon in pmon docker using supervisorctl stop command.
        """
        pmon_daemon_stop_cmd = "docker exec pmon supervisorctl stop {}".format(daemon_name)

        self.shell(pmon_daemon_stop_cmd, module_ignore_errors=True)

    def get_pmon_daemon_status(self, daemon_name):
        """
        @summary: get daemon status in pmon docker using supervisorctl status command.

        @return: daemon_status - "RUNNING"/"STOPPED"/"EXITED"
                 daemon_pid - integer number
        """
        daemon_status = None
        daemon_pid = -1

        daemon_info = self.shell("docker exec pmon supervisorctl status {}"
                                 .format(daemon_name), module_ignore_errors=True)["stdout"]
        if daemon_info.find(daemon_name) != -1:
            daemon_status = daemon_info.split()[1].strip()
            if daemon_status == "RUNNING":
                daemon_pid = int(daemon_info.split()[3].strip(','))

        logging.info("Daemon '{}' in the '{}' state with pid {}".format(daemon_name, daemon_status, daemon_pid))

        return daemon_status, daemon_pid

    def kill_pmon_daemon_pid_w_sig(self, pid, sig_name):
        """
        @summary: stop daemon in pmon docker using kill with a sig.

        @return: True if it is stopped or False if not
        """
        if pid != -1:
            daemon_kill_sig_cmd = "docker exec pmon bash -c 'kill {} {}'".format(sig_name, pid)
            self.shell(daemon_kill_sig_cmd, module_ignore_errors=True)

    def stop_pmon_daemon(self, daemon_name, sig_name=None, pid=-1):
        """
        @summary: stop daemon in pmon docker.

        @return: True if it is stopped or False if not
        """
        if sig_name is None:
            self.stop_pmon_daemon_service(daemon_name)
        else:
            self.kill_pmon_daemon_pid_w_sig(pid, sig_name)

    def get_pmon_daemon_states(self):
        """
        @summary: get state list of daemons from pmon docker.
                  Referencing (/usr/share/sonic/device/{platform}/pmon_daemon_control.json)
                  if some daemon is disabled in the config file, then remove it from the daemon list.

        @return: dictionary of { service_name1 : state1, ... ... }
        """
        # some services are meant to have a short life span or not part of the daemons
        exemptions = ['lm-sensors', 'start.sh', 'rsyslogd', 'start', 'dependent-startup', 'chassis_db_init']

        daemons = self.shell('docker exec pmon supervisorctl status', module_ignore_errors=True)['stdout_lines']

        daemon_list = [line.strip().split()[0] for line in daemons if len(line.strip()) > 0]

        daemon_ctl_key_prefix = 'skip_'
        daemon_config_file_path = os.path.join('/usr/share/sonic/device',
                                               self.facts["platform"], 'pmon_daemon_control.json')

        try:
            output = self.shell('cat %s' % daemon_config_file_path)
            json_data = json.loads(output["stdout"])
            logging.debug("Original file content is %s" % str(json_data))
            for key in daemon_list:
                if (daemon_ctl_key_prefix + key) not in json_data:
                    logging.debug("Daemon %s is enabled" % key)
                elif not json_data[daemon_ctl_key_prefix + key]:
                    logging.debug("Daemon %s is enabled" % key)
                else:
                    logging.debug("Daemon %s is disabled" % key)
                    exemptions.append(key)

            if self.sonic_release in ['201911']:
                exemptions.append('platform_api_server')
        except Exception:
            # if pmon_daemon_control.json not exist, then it's using default setting,
            # all the pmon daemons expected to be running after boot up.
            pass

        # Collect state of services that are not on the exemption list.
        daemon_states = {}
        for line in daemons:
            words = line.strip().split()
            if len(words) >= 2 and words[0] not in exemptions:
                daemon_states[words[0]] = words[1]

        logging.info("Pmon daemon state list for this platform is %s" % str(daemon_states))
        return daemon_states

    def num_asics(self):
        """
        return the number of NPUs on the DUT
        """
        return self.facts["num_asic"]

    def get_syncd_docker_names(self):
        """
        @summary: get the list of syncd dockers names for the number of NPUs present on the DUT
        for a single NPU dut the list will have only "syncd" in it
        """
        syncd_docker_names = []
        if self.facts["num_asic"] == 1:
            syncd_docker_names.append("syncd")
        else:
            num_asics = int(self.facts["num_asic"])
            for asic in range(0, num_asics):
                syncd_docker_names.append("syncd{}".format(asic))
        return syncd_docker_names

    def get_swss_docker_names(self):
        swss_docker_names = []
        if self.facts["num_asic"] == 1:
            swss_docker_names.append("swss")
        else:
            num_asics = self.facts["num_asic"]
            for asic in range(0, num_asics):
                swss_docker_names.append("swss{}".format(asic))
        return swss_docker_names

    def get_namespace_ids(self, container_name):
        """
        Gets ids of namespace where the container should reside in.

        Returns:
            A list contains ids of namespace such as [DEFAULT_ASIC_ID, "0", "1", ...]}
        """
        has_global_scope = ""
        has_per_asic_scope = ""
        namespace_ids = []

        num_asics = int(self.facts["num_asic"])
        command_config_entry = "sonic-db-cli CONFIG_DB hgetall \"FEATURE|{}\"".format(container_name)
        command_output = self.shell(command_config_entry)
        exit_code = command_output["rc"]
        if exit_code != 0:
            return namespace_ids, False

        config_info = command_output["stdout_lines"]
        for index, item in enumerate(config_info):
            if item == "has_global_scope":
                has_global_scope = config_info[index + 1]
            elif item == "has_per_asic_scope":
                has_per_asic_scope = config_info[index + 1]

        if num_asics > 1:
            if has_global_scope == "True":
                namespace_ids.append(DEFAULT_ASIC_ID)
            if has_per_asic_scope == "True":
                for asic_id in range(0, num_asics):
                    namespace_ids.append(str(asic_id))
        else:
            namespace_ids.append(DEFAULT_ASIC_ID)

        return namespace_ids, True

    def get_up_time(self, utc_timezone=False):

        if utc_timezone:
            current_time = self.get_now_time(utc_timezone=True)
            uptime_seconds = self.get_uptime()
            uptime_since = current_time - uptime_seconds
        else:
            up_time_text = self.command("uptime -s")["stdout"]
            uptime_since = datetime.strptime(up_time_text, "%Y-%m-%d %H:%M:%S")

        return uptime_since

    def get_now_time(self, utc_timezone=False):

        command = 'date +"%Y-%m-%d %H:%M:%S"'
        if utc_timezone:
            command += ' -u'
        now_time_text = self.command(command)["stdout"]

        return datetime.strptime(now_time_text, "%Y-%m-%d %H:%M:%S")

    def get_uptime(self):
        uptime_text = self.command("awk '{print $1}' /proc/uptime")["stdout"]
        return timedelta(seconds=float(uptime_text))

    def get_networking_uptime(self):
        start_time = self.get_service_props("networking", props=["ExecMainStartTimestamp", ])
        try:
            return self.get_now_time() - datetime.strptime(start_time["ExecMainStartTimestamp"],
                                                           "%a %Y-%m-%d %H:%M:%S %Z")
        except Exception as e:
            logging.error("Exception raised while getting networking restart time: %s" % repr(e))
            return None

    def get_image_info(self):
        """
        @summary: get list of images installed on the dut.
                  return a dictionary of "current, next, installed_list"
        """
        lines = self.command("sonic_installer list")["stdout_lines"]
        ret = {}
        images = []
        for line in lines:
            words = line.strip().split()
            if len(words) == 2:
                if words[0] == 'Current:':
                    ret['current'] = words[1]
                elif words[0] == 'Next:':
                    ret['next'] = words[1]
            elif len(words) == 1 and words[0].startswith('SONiC-OS'):
                images.append(words[0])

        ret['installed_list'] = images
        return ret

    def shutdown(self, ifname):
        """
            Shutdown interface specified by ifname

            Args:
                ifname: the interface to shutdown
        """
        logging.info("Shutting down {}".format(ifname))
        return self.command("sudo config interface shutdown {}".format(ifname))

    def shutdown_multiple(self, ifnames):
        """
            Shutdown multiple interfaces

            Args:
                ifnames (list): the interface names to shutdown
        """
        image_info = self.get_image_info()
        # 201811 image does not support multiple interfaces shutdown
        # Change the batch shutdown call to individual call here
        if "201811" in image_info.get("current"):
            for ifname in ifnames:
                self.shutdown(ifname)
            return
        else:
            intf_str = ','.join(ifnames)
            return self.shutdown(intf_str)

    def no_shutdown(self, ifname):
        """
            Bring up interface specified by ifname

            Args:
                ifname: the interface to bring up
        """
        logging.info("Starting up {}".format(ifname))
        return self.command("sudo config interface startup {}".format(ifname))

    def no_shutdown_multiple(self, ifnames):
        """
            Bring up multiple interfaces

            Args:
                ifnames (list): the interface names to bring up
        """
        image_info = self.get_image_info()
        # 201811 image does not support multiple interfaces startup
        # Change the batch startup call to individual call here
        if "201811" in image_info.get("current"):
            for ifname in ifnames:
                self.no_shutdown(ifname)
            return
        else:
            intf_str = ','.join(ifnames)
            return self.no_shutdown(intf_str)

    def get_ip_route_info(self, dstip, ns=""):
        """
        @summary: return route information for a destionation. The destination could an ip address or ip prefix.

        @param dstip: destination. either ip_address or ip_network

        Please beware: if dstip is an ip network, you will receive all ECMP nexthops
        But if dstip is an ip address, only one nexthop will be returned,
        the one which is going to be used to send a packet to the destination.

        Exanples:
----------------
get_ip_route_info(ipaddress.ip_address(unicode("192.168.8.0")))
returns {'set_src': IPv4Address(u'10.1.0.32'), 'nexthops': [(IPv4Address(u'10.0.0.13'), u'PortChannel0004')]}

raw data
192.168.8.0 via 10.0.0.13 dev PortChannel0004 src 10.1.0.32
    cache
----------------
get_ip_route_info(ipaddress.ip_network(unicode("192.168.8.0/25")))
returns {'set_src': IPv4Address(u'10.1.0.32'), 'nexthops': [(IPv4Address(u'10.0.0.1'), u'PortChannel0001'),
                                                            (IPv4Address(u'10.0.0.5'), u'PortChannel0002'),
                                                            (IPv4Address(u'10.0.0.9'), u'PortChannel0003'),
                                                            (IPv4Address(u'10.0.0.13'), u'PortChannel0004')]}

raw data
192.168.8.0/25 proto 186 src 10.1.0.32 metric 20
        nexthop via 10.0.0.1  dev PortChannel0001 weight 1
        nexthop via 10.0.0.5  dev PortChannel0002 weight 1
        nexthop via 10.0.0.9  dev PortChannel0003 weight 1
        nexthop via 10.0.0.13  dev PortChannel0004 weight 1

raw data (starting from Bullseye)
192.168.8.0/25 nhid 296 proto bgp src 10.1.0.32 metric 20
        nexthop via 10.0.0.57 dev PortChannel0001 weight 1
        nexthop via 10.0.0.59 dev PortChannel0002 weight 1
        nexthop via 10.0.0.61 dev PortChannel0003 weight 1
        nexthop via 10.0.0.63 dev PortChannel0004 weight 1
----------------
get_ip_route_info(ipaddress.ip_address(unicode("20c0:a818::")))
returns {'set_src': IPv6Address(u'fc00:1::32'), 'nexthops': [(IPv6Address(u'fc00::1a'), u'PortChannel0004')]}

raw data
20c0:a818:: from :: via fc00::1a dev PortChannel0004 proto 186 src fc00:1::32 metric 20  pref medium
----------------
get_ip_route_info(ipaddress.ip_network(unicode("20c0:a818::/64")))
returns {'set_src': IPv6Address(u'fc00:1::32'), 'nexthops': [(IPv6Address(u'fc00::2'), u'PortChannel0001'),
                                                             (IPv6Address(u'fc00::a'), u'PortChannel0002'),
                                                             (IPv6Address(u'fc00::12'), u'PortChannel0003'),
                                                             (IPv6Address(u'fc00::1a'), u'PortChannel0004')]}

raw data
20c0:a818::/64 via fc00::2 dev PortChannel0001 proto 186 src fc00:1::32 metric 20  pref medium
20c0:a818::/64 via fc00::a dev PortChannel0002 proto 186 src fc00:1::32 metric 20  pref medium
20c0:a818::/64 via fc00::12 dev PortChannel0003 proto 186 src fc00:1::32 metric 20  pref medium
20c0:a818::/64 via fc00::1a dev PortChannel0004 proto 186 src fc00:1::32 metric 20  pref medium

raw data (starting from Bullseye)
20c0:a818::/64 nhid 224 proto bgp src fc00:1::32 metric 20 pref medium
        nexthop via fc00::72 dev PortChannel0001 weight 1
        nexthop via fc00::76 dev PortChannel0002 weight 1
        nexthop via fc00::7a dev PortChannel0003 weight 1
        nexthop via fc00::7e dev PortChannel0004 weight 1
----------------
get_ip_route_info(ipaddress.ip_network(unicode("0.0.0.0/0")))
returns {'set_src': IPv4Address(u'10.1.0.32'), 'nexthops': [(IPv4Address(u'10.0.0.1'), u'PortChannel0001'),
                                                            (IPv4Address(u'10.0.0.5'), u'PortChannel0002'),
                                                            (IPv4Address(u'10.0.0.9'), u'PortChannel0003'),
                                                            (IPv4Address(u'10.0.0.13'), u'PortChannel0004')]}

raw data
default proto 186 src 10.1.0.32 metric 20
        nexthop via 10.0.0.1  dev PortChannel0001 weight 1
        nexthop via 10.0.0.5  dev PortChannel0002 weight 1
        nexthop via 10.0.0.9  dev PortChannel0003 weight 1
        nexthop via 10.0.0.13  dev PortChannel0004 weight 1

raw data (starting from Bullseye)
default nhid 296 proto bgp src 10.1.0.32 metric 20
        nexthop via 10.0.0.57 dev PortChannel0001 weight 1
        nexthop via 10.0.0.59 dev PortChannel0002 weight 1
        nexthop via 10.0.0.61 dev PortChannel0003 weight 1
        nexthop via 10.0.0.63 dev PortChannel0004 weight 1
----------------
get_ip_route_info(ipaddress.ip_network(unicode("::/0")))
returns {'set_src': IPv6Address(u'fc00:1::32'), 'nexthops': [(IPv6Address(u'fc00::2'), u'PortChannel0001'),
                                                             (IPv6Address(u'fc00::a'), u'PortChannel0002'),
                                                             (IPv6Address(u'fc00::12'), u'PortChannel0003'),
                                                             (IPv6Address(u'fc00::1a'), u'PortChannel0004')]}

raw data
default via fc00::2 dev PortChannel0001 proto 186 src fc00:1::32 metric 20  pref medium
default via fc00::a dev PortChannel0002 proto 186 src fc00:1::32 metric 20  pref medium
default via fc00::12 dev PortChannel0003 proto 186 src fc00:1::32 metric 20  pref medium
default via fc00::1a dev PortChannel0004 proto 186 src fc00:1::32 metric 20  pref medium

raw data (starting from Bullseye)
default nhid 224 proto bgp src fc00:1::32 metric 20 pref medium
        nexthop via fc00::72 dev PortChannel0001 weight 1
        nexthop via fc00::76 dev PortChannel0002 weight 1
        nexthop via fc00::7a dev PortChannel0003 weight 1
        nexthop via fc00::7e dev PortChannel0004 weight 1
----------------
        """

        rtinfo = {'set_src': None, 'nexthops': []}

        if isinstance(dstip, ipaddress.IPv4Network) or isinstance(dstip, ipaddress.IPv6Network):
            if dstip.version == 4:
                rt = self.command("ip {} route list exact {}".format(ns, dstip))['stdout_lines']
            else:
                rt = self.command("ip {} -6 route list exact {}".format(ns, dstip))['stdout_lines']

            logging.info("route raw info for {}: {}".format(dstip, rt))

            if len(rt) == 0:
                return rtinfo

            # parse set_src
            m = re.match(r"^(default|\S+) proto (zebra|bgp|186) src (\S+)", rt[0])
            m1 = re.match(r"^(default|\S+) via (\S+) dev (\S+) proto (zebra|bgp|186) src (\S+)", rt[0])
            m2 = re.match(r"^(default|\S+) nhid (\d+) proto (zebra|bgp|186) src (\S+)", rt[0])
            # For case when there is no ecmp (below is example on Bullseye)
            # default nhid 2270 via fc00::2 dev PortChannel102 proto bgp src fc00:10::1 metric 20 pref medium
            m3 = re.match(r"^(default|\S+) nhid (\d+) via\s+(\S+)\s+dev\s+(\S+) proto (zebra|bgp|186) src (\S+)", rt[0])
            if m:
                rtinfo['set_src'] = ipaddress.ip_address((m.group(3)).encode().decode())
            elif m1:
                rtinfo['set_src'] = ipaddress.ip_address((m1.group(5)).encode().decode())
            elif m2:
                rtinfo['set_src'] = ipaddress.ip_address((m2.group(4)).encode().decode())
            elif m3:
                rtinfo['set_src'] = ipaddress.ip_address((m3.group(6)).encode().decode())

            # parse nexthops
            for route_entry in rt:
                m = re.search(r"(default|nexthop|\S+)\s+via\s+(\S+)\s+dev\s+(\S+)", route_entry)
                if m:
                    rtinfo['nexthops'].append((ipaddress.ip_address((m.group(2)).encode().decode()),
                                               (m.group(3)).encode().decode()))

        elif isinstance(dstip, ipaddress.IPv4Address) or isinstance(dstip, ipaddress.IPv6Address):
            rt = self.command("ip {} route get {}".format(ns, dstip))['stdout_lines']
            logging.info("route raw info for {}: {}".format(dstip, rt))

            if len(rt) == 0:
                return rtinfo

            m = re.match(r".+\s+via\s+(\S+)\s+.*dev\s+(\S+)\s+.*src\s+(\S+)\s+", rt[0])
            if m:
                nexthop_ip = ipaddress.ip_address(m.group(1))
                gw_if = m.group(2)
                rtinfo['nexthops'].append((nexthop_ip, gw_if))
                rtinfo['set_src'] = ipaddress.ip_address(m.group(3))
        else:
            raise ValueError("Wrong type of dstip")

        logging.info("route parsed info for {}: {}".format(dstip, rtinfo))
        return rtinfo

    def check_default_route(self, ipv4=True, ipv6=True):
        """
        @summary: return default route status

        @param ipv4: check ipv4 default
        @param ipv6: check ipv6 default
        """
        if ipv4:
            rtinfo_v4 = self.get_ip_route_info(ipaddress.ip_network('0.0.0.0/0'))
            if len(rtinfo_v4['nexthops']) == 0:
                return False

        if ipv6:
            rtinfo_v6 = self.get_ip_route_info(ipaddress.ip_network('::/0'))
            if len(rtinfo_v6['nexthops']) == 0:
                return False

        return True

    def check_intf_link_state(self, interface_name):
        intf_status = self.show_interface(command="status", interfaces=[interface_name])["ansible_facts"]['int_status']
        return intf_status[interface_name]['oper_state'] == 'up'

    def get_intf_link_local_ipv6_addr(self, intf):
        """
        Get the link local ipv6 address of the interface

        Args:
            intf: The SONiC interface name

        Returns:
            The link local ipv6 address of the interface or empty string if not found

        Sample output:
            fe80::2edd:e9ff:fefc:dd58
        """
        cmd = "ip addr show %s | grep inet6 | grep 'scope link' | awk '{print $2}' | cut -d '/' -f1" % intf
        addr = self.shell(cmd)["stdout"]
        return addr

    def get_bgp_neighbor_info(self, neighbor_ip):
        """
        @summary: return bgp neighbor info

        @param neighbor_ip: bgp neighbor IP
        """
        nbip = ipaddress.ip_address(neighbor_ip)
        if nbip.version == 4:
            out = self.command("vtysh -c \"show ip bgp neighbor {} json\"".format(neighbor_ip))
        else:
            out = self.command("vtysh -c \"show bgp ipv6 neighbor {} json\"".format(neighbor_ip))
        nbinfo = json.loads(re.sub(r"\\\"", '"', re.sub(r"\\n", "", out['stdout'])))
        logging.info("bgp neighbor {} info {}".format(neighbor_ip, nbinfo))

        return nbinfo[str(neighbor_ip)]

    def check_bgp_session_nsf(self, neighbor_ip):
        """
        @summary: check if bgp neighbor session enters NSF state or not

        @param neighbor_ip: bgp neighbor IP
        """
        nbinfo = self.get_bgp_neighbor_info(neighbor_ip)
        if 'bgpState' in nbinfo and nbinfo['bgpState'].lower() == "Active".lower():
            if 'bgpStateIs' in nbinfo and nbinfo['bgpStateIs'].lower() == "passiveNSF".lower():
                return True
        return False

    def _parse_route_summary(self, output):
        """
        Sample command output:
Route Source         Routes               FIB  (vrf default)
kernel               34                   34
connected            11                   11
static               1                    0
ebgp                 6404                 6404
ibgp                 0                    0
------
Totals               6450                 6449

        Sample parsing output:
        {
            'kernel' : { 'routes' : 34 , 'FIB' : 34 },
            ... ...
            'Totals' : { 'routes' : 6450, 'FIB' : 6449 }
        }
        """
        ret = {}
        for line in output:
            tokens = line.split()
            if len(tokens) > 1:
                key = tokens[0]
                if key in ret:
                    val = ret[key]
                else:
                    val = {'routes': 0, 'FIB': 0}
                if tokens[1].isdigit():
                    val['routes'] += int(tokens[1])
                    if len(tokens) > 2 and tokens[2].isdigit():
                        val['FIB'] += int(tokens[2])
                    ret[key] = val
        return ret

    def get_ip_route_summary(self, skip_kernel_tunnel=False):
        """
        @summary: issue "show ip[v6] route summary" and parse output into dicitionary.
                  Going forward, this show command should use tabular output so that
                  we can simply call show_and_parse() function.
        """
        ipv4_output = self.shell("show ip route sum")["stdout_lines"]
        ipv4_summary = self._parse_route_summary(ipv4_output)

        if skip_kernel_tunnel is True:
            ipv4_route_kernel_output = self.shell("show ip route kernel")["stdout_lines"]
            ipv4_route_kernel_count = 0
            for string in ipv4_route_kernel_output:
                if re.search('tun', string):
                    ipv4_route_kernel_count += 1
            logging.debug("IPv4 kernel tun route {}, {}".format(ipv4_route_kernel_count, ipv4_route_kernel_output))

            if ipv4_route_kernel_count > 0:
                ipv4_summary['kernel']['routes'] -= ipv4_route_kernel_count
                ipv4_summary['kernel']['FIB'] -= ipv4_route_kernel_count
                ipv4_summary['Totals']['routes'] -= ipv4_route_kernel_count
                ipv4_summary['Totals']['FIB'] -= ipv4_route_kernel_count

        ipv6_output = self.shell("show ipv6 route sum")["stdout_lines"]
        ipv6_summary = self._parse_route_summary(ipv6_output)

        if skip_kernel_tunnel is True:
            ipv6_route_kernel_output = self.shell("show ipv6 route kernel")["stdout_lines"]
            ipv6_route_kernel_count = 0
            for string in ipv6_route_kernel_output:
                if re.search('tun', string):
                    ipv6_route_kernel_count += 1
            logging.debug("IPv6 kernel tun route {}, {}".format(ipv6_route_kernel_count, ipv6_route_kernel_output))

            if ipv6_route_kernel_count > 0:
                ipv6_summary['kernel']['routes'] -= ipv6_route_kernel_count
                ipv6_summary['kernel']['FIB'] -= ipv6_route_kernel_count
                ipv6_summary['Totals']['routes'] -= ipv6_route_kernel_count
                ipv6_summary['Totals']['FIB'] -= ipv6_route_kernel_count

        return ipv4_summary, ipv6_summary

    def get_dut_iface_mac(self, iface_name):
        """
        Gets the MAC address of specified interface.

        Returns:
            str: The MAC address of the specified interface, or None if it is not found.
        """
        try:
            mac = self.command('cat /sys/class/net/{}/address'.format(iface_name))['stdout']
            return mac
        except Exception as e:
            logger.error('Failed to get MAC address for interface "{}", exception: {}'.format(iface_name, repr(e)))
            return None

    def iface_macsec_ok(self, interface_name):
        """
        Check if macsec is functional on specified interface.

        Returns: True or False
        """
        try:
            cmd = 'sonic-db-cli STATE_DB HGET \"MACSEC_PORT_TABLE|{}\" state'.format(interface_name)
            state = self.shell(cmd)['stdout'].strip()
            return state == 'ok'
        except Exception as e:
            logger.error('Failed to get macsec status for interface "{}", exception: {}'
                         .format(interface_name, repr(e)))
            return False

    def get_container_autorestart_states(self):
        """
        @summary: Get container names and their autorestart states by analyzing
                  the command output of "show feature autorestart"
        @return:  A dictionary where keys are the names of containers which have the
                  autorestart feature implemented and values are the autorestart feature
                  state for that container
        """
        container_autorestart_states = {}

        show_cmd_output = self.shell("show feature autorestart")
        for line in show_cmd_output["stdout_lines"]:
            container_name = line.split()[0].strip()
            container_state = line.split()[1].strip()
            if container_state in ["enabled", "disabled"]:
                container_autorestart_states[container_name] = container_state

        return container_autorestart_states

    def get_feature_status(self):
        """
        Gets the list of features and states

        Returns:
            dict: feature status dict. { <feature name> : <status: enabled | disabled> }
            bool: status obtained successfully (True | False)
        """
        feature_status = {}
        command_list = ['show feature status', 'show features']
        for cmd in command_list:
            command_output = self.shell(cmd, module_ignore_errors=True)
            if command_output['rc'] == 0:
                break
        else:
            return feature_status, False

        features_stdout = command_output['stdout_lines']
        lines = features_stdout[2:]
        for x in lines:
            if sys.version_info.major < 3:
                result = x.encode('UTF-8')
            else:
                result = x
            r = result.split()
            feature_status[r[0]] = r[1]
        return feature_status, True

    def _parse_column_positions(self, sep_line, sep_char='-'):
        """Parse the position of each columns in the command output

        Args:
            sep_line: The output line separating actual data and column headers
            sep_char: The character used in separation line. Defaults to '-'.

        Returns:
            Returns a list. Each item is a tuple with two elements. The first element is start position of a column.
            The second element is the end position of the column.
        """
        prev = ' ',
        positions = []
        for pos, char in enumerate(sep_line + ' '):
            if char == sep_char:
                if char != prev:
                    left = pos
            else:
                if char != prev:
                    right = pos
                    positions.append((left, right))
            prev = char
        return positions

    def _parse_show(self, output_lines, header_len=1):

        result = []

        sep_line_pattern = re.compile(r"^( *-+ *)+$")
        sep_line_found = False
        for idx, line in enumerate(output_lines):
            if sep_line_pattern.match(line):
                sep_line_found = True
                header_lines = output_lines[idx - header_len:idx]
                sep_line = output_lines[idx]
                content_lines = output_lines[idx + 1:]
                break

        if not sep_line_found:
            logging.error('Failed to find separation line in the show command output')
            return result

        try:
            positions = self._parse_column_positions(sep_line)
        except Exception as e:
            logging.error('Possibly bad command output, exception: {}'.format(repr(e)))
            return result

        headers = []
        for (left, right) in positions:
            header = " ".join([header_line[left:right].strip().lower() for header_line in header_lines]).strip()
            headers.append(header)

        for content_line in content_lines:
            # When an empty line is encountered while parsing the tabulate content, it is highly possible that the
            # tabulate content has been drained. The empty line and rest of the lines should not be parsed.
            if len(content_line) == 0:
                break
            item = {}
            for idx, (left, right) in enumerate(positions):
                k = headers[idx]
                v = content_line[left:right].strip()
                item[k] = v
            result.append(item)

        return result

    def show_and_parse(self, show_cmd, header_len=1, **kwargs):
        """Run a show command and parse the output using a generic pattern.

        This method can adapt to the column changes as long as the output format follows the pattern of
        'show interface status'.

        The key is to have a line of headers. Then a separation line with '-' under each column header. Both header and
        column content are within the width of '-' chars for that column.

        For example, part of the output of command 'show interface status':

        admin@str-msn2700-02:~$ show interface status
              Interface            Lanes    Speed    MTU    FEC    Alias             Vlan    Oper    Admin             Type    Asym PFC     # noqa E501
        ---------------  ---------------  -------  -----  -----  -------  ---------------  ------  -------  ---------------  ----------     # noqa E501
              Ethernet0          0,1,2,3      40G   9100    N/A     etp1  PortChannel0002      up       up   QSFP+ or later         off     # noqa E501
              Ethernet4          4,5,6,7      40G   9100    N/A     etp2  PortChannel0002      up       up   QSFP+ or later         off     # noqa E501
              Ethernet8        8,9,10,11      40G   9100    N/A     etp3  PortChannel0005      up       up   QSFP+ or later         off     # noqa E501
        ...

        The parsed example will be like:
            [{
                "oper": "up",
                "lanes": "0,1,2,3",
                "fec": "N/A",
                "asym pfc": "off",
                "admin": "up",
                "type": "QSFP+ or later",
                "vlan": "PortChannel0002",
                "mtu": "9100",
                "alias": "etp1",
                "interface": "Ethernet0",
                "speed": "40G"
              },
              {
                "oper": "up",
                "lanes": "4,5,6,7",
                "fec": "N/A",
                "asym pfc": "off",
                "admin": "up",
                "type": "QSFP+ or later",
                "vlan": "PortChannel0002",
                 "mtu": "9100",
                 "alias": "etp2",
                "interface": "Ethernet4",
                "speed": "40G"
              },
              {
                "oper": "up",
                "lanes": "8,9,10,11",
                "fec": "N/A",
                "asym pfc": "off",
                "admin": "up",
                "type": "QSFP+ or later",
                "vlan": "PortChannel0005",
                "mtu": "9100",
                "alias": "etp3",
                "interface": "Ethernet8",
                "speed": "40G"
              },
              ...
            ]

        Args:
            show_cmd: The show command that will be executed.

        Returns:
            Return the parsed output of the show command in a list of dictionary. Each list item is a dictionary,
            corresponding to one content line under the header in the output. Keys of the dictionary are the column
            headers in lowercase.
        """
        start_line_index = kwargs.pop("start_line_index", 0)
        end_line_index = kwargs.pop("end_line_index", None)
        output = self.shell(show_cmd, **kwargs)["stdout_lines"]
        if end_line_index is None:
            output = output[start_line_index:]
        else:
            output = output[start_line_index:end_line_index]
        return self._parse_show(output, header_len)

    @cached(name='mg_facts')
    def get_extended_minigraph_facts(self, tbinfo, namespace=DEFAULT_NAMESPACE):
        mg_facts = self.minigraph_facts(host=self.hostname, namespace=namespace)['ansible_facts']
        mg_facts['minigraph_ptf_indices'] = {}

        # Fix the ptf port index for multi-dut testbeds. These testbeds have
        # multiple DUTs sharing a same PTF host. Therefore, the indices from
        # the minigraph facts are not always match up with PTF port indices.
        try:
            dut_index = tbinfo['duts'].index(self.hostname)
            map = tbinfo['topo']['ptf_map'][str(dut_index)]
            if map:
                for port, index in list(mg_facts['minigraph_port_indices'].items()):
                    if str(index) in map:
                        mg_facts['minigraph_ptf_indices'][port] = map[str(index)]
        except (ValueError, KeyError):
            pass

        # set 'backend' flag for mg_facts
        # a 'backend' topology may has different name convention for some parameter
        self.update_backend_flag(tbinfo, mg_facts)

        return mg_facts

    def update_backend_flag(self, tbinfo, mg_facts):
        mg_facts[constants.IS_BACKEND_TOPOLOGY_KEY] = self.assert_topo_is_backend(tbinfo)

    # assert whether a topo is 'backend' type
    def assert_topo_is_backend(self, tbinfo):
        topo_key = constants.TOPO_KEY
        name_key = constants.NAME_KEY
        if topo_key in list(tbinfo.keys()) and name_key in list(tbinfo[topo_key].keys()):
            topo_name = tbinfo[topo_key][name_key]
            if constants.BACKEND_TOPOLOGY_IND in topo_name:
                return True
        return False

    def run_sonic_db_cli_cmd(self, sonic_db_cmd):
        cmd = "sonic-db-cli {}".format(sonic_db_cmd)
        return self.command(cmd, verbose=False)

    def run_redis_cli_cmd(self, redis_cmd):
        cmd = "/usr/bin/redis-cli {}".format(redis_cmd)
        return self.command(cmd, verbose=False)

    def get_asic_name(self):
        asic = "unknown"
        output = self.shell("lspci", module_ignore_errors=True)["stdout"]
        if ("Broadcom Limited Device b960" in output or
                "Broadcom Limited Broadcom BCM56960" in output):
            asic = "th"
        elif "Device b971" in output:
            asic = "th2"
        elif ("Broadcom Limited Device b850" in output or
                "Broadcom Limited Broadcom BCM56850" in output or
                "Broadcom Inc. and subsidiaries Broadcom BCM56850" in output):
            asic = "td2"
        elif ("Broadcom Limited Device b870" in output or
                "Broadcom Inc. and subsidiaries Device b870" in output):
            asic = "td3"
        elif "Broadcom Limited Device b980" in output:
            asic = "th3"
        elif "Cisco Systems Inc Device a001" in output:
            asic = "gb"
        elif "Mellanox Technologies" in output:
            asic = "spc"

        return asic

    def is_nvidia_platform(self):
        return 'mellanox' == self.facts['asic_type']

    def _get_platform_asic(self, platform):
        platform_asic = os.path.join(
            "/usr/share/sonic/device", platform, "platform_asic"
        )
        output = self.shell(
            "cat {}".format(platform_asic), module_ignore_errors=True
        )
        if output["rc"] == 0:
            return output["stdout_lines"][0]
        return None

    def get_facts(self):
        return self.facts

    def get_running_config_facts(self):
        return self.config_facts(host=self.hostname, source='running', verbose=False)['ansible_facts']

    def get_vlan_intfs(self):
        '''
        Get any interfaces belonging to a VLAN
        '''
        vlan_members_facts = self.get_running_config_facts().get('VLAN_MEMBER', {})
        vlan_intfs = []

        for vlan in vlan_members_facts:
            for intf in vlan_members_facts[vlan]:
                vlan_intfs.append(intf)

        return vlan_intfs

    def get_vlan_brief(self):
        """
        Get vlan brief
        Sample output:
            {
                "Vlan1000": {
                    "interface_ipv4": [ "192.168.0.1/24" ],
                    "interface_ipv6": [ "fc02:1000::1/64" ],
                    "members": ["Ethernet0", "Ethernet1"]
                },
                "Vlan2000": {
                    "interface_ipv4": [ "192.168.1.1/24" ],
                    "interface_ipv6": [ "fc02:1001::1/64" ],
                    "members": ["Ethernet3", "Ethernet4"]
                }
            }
        """
        config = self.get_running_config_facts()
        vlan_brief = {}
        for vlan_name, members in config["VLAN_MEMBER"].items():
            vlan_brief[vlan_name] = {
                "interface_ipv4": [],
                "interface_ipv6": [],
                "members": list(members.keys())
            }
        for vlan_name, vlan_info in config["VLAN_INTERFACE"].items():
            if vlan_name not in vlan_brief:
                continue
            for prefix in vlan_info.keys():
                if '.' in prefix:
                    vlan_brief[vlan_name]["interface_ipv4"].append(prefix)
                elif ':' in prefix:
                    vlan_brief[vlan_name]["interface_ipv6"].append(prefix)
        return vlan_brief

    def get_interfaces_status(self):
        '''
        Get intnerfaces status by running 'show interfaces status' on the DUT, and parse the result into a dict.

        Example output:
            {
                "Ethernet0": {
                    "oper": "down",
                    "lanes": "25,26,27,28",
                    "fec": "N/A",
                    "asym pfc": "off",
                    "admin": "down",
                    "type": "N/A",
                    "vlan": "routed",
                    "mtu": "9100",
                    "alias": "fortyGigE0/0",
                    "interface": "Ethernet0",
                    "speed": "40G"
                },
                "PortChannel101": {
                    "oper": "up",
                    "lanes": "N/A",
                    "fec": "N/A",
                    "asym pfc": "N/A",
                    "admin": "up",
                    "type": "N/A",
                    "vlan": "routed",
                    "mtu": "9100",
                    "alias": "N/A",
                    "interface": "PortChannel101",
                    "speed": "40G"
                }
            }
        '''
        return {x.get('interface'): x for x in self.show_and_parse('show interfaces status')}

    def get_crm_facts(self):
        """Run various 'crm show' commands and parse their output to gather CRM facts

        Executed commands:
            crm show summary
            crm show thresholds
            crm show resources all

        Example output:
            {
                "acl_group": [
                    {
                        "resource name": "acl_group",
                        "bind point": "PORT",
                        "available count": "200",
                        "used count": "24",
                        "stage": "INGRESS"
                    },
                   ...
                ],
                "acl_table": [
                    {
                        "table id": "",
                        "resource name": "",
                        "used count": "",
                        "available count": ""
                    },
                    ...
                ],
                "thresholds": {
                        "ipv4_route": {
                            "high": 85,
                            "type": "percentage",
                            "low": 70
                        },
                    ...
                },
                "resources": {
                    "ipv4_route": {
                        "available": 100000,
                        "used": 16
                    },
                    ...
                },
                "polling_interval": 300
            }

        Returns:
            dict: Gathered CRM facts.
        """
        crm_facts = {}

        # Get polling interval
        output = self.command('crm show summary')['stdout']
        parsed = re.findall(r'Polling Interval: +(\d+) +second', output)
        if parsed:
            crm_facts['polling_interval'] = int(parsed[0])

        # Get thresholds
        crm_facts['thresholds'] = {}
        thresholds = self.show_and_parse('crm show thresholds all')
        for threshold in thresholds:
            crm_facts['thresholds'][threshold['resource name']] = {
                'high': int(threshold['high threshold']),
                'low': int(threshold['low threshold']),
                'type': threshold['threshold type']
            }

        def _show_and_parse_crm_resources():
            # Get output of all resources
            not_ready_prompt = "CRM counters are not ready"
            output = self.command('crm show resources all')['stdout_lines']
            in_section = False
            sections = defaultdict(list)
            section_id = 0
            for line in output:
                if not_ready_prompt in line:
                    return False
                if len(line.strip()) != 0:
                    if not in_section:
                        in_section = True
                        section_id += 1
                    sections[section_id].append(line)
                else:
                    in_section = False
                    continue
            # Output of 'crm show resources all' has 3 sections(4 on DPU platform).
            #   section 1: resources usage
            #   section 2: ACL group
            #   section 3: ACL table
            #   section 4: DASH(DPU) ACL rules
            if 1 in list(sections.keys()):
                crm_facts['resources'] = {}
                resources = self._parse_show(sections[1])
                for resource in resources:
                    crm_facts['resources'][resource['resource name']] = {
                        'used': int(resource['used count']),
                        'available': int(resource['available count'])
                    }

            if 2 in list(sections.keys()):
                crm_facts['acl_group'] = self._parse_show(sections[2])

            if 3 in list(sections.keys()):
                crm_facts['acl_table'] = self._parse_show(sections[3])

            if 4 in list(sections.keys()):
                crm_facts['dash_acl_group'] = self._parse_show(sections[4])
            return True
        # Retry until crm resources are ready
        timeout = crm_facts['polling_interval'] + 10
        while timeout >= 0:
            ret = _show_and_parse_crm_resources()
            if ret:
                break
            logging.warning("CRM counters are not ready yet, will retry after 10 seconds")
            time.sleep(10)
            timeout -= 10
        assert (timeout >= 0)

        return crm_facts

    def start_service(self, service_name, docker_name):
        logging.debug("Starting {}".format(service_name))
        if not self.is_service_fully_started(docker_name):
            self.command("sudo systemctl start {}".format(service_name))
            logging.debug("started {}".format(service_name))

    def stop_service(self, service_name, docker_name):
        logging.debug("Stopping {}".format(service_name))
        if self.is_service_fully_started(docker_name):
            self.command("sudo systemctl stop {}".format(service_name))
        logging.debug("Stopped {}".format(service_name))

    def restart_service(self, service_name, docker_name):
        logging.debug("Restarting {}".format(service_name))
        if self.is_service_fully_started(docker_name):
            self.command("sudo systemctl restart {}".format(service_name))
            logging.debug("Restarted {}".format(service_name))
        else:
            self.command("sudo systemctl start {}".format(service_name))
            logging.debug("started {}".format(service_name))

    def reset_service(self, service_name, docker_name):
        logging.debug("Stopping {}".format(service_name))
        self.command("sudo systemctl reset-failed {}".format(service_name))
        logging.debug("Resetting {}".format(service_name))

    def delete_container(self, service):
        self.command(
            "docker rm {}".format(service), module_ignore_errors=True
        )

    def start_bgpd(self):
        return self.command("sudo config feature state bgp enabled")

    def no_shutdown_bgp(self, asn):
        logging.warning("SONiC don't support `no shutdown bgp`")
        return None

    def no_shutdown_bgp_neighbors(self, asn, neighbors=[]):
        if not neighbors:
            return
        command = "vtysh -c 'config' -c 'router bgp {}'".format(asn)
        for nbr in neighbors:
            command += " -c 'no neighbor {} shutdown'".format(nbr)
        logging.info('No shut BGP neighbors: {}'.format(json.dumps(neighbors)))
        return self.command(command)

    def is_bgp_state_idle(self):
        """
        Check if all BGP peers are in IDLE state.

        Returns:
            True or False
        """
        bgp_summary = self.command("show ip bgp summary")["stdout_lines"]

        idle_count = 0
        expected_idle_count = 0
        bgp_monitor_count = 0
        for line in bgp_summary:
            if "Idle (Admin)" in line:
                idle_count += 1

            if "Total number of neighbors" in line:
                tokens = line.split()
                expected_idle_count = int(tokens[-1])

            if "BGPMonitor" in line:
                bgp_monitor_count += 1

        return idle_count == (expected_idle_count - bgp_monitor_count)

    def is_service_running(self, service_name, docker_name):
        """
        Check if service is running. Service can be a service within a docker

        Args:
            service name, docker name
        Returns:
            True or False
        """
        service_status = self.command(
            "docker exec {} supervisorctl status {}".format(
                docker_name, service_name
            ),
            module_ignore_errors=True
        )["stdout"]

        logging.info("service {}:{} status: {} ".format(
            docker_name, service_name, service_status)
        )

        return "RUNNING" in service_status

    def get_up_ip_ports(self):
        """
        Get a list for all up ip interfaces
        """
        up_ip_ports = []
        ip_intf_facts = self.show_ip_interface()['ansible_facts']['ip_interfaces']
        for intf in ip_intf_facts:
            try:
                if ip_intf_facts[intf]['oper_state'] == 'up':
                    up_ip_ports.append(intf)
            except KeyError:
                pass
        return up_ip_ports

    def get_supported_speeds(self, interface_name):
        """Get supported speeds for a given interface

        Args:
            interface_name (str): Interface name

        Returns:
            list: A list of supported speed strings or None
        """
        cmd = 'sonic-db-cli STATE_DB HGET \"PORT_TABLE|{}\" \"{}\"'.format(interface_name, 'supported_speeds')
        supported_speeds = self.shell(cmd)['stdout'].strip()
        return None if not supported_speeds else supported_speeds.split(',')

    def set_auto_negotiation_mode(self, interface_name, mode):
        """Set auto negotiation mode for a given interface

        Args:
            interface_name (str): Interface name
            mode (boolean): True to enable auto negotiation else disable

        Returns:
            boolean: False if the operation is not supported else True
        """
        cmd = 'config interface autoneg {} {}'.format(interface_name, 'enabled' if mode else 'disabled')
        self.shell(cmd)
        return True

    def get_auto_negotiation_mode(self, interface_name):
        """Get auto negotiation mode for a given interface

        Args:
            interface_name (str): Interface name

        Returns:
            boolean: True if auto negotiation mode is enabled else False. Return None if
            the auto negotiation mode is unknown or unsupported.
        """
        cmd = 'sonic-db-cli APPL_DB HGET \"PORT_TABLE:{}\" \"{}\"'.format(interface_name, 'autoneg')
        try:
            mode = self.shell(cmd)['stdout'].strip()
        except RunAnsibleModuleFail:
            return None
        if not mode:
            return None
        return True if mode == 'on' else False

    def set_speed(self, interface_name, speed):
        """Set interface speed according to the auto negotiation mode. When auto negotiation mode
        is enabled, set the advertised speeds; otherwise, set the force speed.

        Args:
            interface_name (str): Interface name
            speed (str): SONiC style interface speed. E.g, 1G=1000, 10G=10000, 100G=100000. If the speed
            is None and auto negotiation mode is enabled, it sets the advertised speeds to all supported
            speeds.

        Returns:
            boolean: True if success. Usually, the method return False only if the operation
            is not supported or failed.
        """
        auto_neg_mode = self.get_auto_negotiation_mode(interface_name)
        if not auto_neg_mode:
            cmd = 'config interface speed {} {}'.format(interface_name, speed)
        else:
            cmd = 'config interface advertised-speeds {} {}'.format(interface_name, speed)
        self.shell(cmd)
        return True

    def get_speed(self, interface_name):
        """Get interface speed

        Args:
            interface_name (str): Interface name

        Returns:
            str: SONiC style interface speed value. E.g, 1G=1000, 10G=10000, 100G=100000.
        """
        cmd = 'sonic-db-cli APPL_DB HGET \"PORT_TABLE:{}\" \"{}\"'.format(interface_name, 'speed')
        speed = self.shell(cmd)['stdout'].strip()
        return speed

    def get_rsyslog_ipv4(self):
        if not self.is_multi_asic:
            return "127.0.0.1"
        ip_ifs = self.show_ip_interface()["ansible_facts"]
        ns_docker_if_ipv4 = ip_ifs["ip_interfaces"]["docker0"]["ipv4"]
        try:
            socket.inet_aton(ns_docker_if_ipv4)
        except socket.error:
            raise Exception("Invalid V4 address {}".format(ns_docker_if_ipv4))
        return ns_docker_if_ipv4

    def ping_v4(self, ipv4, count=1, ns_arg=""):
        """
        Returns 'True' if ping to IP address works, else 'False'
        Args:
            IPv4 address

        Returns:
            True or False
        """
        try:
            socket.inet_aton(ipv4)
        except socket.error:
            raise Exception("Invalid IPv4 address {}".format(ipv4))

        netns_arg = ""
        if ns_arg is not DEFAULT_NAMESPACE:
            netns_arg = "sudo ip netns exec {} ".format(ns_arg)

        try:
            self.shell("{}ping -q -c{} {} > /dev/null".format(
                netns_arg, count, ipv4
            ))
        except RunAnsibleModuleFail:
            return False
        return True

    def is_backend_portchannel(self, port_channel, mg_facts):
        ports = mg_facts["minigraph_portchannels"].get(port_channel)
        # minigraph facts does not have backend portchannel IFs
        if ports is None:
            return True
        return False if "Ethernet-BP" not in ports["members"][0] else True

    def is_backend_port(self, port, mg_facts):
        return True if "Ethernet-BP" in port else False

    def active_ip_interfaces(self, ip_ifs, tbinfo, ns_arg=DEFAULT_NAMESPACE, intf_num="all"):
        """
        Return a dict of active IP (Ethernet or PortChannel) interfaces, with
        interface and peer IPv4 address.

        Returns:
            Dict of Interfaces and their IPv4 address
        """
        active_ip_intf_cnt = 0
        mg_facts = self.get_extended_minigraph_facts(tbinfo, ns_arg)
        ip_ifaces = {}
        for k, v in list(ip_ifs.items()):
            if ((k.startswith("Ethernet") and not is_inband_port(k)) or
               (k.startswith("PortChannel") and not
               self.is_backend_portchannel(k, mg_facts))):
                # Ping for some time to get ARP Re-learnt.
                # We might have to tune it further if needed.
                if (v["admin"] == "up" and v["oper_state"] == "up" and
                   self.ping_v4(v["peer_ipv4"], count=3, ns_arg=ns_arg)):
                    ip_ifaces[k] = {
                        "ipv4": v["ipv4"],
                        "peer_ipv4": v["peer_ipv4"],
                        "bgp_neighbor": v["bgp_neighbor"]
                    }
                    active_ip_intf_cnt += 1

                if isinstance(intf_num, int) and intf_num > 0 and active_ip_intf_cnt == intf_num:
                    break

        return ip_ifaces

    def show_syslog(self):
        """
        Show syslog config

        Args:
            dut (SonicHost): The target device
        Return: Syslog config like below
            [{
                "server": "2.2.2.2",
                "source": "1.1.1.1",
                "port": "514",
                "vrf": "default",
              },
              {
                "server": "3.3.3.3",
                "source": "4.4.4.4",
                "port": "514",
                "vrf": "mgmt",
              },
              ...
            ]
        """
        return self.show_and_parse('show syslog')

    def clear_acl_counters(self):
        """
        Clear ACL counters statistics.
        """
        self.command('aclshow -c')

    def get_acl_counter(self, acl_table_name, acl_rule_name,
                        timeout=ACL_COUNTERS_UPDATE_INTERVAL_IN_SEC * 2,
                        interval=ACL_COUNTERS_UPDATE_INTERVAL_IN_SEC):
        """
        Read ACL counter of specific ACL table and ACL rule.

        Args:
            acl_table_name (str): Name of ACL table.
            acl_rule_name (str): Name of ACL rule.
            timeout (int): Maximum time (in second) wait for ACL counter available.
            interval (int): Retry interval (in second) between read ACL counter.

        Return:
            packets_count (int): count of packets hit the specific ACL rule.
        """
        assert timeout >= 0 and interval > 0  # Validate arguments to avoid infinite loop
        while timeout >= 0:
            time.sleep(interval)  # Wait for orchagent to update the ACL counters
            timeout -= interval
            result = self.show_and_parse('aclshow -a')
            for rule in result:
                if acl_table_name == rule['table name'] and acl_rule_name == rule['rule name']:
                    try:
                        packets_count = int(rule['packets count'])
                        return packets_count
                    except ValueError:
                        if rule['packets count'] == 'N/A':
                            logging.warning("ACL counters are not ready yet, will retry after {} seconds"
                                            .format(interval))
                        else:
                            raise ValueError('Got invalid packets count "{}" for {}|{}'
                                             .format(acl_table_name, acl_rule_name, rule['packets count']))
        raise Exception("Failed to read acl counter for {}|{}".format(acl_table_name, acl_rule_name))

    def get_port_counters(self, in_json=True):
        cli = "portstat"
        if in_json:
            cli += " -j"
        res = self.shell(cli)['stdout']
        return re.sub(r"Last cached time was.*\d+\n", "", res)

    def add_acl_table(self, table_name, table_type, acl_stage=None, bind_ports=None, description=None):
        """
        Add ACL table via 'config acl add table' command.
        Command sample:
            config acl add table TEST_TABLE L3 -s ingress -p Ethernet0,Ethernet4 -d "Test ACL table"

        Args:
            table_name: name of new acl table
            table_type: type of the acl table
            acl_stage: acl stage, ingress or egress
            bind_ports: ports bind to the acl table
            description: description of the acl table
        """
        cmd = "config acl add table {} {}".format(table_name, table_type)

        if acl_stage:
            cmd += " -s {}".format(acl_stage)

        if bind_ports:
            if isinstance(bind_ports, list):
                bind_ports = ",".join(bind_ports)
            cmd += " -p {}".format(bind_ports)

        if description:
            cmd += " -d {}".format(description)

        self.command(cmd)

    def remove_acl_table(self, acl_table):
        """
        Remove acl table

        Args:
            acl_table: name of acl table to be removed
        """
        self.command("config acl remove table {}".format(acl_table))

    def del_member_from_vlan(self, vlan_id, member_name):
        """
        Del vlan member

        Args:
            vlan_id: id of vlan
            member_name: interface deled from vlan
        """
        self.command("config vlan member del {} {}".format(vlan_id, member_name))

    def add_member_to_vlan(self, vlan_id, member_name, is_tagged=True):
        """
        Add vlan member

        Args:
            vlan_id: id of vlan
            member_name: interface added to vlan
            is_tagged: True - add tagged member. False - add untagged member.
        """
        self.command("config vlan member add {} {} {}".format("" if is_tagged else "-u", vlan_id, member_name))

    def remove_ip_from_port(self, port, ip=None):
        """
        Remove ip addresses from port. If get ip from running config successfully, ignore arg ip provided

        Args:
            port: port name
            ip: IP address
        """
        ip_addresses = self.config_facts(host=self.hostname,
                                         source="running")["ansible_facts"].get("INTERFACE", {}).get(port, {})
        if ip_addresses:
            for ip in ip_addresses:
                self.command("config interface ip remove {} {}".format(port, ip))
        elif ip:
            self.command("config interface ip remove {} {}".format(port, ip))

    def remove_ip_addr_from_port(self, port, ip):
        """
        Remove ip addr from the port.
        :param port: port name
        :param ip: IP address
        """
        self.command("config interface ip remove {} {}".format(port, ip))

    def add_ip_addr_to_port(self, port, ip, gwaddr):
        """
        Add ip addr on the port.
        :param port: port name
        :param ip: IP address
        """
        self.command("config interface ip add {} {} {}".format(port, ip, gwaddr))

    def remove_ip_addr_from_vlan(self, vlan, ip):
        """
        Remove ip addr from the vlan.
        :param vlan: vlan name
        :param ip: IP address

        Example:
            config interface ip remove Vlan1000 192.168.0.0/24
        """
        self.command("config interface ip remove {} {}".format(vlan, ip))

    def add_ip_addr_to_vlan(self, vlan, ip):
        """
        Add ip addr to the vlan.
        :param vlan: vlan name
        :param ip: IP address

        Example:
            config interface ip add Vlan1000 192.168.0.0/24
        """
        self.command("config interface ip add {} {}".format(vlan, ip))

    def remove_vlan(self, vlan_id):
        """
        Remove vlan
        """
        self.command("config vlan del {}".format(vlan_id))

    def get_port_channel_status(self, port_channel_name):
        """
        Collect port channel information by command docker teamdctl

        Args:
            port_channel_name: name of port channel

        Returns:
            port channel status, key information example:
            {
                "ports": {
                    "Ethernet28": {
                        "runner": {
                            "selected": True,
                            "state": "current"
                        },
                        "link": {
                            "duplex": "full",
                            "speed": 10,
                            "up": True
                        }
                    }
                }
            }
        """
        commond_output = self.command("docker exec -i teamd teamdctl {} state dump".format(port_channel_name))
        json_info = json.loads(commond_output["stdout"])
        return json_info

    def links_status_down(self, ports):
        show_int_result = self.command("show interface status")
        for output_line in show_int_result['stdout_lines']:
            output_port = output_line.strip().split(' ')[0]
            # Only care about port that connect to current DUT
            if output_port in ports:
                # Either oper or admin status 'down' means link down
                # for SONiC OS, oper/admin status could only be up/down, so only 2 conditions here
                if 'down' in output_line:
                    logging.info("Interface {} is down on {}".format(output_port, self.hostname))
                    continue
                else:
                    logging.info("Interface {} is up on {}".format(output_port, self.hostname))
                    return False
        return True

    def links_status_up(self, ports):
        show_int_result = self.command("show interface status")
        for output_line in show_int_result['stdout_lines']:
            output_port = output_line.strip().split(' ')[0]
            # Only care about port that connect to current DUT
            if output_port in ports:
                # Either oper or admin status 'down' means link down
                if 'down' in output_line:
                    logging.info("Interface {} is down on {}".format(output_port, self.hostname))
                    return False
                logging.info("Interface {} is up on {}".format(output_port, self.hostname))
        return True

    def get_port_fec(self, portname):
        out = self.shell('redis-cli -n 4 HGET "PORT|{}" "fec"'.format(portname))
        assert_exit_non_zero(out)
        if out["stdout_lines"]:
            return out["stdout_lines"][0]
        else:
            return None

    def set_port_fec(self, portname, state):
        if not state:
            state = 'none'
        res = self.shell('sudo config interface fec {} {}'.format(portname, state))
        return res['rc'] == 0

    def count_portlanes(self, portname):
        out = self.shell('redis-cli -n 4 HGET "PORT|{}" "lanes"'.format(portname))
        assert_exit_non_zero(out)
        lanes = out["stdout_lines"][0].split(',')
        return len(lanes)

    def get_sfp_type(self, portname):
        out = self.shell('redis-cli -n 6 HGET "TRANSCEIVER_INFO|{}" "type"'.format(portname))
        assert_exit_non_zero(out)
        sfp_type = re.search(r'[QO]?SFP-?[\d\w]{0,3}', out["stdout_lines"][0]).group()
        return sfp_type

    def get_switch_hash_capabilities(self):
        out = self.shell('show switch-hash capabilities --json')
        assert_exit_non_zero(out)
        return SonicHost._parse_hash_fields(out)

    def get_switch_hash_configurations(self):
        out = self.shell('show switch-hash global  --json')
        assert_exit_non_zero(out)
        return SonicHost._parse_hash_fields(out)

    def set_switch_hash_global(self, hash_type, fields, validate=True):
        cmd = 'config switch-hash global {}-hash'.format(hash_type)
        for field in fields:
            cmd += ' ' + field
        out = self.shell(cmd, module_ignore_errors=True)
        if validate:
            assert_exit_non_zero(out)
        return out

    def set_switch_hash_global_algorithm(self, hash_type, algorithm, validate=True):
        cmd = 'config switch-hash global {}-hash-algorithm {}'.format(hash_type, algorithm)
        out = self.shell(cmd, module_ignore_errors=True)
        if validate:
            assert_exit_non_zero(out)
        return out

    @staticmethod
    def _parse_hash_fields(cli_output):
        ecmp_hash_fields = []
        lag_hash_fields = []
        ecmp_hash_algorithm = lag_hash_algorithm = ''
        if "No configuration is present in CONFIG DB" in cli_output['stdout']:
            logger.info("No configuration is present in CONFIG DB")
        else:
            out_json = json.loads(cli_output['stdout'])
            ecmp_hash_fields = out_json["ecmp"]["hash_field"]
            lag_hash_fields = out_json["lag"]["hash_field"]
            ecmp_hash_algorithm = out_json["ecmp"]["algorithm"]
            lag_hash_algorithm = out_json["lag"]["algorithm"]
        return {'ecmp': ecmp_hash_fields,
                'lag': lag_hash_fields,
                'ecmp_algo': ecmp_hash_algorithm,
                'lag_algo': lag_hash_algorithm}

    def get_counter_poll_status(self):
        result_dict = {}
        output = self.shell("counterpoll show")["stdout_lines"][2::]
        for line in output:
            counter_type, interval, status = re.split(r'\s\s+', line)
            interval = int(re.search(r'\d+', interval).group(0))
            result_dict[counter_type] = {}
            result_dict[counter_type]['interval'] = interval
            result_dict[counter_type]['status'] = status
        return result_dict


def assert_exit_non_zero(shell_output):
    if shell_output['rc'] != 0:
        raise Exception(shell_output['stderr'])
