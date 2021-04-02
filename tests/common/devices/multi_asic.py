import copy
import ipaddress
import json
import logging

from tests.common.devices.sonic import SonicHost
from tests.common.devices.sonic_asic import SonicAsic
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_ASIC_ID, DEFAULT_NAMESPACE

logger = logging.getLogger(__name__)


class MultiAsicSonicHost(object):
    """ This class represents a Multi-asic SonicHost It has two attributes:
    sonic_host: a SonicHost instance. This object is for interacting with the SONiC host through pytest_ansible.
    asics: a list of SonicAsic instances.

    The 'duthost' fixture will return an instance of a MultiAsicSonicHost.
    So, even a single asic pizza box is represented as a MultiAsicSonicHost with 1 SonicAsic.
    """

    _DEFAULT_SERVICES = ["pmon", "snmp", "lldp", "database"]

    def __init__(self, ansible_adhoc, hostname):
        """ Initializing a MultiAsicSonicHost.

        Args:
            ansible_adhoc : The pytest-ansible fixture
            hostname: Name of the host in the ansible inventory
        """
        self.sonichost = SonicHost(ansible_adhoc, hostname)
        self.asics = [SonicAsic(self.sonichost, asic_index) for asic_index in range(self.sonichost.facts["num_asic"])]

        # Get the frontend and backend asics in a multiAsic device.
        self.frontend_asics = []
        self.backend_asics = []
        if self.sonichost.is_multi_asic:
            for asic in self.asics:
                if asic.is_it_frontend():
                    self.frontend_asics.append(asic)
                elif asic.is_it_backend():
                    self.backend_asics.append(asic)

        self.critical_services_tracking_list()

    def __repr__(self):
        return '<MultiAsicSonicHost> {}'.format(self.hostname)

    def critical_services_tracking_list(self):
        """Get the list of services running on the DUT
           The services on the sonic devices are:
              - services running on the host
              - services which are replicated per asic
            Returns:
            [list]: list of the services running the device
        """
        service_list = []
        service_list+= self._DEFAULT_SERVICES
        for asic in self.asics:
            service_list += asic.get_critical_services()
        self.sonichost.reset_critical_services_tracking_list(service_list)

    def get_default_critical_services_list(self):
        return self._DEFAULT_SERVICES

    def _run_on_asics(self, *module_args, **complex_args):
        """ Run an asible module on asics based on 'asic_index' keyword in complex_args

        Args:
            module_args: other ansible module args passed from the caller
            complex_args: other ansible keyword args

        Raises:
            ValueError:  if asic_index is specified and it is neither an int or string 'all'.
            ValueError: if asic_index is specified and is an int, but greater than number of asics in the SonicHost

        Returns:
            if asic_index is not specified, then we return the output of the ansible module on global namespace (using SonicHost)
            else
                if asic_index is an int, the output of the ansible module on that asic namespace
                    - for single asic SonicHost this would still be the same as the ansible module on the global namespace
                else if asic_index is string 'all', then a list of ansible module output for all the asics on the SonicHost
                    - for single asic, this would be a list of size 1.
        """
        if "asic_index" not in complex_args:
            # Default ASIC/namespace
            return getattr(self.sonichost, self.multi_asic_attr)(*module_args, **complex_args)
        else:
            asic_complex_args = copy.deepcopy(complex_args)
            asic_index = asic_complex_args.pop("asic_index")
            if type(asic_index) == int:
                # Specific ASIC/namespace
                if self.sonichost.facts['num_asic'] == 1:
                    if asic_index != 0:
                        raise ValueError("Trying to run module '{}' against asic_index '{}' on a single asic dut '{}'".format(self.multi_asic_attr, asic_index, self.sonichost.hostname))
                return getattr(self.asics[asic_index], self.multi_asic_attr)(*module_args, **asic_complex_args)
            elif type(asic_index) == str and asic_index.lower() == "all":
                # All ASICs/namespace
                return [getattr(asic, self.multi_asic_attr)(*module_args, **asic_complex_args) for asic in self.asics]
            else:
                raise ValueError("Argument 'asic_index' must be an int or string 'all'.")

    def get_frontend_asic_ids(self):
        if self.sonichost.facts['num_asic'] == 1:
            return [DEFAULT_ASIC_ID]

        return [asic.asic_index for asic in self.frontend_asics]

    def get_frontend_asic_namespace_list(self):
        if self.sonichost.facts['num_asic'] == 1:
            return [DEFAULT_NAMESPACE]

        return [asic.namespace for asic in self.frontend_asics]

    def get_sonic_host_and_frontend_asic_instance(self):
        if self.sonichost.facts['num_asic'] == 1:
            return [self.sonichost]

        return [self.sonichost] + [asic for asic in self.frontend_asics]

    def get_backend_asic_ids(self):
        if self.sonichost.facts['num_asic'] == 1:
            return [DEFAULT_ASIC_ID]

        return [asic.asic_index for asic in self.backend_asics]

    def get_backend_asic_namespace_list(self):
        if self.sonichost.facts['num_asic'] == 1:
            return [DEFAULT_NAMESPACE]

        return [asic.namespace for asic in self.backend_asics]

    def asic_instance(self, asic_index):
        if asic_index is None:
            return self.asics[0]
        return self.asics[asic_index]

    def asic_instance_from_namespace(self, namespace=DEFAULT_NAMESPACE):
        if not namespace:
            return self.asics[0]

        for asic in self.asics:
            if asic.namespace == namespace:
                return asic
        return None

    def get_asic_ids(self):
        if self.sonichost.facts['num_asic'] == 1:
            return [DEFAULT_ASIC_ID]

        return [asic.asic_index for asic in self.asics]

    def get_asic_namespace_list(self):
        if self.sonichost.facts['num_asic'] == 1:
            return [DEFAULT_NAMESPACE]

        return [asic.namespace for asic in self.asics]

    def get_asic_id_from_namespace(self, namespace):
        if self.sonichost.facts['num_asic'] == 1 or namespace == DEFAULT_NAMESPACE:
            return DEFAULT_ASIC_ID

        for asic in self.asics:
            if namespace == asic.namespace:
                return asic.asic_index

        # Raise an error if we reach here
        raise ValueError("Invalid namespace '{}' passed as input".format(namespace))

    def get_namespace_from_asic_id(self, asic_id):
        if self.sonichost.facts['num_asic'] == 1 or asic_id == DEFAULT_ASIC_ID:
            return DEFAULT_NAMESPACE

        for asic in self.asics:
            if asic_id == asic.asic_index:
                return asic.namespace

        # Raise an error if we reach here
        raise ValueError("Invalid asic_id '{}' passed as input".format(asic_id))

    def get_vtysh_cmd_for_namespace(self, cmd, namespace):
        asic_id = self.get_asic_id_from_namespace(namespace)
        if asic_id == DEFAULT_ASIC_ID:
            return cmd
        ns_cmd = cmd.replace('vtysh', 'vtysh -n {}'.format(asic_id))
        return ns_cmd
    
    def get_linux_ip_cmd_for_namespace(self, cmd, namespace):
        if not namespace:
            return cmd
        ns_cmd = cmd.replace('ip', 'ip -n {}'.format(namespace))
        return ns_cmd

    def get_route(self, prefix, namespace=DEFAULT_NAMESPACE):
        asic_id = self.get_asic_id_from_namespace(namespace)
        if asic_id == DEFAULT_ASIC_ID:
           ns_prefix = ''
        else:
           ns_prefix = '-n ' + str(asic_id)
        cmd = 'show bgp ipv4' if ipaddress.ip_network(unicode(prefix)).version == 4 else 'show bgp ipv6'
        return json.loads(self.shell('vtysh {} -c "{} {} json"'.format(ns_prefix, cmd, prefix))['stdout'])

    def __getattr__(self, attr):
        """ To support calling an ansible module on a MultiAsicSonicHost.

        Args:
            attr: attribute to get

        Returns:
            if attr doesn't start with '_' and is a method of SonicAsic, attr will be ansible module that has dependency on ASIC,
                return the output of the ansible module on asics requested - using _run_on_asics method.
            else
                return the attribute from SonicHost.
        """
        sonic_asic_attr = getattr(SonicAsic, attr, None)
        if not attr.startswith("_") and sonic_asic_attr and callable(sonic_asic_attr):
            self.multi_asic_attr = attr
            return self._run_on_asics
        else:
            return getattr(self.sonichost, attr)  # For backward compatibility

    def get_asic_or_sonic_host(self, asic_id):
        if asic_id == DEFAULT_ASIC_ID:
            return self.sonichost
        return self.asics[asic_id]

    def stop_service(self, service):
        if service in self._DEFAULT_SERVICES:
            return self.sonichost.stop_service(service, service)

        for asic in self.asics:
            asic.stop_service(service)

    def delete_container(self, service):
        if service in self._DEFAULT_SERVICES:
            return self.sonichost.delete_container(service)

        for asic in self.asics:
            asic.delete_container(service)

    def is_container_running(self, service):
        if service in self._DEFAULT_SERVICES:
            return self.sonichost.is_container_running(service)

        for asic in self.asics:
            if asic.is_container_running(service):
                return True

        return False

    def is_bgp_state_idle(self):
        return self.sonichost.is_bgp_state_idle()

    def is_service_running(self, service_name, docker_name=None):
        docker_name = service_name if docker_name is None else docker_name

        if docker_name in self._DEFAULT_SERVICES:
            return self.sonichost.is_service_running(service_name, docker_name)

        for asic in self.asics:
            if not asic.is_service_running(service_name, docker_name):
                return False

        return True

    def get_port_asic_instance(self, port):
        """
        Returns the ASIC instance to which the port belongs
        Args:
            port: Port ID

        Returns:
            returns the ASIC instance if found, else None
        """
        for asic in self.asics:
            if asic.port_exists(port):
                return asic

        pytest_assert(
            False,
            "ASIC instance not found for port {}".format(port)
        )

    def get_queue_oid_asic_instance(self, queue_oid):
        """
        Returns the ASIC instance which has the queue OID saved.
        Queue OIDs are saved only when requested for a given port and queue.

        Args:
            queue_oid: Queue OID

        Returns:
            returns the ASIC instance if found, else None
        """
        asic = None
        for asic in self.asics:
            if queue_oid in asic.queue_oid:
                return asic

        pytest_assert(
            False,
            "ASIC instance not found for queue OID {}".format(queue_oid)
        )

    def get_queue_oid(self, port, queue_num):
        """
        Get the queue OID of given port and queue number. The queue OID is
        saved for the purpose of returning the ASIC instance of the
        queue OID

        Args:
            port: Port ID
            queue_num: Queue
        Returns:
            Queue OID
        """
        asic = self.get_port_asic_instance(port)
        return asic.get_queue_oid(port, queue_num)
