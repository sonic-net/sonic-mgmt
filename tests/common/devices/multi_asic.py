import copy
import ipaddress
import json
import logging

from tests.common.errors import RunAnsibleModuleFail
from tests.common.devices.sonic import SonicHost
from tests.common.devices.sonic_asic import SonicAsic
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_ASIC_ID, DEFAULT_NAMESPACE, ASICS_PRESENT

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
        self.asics = [SonicAsic(self.sonichost, asic_index) for asic_index in self.sonichost.facts[ASICS_PRESENT]]

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

    def __str__(self):
        return '<MultiAsicSonicHost {}>'.format(self.hostname)

    def __repr__(self):
        return self.__str__()

    def critical_services_tracking_list(self):
        """Get the list of services running on the DUT
           The services on the sonic devices are:
              - services running on the host
              - services which are replicated per asic
            Returns:
            [list]: list of the services running the device
        """
        service_list = []
        active_asics = self.asics
        if self.sonichost.is_supervisor_node() and self.get_facts()['asic_type'] != 'vs':
            active_asics = []
            sonic_db_cli_out = self.command("sonic-db-cli CHASSIS_STATE_DB keys \"CHASSIS_ASIC_TABLE|asic*\"")
            for a_asic_line in sonic_db_cli_out["stdout_lines"]:
                a_asic_name = a_asic_line.split("|")[1]
                a_asic_instance = self.asic_instance_from_namespace(namespace=a_asic_name)
                active_asics.append(a_asic_instance)
        service_list += self._DEFAULT_SERVICES
        for asic in active_asics:
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
                return getattr(self.asic_instance(asic_index), self.multi_asic_attr)(*module_args, **asic_complex_args)
            elif type(asic_index) == str and asic_index.lower() == "all":
                # All ASICs/namespace
                return [getattr(asic, self.multi_asic_attr)(*module_args, **asic_complex_args) for asic in self.asics]
            else:
                raise ValueError("Argument 'asic_index' must be an int or string 'all'.")

    def get_dut_iface_mac(self, iface_name):
        """
        Gets the MAC address of specified interface.

        Returns:
            str: The MAC address of the specified interface, or None if it is not found.
        """
        try:
            if self.sonichost.facts['num_asic'] == 1:
                cmd_prefix = " "
            else:
                asic = self.get_port_asic_instance(iface_name)
                cmd_prefix = "sudo ip netns exec {} ".format(asic.namespace)
 
            mac = self.command('{} cat /sys/class/net/{}/address'.format(cmd_prefix, iface_name))['stdout']
            return mac
        except Exception as e:
            logger.error('Failed to get MAC address for interface "{}", exception: {}'.format(iface_name, repr(e)))
            return None

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

    def asic_instance(self, asic_index=None):
        if asic_index is None:
            return self.asics[0]
        # if asics_present is defined in the host_vars of the host (in the inventory), then
        # self.asics is populated based on asics_present (PR# 5828). In this case, self.asics is a list of only
        # asics present, and not all possible asics. Thus, need to find asic with the right asic_index.
        for a_asic in self.asics:
            if a_asic.asic_index == asic_index:
                return a_asic
        return None

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

    @property
    def ttl_decr_value(self):
        """
        Decrement in TTL value for L3 forwarding. On Multi ASIC TTL value
        decreases by 3 when forwarding across tiers (e.g. T0 to T2).
        """
        if not self.sonichost.is_multi_asic:
            return 1
        return 3

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

    def get_asic_or_sonic_host_from_namespace(self, namespace=DEFAULT_NAMESPACE):
        if not namespace:
            return self.sonichost
        for asic in self.asics:
            if asic.namespace == namespace:
                return asic
        return None

    def start_service(self, service):
        if service in self._DEFAULT_SERVICES:
            return self.sonichost.start_service(service, service)

        for asic in self.asics:
            asic.start_service(service)

    def stop_service(self, service):
        if service in self._DEFAULT_SERVICES:
            return self.sonichost.stop_service(service, service)

        for asic in self.asics:
            asic.stop_service(service)
            
    def reset_service(self, service):
        if service in self._DEFAULT_SERVICES:
            return self.sonichost.reset_service(service, service)

        for asic in self.asics:
            asic.reset_service(service)
        
    def restart_service(self, service):
        if service in self._DEFAULT_SERVICES:
            return self.sonichost.restart_service(service, service)

        for asic in self.asics:
            asic.restart_service(service)

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

    def get_asic_index_for_portchannel(self, portchannel):
        for asic in self.asics:
            if asic.portchannel_on_asic(portchannel):
                return asic.asic_index
        return None

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

    def has_config_subcommand(self, command):
        """
        Check if a config/show subcommand exists on the device

        It is up to the caller of the function to ensure that `command`
        does not have any unintended side effects when run

        Args:
            command (str): the command to be checked, which should begin with 'config' or 'show'
        Returns:
            (bool) True if the command exists, false otherwise
        """
        try:
            self.shell(command)
            # If the command executes successfully, we can assume it exists
            return True
        except RunAnsibleModuleFail as e:
            # If 'No such command' is found in stderr, the command doesn't exist
            return 'No such command' not in e.results['stderr']

    def modify_syslog_rate_limit(self, feature, rl_option='disable'):
        """
        Disable Rate limit for a given service
        """
        services = [feature]

        if (feature in self.sonichost.DEFAULT_ASIC_SERVICES):
            services = []
            for asic in self.asics:
                service_name = asic.get_docker_name(feature)
                if service_name in self.sonichost.critical_services:
                    services.append(service_name)

        for docker in services:
            #TODO: https://github.com/Azure/sonic-mgmt/issues/5970
            if self.sonichost.is_multi_asic and docker == "gbsyncd":
                continue
            cmd_disable_rate_limit = (
                r"docker exec -i {} sed -i "
                r"'s/^\$SystemLogRateLimit/#\$SystemLogRateLimit/g' "
                r"/etc/rsyslog.conf"
            )
            cmd_enable_rate_limit = (
                r"docker exec -i {} sed -i "
                r"'s/^#\$SystemLogRateLimit/\$SystemLogRateLimit/g' "
                r"/etc/rsyslog.conf"
            )
            cmd_reload = r"docker exec -i {} supervisorctl restart rsyslogd"
            cmds = []

            if rl_option == 'disable':
                cmds.append(cmd_disable_rate_limit.format(docker))
            else:
                cmds.append(cmd_enable_rate_limit.format(docker))
            cmds.append(cmd_reload.format(docker))
            self.sonichost.shell_cmds(cmds=cmds)

    def get_bgp_neighbors(self):
        """
        Get a diction of BGP neighbor states

        Args: None

        Returns: dictionary { (neighbor_ip : info_dict)* }

        """
        bgp_neigh = {}
        for asic in self.asics:
            bgp_info = asic.bgp_facts()
            bgp_neigh.update(bgp_info["ansible_facts"]["bgp_neighbors"])

        return bgp_neigh

    def get_bgp_neighbors_per_asic(self, state="established"):
        """
        Get a diction of BGP neighbor states

        Args: 
        state: BGP session state, return neighbor IP of sessions that match this state
        Returns: dictionary {namespace: { (neighbor_ip : info_dict)* }}

        """
        bgp_neigh = {}
        for asic in self.asics:
            bgp_neigh[asic.namespace] = {}
            bgp_info = asic.bgp_facts()["ansible_facts"]["bgp_neighbors"]
            for k, v in bgp_info.items():
                if v["state"] != state:
                    bgp_info.pop(k)                    
            bgp_neigh[asic.namespace].update(bgp_info)

        return bgp_neigh

    def check_bgp_session_state(self, neigh_ips, state="established"):
        """
        @summary: check if current bgp session equals to the target state

        @param neigh_ips: bgp neighbor IPs
        @param state: target state
        """
        neigh_ips = [ip.lower() for ip in neigh_ips]
        neigh_ok = []

        for asic in self.asics:
            bgp_facts = asic.bgp_facts()['ansible_facts']
            for k, v in bgp_facts['bgp_neighbors'].items():
                if v['state'] == state:
                    if k.lower() in neigh_ips:
                        neigh_ok.append(k)
            logging.info("bgp neighbors that match the state: {}".format(neigh_ok))

        if len(neigh_ips) == len(neigh_ok):
            return True

        return False

    def check_bgp_session_state_all_asics(self, bgp_neighbors, state="established"):
        """
        @summary: check if current bgp session equals to the target state in each namespace

        @param bgp_neighbors: dictionary {namespace: { (neighbor_ip : info_dict)* }} 
        @param state: target state
        """
        for asic in self.asics:
            if asic.namespace in bgp_neighbors:
                neigh_ips = [ k.lower() for k, v in bgp_neighbors[asic.namespace].items() if v["state"] == state ]
                if not asic.check_bgp_session_state(neigh_ips, state):
                    return False
        return True

    def get_bgp_route(self, *args, **kwargs):
        """
            @summary: return BGP routes information from BGP docker. On
                      single ASIC platform ansible module is called directly.
                      On multi ASIC platform one of the frontend ASIC is
                      used unless a neighbor is provided, in which case it
                      fetches from the ASIC where neighbor is present
        """
        if not self.sonichost.is_multi_asic:
            return self.bgp_route(*args, **kwargs)

        asic_index = self.frontend_asics[0].asic_index

        if kwargs.get('neighbor') is not None:
            #find out which ASIC has the neighbor
            for asic in self.frontend_asics:
                bgp_facts = asic.bgp_facts()['ansible_facts']
                if kwargs.get('neighbor') in bgp_facts['bgp_neighbors']:
                    asic_index = asic.asic_index
                    break

        # return from one of the frontend asics or the one where
        # the given neighbor exists
        kwargs['namespace_id'] = asic_index
        return self.bgp_route(*args, **kwargs)

    def get_bgp_route_info(self, prefix, ns=None):
        """
        @summary: return BGP routes information.

        @param prefix: IP prefix
        @param ns: network namespace
        """
        prefix = ipaddress.ip_network(unicode(str(prefix)))
        if isinstance(prefix, ipaddress.IPv4Network):
            check_cmd = "vtysh -c 'show bgp ipv4 %s json'"
        else:
            check_cmd = "vtysh -c 'show bgp ipv6 %s json'"
        check_cmd %= prefix
        if ns is not None:
            check_cmd = self.get_vtysh_cmd_for_namespace(check_cmd, ns)
        return json.loads(self.shell(check_cmd, verbose=False)['stdout'])


    def check_bgp_default_route(self, ipv4=True,  ipv6=True):
        """
        @summary: check if bgp default route is present.

        @param ipv4: check ipv4 default
        @param ipv6: check ipv6 default
        """
        if ipv4 and len(self.get_bgp_route_info("0.0.0.0/0")) == 0:
            return False
        if ipv6 and len(self.get_bgp_route_info("::/0")) == 0:
            return False
        return True

    def update_ip_route(self, ip, nexthop, op="", namespace=DEFAULT_NAMESPACE):
        """
        Update route to add/remove for a given IP <ip> with nexthop IP address

         Args:
            duthost(Ansible Fixture): instance of SonicHost class of DUT
            ip(str): IP to add/remove route for
            nexthp(str): Nexthop IP
            op(str): operation add/remove to be performed, default add
            namespace: ASIC namespace

        Returns:
            None
        """
        logger.info("{0} route to '{1}' via '{2}'".format(
            "Deleting" if "no" == op else "Adding", ip, nexthop
        ))

        vty_cmd_args = "-c \"configure terminal\" -c \"{} ip route {} {}\"".format(
            op, ipaddress.ip_interface(ip + "/24".encode().decode()).network, nexthop
        )

        if namespace != DEFAULT_NAMESPACE:
            dutasic = self.asic_instance_from_namespace(namespace)
            dutasic.run_vtysh(vty_cmd_args)
        else:
            for dutasic in self.asics:
                dutasic.run_vtysh(vty_cmd_args)

    def get_internal_bgp_peers(self):
        """
        Get Internal BGP peers. API iterates through frontend ASIC
        index to get the BGP internal peers from running configuration

        Returns:
              Dict of {BGP peer: Peer Info}
        """
        if not self.sonichost.is_multi_asic:
            return {}
        bgp_internal_neighbors = {}
        for asic in self.frontend_asics:
            config_facts = self.config_facts(
                host=self.hostname, source="running",
                namespace=asic.namespace
            )['ansible_facts']
            bgp_internal_neighbors.update(
                config_facts.get("BGP_INTERNAL_NEIGHBOR", {})
            )
        return bgp_internal_neighbors

    def docker_cmds_on_all_asics(self, cmd, container_name):
        """This function iterate for ALL asics and execute cmds"""
        duthost = self.sonichost
        if duthost.is_multi_asic:
            for a_asic in self.asics:
                container = a_asic.get_docker_name(container_name)
                self.shell(argv=["docker", "exec", container, "bash", "-c", cmd])
        else:
            self.shell(argv=["docker", "exec", container_name, "bash", "-c", cmd])

    def docker_copy_to_all_asics(self, container_name, src, dst):
        """This function copy from host to ALL asics"""
        duthost = self.sonichost
        if duthost.is_multi_asic:
            for a_asic in self.asics:
                container = a_asic.get_docker_name(container_name)
                self.shell("sudo docker cp {} {}:{}".format(src, container, dst))
        else:
            self.shell("sudo docker cp {} {}:{}".format(src, container_name, dst))

    def docker_copy_from_asic(self, container_name, src, dst, asic_id = 0):
        """This function copy from one asic to host"""
        duthost = self.sonichost
        if duthost.is_multi_asic:
            container_name += str(asic_id)
        self.shell("sudo docker cp {}:{} {}".format(container_name, src, dst))
        
    def is_service_fully_started_per_asic_or_host(self, service):
        """This function tell if service is fully started base on multi-asic/single-asic"""
        duthost = self.sonichost
        if duthost.is_multi_asic:
            for asic in self.asics:
                docker_name = asic.get_docker_name(service)
                if not duthost.is_service_fully_started(docker_name): 
                    return False
            return True
        else:
            return duthost.is_service_fully_started(service)

    def restart_service_on_asic(self, service, asic_index=DEFAULT_ASIC_ID):
        """Restart service on an asic passed or None(DEFAULT_ASIC_ID)"""
        self.asic_instance(asic_index).restart_service(service)

    def docker_exec_swssconfig(self, json_name, container_name, asic_idx):
        if self.sonichost.is_multi_asic:
            container = container_name + str(asic_idx)
            return self.shell('docker exec -i {} swssconfig {}'.format(container, json_name),
                           module_ignore_errors=True)
        else:
            return self.shell('docker exec -i {} swssconfig {}'.format(container_name, json_name),
                           module_ignore_errors=True)
      
    def get_bgp_name_to_ns_mapping(self):
        """ This function returns mapping of bgp name -- namespace
            e.g. {'ARISTAT2': 'asic0', ...}
        """
        mg_facts = self.sonichost.minigraph_facts(
            host = self.sonichost.hostname
        )['ansible_facts']
        neighbors = mg_facts['minigraph_neighbors']
        mapping = dict()
        for neigh in neighbors.values():
            mapping[neigh['name']] = neigh['namespace']        
        return mapping

    def get_default_route_from_app_db(self, af='ipv4'):
        default_routes = dict()
        if self.sonichost.is_multi_asic:
            for front_asic in self.frontend_asics:
                default_routes[front_asic.namespace] = front_asic.get_default_route_from_app_db(af)
        else:
            default_routes = self.asic_instance(0).get_default_route_from_app_db(af)
        return default_routes
    
    def is_default_route_removed_from_app_db(self, uplink_asics = DEFAULT_NAMESPACE):
        if self.sonichost.is_multi_asic:
            for ns in uplink_asics:
                if not self.asic_instance_from_namespace(ns).is_default_route_removed_from_app_db():
                    return False
        else:
            if not self.asic_instance(0).is_default_route_removed_from_app_db():
                return False
        return True

