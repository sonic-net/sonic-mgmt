import os
import contextlib
import ipaddress
import json
import logging
import netaddr
import pytest
import random
import re
import six
import socket

from jinja2 import Template
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.helpers.generators import generate_ips
from tests.common.helpers.parallel import parallel_run
from tests.common.helpers.parallel import reset_ansible_local_tmp
from tests.common.utilities import wait_until, get_plt_reboot_ctrl
from tests.common.utilities import wait_tcp_connection
from tests.common import config_reload
from bgp_helpers import define_config, apply_default_bgp_config, DUT_TMP_DIR, TEMPLATE_DIR, BGP_PLAIN_TEMPLATE,\
    BGP_NO_EXPORT_TEMPLATE, DUMP_FILE, CUSTOM_DUMP_SCRIPT, CUSTOM_DUMP_SCRIPT_DEST,\
    BGPMON_TEMPLATE_FILE, BGPMON_CONFIG_FILE, BGP_MONITOR_NAME, BGP_MONITOR_PORT
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common import constants


logger = logging.getLogger(__name__)


def check_results(results):
    """Helper function for checking results of parallel run.

    Args:
        results (Proxy to shared dict): Results of parallel run, indexed by node name.
    """
    failed_results = {}
    for node_name, node_results in list(results.items()):
        failed_node_results = [res for res in node_results if res['failed']]
        if len(failed_node_results) > 0:
            failed_results[node_name] = failed_node_results
    if failed_results:
        logger.error('failed_results => {}'.format(json.dumps(failed_results, indent=2)))
        pt_assert(False, 'Some processes for updating nbr hosts configuration returned failed results')


@pytest.fixture(scope='module')
def setup_bgp_graceful_restart(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo, cct=24):
    duthost = duthosts[rand_one_dut_hostname]

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})

    @reset_ansible_local_tmp
    def configure_nbr_gr(node=None, results=None):
        """Target function will be used by multiprocessing for configuring VM hosts.

        Args:
            node (object, optional): A value item of the dict type fixture 'nbrhosts'. Defaults to None.
            results (Proxy to shared dict, optional): An instance of multiprocessing.Manager().dict(). Proxy to a dict
                shared by all processes for returning execution results. Defaults to None.
        """
        if node is None or results is None:
            logger.error('Missing kwarg "node" or "results"')
            return

        node_results = []
        logger.info('enable graceful restart on neighbor host {}'.format(node['host'].hostname))
        logger.info('bgp asn {}'.format(node['conf']['bgp']['asn']))
        node_results.append(node['host'].eos_config(
                lines=['graceful-restart restart-time 300'],
                parents=['router bgp {}'.format(node['conf']['bgp']['asn'])],
                module_ignore_errors=True)
            )
        node_results.append(node['host'].eos_config(
                lines=['graceful-restart'],
                parents=['router bgp {}'.format(node['conf']['bgp']['asn']), 'address-family ipv4'],
                module_ignore_errors=True)
            )
        node_results.append(node['host'].eos_config(
                lines=['graceful-restart'],
                parents=['router bgp {}'.format(node['conf']['bgp']['asn']), 'address-family ipv6'],
                module_ignore_errors=True)
            )
        results[node['host'].hostname] = node_results

    @reset_ansible_local_tmp
    def restore_nbr_gr(node=None, results=None):
        """Target function will be used by multiprocessing for restoring configuration for the VM hosts.

        Args:
            node (object, optional): A value item of the dict type fixture 'nbrhosts'. Defaults to None.
            results (Proxy to shared dict, optional): An instance of multiprocessing.Manager().dict(). Proxy to a dict
                shared by all processes for returning execution results. Defaults to None.
        """
        if node is None or results is None:
            logger.error('Missing kwarg "node" or "results"')
            return

        # start bgpd if not started
        node_results = []
        node['host'].start_bgpd()
        logger.info('disable graceful restart on neighbor {}'.format(node))
        node_results.append(node['host'].eos_config(
                lines=['no graceful-restart'],
                parents=['router bgp {}'.format(node['conf']['bgp']['asn']), 'address-family ipv4'],
                module_ignore_errors=True)
            )
        node_results.append(node['host'].eos_config(
                lines=['no graceful-restart'],
                parents=['router bgp {}'.format(node['conf']['bgp']['asn']), 'address-family ipv6'],
                module_ignore_errors=True)
            )
        results[node['host'].hostname] = node_results

    results = parallel_run(configure_nbr_gr, (), {}, list(nbrhosts.values()), timeout=120, concurrent_tasks=cct)

    check_results(results)

    logger.info("bgp neighbors: {}".format(list(bgp_neighbors.keys())))
    res = True
    err_msg = ""
    if not wait_until(300, 10, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())):
        res = False
        err_msg = "not all bgp sessions are up after enable graceful restart"

    is_backend_topo = "backend" in tbinfo["topo"]["name"]
    if not is_backend_topo and res and not wait_until(100, 5, 0, duthost.check_bgp_default_route):
        res = False
        err_msg = "ipv4 or ipv6 bgp default route not available"

    if not res:
        # Disable graceful restart in case of failure
        parallel_run(restore_nbr_gr, (), {}, list(nbrhosts.values()), timeout=120, concurrent_tasks=cct)
        pytest.fail(err_msg)

    yield

    results = parallel_run(restore_nbr_gr, (), {}, list(nbrhosts.values()), timeout=120, concurrent_tasks=cct)

    check_results(results)

    if not wait_until(300, 10, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())):
        pytest.fail("not all bgp sessions are up after disable graceful restart")


@pytest.fixture(scope="module")
def setup_interfaces(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, request, tbinfo, topo_scenario):
    """Setup interfaces for the new BGP peers on PTF."""

    def _is_ipv4_address(ip_addr):
        return ipaddress.ip_address(ip_addr).version == 4

    def _duthost_cleanup_ip(asichost, ip):
        """
        Search if "ip" is configured on any DUT interface. If yes, remove it.
        """

        for line in duthost.shell("{} ip addr show | grep 'inet '".format(asichost.ns_arg))['stdout_lines']:
            # Example line: '''    inet 10.0.0.2/31 scope global Ethernet104'''
            fields = line.split()
            intf_ip = fields[1].split("/")[0]
            if intf_ip == ip:
                intf_name = fields[-1]
                asichost.config_ip_intf(intf_name, ip, "remove")

        ip_intfs = duthost.show_and_parse('show ip interface {}'.format(asichost.cli_ns_option))

        # For interface that has two IP configured, the output looks like:
        #       admin@vlab-03:~$ show ip int
        #       Interface        Master    IPv4 address/mask    Admin/Oper    BGP Neighbor    Neighbor IP
        #       ---------------  --------  -------------------  ------------  --------------  -------------
        #       Ethernet100                10.0.0.50/31         up/up         ARISTA10T0      10.0.0.51
        #       Ethernet104                10.0.0.2/31          up/up         N/A             N/A
        #                                  10.0.0.52/31                       ARISTA11T0      10.0.0.53
        #       Ethernet108                10.0.0.54/31         up/up         ARISTA12T0      10.0.0.55
        #       Ethernet112                10.0.0.56/31         up/up         ARISTA13T0      10.0.0.57
        #
        # For interface Ethernet104, it has two entries in the output list:
        #   [{
        #     "ipv4 address/mask": "10.0.0.2/31",
        #     "neighbor ip": "N/A",
        #     "master": "",
        #     "admin/oper": "up/up",
        #     "interface": "Ethernet104",
        #     "bgp neighbor": "N/A"
        #   },
        #   {
        #     "ipv4 address/mask": "10.0.0.52/31",
        #     "neighbor ip": "10.0.0.53",
        #     "master": "",
        #     "admin/oper": "",
        #     "interface": "",
        #     "bgp neighbor": "ARISTA11T0"
        #   },]
        # The second item has empty value for key "interface". Below code is to fill "Ethernet104" for the second item.
        last_interface = ""
        for ip_intf in ip_intfs:
            if ip_intf["interface"] == "":
                ip_intf["interface"] = last_interface
            else:
                last_interface = ip_intf["interface"]

        # Remove the specified IP from interfaces
        for ip_intf in ip_intfs:
            if ip_intf["ipv4 address/mask"].split("/")[0] == ip:
                asichost.config_ip_intf(ip_intf["interface"], ip, "remove")

    def _find_vlan_intferface(mg_facts):
        for vlan_intf in mg_facts["minigraph_vlan_interfaces"]:
            if _is_ipv4_address(vlan_intf["addr"]):
                return vlan_intf
        raise ValueError("No Vlan interface defined in current topo")

    def _find_loopback_interface(mg_facts):
        loopback_intf_name = "Loopback0"
        for loopback in mg_facts["minigraph_lo_interfaces"]:
            if loopback["name"] == loopback_intf_name:
                return loopback
        raise ValueError("No loopback interface %s defined." % loopback_intf_name)

    @contextlib.contextmanager
    def _setup_interfaces_dualtor(mg_facts, peer_count):
        try:
            connections = []
            vlan_intf = _find_vlan_intferface(mg_facts)
            loopback_intf = _find_loopback_interface(mg_facts)
            vlan_intf_addr = vlan_intf["addr"]
            vlan_intf_prefixlen = vlan_intf["prefixlen"]
            loopback_intf_addr = loopback_intf["addr"]
            loopback_intf_prefixlen = loopback_intf["prefixlen"]

            mux_configs = mux_cable_server_ip(duthost)
            local_interfaces = random.sample(list(mux_configs.keys()), peer_count)
            for local_interface in local_interfaces:
                connections.append(
                    {
                        "local_intf": loopback_intf["name"],
                        "local_addr": "%s/%s" % (loopback_intf_addr, loopback_intf_prefixlen),
                        # Note: Config same subnets on PTF will generate two connect routes on PTF.
                        # This may lead different IPs has same FDB entry on DUT even they are on different
                        # interface and cause layer3 packet drop on PTF, so here same interface for different
                        # neighbor.
                        "neighbor_intf": "eth%s" % mg_facts["minigraph_port_indices"][local_interfaces[0]],
                        "neighbor_addr": "%s/%s" % (mux_configs[local_interface]["server_ipv4"].split("/")[0],
                                                    vlan_intf_prefixlen)
                    }
                )

            ptfhost.remove_ip_addresses()
            # let's stop arp_responder and garp_service as they could pollute
            # devices' arp tables.
            ptfhost.shell("supervisorctl stop garp_service", module_ignore_errors=True)
            ptfhost.shell("supervisorctl stop arp_responder", module_ignore_errors=True)

            first_neighbor_port = None
            for conn in connections:
                ptfhost.shell("ip address add %s dev %s" % (conn["neighbor_addr"], conn["neighbor_intf"]))
                if not first_neighbor_port:
                    first_neighbor_port = conn["neighbor_intf"]
                # NOTE: this enables the standby ToR to passively learn
                # all the neighbors configured on the ptf interfaces.
                # As the ptf is a multihomed environment, the packets to the
                # vlan gateway will always egress the first ptf port that has
                # vlan subnet address assigned, so let's use the first
                # ptf port to announce the neigbors.
                ptfhost.shell(
                    "arping %s -S %s -i %s -C 5" % (
                        vlan_intf_addr, conn["neighbor_addr"].split("/")[0], first_neighbor_port
                    ),
                    module_ignore_errors=True
                )

            ptfhost.shell("ip route add %s via %s" % (loopback_intf_addr, vlan_intf_addr))
            yield connections

        finally:
            ptfhost.shell("ip route delete %s" % loopback_intf_addr)
            for conn in connections:
                ptfhost.shell("ifconfig %s 0.0.0.0" % conn["neighbor_intf"])

    @contextlib.contextmanager
    def _setup_interfaces_t0_or_mx(mg_facts, peer_count):
        try:
            connections = []
            is_backend_topo = "backend" in tbinfo["topo"]["name"]
            vlan_intf = _find_vlan_intferface(mg_facts)
            vlan_intf_name = vlan_intf["attachto"]
            vlan_intf_addr = "%s/%s" % (vlan_intf["addr"], vlan_intf["prefixlen"])
            vlan_members = mg_facts["minigraph_vlans"][vlan_intf_name]["members"]
            is_vlan_tagged = mg_facts["minigraph_vlans"][vlan_intf_name].get("type", "").lower() == "tagged"
            vlan_id = mg_facts["minigraph_vlans"][vlan_intf_name]["vlanid"]
            local_interfaces = random.sample(vlan_members, peer_count)
            neighbor_addresses = generate_ips(
                peer_count,
                vlan_intf["subnet"],
                [netaddr.IPAddress(vlan_intf["addr"])]
            )

            loopback_ip = None
            for intf in mg_facts["minigraph_lo_interfaces"]:
                if netaddr.IPAddress(intf["addr"]).version == 4:
                    loopback_ip = intf["addr"]
                    break
            if not loopback_ip:
                pytest.fail("ipv4 lo interface not found")

            neighbor_intf = random.choice(local_interfaces)
            for neighbor_addr in neighbor_addresses:
                conn = {}
                conn["local_intf"] = vlan_intf_name
                conn["local_addr"] = vlan_intf_addr
                conn["neighbor_addr"] = neighbor_addr
                conn["neighbor_intf"] = "eth%s" % mg_facts["minigraph_port_indices"][neighbor_intf]
                if is_backend_topo and is_vlan_tagged:
                    conn["neighbor_intf"] += (constants.VLAN_SUB_INTERFACE_SEPARATOR + vlan_id)
                conn["loopback_ip"] = loopback_ip
                connections.append(conn)

            ptfhost.remove_ip_addresses()  # In case other case did not cleanup IP address configured on PTF interface

            for conn in connections:
                ptfhost.shell("ip address add %s/%d dev %s" % (
                    conn["neighbor_addr"], vlan_intf["prefixlen"], conn["neighbor_intf"]
                ))

            yield connections

        finally:
            for conn in connections:
                ptfhost.shell("ip address flush %s scope global" % conn["neighbor_intf"])

    @contextlib.contextmanager
    def _setup_interfaces_t1_or_t2(mg_facts, peer_count):
        try:
            connections = []
            is_backend_topo = "backend" in tbinfo["topo"]["name"]
            ipv4_interfaces = []
            used_subnets = set()
            asic_idx = 0
            if mg_facts["minigraph_interfaces"]:
                for intf in mg_facts["minigraph_interfaces"]:
                    if _is_ipv4_address(intf["addr"]):
                        intf_asic_idx = duthost.get_port_asic_instance(intf["attachto"]).asic_index
                        if not ipv4_interfaces:
                            ipv4_interfaces.append(intf["attachto"])
                            asic_idx = intf_asic_idx
                            used_subnets.add(ipaddress.ip_network(intf["subnet"]))
                        else:
                            if intf_asic_idx != asic_idx:
                                continue
                            else:
                                ipv4_interfaces.append(intf["attachto"])
                        used_subnets.add(ipaddress.ip_network(intf["subnet"]))

            ipv4_lag_interfaces = []
            if mg_facts["minigraph_portchannel_interfaces"]:
                for pt in mg_facts["minigraph_portchannel_interfaces"]:
                    if _is_ipv4_address(pt["addr"]):
                        pt_members = mg_facts["minigraph_portchannels"][pt["attachto"]]["members"]
                        # Only use LAG with 1 member for bgpmon session between PTF,
                        # It's because exabgp on PTF is bind to single interface
                        if len(pt_members) == 1:
                            # If first time, we record the asic index
                            if not ipv4_lag_interfaces:
                                ipv4_lag_interfaces.append(pt["attachto"])
                                asic_idx = duthost.get_asic_index_for_portchannel(pt["attachto"])
                            # Not first time, only append the portchannel that belongs to the same asic in current list
                            else:
                                asic = duthost.get_asic_index_for_portchannel(pt["attachto"])
                                if asic != asic_idx:
                                    continue
                                else:
                                    ipv4_lag_interfaces.append(pt["attachto"])
                        used_subnets.add(ipaddress.ip_network(pt["subnet"]))

            vlan_sub_interfaces = []
            if is_backend_topo:
                for intf in mg_facts.get("minigraph_vlan_sub_interfaces"):
                    if _is_ipv4_address(intf["addr"]):
                        vlan_sub_interfaces.append(intf["attachto"])
                        used_subnets.add(ipaddress.ip_network(intf["subnet"]))

            subnet_prefixlen = list(used_subnets)[0].prefixlen
            # Use a subnet which doesnt conflict with other subnets used in minigraph
            subnets = ipaddress.ip_network(six.text_type("20.0.0.0/24")).subnets(new_prefix=subnet_prefixlen)

            loopback_ip = None
            for intf in mg_facts["minigraph_lo_interfaces"]:
                if netaddr.IPAddress(intf["addr"]).version == 4:
                    loopback_ip = intf["addr"]
                    break
            if not loopback_ip:
                pytest.fail("ipv4 lo interface not found")

            num_intfs = len(ipv4_interfaces + ipv4_lag_interfaces + vlan_sub_interfaces)
            if num_intfs < peer_count:
                pytest.skip("Found {} IPv4 interfaces or lags with 1 port member,"
                            " but require {} interfaces".format(num_intfs, peer_count))

            for intf, subnet in zip(random.sample(ipv4_interfaces + ipv4_lag_interfaces + vlan_sub_interfaces,
                                                  peer_count), subnets):
                def _get_namespace(minigraph_config, intf):
                    namespace = DEFAULT_NAMESPACE
                    if intf in minigraph_config and 'namespace' in minigraph_config[intf] and \
                            minigraph_config[intf]['namespace']:
                        namespace = minigraph_config[intf]['namespace']
                    return namespace
                conn = {}
                local_addr, neighbor_addr = [_ for _ in subnet][:2]
                conn["local_intf"] = "%s" % intf
                conn["local_addr"] = "%s/%s" % (local_addr, subnet_prefixlen)
                conn["neighbor_addr"] = "%s/%s" % (neighbor_addr, subnet_prefixlen)
                conn["loopback_ip"] = loopback_ip
                conn["namespace"] = _get_namespace(mg_facts['minigraph_neighbors'], intf)

                if intf.startswith("PortChannel"):
                    member_intf = mg_facts["minigraph_portchannels"][intf]["members"][0]
                    conn["neighbor_intf"] = "eth%s" % mg_facts["minigraph_ptf_indices"][member_intf]
                    conn["namespace"] = _get_namespace(mg_facts["minigraph_portchannels"], intf)
                elif constants.VLAN_SUB_INTERFACE_SEPARATOR in intf:
                    orig_intf, vlan_id = intf.split(constants.VLAN_SUB_INTERFACE_SEPARATOR)
                    ptf_port_index = str(mg_facts["minigraph_port_indices"][orig_intf])
                    conn["neighbor_intf"] = "eth" + ptf_port_index + constants.VLAN_SUB_INTERFACE_SEPARATOR + vlan_id
                else:
                    conn["neighbor_intf"] = "eth%s" % mg_facts["minigraph_ptf_indices"][intf]
                connections.append(conn)

            ptfhost.remove_ip_addresses()  # In case other case did not cleanup IP address configured on PTF interface

            for conn in connections:
                asichost = duthost.asic_instance_from_namespace(conn['namespace'])

                # Find out if any other interface has the same IP configured. If yes, remove it
                # Otherwise, there may be conflicts and test would fail.
                _duthost_cleanup_ip(asichost, conn["local_addr"])

                # bind the ip to the interface and notify bgpcfgd
                asichost.config_ip_intf(conn["local_intf"], conn["local_addr"], "add")

                ptfhost.shell("ifconfig %s %s" % (conn["neighbor_intf"], conn["neighbor_addr"]))

                # add route to loopback address on PTF host
                nhop_ip = re.split("/", conn["local_addr"])[0]
                try:
                    socket.inet_aton(nhop_ip)
                    ptfhost.shell(
                        "ip route del {}/32".format(conn["loopback_ip"]),
                        module_ignore_errors=True
                    )
                    ptfhost.shell("ip route add {}/32 via {}".format(
                        conn["loopback_ip"], nhop_ip
                    ))
                except socket.error:
                    raise Exception("Invalid V4 address {}".format(nhop_ip))

            yield connections

        finally:
            for conn in connections:
                asichost = duthost.asic_instance_from_namespace(conn['namespace'])
                asichost.config_ip_intf(conn["local_intf"], conn["local_addr"], "remove")
                ptfhost.shell("ifconfig %s 0.0.0.0" % conn["neighbor_intf"])
                ptfhost.shell(
                    "ip route del {}/32".format(conn["loopback_ip"]),
                    module_ignore_errors=True
                )

    peer_count = getattr(request.module, "PEER_COUNT", 1)
    if "dualtor" in tbinfo["topo"]["name"]:
        setup_func = _setup_interfaces_dualtor
    elif tbinfo["topo"]["type"] in ["t0", "mx"]:
        setup_func = _setup_interfaces_t0_or_mx
    elif tbinfo["topo"]["type"] in set(["t1", "t2"]):
        setup_func = _setup_interfaces_t1_or_t2
    elif tbinfo["topo"]["type"] == "m0":
        if topo_scenario == "m0_l3_scenario":
            setup_func = _setup_interfaces_t1_or_t2
        else:
            setup_func = _setup_interfaces_t0_or_mx
    else:
        raise TypeError("Unsupported topology: %s" % tbinfo["topo"]["type"])

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    with setup_func(mg_facts, peer_count) as connections:
        yield connections

    duthost.shell("sonic-clear arp")


@pytest.fixture(scope="module")
def deploy_plain_bgp_config(duthost):
    """
    Deploy bgp plain config on the DUT

    Args:
        duthost: DUT host object

    Returns:
        Pathname of the bgp plain config on the DUT
    """
    bgp_plain_template_src_path = os.path.join(TEMPLATE_DIR, BGP_PLAIN_TEMPLATE)
    bgp_plain_template_path = os.path.join(DUT_TMP_DIR, BGP_PLAIN_TEMPLATE)

    define_config(duthost, bgp_plain_template_src_path, bgp_plain_template_path)

    return bgp_plain_template_path


@pytest.fixture(scope="module")
def deploy_no_export_bgp_config(duthost):
    """
    Deploy bgp no export config on the DUT

    Args:
        duthost: DUT host object

    Returns:
        Pathname of the bgp no export config on the DUT
    """
    bgp_no_export_template_src_path = os.path.join(TEMPLATE_DIR, BGP_NO_EXPORT_TEMPLATE)
    bgp_no_export_template_path = os.path.join(DUT_TMP_DIR, BGP_NO_EXPORT_TEMPLATE)

    define_config(duthost, bgp_no_export_template_src_path, bgp_no_export_template_path)

    return bgp_no_export_template_path


@pytest.fixture(scope="module")
def backup_bgp_config(duthost):
    """
    Copy default bgp configuration to the DUT and apply default configuration on the bgp
    docker after test

    Args:
        duthost: DUT host object
    """
    apply_default_bgp_config(duthost, copy=True)
    yield
    try:
        apply_default_bgp_config(duthost)
    except Exception:
        config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
        apply_default_bgp_config(duthost)


@pytest.fixture(scope="module")
def bgpmon_setup_teardown(ptfhost, duthosts, enum_rand_one_per_hwsku_frontend_hostname, localhost, setup_interfaces):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    connection = setup_interfaces[0]
    dut_lo_addr = connection["loopback_ip"].split("/")[0]
    peer_addr = connection['neighbor_addr'].split("/")[0]
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    asn = mg_facts['minigraph_bgp_asn']
    # TODO: Add a common method to load BGPMON config for test_bgpmon and test_traffic_shift
    logger.info("Configuring bgp monitor session on DUT")
    bgpmon_args = {
        'db_table_name': 'BGP_MONITORS',
        'peer_addr': peer_addr,
        'asn': asn,
        'local_addr': dut_lo_addr,
        'peer_name': BGP_MONITOR_NAME
    }
    bgpmon_template = Template(open(BGPMON_TEMPLATE_FILE).read())
    duthost.copy(content=bgpmon_template.render(**bgpmon_args),
                 dest=BGPMON_CONFIG_FILE)
    # Start bgpmon on DUT
    logger.info("Starting bgpmon on DUT")
    asichost = duthost.asic_instance_from_namespace(connection['namespace'])
    asichost.write_to_config_db(BGPMON_CONFIG_FILE)

    logger.info("Starting bgp monitor session on PTF")

    # Clean up in case previous run failed to clean up.
    ptfhost.exabgp(name=BGP_MONITOR_NAME, state="absent")
    ptfhost.file(path=CUSTOM_DUMP_SCRIPT_DEST, state="absent")

    # Start bgp monitor session on PTF
    ptfhost.file(path=DUMP_FILE, state="absent")
    ptfhost.copy(src=CUSTOM_DUMP_SCRIPT, dest=CUSTOM_DUMP_SCRIPT_DEST)
    ptfhost.exabgp(name=BGP_MONITOR_NAME,
                   state="started",
                   local_ip=peer_addr,
                   router_id=peer_addr,
                   peer_ip=dut_lo_addr,
                   local_asn=asn,
                   peer_asn=asn,
                   port=BGP_MONITOR_PORT,
                   dump_script=CUSTOM_DUMP_SCRIPT_DEST)

    # Flush neighbor and route in advance to avoid possible "RTNETLINK answers: File exists"
    ptfhost.shell("ip neigh flush to %s nud permanent" % dut_lo_addr)
    ptfhost.shell("ip route del %s" % dut_lo_addr + "/32", module_ignore_errors=True)

    # Add the route to DUT loopback IP  and the interface router mac
    ptfhost.shell("ip neigh add %s lladdr %s dev %s" % (dut_lo_addr,
                                                        duthost.facts["router_mac"],
                                                        connection["neighbor_intf"]))
    ptfhost.shell("ip route add %s dev %s" % (dut_lo_addr + "/32", connection["neighbor_intf"]))

    pt_assert(wait_tcp_connection(localhost, ptfhost.mgmt_ip, BGP_MONITOR_PORT, timeout_s=60),
              "Failed to start bgp monitor session on PTF")
    pt_assert(wait_until(20, 5, 0, duthost.check_bgp_session_state, [peer_addr]),
              'BGP session {} on duthost is not established'.format(BGP_MONITOR_NAME))

    yield connection
    # Cleanup bgp monitor
    asichost.run_sonic_db_cli_cmd("CONFIG_DB DEL 'BGP_MONITORS|{}'".format(peer_addr))

    ptfhost.exabgp(name=BGP_MONITOR_NAME, state="absent")
    ptfhost.file(path=CUSTOM_DUMP_SCRIPT_DEST, state="absent")
    ptfhost.file(path=DUMP_FILE, state="absent")
    # Remove the route to DUT loopback IP  and the interface router mac
    ptfhost.shell("ip route del %s" % dut_lo_addr + "/32")
    ptfhost.shell("ip neigh flush to %s nud permanent" % dut_lo_addr)


def pytest_addoption(parser):
    """
    Adds options to pytest that are used by bgp suppress fib pending test
    """

    parser.addoption(
        "--bgp_suppress_fib_pending",
        action="store_true",
        dest="bgp_suppress_fib_pending",
        default=False,
        help="enable bgp suppress fib pending function, by default it will not enable bgp suppress fib pending function"
    )
    parser.addoption(
        "--bgp_suppress_fib_reboot_type",
        action="store",
        dest="bgp_suppress_fib_reboot_type",
        type=str,
        choices=["reload", "fast", "warm", "cold", "random"],
        default="reload",
        help="reboot type such as reload, fast, warm, cold, random"
    )
    parser.addoption(
        "--continuous_boot_times",
        action="store",
        dest="continuous_boot_times",
        type=int,
        default=3,
        help="continuous reboot time number. default is 3"
    )


@pytest.fixture(scope="module", autouse=True)
def config_bgp_suppress_fib(duthosts, rand_one_dut_hostname, request):
    """
    Enable or disable bgp suppress-fib-pending function
    """
    duthost = duthosts[rand_one_dut_hostname]
    config = request.config.getoption("--bgp_suppress_fib_pending")
    logger.info("--bgp_suppress_fib_pending:{}".format(config))

    if config:
        logger.info("Check if bgp suppress fib pending is supported")
        res = duthost.command("show suppress-fib-pending", module_ignore_errors=True)
        if res['rc'] != 0:
            pytest.skip('BGP suppress fib pending function is not supported')
        logger.info('Enable BGP suppress fib pending function')
        duthost.shell('sudo config suppress-fib-pending enabled')
        duthost.shell('sudo config save -y')

    yield

    if config:
        logger.info('Disable BGP suppress fib pending function')
        duthost.shell('sudo config suppress-fib-pending disabled')
        duthost.shell('sudo config save -y')


@pytest.fixture(scope="module")
def dut_with_default_route(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    if tbinfo['topo']['type'] == 't2':
        # For T2 setup, default route via eBGP is only advertised from T3 VM's which are connected to one of the
        # linecards and not the other. So, can't use enum_rand_one_per_hwsku_frontend_hostname for T2.
        dut_to_T3 = None
        for a_dut in duthosts.frontend_nodes:
            minigraph_facts = a_dut.get_extended_minigraph_facts(tbinfo)
            minigraph_neighbors = minigraph_facts['minigraph_neighbors']
            for key, value in list(minigraph_neighbors.items()):
                if 'T3' in value['name']:
                    dut_to_T3 = a_dut
                    break
            if dut_to_T3:
                break
        if dut_to_T3 is None:
            pytest.fail("Did not find any DUT in the DUTs (linecards) that are connected to T3 VM's")
        return dut_to_T3
    else:
        return duthosts[enum_rand_one_per_hwsku_frontend_hostname]


@pytest.fixture(scope="module")
def set_timeout_for_bgpmon(duthost):
    """
    For chassis testbeds, we need to specify plt_reboot_ctrl in inventory file,
    to let MAX_TIME_TO_REBOOT to be overwritten by specified timeout value
    """
    global MAX_TIME_FOR_BGPMON
    plt_reboot_ctrl = get_plt_reboot_ctrl(duthost, 'test_bgpmon.py', 'cold')
    if plt_reboot_ctrl:
        MAX_TIME_FOR_BGPMON = plt_reboot_ctrl.get('timeout', 180)


@pytest.fixture(scope="module")
def is_quagga(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Return True if current bgp is using Quagga."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    show_res = duthost.asic_instance().run_vtysh("-c 'show version'")
    return "Quagga" in show_res["stdout"]


@pytest.fixture(scope="module")
def is_dualtor(tbinfo):
    return "dualtor" in tbinfo["topo"]["name"]


@pytest.fixture(scope="module")
def traffic_shift_community(duthost):
    community = duthost.shell('sonic-cfggen -y /etc/sonic/constants.yml -v constants.bgp.traffic_shift_community')[
        'stdout']
    return community
