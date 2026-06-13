'''

This script is to Verify applied communities manipulate traffic as
expected between 4-byte and 2-byte AS neighbors.

Step 1: Configure DUT and neighbor with 4Byte ASN
Step 2: Verify 4-byte BGP session between DUT and neighbor is established

'''
import logging

import pytest
import time
import textfsm
import re
from tests.bgp.bgp_helpers import eos_bgp_neighbor_config_parents
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)
dut_4byte_asn = 400003
neighbor_4byte_asn = 400001
bgp_sleep = 120
bgp_id_textfsm = "./bgp/templates/bgp_id.template"
# Full startup-config backup for converged multi-VRF cEOS
EOS_NEIGH_BACKUP_CONFIG_FILE = "/tmp/bgp_4byte_asn_community_eos_backup_{}"

pytestmark = [
    pytest.mark.topology('t2', 'lrh', 'urh')
]


class BGPRouter(ABC):
    def __init__(self, host, asn):
        self.host = host
        self.asn = asn
        self.saved_bgp_config = None

    def __str__(self):
        return f"{self.host} {self.asn}"

    @abstractmethod
    def get_router_id(self):
        pass

    @abstractmethod
    def get_current_bgp_asn(self):
        pass

    @abstractmethod
    def save_bgp_config(self):
        pass

    @abstractmethod
    def remove_bgp_config(self, asn=None):
        pass

    @abstractmethod
    def restore_bgp_config(self, asn_to_be_removed):
        pass

    @abstractmethod
    def get_bgp_config(self):
        pass

    @abstractmethod
    def get_originated_ipv4_networks(self):
        pass

    @abstractmethod
    def get_originated_ipv6_networks(self):
        pass


class SonicBGPRouter(BGPRouter):
    def __init__(self, host, asn):
        super().__init__(host, asn)
        self.os_type = 'sonic'

    def get_router_id(self):
        # TODO: Add SONiC implementation
        pass

    def get_current_bgp_asn(self):
        # TODO: Add SONiC implementation
        pass

    def save_bgp_config(self):
        # TODO: Add SONiC implementation
        pass

    def remove_bgp_config(self, asn=None):
        # TODO: Add SONiC implementation
        pass

    def restore_bgp_config(self, asn_to_be_removed):
        # TODO: Add SONiC implementation
        pass

    def get_bgp_config(self):
        # TODO: Add SONiC implementation
        pass

    def get_originated_ipv4_networks(self):
        # TODO: Add SONiC implementation
        pass

    def get_originated_ipv6_networks(self):
        # TODO: Add SONiC implementation
        pass


class EosBGPRouter(BGPRouter):
    def __init__(self, host, asn, eos_bgp_summary_vrf=None, eos_bgp_parents=None, dut_peer_addrs=None,
                 eos_restore_backup_path=None):
        super().__init__(host, asn)
        self.os_type = 'eos'
        # Converged multi-VRF cEOS: default VRF "show ip bgp summary" can be empty; use vrf <logical_peer>.
        self.eos_bgp_summary_vrf = eos_bgp_summary_vrf
        self.eos_bgp_parents = eos_bgp_parents
        self.dut_peer_addrs = dut_peer_addrs
        self.eos_restore_backup_path = eos_restore_backup_path

    def _ip_bgp_summary_cmd(self):
        cmd = "show ip bgp summary"
        if self.eos_bgp_summary_vrf:
            cmd += " vrf {}".format(self.eos_bgp_summary_vrf)
        return cmd

    def _ipv6_bgp_summary_cmd(self):
        cmd = "show ipv6 bgp summary"
        if self.eos_bgp_summary_vrf:
            cmd += " vrf {}".format(self.eos_bgp_summary_vrf)
        return cmd

    def get_router_id(self):
        neigh_ip_bgp_sum = self.get_command_output(self._ip_bgp_summary_cmd())
        # Classic EOS: "Router identifier ..."; SONiC/FRR-style: "BGP router identifier ..."
        match = re.search(
            r'(?:BGP\s+router\s+identifier|Router\s+identifier)\s+(\d+\.\d+\.\d+\.\d+)',
            neigh_ip_bgp_sum,
            re.IGNORECASE,
        )
        pytest_assert(
            match,
            "Failed to get BGP router ID from [{}] on {}".format(neigh_ip_bgp_sum, self.host),
        )
        return match.group(1)

    def get_current_bgp_asn(self):
        current_bgp_asn = self.get_command_output("show run section bgp | sec router bgp")
        match = re.search(r'router bgp (\d+)', current_bgp_asn)
        pytest_assert(match, "Failed to get BGP ASN from [{}] on {}".format(current_bgp_asn, self.host))
        return match.group(1)

    def save_bgp_config(self):
        self.saved_bgp_config = self.get_command_output("show run section bgp")

    def remove_bgp_config(self, asn=None):
        # Converged multi-VRF: do not run "no router bgp <primary_asn>" on a shared cEOS VM.
        if self.eos_bgp_parents and self.dut_peer_addrs:
            cv4, cv6 = self.dut_peer_addrs
            cleanup = [
                "no neighbor {}".format(cv4),
                "no neighbor {}".format(cv6),
            ]
            self.host.eos_config(
                lines=cleanup, parents=self.eos_bgp_parents)
            return
        if asn is None:
            asn = self.get_current_bgp_asn()
        self.host.eos_config(
            lines=["no router bgp {}".format(asn)])

    def restore_bgp_config(self, asn_to_be_removed):
        if self.eos_restore_backup_path:
            self.host.load_configuration(self.eos_restore_backup_path)
            return
        if self.eos_bgp_parents and self.dut_peer_addrs:
            self.remove_bgp_config()
        else:
            self.remove_bgp_config(asn=asn_to_be_removed)
        self.host.eos_config(lines=list(self.saved_bgp_config.split("\n")))

    def get_bgp_config(self):
        current_bgp_config = self.get_command_output("show run section bgp")
        return current_bgp_config

    def get_originated_ipv4_networks(self):
        ipv4_af_output = self.get_command_output("show run section bgp | sec address-family ipv4")
        match = re.search(r'network (\d+\.\d+\.\d+\.\d+/\d+)', ipv4_af_output)
        pytest_assert(match, "Failed to get IPv4 network from [{}] on {}".format(ipv4_af_output, self.host))
        return match.group(1)

    def get_originated_ipv6_networks(self):
        ipv6_af_network = self.get_command_output("show run section bgp | sec address-family ipv6")
        match = re.search(r'network ([a-fA-F0-9:]+/\d+)', ipv6_af_network)
        pytest_assert(match, "Failed to get IPv6 network from [{}] on {}".format(ipv6_af_network, self.host))
        return match.group(1)

    def get_command_output(self, command):
        out = self.host.eos_command(commands=[command])['stdout']
        if not out:
            return ''
        # Ansible may return one string per screen line; join for reliable parsing.
        if len(out) == 1:
            return out[0]
        return '\n'.join(out)

    def eos_bgp_summary_include_cmd(self, ip, ipv6=False):
        base = self._ipv6_bgp_summary_cmd() if ipv6 else self._ip_bgp_summary_cmd()
        return "{} | include {}".format(base, ip)

    def eos_bgp_neighbor_routes_cmd(self, nbr_ip, ipv6=False):
        if ipv6:
            base = "show ipv6 bgp peers {} routes".format(nbr_ip)
        else:
            base = "show ip bgp neighbors {} routes".format(nbr_ip)
        if self.eos_bgp_summary_vrf:
            base += " vrf {}".format(self.eos_bgp_summary_vrf)
        return base


def check_bgp_neighbor(duthost, bgp_neighbors):
    """
    Validate all the bgp neighbors are established
    """
    pytest_assert(
        wait_until(300, 10, 0, duthost.check_bgp_session_state, bgp_neighbors),
        "bgp sessions {} are not up".format(bgp_neighbors)
    )


def setup_ceos(tbinfo, nbrhosts, duthosts, enum_frontend_dut_hostname, enum_rand_one_frontend_asic_index, request):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_frontend_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + str(asic_index)
    else:
        cli_options = ''

    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    neighbors = dict()

    def _all_ebgp_neighbors_established():
        """Same peer filter as the setup loop below: every non-INTERNAL / non-VOQ_CHASSIS session must be up."""
        facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
        for _k, v in facts['bgp_neighbors'].items():
            if "INTERNAL" in v["peer group"] or "VOQ_CHASSIS" in v["peer group"]:
                continue
            if v['state'] != 'established':
                return False
        return True

    # If a prior run failed before fixture teardown, the DUT can still be on 4-byte test BGP while neighbors are not
    # teardown (restore + config_reload) never ran because yield was not reached. Recover once.
    if not wait_until(120, 10, 0, _all_ebgp_neighbors_established):
        logger.warning(
            "eBGP not fully established before 4-byte ASN community setup; reloading DUT to clear stale state"
        )
        config_reload(duthost, safe_reload=True, wait_for_bgp=True)
    pytest_assert(
        wait_until(300, 10, 0, _all_ebgp_neighbors_established),
        "eBGP sessions are not all established after optional config_reload; fix topology or neighbor VMs",
    )

    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    ceosNeighbors = [v['description'] for v in bgp_facts['bgp_neighbors'].values()
                     if 'asic' not in v['description'].lower()]
    if not ceosNeighbors:
        pytest.skip("No ceos neighbors found")
    neigh = ceosNeighbors[0]
    logger.debug("Neighbor is: {}".format(neigh))
    neigh_asn = dict()

    # verify sessions are established and gather neighbor information
    for k, v in bgp_facts['bgp_neighbors'].items():
        # skip iBGP neighbors
        if "INTERNAL" not in v["peer group"] and "VOQ_CHASSIS" not in v["peer group"]:
            if v['description'] == neigh:
                if v['ip_version'] == 4:
                    neigh_ip_v4 = k
                    peer_group_v4 = v['peer group']
                elif v['ip_version'] == 6:
                    neigh_ip_v6 = k
                    peer_group_v6 = v['peer group']
            assert v['state'] == 'established'
            neigh_asn[v['description']] = v['remote AS']
            neighbors[v['description']] = nbrhosts[v['description']]["host"]

    neigh_cli_options = ''

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][neigh]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][neigh]['bgp']['peers'][dut_asn][1]

    dut_ip_bgp_sum = duthost.shell('show ip bgp summary')['stdout']

    nbr_ent = nbrhosts[neigh]
    neigh_eos_bgp_parents = eos_bgp_neighbor_config_parents(tbinfo, nbrhosts, neigh, neigh_asn[neigh])
    multi_vrf = bool(nbr_ent.get("is_multi_vrf_peer"))
    vrf_name = nbr_ent.get("multi_vrf_data", {}).get("vrf") if multi_vrf else None
    dut_peer_addrs = (dut_ip_v4, dut_ip_v6) if multi_vrf else None
    eos_parents_for_cleanup = neigh_eos_bgp_parents if multi_vrf else None
    neigh_eos_restore_backup = (
        EOS_NEIGH_BACKUP_CONFIG_FILE.format(neighbors[neigh].hostname) if multi_vrf else None)

    bgp_neigh = EosBGPRouter(
        nbrhosts[neigh]["host"],
        neigh_asn[neigh],
        eos_bgp_summary_vrf=vrf_name,
        eos_bgp_parents=eos_parents_for_cleanup,
        dut_peer_addrs=dut_peer_addrs,
        eos_restore_backup_path=neigh_eos_restore_backup,
    )
    neigh_bgp_id = bgp_neigh.get_router_id()
    with open(bgp_id_textfsm) as template:
        fsm = textfsm.TextFSM(template)
        dut_bgp_id = fsm.ParseText(dut_ip_bgp_sum)[0][0]

    dut_ipv4_network = duthost.shell("show run bgp | grep 'ip prefix-list PL_Loopback'")['stdout'].split()[6]
    dut_ipv6_network = duthost.shell("show run bgp | grep 'ipv6 prefix-list PL_Loopback'")['stdout'].split()[6]
    neigh_ipv4_network = bgp_neigh.get_originated_ipv4_networks()
    neigh_ipv6_network = bgp_neigh.get_originated_ipv6_networks()

    setup_info = {
        'bgp_neigh': bgp_neigh,
        'duthost': duthost,
        'neighhost': neighbors[neigh],
        'neigh': neigh,
        'dut_asn': dut_asn,
        'neigh_asn': neigh_asn[neigh],
        'asn_dict':  neigh_asn,
        'neighbors': neighbors,
        'cli_options': cli_options,
        'neigh_cli_options': neigh_cli_options,
        'dut_ip_v4': dut_ip_v4,
        'dut_ip_v6': dut_ip_v6,
        'neigh_ip_v4': neigh_ip_v4,
        'neigh_ip_v6': neigh_ip_v6,
        'peer_group_v4': peer_group_v4,
        'peer_group_v6': peer_group_v6,
        'asic_index': asic_index,
        'dut_bgp_id': dut_bgp_id,
        'neigh_bgp_id': neigh_bgp_id,
        'dut_ipv4_network': dut_ipv4_network,
        'dut_ipv6_network': dut_ipv6_network,
        'neigh_ipv4_network': neigh_ipv4_network,
        'neigh_ipv6_network': neigh_ipv6_network,
        'neigh_eos_bgp_parents': neigh_eos_bgp_parents if multi_vrf else None,
    }

    logger.debug("DUT BGP Config: {}".format(duthost.shell("show run bgp", module_ignore_errors=True)['stdout']))
    logger.debug("Neighbor BGP Config: {}".format(bgp_neigh.get_bgp_config()))
    logger.debug('Setup_info: {}'.format(setup_info))
    bgp_neigh.save_bgp_config()
    if neigh_eos_restore_backup:
        neighbors[neigh].eos_config(
            backup=True,
            backup_options={'filename': neigh_eos_restore_backup},
        )

    yield setup_info

    bgp_neigh.restore_bgp_config(asn_to_be_removed=neighbor_4byte_asn)
    # restore config to original state
    config_reload(duthost, safe_reload=True, wait_for_bgp=True)


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, enum_frontend_dut_hostname, enum_rand_one_frontend_asic_index, request):
    # verify neighbors are type sonic and skip if not
    if request.config.getoption("neighbor_type") != "sonic":
        yield from setup_ceos(tbinfo, nbrhosts, duthosts, enum_frontend_dut_hostname,
                              enum_rand_one_frontend_asic_index, request)
        return
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_frontend_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
    else:
        cli_options = ''

    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']
    neigh = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()[1]
    logger.debug("Neighbor is: {}".format(neigh))

    neighbors = dict()
    skip_hosts = duthost.get_asic_namespace_list()
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    neigh_asn = dict()

    # verify sessions are established and gather neighbor information
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            if v['description'] == neigh:
                if v['ip_version'] == 4:
                    neigh_ip_v4 = k
                    peer_group_v4 = v['peer group']
                elif v['ip_version'] == 6:
                    neigh_ip_v6 = k
                    peer_group_v6 = v['peer group']
            assert v['state'] == 'established'
            neigh_asn[v['description']] = v['remote AS']
            neighbors[v['description']] = nbrhosts[v['description']]["host"]

    if neighbors[neigh].is_multi_asic:
        neigh_cli_options = " -n " + neigh.get_namespace_from_asic_id(asic_index)
    else:
        neigh_cli_options = ''

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][neigh]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][neigh]['bgp']['peers'][dut_asn][1]

    dut_ip_bgp_sum = duthost.shell('show ip bgp summary')['stdout']
    neigh_ip_bgp_sum = nbrhosts[neigh]["host"].shell('show ip bgp summary')['stdout']
    with open(bgp_id_textfsm) as template:
        fsm = textfsm.TextFSM(template)
        dut_bgp_id = fsm.ParseText(dut_ip_bgp_sum)[0][0]
        neigh_parsed = fsm.ParseText(neigh_ip_bgp_sum)
        pytest_assert(neigh_parsed, "Failed to parse BGP router id from neighbor summary")
        neigh_bgp_id = neigh_parsed[-1][0]

    dut_ipv4_network = duthost.shell("show run bgp | grep 'ip prefix-list PL_Loopback'")['stdout'].split()[6]
    dut_ipv6_network = duthost.shell("show run bgp | grep 'ipv6 prefix-list PL_Loopback'")['stdout'].split()[6]
    neigh_ipv4_network = nbrhosts[neigh]["host"].shell(
        "show run bgp | grep 'ip prefix-list PL_Loopback'")['stdout'].split()[6]
    neigh_ipv6_network = nbrhosts[neigh]["host"].shell(
        "show run bgp | grep 'ipv6 prefix-list PL_Loopback'")['stdout'].split()[6]

    setup_info = {
        'bgp_neigh': SonicBGPRouter(neighbors[neigh], neigh_asn[neigh]),
        'duthost': duthost,
        'neighhost': neighbors[neigh],
        'neigh': neigh,
        'dut_asn': dut_asn,
        'neigh_asn': neigh_asn[neigh],
        'asn_dict':  neigh_asn,
        'neighbors': neighbors,
        'cli_options': cli_options,
        'neigh_cli_options': neigh_cli_options,
        'dut_ip_v4': dut_ip_v4,
        'dut_ip_v6': dut_ip_v6,
        'neigh_ip_v4': neigh_ip_v4,
        'neigh_ip_v6': neigh_ip_v6,
        'peer_group_v4': peer_group_v4,
        'peer_group_v6': peer_group_v6,
        'asic_index': asic_index,
        'dut_bgp_id': dut_bgp_id,
        'neigh_bgp_id': neigh_bgp_id,
        'dut_ipv4_network': dut_ipv4_network,
        'dut_ipv6_network': dut_ipv6_network,
        'neigh_ipv4_network': neigh_ipv4_network,
        'neigh_ipv6_network': neigh_ipv6_network
    }

    logger.debug("DUT BGP Config: {}".format(duthost.shell("show run bgp", module_ignore_errors=True)['stdout']))
    logger.debug("Neighbor BGP Config: {}".format(nbrhosts[neigh]["host"].shell("show run bgp")['stdout']))
    logger.debug('Setup_info: {}'.format(setup_info))

    yield setup_info

    # restore config to original state
    config_reload(duthost)
    config_reload(neighbors[neigh], is_dut=False)

    # verify sessions are established
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            logger.debug(v['description'])
            assert v['state'] == 'established'


def config_dut_4_byte_asn_dut(setup):
    # configure BGP with 4-byte ASN using the standard T2 config and existing route-maps on DUT
    # as route-map names varies dependin on the topology, used ALLOW_ANY route-map to
    # allow all routes as we only have two neighbors.
    cmd = 'vtysh{} \
    -c "config" \
    -c "no router bgp {}" \
    -c "route-map ALLOW_ANY permit 10" \
    -c "router bgp {}" \
    -c "bgp router-id {}" \
    -c "bgp log-neighbor-changes" \
    -c "no bgp ebgp-requires-policy" \
    -c "no bgp default ipv4-unicast" \
    -c "bgp bestpath as-path multipath-relax" \
    -c "neighbor {} peer-group" \
    -c "neighbor {} peer-group" \
    -c "neighbor {} remote-as {}" \
    -c "neighbor {} peer-group {}" \
    -c "neighbor {} description {}" \
    -c "neighbor {} timers 3 10" \
    -c "neighbor {} timers connect 10" \
    -c "neighbor {} remote-as {}" \
    -c "neighbor {} peer-group {}" \
    -c "neighbor {} description {}" \
    -c "neighbor {} timers 3 10" \
    -c "neighbor {} timers connect 10" \
    -c "address-family ipv4 unicast" \
    -c "network {}" \
    -c "neighbor {} soft-reconfiguration inbound" \
    -c "neighbor {} route-map ALLOW_ANY in" \
    -c "neighbor {} route-map ALLOW_ANY out" \
    -c "neighbor {} activate" \
    -c "maximum-paths 64" \
    -c "exit-address-family" \
    -c "address-family ipv6 unicast" \
    -c "network {}" \
    -c "neighbor {} soft-reconfiguration inbound" \
    -c "neighbor {} route-map ALLOW_ANY in" \
    -c "neighbor {} route-map ALLOW_ANY out" \
    -c "neighbor {} activate" \
    -c "maximum-paths 64" \
    -c "exit-address-family" \
    '.format(setup['cli_options'], setup['dut_asn'], dut_4byte_asn, setup['dut_bgp_id'],
             setup['peer_group_v4'], setup['peer_group_v6'], setup['neigh_ip_v4'], neighbor_4byte_asn,
             setup['neigh_ip_v4'], setup['peer_group_v4'], setup['neigh_ip_v4'], setup['neigh'], setup['neigh_ip_v4'],
             setup['neigh_ip_v4'], setup['neigh_ip_v6'], neighbor_4byte_asn, setup['neigh_ip_v6'],
             setup['peer_group_v6'], setup['neigh_ip_v6'], setup['neigh'], setup['neigh_ip_v6'], setup['neigh_ip_v6'],
             setup['dut_ipv4_network'], setup['peer_group_v4'], setup['peer_group_v4'], setup['peer_group_v4'],
             setup['neigh_ip_v4'], setup['dut_ipv6_network'], setup['peer_group_v6'], setup['peer_group_v6'],
             setup['peer_group_v6'], setup['neigh_ip_v6'])
    logger.debug(setup['duthost'].shell(cmd, module_ignore_errors=True))


def run_bgp_4_byte_asn_community_sonic(setup):
    config_dut_4_byte_asn_dut(setup)

    # configure BGP with 4-byte ASN using the standard T2 config and existing route-maps on neighbor device
    cmd = 'vtysh{}\
    -c "config" \
    -c "no router bgp {}" \
    -c "router bgp {}" \
    -c "bgp router-id {}" \
    -c "bgp log-neighbor-changes" \
    -c "no bgp ebgp-requires-policy" \
    -c "no bgp default ipv4-unicast" \
    -c "bgp bestpath as-path multipath-relax" \
    -c "neighbor {} peer-group" \
    -c "neighbor {} peer-group" \
    -c "neighbor {} remote-as {}" \
    -c "neighbor {} peer-group {}" \
    -c "neighbor {} description {}" \
    -c "neighbor {} timers 3 10" \
    -c "neighbor {} timers connect 10" \
    -c "neighbor {} remote-as {}" \
    -c "neighbor {} peer-group {}" \
    -c "neighbor {} description {}" \
    -c "neighbor {} timers 3 10" \
    -c "neighbor {} timers connect 10" \
    -c "address-family ipv4 unicast" \
    -c "network {}" \
    -c "neighbor {} soft-reconfiguration inbound" \
    -c "neighbor {} route-map FROM_BGP_PEER_V4 in" \
    -c "neighbor {} route-map TO_BGP_PEER_V4 out" \
    -c "neighbor {} activate" \
    -c "maximum-paths 64" \
    -c "exit-address-family" \
    -c "address-family ipv6 unicast" \
    -c "network {}" \
    -c "neighbor {} soft-reconfiguration inbound" \
    -c "neighbor {} route-map FROM_BGP_PEER_V6 in" \
    -c "neighbor {} route-map TO_BGP_PEER_V6 out" \
    -c "neighbor {} activate" \
    -c "maximum-paths 64" \
    -c "exit-address-family" \
    '.format(setup['neigh_cli_options'], setup['neigh_asn'], neighbor_4byte_asn, setup['neigh_bgp_id'],
             setup['peer_group_v4'], setup['peer_group_v6'], setup['dut_ip_v4'], dut_4byte_asn, setup['dut_ip_v4'],
             setup['peer_group_v4'], setup['dut_ip_v4'], 'DUT', setup['dut_ip_v4'], setup['dut_ip_v4'],
             setup['dut_ip_v6'], dut_4byte_asn, setup['dut_ip_v6'], setup['peer_group_v6'], setup['dut_ip_v6'], 'DUT',
             setup['dut_ip_v6'], setup['dut_ip_v6'], setup['neigh_ipv4_network'], setup['peer_group_v4'],
             setup['peer_group_v4'], setup['peer_group_v4'], setup['dut_ip_v4'], setup['neigh_ipv6_network'],
             setup['peer_group_v6'], setup['peer_group_v6'], setup['peer_group_v6'], setup['dut_ip_v6'])

    logger.debug(setup['neighhost'].shell(cmd, module_ignore_errors=True))

    logger.debug("DUT BGP Config: {}".format(setup['duthost'].shell("show run bgp")['stdout']))
    logger.debug("Neighbor BGP Config: {}".format(setup['neighhost'].shell("show run bgp")['stdout']))

    time.sleep(bgp_sleep)

    output = setup['duthost'].shell("show ip bgp summary | grep {}".format(setup['neigh_ip_v4']))['stdout']
    assert str(neighbor_4byte_asn) in output.split()[2]
    output = setup['duthost'].shell("show ipv6 bgp summary | grep {}".format(setup['neigh_ip_v6'].lower()))['stdout']
    assert str(neighbor_4byte_asn) in output.split()[2]
    output = setup['duthost'].shell("show ip bgp neighbors {} routes".format(setup['neigh_ip_v4']))['stdout']
    assert str(neighbor_4byte_asn) in str(output.split('\n')[9].split()[5])
    output = setup['duthost'].shell("show ipv6 bgp neighbors {} routes".format(setup['neigh_ip_v6'].lower()))['stdout']
    # Command output 'show ipv6 bgp neighbors <xxx> routes'  may split into two lines, hence checking both the lines
    #    Network          Next Hop             Metric LocPrf Weight Path
    # *> 2064:100::1/128  fe80::4cc2:44ff:feee:73ff
    #                                                       0 400001 i
    assert (str(neighbor_4byte_asn) in str(output.split('\n')[9]) or
            str(neighbor_4byte_asn) in str(output.split('\n')[10]))

    output = setup['neighhost'].shell("show ip bgp summary | grep {}".format(setup['dut_ip_v4']))['stdout']
    assert str(dut_4byte_asn) in output.split()[2]
    output = setup['neighhost'].shell("show ipv6 bgp summary | grep {}".format(setup['dut_ip_v6'].lower()))['stdout']
    assert str(dut_4byte_asn) in output.split()[2]
    output = setup['neighhost'].shell("show ip bgp neighbors {} routes".format(setup['dut_ip_v4']))['stdout']
    assert str(dut_4byte_asn) in str(output.split('\n')[9].split()[5])
    output = setup['neighhost'].shell("show ipv6 bgp neighbors {} routes".format(setup['dut_ip_v6'].lower()))['stdout']
    assert str(dut_4byte_asn) in str(output.split('\n')[9].split()[5])


def run_bgp_4_byte_asn_community_eos(setup):
    config_dut_4_byte_asn_dut(setup)

    bgp_neigh = setup['bgp_neigh']
    parents = setup.get('neigh_eos_bgp_parents')
    vrf_neighbor_lines = [
        "router-id {}".format(setup['neigh_bgp_id']),
        "neighbor {} remote-as {}".format(setup['dut_ip_v4'], dut_4byte_asn),
        "neighbor {} description {}".format(setup['dut_ip_v4'], 'DUT'),
        "neighbor {} maximum-routes 0".format(setup['dut_ip_v4']),
        "neighbor {} remote-as {}".format(setup['dut_ip_v6'], dut_4byte_asn),
        "neighbor {} description {}".format(setup['dut_ip_v6'], 'DUT'),
        "neighbor {} maximum-routes 0".format(setup['dut_ip_v6']),
    ]
    # Converged multi-VRF: BGP process stays "router bgp <primary> vrf …" so the real local ASN is still the
    # primary ASN. The DUT is renumbered to router bgp 400003 and expects the peer as remote-as 400001 — match
    # that with local-as … no-prepend replace-as on the neighbor toward the DUT (only EOS requires those modifiers).
    if parents:
        # EOS requires modifiers after local-as (bare "local-as <asn>" is % Incomplete command).
        vrf_neighbor_lines.extend([
            "neighbor {} local-as {} no-prepend replace-as".format(setup['dut_ip_v4'], neighbor_4byte_asn),
            "neighbor {} local-as {} no-prepend replace-as".format(setup['dut_ip_v6'], neighbor_4byte_asn),
        ])
    bgp_neigh.remove_bgp_config()
    # configure BGP with 4-byte ASN using the standard T2 config and existing route-maps on neighbor device
    if parents:
        # Ansible eos_config only applies 'lines' under the fixed 'parents' context. It does NOT treat
        # "address-family …" lines as a new nesting level, so neighbor activate/network must be pushed
        # with full parent paths including each address-family.
        host = bgp_neigh.host
        logger.debug(host.eos_config(lines=vrf_neighbor_lines, parents=parents))
        logger.debug(host.eos_config(
            lines=["network {}".format(setup['neigh_ipv4_network'])],
            parents=parents + ["address-family ipv4"],
        ))
        logger.debug(host.eos_config(
            lines=[
                "neighbor {} activate".format(setup['dut_ip_v6']),
                "network {}".format(setup['neigh_ipv6_network']),
            ],
            parents=parents + ["address-family ipv6"],
        ))
    else:
        bgp_lines = (
            ["router bgp {}".format(neighbor_4byte_asn)]
            + vrf_neighbor_lines
            + [
                "!",
                "address-family ipv4",
                "neighbor {} activate".format(setup['dut_ip_v4']),
                "network {}".format(setup['neigh_ipv4_network']),
                "!",
                "address-family ipv6",
                "neighbor {} activate".format(setup['dut_ip_v6']),
                "network {}".format(setup['neigh_ipv6_network']),
            ]
        )
        logger.debug(bgp_neigh.host.eos_config(lines=bgp_lines))

    logger.debug("DUT BGP Config: {}".format(setup['duthost'].shell("show run bgp")['stdout']))
    logger.debug("Neighbor BGP Config: {}".format(bgp_neigh.get_bgp_config()))

    time.sleep(60)
    check_bgp_neighbor(setup['duthost'], [setup['neigh_ip_v4'], setup['neigh_ip_v6']])

    output = setup['duthost'].shell("show ip bgp summary | grep {}".format(setup['neigh_ip_v4']))['stdout']
    assert str(neighbor_4byte_asn) in output.split()[2]
    output = setup['duthost'].shell("show ipv6 bgp summary | grep {}".format(setup['neigh_ip_v6'].lower()))['stdout']
    assert str(neighbor_4byte_asn) in output.split()[2]
    output = setup['duthost'].shell("show ip bgp neighbors {} routes".format(setup['neigh_ip_v4']))['stdout']
    assert str(neighbor_4byte_asn) in str(output.split('\n')[9])
    output = setup['duthost'].shell("show ipv6 bgp neighbors {} routes".format(setup['neigh_ip_v6'].lower()))['stdout']
    # show ipv6 bgp neighbors <xxx> routes  may split into two lines, hence checking both lines
    #     Network          Next Hop            Metric LocPrf Weight Path
    # *> 2064:100::1d/128 fe80::4059:38ff:feaa:82db
    #                                                       0 400001 i
    assert (str(neighbor_4byte_asn) in str(output.split('\n')[9]) or
           str(neighbor_4byte_asn) in str(output.split('\n')[10]))

    output = bgp_neigh.get_command_output(bgp_neigh.eos_bgp_summary_include_cmd(setup['dut_ip_v4']))
    assert str(dut_4byte_asn) in output
    output = bgp_neigh.get_command_output(
        bgp_neigh.eos_bgp_summary_include_cmd(setup['dut_ip_v6'].lower(), ipv6=True))
    assert str(dut_4byte_asn) in output
    output = bgp_neigh.get_command_output(bgp_neigh.eos_bgp_neighbor_routes_cmd(setup['dut_ip_v4'], ipv6=False))
    assert str(dut_4byte_asn) in str(output.split('\n')[-1])
    output = bgp_neigh.get_command_output(
        bgp_neigh.eos_bgp_neighbor_routes_cmd(setup['dut_ip_v6'].lower(), ipv6=True))
    assert str(dut_4byte_asn) in str(output.split('\n')[-1]) or str(dut_4byte_asn) in str(output.split('\n')[-2])


def test_4_byte_asn_community(setup):
    if setup['bgp_neigh'].os_type == 'eos':
        run_bgp_4_byte_asn_community_eos(setup)
    else:
        run_bgp_4_byte_asn_community_sonic(setup)
