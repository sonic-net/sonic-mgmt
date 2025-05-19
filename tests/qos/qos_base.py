import ipaddress
import json
import logging
import pytest
import re
import yaml
import random
import collections

from tests.common.fixtures.ptfhost_utils import ptf_portmap_file  # noqa F401
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice
from tests.common.cisco_data import is_cisco_device
from tests.common.dualtor.dual_tor_utils import lower_tor_host, dualtor_ports  # noqa F401
from tests.common.fixtures.duthost_utils import dut_qos_maps, separated_dscp_to_tc_map_on_uplink  # noqa F401
from tests.ptf_runner import ptf_runner
from tests.common.system_utils import docker  # noqa F401
from tests.common.errors import RunAnsibleModuleFail

logger = logging.getLogger(__name__)


class QosBase:
    """
    Common APIs for qos scripts
    """
    SUPPORTED_T0_TOPOS = [
        "t0", "t0-56", "t0-56-po2vlan", "t0-64", "t0-116", "t0-118", "t0-35", "dualtor-56", "dualtor-64",
        "dualtor-120", "dualtor", "dualtor-64-breakout", "dualtor-aa", "t0-120", "t0-80", "t0-backend",
        "t0-56-o8v48", "t0-8-lag", "t0-standalone-32", "t0-standalone-64", "t0-standalone-128",
        "t0-standalone-256", "t0-28", "t0-isolated-d16u16s1", "t0-isolated-d16u16s2"
    ]
    SUPPORTED_T1_TOPOS = ["t1-lag", "t1-64-lag", "t1-56-lag", "t1-backend", "t1-28-lag", "t1-32-lag",
                          "t1-isolated-d28u1"]
    SUPPORTED_PTF_TOPOS = ['ptf32', 'ptf64']
    SUPPORTED_ASIC_LIST = ["pac", "gr", "gr2", "gb", "td2", "th", "th2", "spc1", "spc2", "spc3", "spc4", "td3", "th3",
                           "j2c+", "jr2", "th5"]

    BREAKOUT_SKUS = ['Arista-7050-QX-32S']

    @pytest.fixture(scope='class', autouse=True)
    def dutTestParams(self, duthosts, dut_test_params_qos, tbinfo, get_src_dst_asic_and_duts):
        """
            Prepares DUT host test params
            Returns:
                dutTestParams (dict): DUT host test params
        """
        # update router mac
        if "t0-backend" in dut_test_params_qos["topo"]:
            duthost = get_src_dst_asic_and_duts['src_dut']
            dut_test_params_qos["basicParams"]["router_mac"] = duthost.shell(
                    'sonic-db-cli CONFIG_DB hget "DEVICE_METADATA|localhost" mac')['stdout']

        elif dut_test_params_qos["topo"] in self.SUPPORTED_T0_TOPOS:
            dut_test_params_qos["basicParams"]["router_mac"] = ''

        elif "dualtor" in tbinfo["topo"]["name"]:
            # For dualtor qos test scenario, DMAC of test traffic is default vlan interface's MAC address.
            # To reduce duplicated code, put "is_dualtor" and "def_vlan_mac" into dutTestParams['basicParams'].
            dut_test_params_qos["basicParams"]["is_dualtor"] = True

            vlan_cfgs = tbinfo['topo']['properties']['topology']['DUT']['vlan_configs']
            if vlan_cfgs and 'default_vlan_config' in vlan_cfgs:
                default_vlan_name = vlan_cfgs['default_vlan_config']
                if default_vlan_name:
                    for vlan in vlan_cfgs[default_vlan_name].values():
                        if 'mac' in vlan and vlan['mac']:
                            dut_test_params_qos["basicParams"]["def_vlan_mac"] = vlan['mac']
                            break

            pytest_assert(dut_test_params_qos["basicParams"]["def_vlan_mac"] is not None,
                          "Dual-TOR miss default VLAN MAC address")
        else:
            try:
                duthost = get_src_dst_asic_and_duts['src_dut']
                asic = duthost.asic_instance().asic_index
                dut_test_params_qos['basicParams']["router_mac"] = duthost.shell(
                    'sonic-db-cli -n asic{} CONFIG_DB hget "DEVICE_METADATA|localhost" mac'.format(asic))['stdout']
            except RunAnsibleModuleFail:
                dut_test_params_qos['basicParams']["router_mac"] = duthost.shell(
                    'sonic-db-cli CONFIG_DB hget "DEVICE_METADATA|localhost" mac')['stdout']

        yield dut_test_params_qos

    def runPtf(self, ptfhost, testDir, testCase='', testParams={}, relax=False, pdb=False):
        """
            Runs QoS test case on PTF host

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                testCase (str): SAI tests test case name
                testParams (dict): Map of test params required by testCase
                relax (bool): Relax ptf verify packet requirements (default: False)

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        custom_options = " --disable-ipv6 --disable-vxlan --disable-geneve" \
            " --disable-erspan --disable-mpls --disable-nvgre"
        # Append a suffix to the logfile name if log_suffix is present in testParams
        log_suffix = testParams.get("log_suffix", "")
        logfile_suffix = "_{0}".format(log_suffix) if log_suffix else ""

        ptf_runner(
            ptfhost,
            testDir,
            testCase,
            platform_dir="ptftests",
            params=testParams,
            log_file="/tmp/{0}{1}.log".format(testCase, logfile_suffix),  # Include suffix in the logfile name,
            qlen=10000,
            is_python3=True,
            relax=relax,
            timeout=1850,
            socket_recv_size=16384,
            custom_options=custom_options,
            pdb=pdb
        )

    def isLonglink(self, dut_host):
        config_facts = dut_host.asics[0].config_facts(source="running")["ansible_facts"]
        buffer_pg = config_facts["BUFFER_PG"]
        for intf, value_of_intf in buffer_pg.items():
            for _, v in value_of_intf.items():
                if "pg_lossless" in v['profile']:
                    profileName = v['profile']
                    logger.info("Lossless Buffer profile is {}".format(profileName))
                    m = re.search("^pg_lossless_[0-9]+_([0-9]+)m_profile", profileName)
                    pytest_assert(m.group(1), "Cannot find cable length")
                    cable_length = int(m.group(1))
                    if cable_length >= 120000:
                        return True
        return False

    @pytest.fixture(scope='class', name="select_src_dst_dut_and_asic",
                    params=["single_asic", "single_dut_multi_asic",
                            "multi_dut_longlink_to_shortlink",
                            "multi_dut_shortlink_to_shortlink",
                            "multi_dut_shortlink_to_longlink"])
    def select_src_dst_dut_and_asic(self, duthosts, request, tbinfo, lower_tor_host): # noqa F811
        test_port_selection_criteria = request.param
        logger.info("test_port_selection_criteria is {}".format(test_port_selection_criteria))
        src_dut_index = 0
        dst_dut_index = 0
        src_asic_index = 0
        dst_asic_index = 0
        src_long_link = False
        dst_long_link = False
        topo = tbinfo["topo"]["name"]
        if 'dualtor' in tbinfo['topo']['name']:
            # index of lower_tor_host
            for a_dut_index in range(len(duthosts)):
                if duthosts[a_dut_index] == lower_tor_host:
                    lower_tor_dut_index = a_dut_index
                    break

        number_of_duts = len(duthosts.frontend_nodes)
        is_longlink_list = [False] * number_of_duts
        for i in range(number_of_duts):
            if self.isLonglink(duthosts.frontend_nodes[i]):
                is_longlink_list[i] = True
        shortlink_indices = [i for i, longlink in enumerate(is_longlink_list) if not longlink]

        duthost = duthosts.frontend_nodes[0]
        if test_port_selection_criteria == 'single_asic':
            # We should randomly pick a dut from duthosts.frontend_nodes and a random asic in that selected DUT
            # for now hard code the first DUT and the first asic
            if 'dualtor' in tbinfo['topo']['name']:
                src_dut_index = lower_tor_dut_index
            elif topo not in (self.SUPPORTED_T0_TOPOS + self.SUPPORTED_T1_TOPOS) and shortlink_indices:
                src_dut_index = random.choice(shortlink_indices)
            else:
                src_dut_index = 0
            dst_dut_index = src_dut_index
            src_asic_index = 0
            dst_asic_index = 0

        elif test_port_selection_criteria == "single_dut_multi_asic":
            found_multi_asic_dut = False
            if topo in self.SUPPORTED_T0_TOPOS or isMellanoxDevice(duthost):
                pytest.skip("single_dut_multi_asic is not supported on T0 topologies")
            if topo not in self.SUPPORTED_T1_TOPOS and shortlink_indices:
                random.shuffle(shortlink_indices)
                for idx in shortlink_indices:
                    a_dut = duthosts.frontend_nodes[idx]
                    if a_dut.sonichost.is_multi_asic:
                        src_dut_index = idx
                        found_multi_asic_dut = True
                        break
            else:
                for a_dut_index in range(len(duthosts.frontend_nodes)):
                    a_dut = duthosts.frontend_nodes[a_dut_index]
                    if a_dut.sonichost.is_multi_asic:
                        src_dut_index = a_dut_index
                        found_multi_asic_dut = True
                        logger.info("Using dut {} for single_dut_multi_asic testing".format(a_dut.hostname))
                        break
            if not found_multi_asic_dut:
                pytest.skip(
                    "Did not find any frontend node that is multi-asic - so can't run single_dut_multi_asic tests")
            dst_dut_index = src_dut_index
            src_asic_index = 0
            dst_asic_index = 1

        else:
            # Dealing with multi-dut
            if topo in self.SUPPORTED_T0_TOPOS or isMellanoxDevice(duthost):
                pytest.skip("multi-dut is not supported on T0 topologies")
            elif topo in self.SUPPORTED_T1_TOPOS:
                pytest.skip("multi-dut is not supported on T1 topologies")

            if (len(duthosts.frontend_nodes)) < 2:
                pytest.skip("Don't have 2 frontend nodes - so can't run multi_dut tests")

            if test_port_selection_criteria == 'multi_dut_shortlink_to_shortlink':
                if is_longlink_list.count(False) < 2:
                    pytest.skip("Don't have 2 shortlink frontend nodes - so can't run {}"
                                "tests".format(test_port_selection_criteria))
                src_dut_index = is_longlink_list.index(False)
                dst_dut_index = is_longlink_list.index(False, src_dut_index + 1)
            else:
                if is_longlink_list.count(False) == 0 or is_longlink_list.count(True) == 0:
                    pytest.skip("Don't have longlink or shortlink frontend nodes - so can't"
                                "run {} tests".format(test_port_selection_criteria))
                if test_port_selection_criteria == 'multi_dut_longlink_to_shortlink':
                    src_dut_index = is_longlink_list.index(True)
                    dst_dut_index = is_longlink_list.index(False)
                    src_long_link = True
                else:
                    src_dut_index = is_longlink_list.index(False)
                    dst_dut_index = is_longlink_list.index(True)
                    dst_long_link = True

            src_asic_index = 0
            dst_asic_index = 0

        yield {
            "src_dut_index": src_dut_index,
            "dst_dut_index": dst_dut_index,
            "src_asic_index": src_asic_index,
            "dst_asic_index": dst_asic_index,
            "src_long_link": src_long_link,
            "dst_long_link": dst_long_link
        }

    @pytest.fixture(scope='class')
    def get_src_dst_asic_and_duts(self, duthosts, tbinfo, select_src_dst_dut_and_asic, lower_tor_host): # noqa F811
        if 'dualtor' in tbinfo['topo']['name']:
            src_dut = lower_tor_host
            dst_dut = lower_tor_host
        else:
            src_dut = duthosts.frontend_nodes[select_src_dst_dut_and_asic["src_dut_index"]]
            dst_dut = duthosts.frontend_nodes[select_src_dst_dut_and_asic["dst_dut_index"]]

        src_asic = src_dut.asics[select_src_dst_dut_and_asic["src_asic_index"]]
        dst_asic = dst_dut.asics[select_src_dst_dut_and_asic["dst_asic_index"]]

        all_asics = [src_asic]
        if src_asic != dst_asic:
            all_asics.append(dst_asic)

        all_duts = [src_dut]
        if src_dut != dst_dut:
            all_duts.append(dst_dut)

        rtn_dict = {
            "src_asic": src_asic,
            "dst_asic": dst_asic,
            "src_dut": src_dut,
            "dst_dut": dst_dut,
            "single_asic_test": (src_dut == dst_dut and src_asic == dst_asic),
            "all_asics": all_asics,
            "all_duts": all_duts
        }
        rtn_dict.update(select_src_dst_dut_and_asic)
        yield rtn_dict

    def __buildTestPorts(self, request, testPortIds, testPortIps, src_port_ids, dst_port_ids,
                         get_src_dst_asic_and_duts, uplinkPortIds, sysPortMap=None):
        """
            Build map of test ports index and IPs

            Args:
                request (Fixture): pytest request object
                testPortIds (list): List of QoS SAI test port IDs
                testPortIps (list): List of QoS SAI test port IPs

            Returns:
                testPorts (dict): Map of test ports index and IPs
                sysPortMap (dict): Map of system port IDs and Qos SAI test port IDs
        """
        dstPorts = request.config.getoption("--qos_dst_ports")
        srcPorts = request.config.getoption("--qos_src_ports")

        logging.debug("__buildTestPorts testPortIds: {}, testPortIps: {}, src_port_ids: {}, \
                      dst_port_ids: {}, get_src_dst_asic_and_duts: {}, uplinkPortIds: {}".format(
                      testPortIds, testPortIps, src_port_ids, dst_port_ids, get_src_dst_asic_and_duts, uplinkPortIds))

        src_dut_port_ids = testPortIds[get_src_dst_asic_and_duts['src_dut_index']]
        src_test_port_ids = src_dut_port_ids[get_src_dst_asic_and_duts['src_asic_index']]
        dst_dut_port_ids = testPortIds[get_src_dst_asic_and_duts['dst_dut_index']]
        dst_test_port_ids = dst_dut_port_ids[get_src_dst_asic_and_duts['dst_asic_index']]

        src_dut_port_ips = testPortIps[get_src_dst_asic_and_duts['src_dut_index']]
        src_test_port_ips = src_dut_port_ips[get_src_dst_asic_and_duts['src_asic_index']]
        dst_dut_port_ips = testPortIps[get_src_dst_asic_and_duts['dst_dut_index']]
        dst_test_port_ips = dst_dut_port_ips[get_src_dst_asic_and_duts['dst_asic_index']]

        if dstPorts is None:
            if dst_port_ids:
                pytest_assert(
                    len(set(dst_test_port_ids).intersection(
                        set(dst_port_ids))) == len(set(dst_port_ids)),
                    "Dest port id passed in qos.yml not valid"
                )
                dstPorts = dst_port_ids
            elif len(dst_test_port_ids) >= 5 and (get_src_dst_asic_and_duts["src_asic"].sonichost.facts["asic_type"]
                                                  in ['cisco-8000']):
                dstPorts = [2, 3, 4]
            elif len(dst_test_port_ids) >= 4:
                dstPorts = [0, 2, 3]
            elif len(dst_test_port_ids) == 3:
                dstPorts = [0, 2, 2]
            else:
                dstPorts = [0, 0, 0]

        if srcPorts is None:
            if src_port_ids:
                pytest_assert(
                    len(set(src_test_port_ids).intersection(
                        set(src_port_ids))) == len(set(src_port_ids)),
                    "Source port id passed in qos.yml not valid"
                )
                # To verify ingress lossless speed/cable-length randomize the source port.
                srcPorts = [random.choice(src_port_ids)]
            else:
                srcPorts = [1]
        if (get_src_dst_asic_and_duts["src_asic"].sonichost.facts["hwsku"]
                in ["Cisco-8101-O8C48", "Cisco-8101-O8V48", "Cisco-8102-28FH-DPU-O-T1"]):
            srcPorts = [testPortIds[0][0].index(uplinkPortIds[0])]
            dstPorts = [testPortIds[0][0].index(x) for x in uplinkPortIds[1:4]]
            logging.debug("Test Port dst:{}, src:{}".format(dstPorts, srcPorts))

        pytest_assert(len(dst_test_port_ids) >= 1 and len(src_test_port_ids) >= 1, "Provide at least 2 test ports")
        logging.debug(
            "Test Port IDs:{} IPs:{}".format(testPortIds, testPortIps)
        )
        logging.debug("Test Port dst:{}, src:{}".format(dstPorts, srcPorts))

        pytest_assert(
            len(set(dstPorts).intersection(set(srcPorts))) == 0,
            "Duplicate destination and source ports '{0}'".format(
                set(dstPorts).intersection(set(srcPorts))
            )
        )

        # TODO: Randomize port selection
        dstPort = dstPorts[0] if dst_port_ids else dst_test_port_ids[dstPorts[0]]
        dstVlan = dst_test_port_ips[dstPort]['vlan_id'] if 'vlan_id' in dst_test_port_ips[dstPort] else None
        dstPort2 = dstPorts[1] if dst_port_ids else dst_test_port_ids[dstPorts[1]]
        dstVlan2 = dst_test_port_ips[dstPort2]['vlan_id'] if 'vlan_id' in dst_test_port_ips[dstPort2] else None
        dstPort3 = dstPorts[2] if dst_port_ids else dst_test_port_ids[dstPorts[2]]
        dstVlan3 = dst_test_port_ips[dstPort3]['vlan_id'] if 'vlan_id' in dst_test_port_ips[dstPort3] else None
        srcPort = srcPorts[0] if src_port_ids else src_test_port_ids[srcPorts[0]]
        srcVlan = src_test_port_ips[srcPort]['vlan_id'] if 'vlan_id' in src_test_port_ips[srcPort] else None

        # collecting the system ports associated with dst ports
        # In case of PortChannel as dst port, all lag ports will be added to the list
        # ex. {dstPort: system_port, dstPort1:system_port1 ...}
        dst_all_sys_port = {}
        if 'platform_asic' in get_src_dst_asic_and_duts["src_dut"].facts and \
                get_src_dst_asic_and_duts["src_dut"].facts['platform_asic'] == 'broadcom-dnx':
            sysPorts = sysPortMap[get_src_dst_asic_and_duts['dst_dut_index']][
                get_src_dst_asic_and_duts['dst_asic_index']]
            for port_id in [dstPort, dstPort2, dstPort3]:
                if port_id in sysPorts and port_id not in dst_all_sys_port:
                    dst_all_sys_port.update({port_id: sysPorts[port_id]['system_port']})
                    if 'PortChannel' in sysPorts[port_id]['port_type']:
                        for sport, sysMap in sysPorts.items():
                            if sysMap['port_type'] == sysPorts[port_id]['port_type'] and sport != port_id:
                                dst_all_sys_port.update({sport: sysMap['system_port']})

        return {
         "dst_port_id": dstPort,
         "dst_port_ip": dst_test_port_ips[dstPort]['peer_addr'],
         "dst_port_vlan": dstVlan,
         "dst_port_2_id": dstPort2,
         "dst_port_2_ip": dst_test_port_ips[dstPort2]['peer_addr'],
         "dst_port_2_vlan": dstVlan2,
         'dst_port_3_id': dstPort3,
         "dst_port_3_ip": dst_test_port_ips[dstPort3]['peer_addr'],
         "dst_port_3_vlan": dstVlan3,
         "src_port_id": srcPort,
         "src_port_ip": src_test_port_ips[srcPorts[0] if src_port_ids else src_test_port_ids[srcPorts[0]]]["peer_addr"],
         "src_port_vlan": srcVlan,
         "dst_sys_ports": dst_all_sys_port
        }

    def __buildPortSpeeds(self, config_facts):
        port_speeds = collections.defaultdict(list)
        for etp, attr in config_facts['PORT'].items():
            port_speeds[attr['speed']].append(etp)
        return port_speeds

    @pytest.fixture(scope='class', autouse=False)
    def configure_ip_on_ptf_intfs(self, ptfhost, get_src_dst_asic_and_duts, tbinfo):
        src_dut = get_src_dst_asic_and_duts['src_dut']
        src_mgFacts = src_dut.get_extended_minigraph_facts(tbinfo)
        topo = tbinfo["topo"]["name"]

        # if PTF64 and is Cisco, set ip IP address on eth interfaces of the ptf"
        if topo == 'ptf64' and is_cisco_device(src_dut):
            minigraph_ip_interfaces = src_mgFacts['minigraph_interfaces']
            for entry in minigraph_ip_interfaces:
                ptfhost.shell("ip addr add {}/31 dev eth{}".format(
                      entry['peer_addr'], src_mgFacts["minigraph_ptf_indices"][entry['attachto']])
                    )
            yield
            for entry in minigraph_ip_interfaces:
                ptfhost.shell("ip addr del {}/31 dev eth{}".format(
                      entry['peer_addr'], src_mgFacts["minigraph_ptf_indices"][entry['attachto']])
                    )
            return
        else:
            yield
            return

    @pytest.fixture(scope='class')
    def dualtor_ports_for_duts(request, get_src_dst_asic_and_duts):
        # Fetch dual ToR ports
        logger.info("Starting fetching dual ToR info")

        fetch_dual_tor_ports_script = "\
            local remap_enabled = redis.call('HGET', 'SYSTEM_DEFAULTS|tunnel_qos_remap', 'status')\
            if remap_enabled ~= 'enabled' then\
                return {}\
            end\
            local type = redis.call('HGET', 'DEVICE_METADATA|localhost', 'type')\
            local expected_neighbor_type\
            local expected_neighbor_suffix\
            if type == 'LeafRouter' then\
                expected_neighbor_type = 'ToRRouter'\
                expected_neighbor_suffix = 'T0'\
            else\
                if type == 'ToRRouter' then\
                    local subtype = redis.call('HGET', 'DEVICE_METADATA|localhost', 'subtype')\
                    if subtype == 'DualToR' then\
                        expected_neighbor_type = 'LeafRouter'\
                        expected_neighbor_suffix = 'T1'\
                    end\
                end\
            end\
            if expected_neighbor_type == nil then\
                return {}\
            end\
            local result = {}\
            local all_ports_with_neighbor = redis.call('KEYS', 'DEVICE_NEIGHBOR|*')\
            for i = 1, #all_ports_with_neighbor, 1 do\
                local neighbor = redis.call('HGET', all_ports_with_neighbor[i], 'name')\
                if neighbor ~= nil and string.sub(neighbor, -2, -1) == expected_neighbor_suffix then\
                    local peer_type = redis.call('HGET', 'DEVICE_NEIGHBOR_METADATA|' .. neighbor, 'type')\
                    if peer_type == expected_neighbor_type then\
                        table.insert(result, string.sub(all_ports_with_neighbor[i], 17, -1))\
                    end\
                end\
            end\
            return result\
        "

        duthost = get_src_dst_asic_and_duts['src_dut']  # noqa F841

        dualtor_ports_str = get_src_dst_asic_and_duts['src_asic'].run_redis_cmd(
            argv=["sonic-db-cli", "CONFIG_DB", "eval", fetch_dual_tor_ports_script, "0"])
        if dualtor_ports_str:
            dualtor_ports_set = set(dualtor_ports_str)
        else:
            dualtor_ports_set = set({})

        logger.info("Finish fetching dual ToR info {}".format(dualtor_ports_set))

        return dualtor_ports_set

    @pytest.fixture(scope='class', autouse=True)
    def dutConfig(
        self, request, duthosts, configure_ip_on_ptf_intfs, get_src_dst_asic_and_duts,
        lower_tor_host, tbinfo, dualtor_ports_for_duts, dut_qos_maps):  # noqa F811
        """
            Build DUT host config pertaining to QoS SAI tests

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                dutConfig (dict): Map of DUT config containing dut interfaces,
                test port IDs, test port IPs, and test ports
        """

        """
        Below are dictionaries with key being dut_index and value a dictionary with key asic_index
        Example for 2 DUTs with 2 asics each
            { 0: { 0: <asic0_value>, 1: <asic1_value>}, 1: { 0: <asic0_value>, 1: <asic1_value> }}
        """
        dutPortIps = {}
        testPortIps = {}
        testPortIds = {}
        dualTorPortIndexes = {}
        uplinkPortIds = []
        uplinkPortIps = []
        uplinkPortNames = []
        downlinkPortIds = []
        downlinkPortIps = []
        downlinkPortNames = []
        sysPortMap = {}

        src_dut_index = get_src_dst_asic_and_duts['src_dut_index']
        src_asic_index = get_src_dst_asic_and_duts['src_asic_index']
        src_dut = get_src_dst_asic_and_duts['src_dut']
        dst_dut = get_src_dst_asic_and_duts['dst_dut']
        src_mgFacts = src_dut.get_extended_minigraph_facts(tbinfo)
        topo = tbinfo["topo"]["name"]
        src_mgFacts['minigraph_ptf_indices'] = {
            key: value
            for key, value in src_mgFacts['minigraph_ptf_indices'].items()
            if not key.startswith("Ethernet-BP")
            }
        src_mgFacts['minigraph_ports'] = {
            key: value
            for key, value in src_mgFacts['minigraph_ports'].items()
            if not key.startswith("Ethernet-BP")
            }

        # LAG ports in T1 TOPO need to be removed in Mellanox devices
        if topo in self.SUPPORTED_T0_TOPOS or (topo in self.SUPPORTED_PTF_TOPOS and isMellanoxDevice(src_dut)):
            # Only single asic is supported for this scenario, so use src_dut and src_asic - which will be the same
            # as dst_dut and dst_asic
            pytest_assert(
                not src_dut.sonichost.is_multi_asic, "Fixture not supported on T0 multi ASIC"
            )
            dutLagInterfaces = []
            testPortIds[src_dut_index] = {}
            for _, lag in src_mgFacts["minigraph_portchannels"].items():
                for intf in lag["members"]:
                    dutLagInterfaces.append(src_mgFacts["minigraph_ptf_indices"][intf])

            config_facts = duthosts.config_facts(host=src_dut.hostname, source="running")
            port_speeds = self.__buildPortSpeeds(config_facts[src_dut.hostname])
            low_speed_portIds = []
            if src_dut.facts['hwsku'] in self.BREAKOUT_SKUS and 'backend' not in topo:
                for speed, portlist in port_speeds.items():
                    if int(speed) < 40000:
                        for portname in portlist:
                            low_speed_portIds.append(src_mgFacts["minigraph_ptf_indices"][portname])

            testPortIds[src_dut_index][src_asic_index] = set(src_mgFacts["minigraph_ptf_indices"][port]
                                                             for port in src_mgFacts["minigraph_ports"].keys())
            testPortIds[src_dut_index][src_asic_index] -= set(dutLagInterfaces)
            testPortIds[src_dut_index][src_asic_index] -= set(low_speed_portIds)
            if isMellanoxDevice(src_dut):
                # The last port is used for up link from DUT switch
                testPortIds[src_dut_index][src_asic_index] -= {len(src_mgFacts["minigraph_ptf_indices"]) - 1}
            testPortIds[src_dut_index][src_asic_index] = sorted(testPortIds[src_dut_index][src_asic_index])
            pytest_require(len(testPortIds[src_dut_index][src_asic_index]) != 0,
                           "Skip test since no ports are available for testing")

            # get current DUT port IPs
            dutPortIps[src_dut_index] = {}
            dutPortIps[src_dut_index][src_asic_index] = {}
            dualTorPortIndexes[src_dut_index] = {}
            dualTorPortIndexes[src_dut_index][src_asic_index] = []
            if 'backend' in topo:
                intf_map = src_mgFacts["minigraph_vlan_sub_interfaces"]
            else:
                intf_map = src_mgFacts["minigraph_interfaces"]

            use_separated_upkink_dscp_tc_map = separated_dscp_to_tc_map_on_uplink(dut_qos_maps)
            for portConfig in intf_map:
                intf = portConfig["attachto"].split(".")[0]
                if ipaddress.ip_interface(portConfig['peer_addr']).ip.version == 4:
                    portIndex = src_mgFacts["minigraph_ptf_indices"][intf]
                    if portIndex in testPortIds[src_dut_index][src_asic_index]:
                        portIpMap = {'peer_addr': portConfig["peer_addr"]}
                        if 'vlan' in portConfig:
                            portIpMap['vlan_id'] = portConfig['vlan']
                        dutPortIps[src_dut_index][src_asic_index].update({portIndex: portIpMap})
                        if intf in dualtor_ports_for_duts:
                            dualTorPortIndexes[src_dut_index][src_asic_index].append(portIndex)
                    # If the leaf router is using separated DSCP_TO_TC_MAP on uplink/downlink ports.
                    # we also need to test them separately
                    # for mellanox device, we run it on t1 topo mocked by ptf32 topo
                    if use_separated_upkink_dscp_tc_map and isMellanoxDevice(src_dut):
                        neighName = src_mgFacts["minigraph_neighbors"].get(intf, {}).get("name", "").lower()
                        if 't0' in neighName:
                            downlinkPortIds.append(portIndex)
                            downlinkPortIps.append(portConfig["peer_addr"])
                            downlinkPortNames.append(intf)
                        elif 't2' in neighName:
                            uplinkPortIds.append(portIndex)
                            uplinkPortIps.append(portConfig["peer_addr"])
                            uplinkPortNames.append(intf)

            if isMellanoxDevice(src_dut):
                dualtor_dut_ports = dualtor_ports_for_duts if topo in self.SUPPORTED_PTF_TOPOS else None
                testPortIds[src_dut_index][src_asic_index] = self.select_port_ids_for_mellnaox_device(
                    src_dut, src_mgFacts, testPortIds[src_dut_index][src_asic_index], dualtor_dut_ports)
                dualTorPortIndexes = testPortIds

            testPortIps[src_dut_index] = {}
            testPortIps[src_dut_index][src_asic_index] = self.__assignTestPortIps(src_mgFacts, topo)

            # restore currently assigned IPs
            if len(dutPortIps[src_dut_index][src_asic_index]) != 0:
                testPortIps.update(dutPortIps)

            if 'backend' in topo:
                # since backend T0 utilize dot1q encap pkts, testPortIds need to be repopulated with the
                # associated sub-interfaces stored in testPortIps
                testPortIds[src_dut_index][src_asic_index] = sorted(
                    list(testPortIps[src_dut_index][src_asic_index].keys()))

        elif topo in self.SUPPORTED_T1_TOPOS or (topo in self.SUPPORTED_PTF_TOPOS and is_cisco_device(src_dut)):
            # T1 is supported only for 'single_asic' or 'single_dut_multi_asic'.
            # So use src_dut as the dut
            use_separated_upkink_dscp_tc_map = separated_dscp_to_tc_map_on_uplink(dut_qos_maps)
            dutPortIps[src_dut_index] = {}
            testPortIds[src_dut_index] = {}
            for dut_asic in get_src_dst_asic_and_duts['all_asics']:
                dutPortIps[src_dut_index][dut_asic.asic_index] = {}
                for iface, addr in dut_asic.get_active_ip_interfaces(tbinfo).items():
                    vlan_id = None
                    if iface.startswith("Ethernet"):
                        portName = iface
                        if "." in iface:
                            portName, vlan_id = iface.split(".")
                        portIndex = src_mgFacts["minigraph_ptf_indices"][portName]
                        portIpMap = {'peer_addr': addr["peer_ipv4"]}
                        if vlan_id is not None:
                            portIpMap['vlan_id'] = vlan_id
                        dutPortIps[src_dut_index][dut_asic.asic_index].update({portIndex: portIpMap})
                    elif iface.startswith("PortChannel"):
                        portName = next(
                            iter(src_mgFacts["minigraph_portchannels"][iface]["members"])
                        )
                        portIndex = src_mgFacts["minigraph_ptf_indices"][portName]
                        portIpMap = {'peer_addr': addr["peer_ipv4"]}
                        dutPortIps[src_dut_index][dut_asic.asic_index].update({portIndex: portIpMap})
                    # If the leaf router is using separated DSCP_TO_TC_MAP on uplink/downlink ports.
                    # we also need to test them separately
                    if (use_separated_upkink_dscp_tc_map or
                        (get_src_dst_asic_and_duts["src_asic"]
                         .sonichost.facts["hwsku"]
                         in ["Cisco-8101-O8C48", "Cisco-8101-O8V48", "Cisco-8102-28FH-DPU-O-T1"])):
                        neighName = src_mgFacts["minigraph_neighbors"].get(portName, {}).get("name", "").lower()
                        if 't0' in neighName:
                            downlinkPortIds.append(portIndex)
                            downlinkPortIps.append(addr["peer_ipv4"])
                            downlinkPortNames.append(portName)
                        elif 't2' in neighName:
                            uplinkPortIds.append(portIndex)
                            uplinkPortIps.append(addr["peer_ipv4"])
                            uplinkPortNames.append(portName)

                testPortIds[src_dut_index][dut_asic.asic_index] = sorted(
                    dutPortIps[src_dut_index][dut_asic.asic_index].keys())

                if isMellanoxDevice(src_dut):
                    # For T1 in dualtor scenario, we always select the dualtor ports as source ports
                    dualtor_dut_ports = dualtor_ports_for_duts if 't1' in tbinfo['topo']['type'] else None
                    testPortIds[src_dut_index][dut_asic.asic_index] = self.select_port_ids_for_mellnaox_device(
                        src_dut, src_mgFacts, testPortIds[src_dut_index][dut_asic.asic_index], dualtor_dut_ports)

            # Need to fix this
            testPortIps[src_dut_index] = {}
            testPortIps[src_dut_index][src_asic_index] = self.__assignTestPortIps(src_mgFacts, topo)

            # restore currently assigned IPs
            if len(dutPortIps[src_dut_index][src_asic_index]) != 0:
                testPortIps.update(dutPortIps)

        elif "t2" in tbinfo["topo"]["type"]:
            src_asic = get_src_dst_asic_and_duts['src_asic']
            dst_dut_index = get_src_dst_asic_and_duts['dst_dut_index']
            dst_asic = get_src_dst_asic_and_duts['dst_asic']
            src_system_port = {}
            if 'platform_asic' in get_src_dst_asic_and_duts["src_dut"].facts and \
                    get_src_dst_asic_and_duts["src_dut"].facts['platform_asic'] == 'broadcom-dnx':
                src_system_port = src_dut.config_facts(host=src_dut.hostname, source='running')['ansible_facts'][
                    'SYSTEM_PORT'][src_dut.hostname]

            # Lets get data for the src dut and src asic
            dutPortIps[src_dut_index] = {}
            sysPortMap[src_dut_index] = {}
            testPortIds[src_dut_index] = {}
            dutPortIps[src_dut_index][src_asic_index] = {}
            sysPortMap[src_dut_index][src_asic_index] = {}
            active_ips = src_asic.get_active_ip_interfaces(tbinfo)
            src_namespace_prefix = src_asic.namespace + '|' if src_asic.namespace else f'Asic{src_asic.asic_index}|'
            for iface, addr in active_ips.items():
                if iface.startswith("Ethernet") and ("Ethernet-Rec" not in iface):
                    portIndex = src_mgFacts["minigraph_ptf_indices"][iface]
                    portIpMap = {'peer_addr': addr["peer_ipv4"], 'port': iface}
                    dutPortIps[src_dut_index][src_asic_index].update({portIndex: portIpMap})
                    # Map port IDs to system port for dnx chassis
                    if 'platform_asic' in get_src_dst_asic_and_duts["src_dut"].facts and \
                            get_src_dst_asic_and_duts["src_dut"].facts['platform_asic'] == 'broadcom-dnx':
                        sys_key = src_namespace_prefix + iface
                        if sys_key in src_system_port:
                            system_port = src_system_port[sys_key]['system_port_id']
                            sysPort = {'port': iface, 'system_port': system_port, 'port_type': iface}
                            sysPortMap[src_dut_index][src_asic_index].update({portIndex: sysPort})

                elif iface.startswith("PortChannel"):
                    portName = next(
                        iter(src_mgFacts["minigraph_portchannels"][iface]["members"])
                    )
                    portIndex = src_mgFacts["minigraph_ptf_indices"][portName]
                    portIpMap = {'peer_addr': addr["peer_ipv4"], 'port': portName}
                    dutPortIps[src_dut_index][src_asic_index].update({portIndex: portIpMap})
                    # Map lag port IDs to system port IDs for dnx chassis
                    if 'platform_asic' in get_src_dst_asic_and_duts["src_dut"].facts and \
                            get_src_dst_asic_and_duts["src_dut"].facts['platform_asic'] == 'broadcom-dnx':
                        for portName in src_mgFacts["minigraph_portchannels"][iface]["members"]:
                            sys_key = src_namespace_prefix + portName
                            port_Index = src_mgFacts["minigraph_ptf_indices"][portName]
                            if sys_key in src_system_port:
                                system_port = src_system_port[sys_key]['system_port_id']
                                sysPort = {'port': portName, 'system_port': system_port, 'port_type': iface}
                                sysPortMap[src_dut_index][src_asic_index].update({port_Index: sysPort})

            testPortIds[src_dut_index][src_asic_index] = sorted(dutPortIps[src_dut_index][src_asic_index].keys())

            if dst_asic != src_asic:
                # Dealing with different asic
                dst_dut = get_src_dst_asic_and_duts['dst_dut']
                dst_asic_index = get_src_dst_asic_and_duts['dst_asic_index']
                if dst_dut_index != src_dut_index:
                    dst_mgFacts = dst_dut.get_extended_minigraph_facts(tbinfo)
                    dutPortIps[dst_dut_index] = {}
                    testPortIds[dst_dut_index] = {}
                    sysPortMap[dst_dut_index] = {}
                    dst_system_port = {}
                    if 'platform_asic' in get_src_dst_asic_and_duts["src_dut"].facts and \
                            get_src_dst_asic_and_duts["src_dut"].facts['platform_asic'] == 'broadcom-dnx':
                        dst_system_port = dst_dut.config_facts(host=dst_dut.hostname, source='running')[
                            'ansible_facts']['SYSTEM_PORT'][dst_dut.hostname]
                else:
                    dst_mgFacts = src_mgFacts
                    dst_system_port = src_system_port
                dutPortIps[dst_dut_index][dst_asic_index] = {}
                sysPortMap[dst_dut_index][dst_asic_index] = {}
                dst_namespace_prefix = dst_asic.namespace + '|' if dst_asic.namespace else f'Asic{dst_asic.asic_index}|'
                active_ips = dst_asic.get_active_ip_interfaces(tbinfo)
                for iface, addr in active_ips.items():
                    if iface.startswith("Ethernet") and ("Ethernet-Rec" not in iface):
                        portIndex = dst_mgFacts["minigraph_ptf_indices"][iface]
                        portIpMap = {'peer_addr': addr["peer_ipv4"], 'port': iface}
                        dutPortIps[dst_dut_index][dst_asic_index].update({portIndex: portIpMap})
                        # Map port IDs to system port IDs
                        if 'platform_asic' in get_src_dst_asic_and_duts["src_dut"].facts and \
                                get_src_dst_asic_and_duts["src_dut"].facts['platform_asic'] == 'broadcom-dnx':
                            sys_key = dst_namespace_prefix + iface
                            if sys_key in dst_system_port:
                                system_port = dst_system_port[sys_key]['system_port_id']
                                sysPort = {'port': iface, 'system_port': system_port, 'port_type': iface}
                                sysPortMap[dst_dut_index][dst_asic_index].update({portIndex: sysPort})

                    elif iface.startswith("PortChannel"):
                        portName = next(
                            iter(dst_mgFacts["minigraph_portchannels"][iface]["members"])
                        )
                        portIndex = dst_mgFacts["minigraph_ptf_indices"][portName]
                        portIpMap = {'peer_addr': addr["peer_ipv4"], 'port': portName}
                        dutPortIps[dst_dut_index][dst_asic_index].update({portIndex: portIpMap})
                        # Map lag port IDs to system port IDs
                        if 'platform_asic' in get_src_dst_asic_and_duts["src_dut"].facts and \
                                get_src_dst_asic_and_duts["src_dut"].facts['platform_asic'] == 'broadcom-dnx':
                            for portName in dst_mgFacts["minigraph_portchannels"][iface]["members"]:
                                sys_key = dst_namespace_prefix + portName
                                port_Index = dst_mgFacts["minigraph_ptf_indices"][portName]
                                if sys_key in dst_system_port:
                                    system_port = dst_system_port[sys_key]['system_port_id']
                                    sysPort = {'port': portName, 'system_port': system_port, 'port_type': iface}
                                    sysPortMap[dst_dut_index][dst_asic_index].update({port_Index: sysPort})

                testPortIds[dst_dut_index][dst_asic_index] = sorted(dutPortIps[dst_dut_index][dst_asic_index].keys())

            # restore currently assigned IPs
            testPortIps.update(dutPortIps)

        vendor = src_dut.facts["asic_type"]
        qosConfigs = {}
        if vendor == "vs":
            with open(r"qos/files/vs/dutConfig.json") as file:
                dutConfig = json.load(file)
                qosConfigs = dutConfig["qosConfigs"]
                dutAsic = "vs"
                dstDutAsic = "vs"
        else:
            with open(r"qos/files/qos.yml") as file:
                qosConfigs = yaml.load(file, Loader=yaml.FullLoader)
            # Assuming the same chipset for all DUTs so can use src_dut to get asic type
            hostvars = src_dut.host.options['variable_manager']._hostvars[src_dut.hostname]
            dutAsic = None
            for asic in self.SUPPORTED_ASIC_LIST:
                vendorAsic = "{0}_{1}_hwskus".format(vendor, asic)
                if vendorAsic in hostvars.keys() and src_mgFacts["minigraph_hwsku"] in hostvars[vendorAsic]:
                    dutAsic = asic
                    break

            pytest_assert(dutAsic, "Cannot identify DUT ASIC type")

            # Get dst_dut asic type
            if dst_dut != src_dut:
                vendor = dst_dut.facts["asic_type"]
                hostvars = dst_dut.host.options['variable_manager']._hostvars[dst_dut.hostname]
                dstDutAsic = None
                for asic in self.SUPPORTED_ASIC_LIST:
                    vendorAsic = "{0}_{1}_hwskus".format(vendor, asic)
                    if vendorAsic in hostvars.keys() and dst_mgFacts["minigraph_hwsku"] in hostvars[vendorAsic]:
                        dstDutAsic = asic
                        break

                pytest_assert(dstDutAsic, "Cannot identify dst DUT ASIC type")
            else:
                dstDutAsic = dutAsic

        dutTopo = "topo-"

        if dutAsic == "gb" and "t2" in topo:
            if get_src_dst_asic_and_duts['src_asic'] == \
                    get_src_dst_asic_and_duts['dst_asic']:
                dutTopo = dutTopo + "any"
            else:
                dutTopo = dutTopo + topo
        elif dutTopo + topo in qosConfigs['qos_params'].get(dutAsic, {}):
            dutTopo = dutTopo + topo
        else:
            # Default topo is any
            dutTopo = dutTopo + "any"

        # Support of passing source and dest ptf port id from qos.yml
        # This is needed when on some asic port are distributed across
        # multiple buffer pipes.
        src_port_ids = None
        dst_port_ids = None
        try:
            if "src_port_ids" in qosConfigs['qos_params'][dutAsic][dutTopo]:
                src_port_ids = qosConfigs['qos_params'][dutAsic][dutTopo]["src_port_ids"]

            if "dst_port_ids" in qosConfigs['qos_params'][dutAsic][dutTopo]:
                dst_port_ids = qosConfigs['qos_params'][dutAsic][dutTopo]["dst_port_ids"]
        except KeyError:
            pass

        dualTor = request.config.getoption("--qos_dual_tor")
        if dualTor:
            testPortIds = dualTorPortIndexes

        testPorts = self.__buildTestPorts(request, testPortIds, testPortIps, src_port_ids, dst_port_ids,
                                          get_src_dst_asic_and_duts, uplinkPortIds, sysPortMap)
        # Update the uplink/downlink ports to testPorts
        testPorts.update({
            "uplink_port_ids": uplinkPortIds,
            "uplink_port_ips": uplinkPortIps,
            "uplink_port_names": uplinkPortNames,
            "downlink_port_ids": downlinkPortIds,
            "downlink_port_ips": downlinkPortIps,
            "downlink_port_names": downlinkPortNames
        })
        logging.debug("testPorts: {}".format(testPorts))

        dutinterfaces = {}
        uplinkPortIds = testPorts.get('uplink_port_ids', [])

        if tbinfo["topo"]["type"] == "t2":
            # dutportIps={0: {0: {0: {'peer_addr': u'10.0.0.1', 'port': u'Ethernet8'},
            # 2: {'peer_addr': u'10.0.0.5', 'port': u'Ethernet17'}}}}
            # { 0: 'Ethernet8', 2: 'Ethernet17' }
            for dut_index, dut_val in dutPortIps.items():
                for asic_index, asic_val in dut_val.items():
                    for ptf_port, ptf_val in asic_val.items():
                        dutinterfaces[ptf_port] = ptf_val['port']
        else:
            dutinterfaces = {
                index: port for port, index in src_mgFacts["minigraph_ptf_indices"].items()
            }

        dutPorts = {}
        # dutPorts = {0: {"portName": "Ethernet0", "lagName": "PortChannel101",
        # "lagMembers": ["Ethernet0", "Ethernet8"]}, 1: {...}}
        for portName, portId in src_mgFacts["minigraph_ptf_indices"].items():
            dutPorts[portId] = {}
            dutPorts[portId]["portName"] = portName
            for portchannelName, value in src_mgFacts["minigraph_portchannels"].items():
                if portName in value["members"]:
                    dutPorts[portId]["lagName"] = portchannelName
                    dutPorts[portId]["lagMembers"] = value["members"]
        if src_dut != dst_dut:
            for portName, portId in dst_mgFacts["minigraph_ptf_indices"].items():
                dutPorts[portId] = {}
                dutPorts[portId]["portName"] = portName
                for portchannelName, value in dst_mgFacts["minigraph_portchannels"].items():
                    if portName in value["members"]:
                        dutPorts[portId]["lagName"] = portchannelName
                        dutPorts[portId]["lagMembers"] = value["members"]

        yield {
            "dutInterfaces": dutinterfaces,
            "uplinkPortIds": uplinkPortIds,
            "testPortIds": testPortIds,
            "testPortIps": testPortIps,
            "testPorts": testPorts,
            "qosConfigs": qosConfigs,
            "dutAsic": dutAsic,
            "dstDutAsic": dstDutAsic,
            "dutTopo": dutTopo,
            "srcDutInstance": src_dut,
            "dstDutInstance": dst_dut,
            "dualTor": request.config.getoption("--qos_dual_tor"),
            "dualTorScenario": len(dualtor_ports_for_duts) != 0,
            "dutPorts": dutPorts
        }

    def copy_dshell_script_cisco_8000(self, dut, asic, dshell_script, script_name):
        if dut.facts['asic_type'] != "cisco-8000":
            raise RuntimeError("This function should have been called only for cisco-8000.")

        script_path = "/tmp/{}".format(script_name)
        dut.copy(content=dshell_script, dest=script_path)
        if dut.sonichost.is_multi_asic:
            dest = f"syncd{asic}"
        else:
            dest = "syncd"
        dut.docker_copy_to_all_asics(
            container_name=dest,
            src=script_path,
            dst="/")

    def copy_set_voq_watchdog_script_cisco_8000(self, dut, asic="", enable=True):
        dshell_script = '''
from common import d0
def set_voq_watchdog(enable):
    d0.set_bool_property(sdk.la_device_property_e_VOQ_WATCHDOG_ENABLED, enable)
set_voq_watchdog({})
    '''.format(enable)

        self.copy_dshell_script_cisco_8000(dut, asic, dshell_script,
                                           script_name="set_voq_watchdog.py")

    def disable_voq_watchdog(self, duthosts, get_src_dst_asic_and_duts):
        dst_dut = get_src_dst_asic_and_duts['dst_dut']
        dst_asic = get_src_dst_asic_and_duts['dst_asic']
        dut_list = [dst_dut]
        asic_index_list = [dst_asic.asic_index]

        if not get_src_dst_asic_and_duts["single_asic_test"]:
            src_dut = get_src_dst_asic_and_duts['src_dut']
            src_asic = get_src_dst_asic_and_duts['src_asic']
            dut_list.append(src_dut)
            asic_index_list.append(src_asic.asic_index)
            # fabric card asics
            for rp_dut in duthosts.supervisor_nodes:
                for asic in rp_dut.asics:
                    dut_list.append(rp_dut)
                    asic_index_list.append(asic.asic_index)

        if dst_dut.facts['asic_type'] != "cisco-8000" or not dst_dut.sonichost.is_multi_asic:
            yield
            return

        # Disable voq watchdog.
        for (dut, asic_index) in zip(dut_list, asic_index_list):
            self.copy_set_voq_watchdog_script_cisco_8000(
                dut=dut,
                asic=asic_index,
                enable=False)
            cmd_opt = "-n asic{}".format(asic_index)
            if not dst_dut.sonichost.is_multi_asic:
                cmd_opt = ""
            dut.shell("sudo show platform npu script {} -s set_voq_watchdog.py".format(cmd_opt))

        yield

        # Enable voq watchdog.
        for (dut, asic_index) in zip(dut_list, asic_index_list):
            self.copy_set_voq_watchdog_script_cisco_8000(
                dut=dut,
                asic=asic_index,
                enable=True)
            cmd_opt = "-n asic{}".format(asic_index)
            if not dst_dut.sonichost.is_multi_asic:
                cmd_opt = ""
            dut.shell("sudo show platform npu script {} -s set_voq_watchdog.py".format(cmd_opt))

        return

    @pytest.fixture(scope="function")
    def function_scope_disable_voq_watchdog(self, duthosts, get_src_dst_asic_and_duts):
        yield from self.disable_voq_watchdog(duthosts, get_src_dst_asic_and_duts)
