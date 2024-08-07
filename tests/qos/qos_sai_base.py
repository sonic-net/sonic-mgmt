import ipaddress
import json
import logging
import pytest
import re
import yaml
import random
import os
import sys
import six
import copy
import time
import collections

from tests.common.fixtures.ptfhost_utils import ptf_portmap_file  # noqa F401
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice
from tests.common.cisco_data import is_cisco_device
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host, dualtor_ports, is_tunnel_qos_remap_enabled  # noqa F401
from tests.common.dualtor.mux_simulator_control \
    import toggle_all_simulator_ports, get_mux_status, check_mux_status, validate_check_result  # noqa F401
from tests.common.dualtor.constants import UPPER_TOR, LOWER_TOR  # noqa F401
from tests.common.utilities import check_qos_db_fv_reference_with_table
from tests.common.fixtures.duthost_utils import dut_qos_maps, separated_dscp_to_tc_map_on_uplink  # noqa F401
from tests.common.utilities import wait_until
from tests.ptf_runner import ptf_runner
from tests.common.system_utils import docker  # noqa F401
from tests.common.errors import RunAnsibleModuleFail
from tests.common import config_reload

logger = logging.getLogger(__name__)


class QosBase:
    """
    Common APIs
    """
    SUPPORTED_T0_TOPOS = ["t0", "t0-56-po2vlan", "t0-64", "t0-116", "t0-35", "dualtor-56", "dualtor-64", "dualtor-120",
                          "dualtor", "dualtor-64-breakout", "t0-120", "t0-80", "t0-backend", "t0-56-o8v48", "t0-8-lag",
                          "t0-standalone-32", "t0-standalone-64", "t0-standalone-128", "t0-standalone-256"]
    SUPPORTED_T1_TOPOS = ["t1-lag", "t1-64-lag", "t1-56-lag", "t1-backend", "t1-28-lag", "t1-32-lag"]
    SUPPORTED_PTF_TOPOS = ['ptf32', 'ptf64']
    SUPPORTED_ASIC_LIST = ["pac", "gr", "gr2", "gb", "td2", "th", "th2", "spc1", "spc2", "spc3", "spc4", "td3", "th3",
                           "j2c+", "jr2", "th5"]

    BREAKOUT_SKUS = ['Arista-7050-QX-32S']

    TARGET_QUEUE_WRED = 3
    TARGET_LOSSY_QUEUE_SCHED = 0
    TARGET_LOSSLESS_QUEUE_SCHED = 3

    buffer_model_initialized = False
    buffer_model = None

    def isBufferInApplDb(self, dut_asic):
        if not self.buffer_model_initialized:
            self.buffer_model = dut_asic.run_redis_cmd(
                argv=[
                    "redis-cli", "-n", "4", "hget",
                    "DEVICE_METADATA|localhost", "buffer_model"
                ]
            )

            self.buffer_model_initialized = True
            logger.info(
                "Buffer model is {}, buffer tables will be fetched from {}".format(
                    self.buffer_model or "not defined",
                    "APPL_DB" if self.buffer_model else "CONFIG_DB"
                )
            )
        return self.buffer_model

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

    def runPtfTest(self, ptfhost, testCase='', testParams={}, relax=False, pdb=False):
        """
            Runs QoS SAI test case on PTF host

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
            "saitests",
            testCase,
            platform_dir="ptftests",
            params=testParams,
            log_file="/tmp/{0}{1}.log".format(testCase, logfile_suffix),  # Include suffix in the logfile name,
            qlen=10000,
            is_python3=True,
            relax=relax,
            timeout=1200,
            socket_recv_size=16384,
            custom_options=custom_options,
            pdb=pdb
        )


class QosSaiBase(QosBase):
    """
        QosSaiBase contains collection of pytest fixtures that ready the
        testbed for QoS SAI test cases.
    """

    def __computeBufferThreshold(self, dut_asic, bufferProfile):
        """
            Computes buffer threshold for dynamic threshold profiles

            Args:
                dut_asic (SonicAsic): Device ASIC Under Test (DUT)
                bufferProfile (dict, inout): Map of puffer profile attributes

            Returns:
                Updates bufferProfile with computed buffer threshold
        """
        if self.isBufferInApplDb(dut_asic):
            db = "0"
            keystr = "BUFFER_POOL_TABLE:"
        else:
            db = "4"
            keystr = "BUFFER_POOL|"
        if check_qos_db_fv_reference_with_table(dut_asic):
            if six.PY2:
                pool = bufferProfile["pool"].encode("utf-8").translate(None, "[]")
            else:
                pool = bufferProfile["pool"].translate({ord(i): None for i in '[]'})
        else:
            pool = keystr + bufferProfile["pool"]
        bufferSize = int(
            dut_asic.run_redis_cmd(
                argv=["redis-cli", "-n", db, "HGET", pool, "size"]
            )[0]
        )
        bufferScale = 2 ** float(bufferProfile["dynamic_th"])
        bufferScale /= (bufferScale + 1)
        bufferProfile.update(
            {"static_th": int(
                bufferProfile["size"]) + int(bufferScale * bufferSize)}
        )

    def __compute_buffer_threshold_for_nvidia_device(self, dut_asic, table, port, pg_q_buffer_profile):
        """
        Computes buffer threshold for dynamic threshold profiles for nvidia device

        Args:
            dut_asic (SonicAsic): Device ASIC Under Test (DUT)
            table (str): Redis table name
            port (str): DUT port alias
            pg_q_buffer_profile (dict, inout): Map of pg or q buffer profile attributes

        Returns:
            Updates bufferProfile with computed buffer threshold
        """

        port_table_name = "BUFFER_PORT_EGRESS_PROFILE_LIST_TABLE" if \
            table == "BUFFER_QUEUE_TABLE" else "BUFFER_PORT_INGRESS_PROFILE_LIST_TABLE"
        db = "0"
        port_profile_res = dut_asic.run_redis_cmd(
            argv=["redis-cli", "-n", db, "HGET", f"{port_table_name}:{port}", "profile_list"]
        )[0]
        port_profile_list = port_profile_res.split(",")

        port_dynamic_th = ''
        for port_profile in port_profile_list:
            buffer_pool_name = dut_asic.run_redis_cmd(
                argv=["redis-cli", "-n", db, "HGET", f'BUFFER_PROFILE_TABLE:{port_profile}', "pool"]
            )[0]
            if buffer_pool_name == pg_q_buffer_profile["pool"]:
                port_dynamic_th = dut_asic.run_redis_cmd(
                    argv=["redis-cli", "-n", db, "HGET", f'BUFFER_PROFILE_TABLE:{port_profile}', "dynamic_th"]
                )[0]
                break
        if port_dynamic_th:

            def calculate_alpha(dynamic_th):
                if dynamic_th == "7":
                    alpha = 64
                else:
                    alpha = 2 ** float(dynamic_th)
                return alpha

            pg_q_alpha = calculate_alpha(pg_q_buffer_profile['dynamic_th'])
            port_alpha = calculate_alpha(port_dynamic_th)
            pool = f'BUFFER_POOL_TABLE:{pg_q_buffer_profile["pool"]}'
            buffer_size = int(
                dut_asic.run_redis_cmd(
                    argv=["redis-cli", "-n", db, "HGET", pool, "size"]
                )[0]
            )

            buffer_scale = port_alpha * pg_q_alpha / (port_alpha * pg_q_alpha + pg_q_alpha + 1)

            pg_q_max_occupancy = int(buffer_size * buffer_scale)

            pg_q_buffer_profile.update(
                {"static_th": int(
                    pg_q_buffer_profile["size"]) + int(pg_q_max_occupancy)}
            )
            pg_q_buffer_profile["pg_q_alpha"] = pg_q_alpha
            pg_q_buffer_profile["port_alpha"] = port_alpha
            pg_q_buffer_profile["pool_size"] = buffer_size
        else:
            raise Exception("Not found port dynamic th")

    def __updateVoidRoidParams(self, dut_asic, bufferProfile):
        """
            Updates buffer profile with VOID/ROID params

            Args:
                dut_asic (SonicAsic): Device Under Test (DUT)
                bufferProfile (dict, inout): Map of puffer profile attributes

            Returns:
                Updates bufferProfile with VOID/ROID obtained from Redis db
        """
        if check_qos_db_fv_reference_with_table(dut_asic):
            if self.isBufferInApplDb(dut_asic):
                if six.PY2:
                    bufferPoolName = bufferProfile["pool"].encode("utf-8").translate(
                        None, "[]").replace("BUFFER_POOL_TABLE:", '')
                else:
                    bufferPoolName = bufferProfile["pool"].translate(
                        {ord(i): None for i in '[]'}).replace("BUFFER_POOL_TABLE:", '')
            else:
                if six.PY2:
                    bufferPoolName = bufferProfile["pool"].encode("utf-8").translate(
                        None, "[]").replace("BUFFER_POOL|", '')
                else:
                    bufferPoolName = bufferProfile["pool"].translate(
                        {ord(i): None for i in '[]'}).replace("BUFFER_POOL|", '')
        else:
            bufferPoolName = six.text_type(bufferProfile["pool"])

        bufferPoolVoid = six.text_type(dut_asic.run_redis_cmd(
            argv=[
                "redis-cli", "-n", "2", "HGET",
                "COUNTERS_BUFFER_POOL_NAME_MAP", bufferPoolName
            ]
        )[0])
        bufferProfile.update({"bufferPoolVoid": bufferPoolVoid})

        bufferPoolRoid = six.text_type(dut_asic.run_redis_cmd(
            argv=["redis-cli", "-n", "1", "HGET", "VIDTORID", bufferPoolVoid]
        )[0]).replace("oid:", '')
        bufferProfile.update({"bufferPoolRoid": bufferPoolRoid})

    def __getBufferProfile(self, request, dut_asic, os_version, table, port, priorityGroup):
        """
            Get buffer profile attribute from Redis db

            Args:
                request (Fixture): pytest request object
                dut_asic(SonicAsic): Device Under Test (DUT)
                table (str): Redis table name
                port (str): DUT port alias
                priorityGroup (str): QoS priority group

            Returns:
                bufferProfile (dict): Map of buffer profile attributes
        """

        if table == "BUFFER_QUEUE_TABLE" and dut_asic.sonichost.facts['switch_type'] == 'voq':
            # For VoQ chassis, the buffer queues config is based on system port
            if dut_asic.sonichost.is_multi_asic:
                port = "{}:{}:{}".format(
                    dut_asic.sonichost.hostname, dut_asic.namespace, port)
            else:
                port = "{}:Asic0:{}".format(dut_asic.sonichost.hostname, port)

        if self.isBufferInApplDb(dut_asic):
            db = "0"
            keystr = "{0}:{1}:{2}".format(table, port, priorityGroup)
            bufkeystr = "BUFFER_PROFILE_TABLE:"
        else:
            db = "4"
            keystr = "{0}|{1}|{2}".format(table, port, priorityGroup)
            bufkeystr = "BUFFER_PROFILE|"

        if check_qos_db_fv_reference_with_table(dut_asic):
            out = dut_asic.run_redis_cmd(argv=["redis-cli", "-n", db, "HGET", keystr, "profile"])[0]
            if six.PY2:
                bufferProfileName = out.encode("utf-8").translate(None, "[]")
            else:
                bufferProfileName = out.translate({ord(i): None for i in '[]'})
        else:
            bufferProfileName = bufkeystr + dut_asic.run_redis_cmd(
                argv=["redis-cli", "-n", db, "HGET", keystr, "profile"])[0]

        result = dut_asic.run_redis_cmd(
            argv=["redis-cli", "-n", db, "HGETALL", bufferProfileName]
        )
        it = iter(result)
        bufferProfile = dict(list(zip(it, it)))
        bufferProfile.update({"profileName": bufferProfileName})

        # Update profile static threshold value if  profile threshold is dynamic
        if "dynamic_th" in list(bufferProfile.keys()):
            if dut_asic.sonichost.facts['platform'] == "x86_64-nvidia_sn5600-r0":
                self.__compute_buffer_threshold_for_nvidia_device(dut_asic, table, port, bufferProfile)
            else:
                self.__computeBufferThreshold(dut_asic, bufferProfile)

        if "pg_lossless" in bufferProfileName:
            pytest_assert(
                "xon" in list(bufferProfile.keys()) and "xoff" in list(
                    bufferProfile.keys()),
                "Could not find xon and/or xoff values for profile '{0}'".format(
                    bufferProfileName
                )
            )

        if "201811" not in os_version:
            self.__updateVoidRoidParams(dut_asic, bufferProfile)

        return bufferProfile

    def __getSharedHeadroomPoolSize(self, request, dut_asic):
        """
            Get shared headroom pool size from Redis db

            Args:
                request (Fixture): pytest request object
                dut_asic (SonicAsic): Device Under Test (DUT)

            Returns:
                size (str) size of shared headroom pool
                None if shared headroom pool isn't enabled
        """
        if self.isBufferInApplDb(dut_asic):
            db = "0"
            keystr = "BUFFER_POOL_TABLE:ingress_lossless_pool"
        else:
            db = "4"
            keystr = "BUFFER_POOL|ingress_lossless_pool"
        result = dut_asic.run_redis_cmd(
            argv=["redis-cli", "-n", db, "HGETALL", keystr]
        )
        it = iter(result)
        ingressLosslessPool = dict(list(zip(it, it)))
        return ingressLosslessPool.get("xoff")

    def __getEcnWredParam(self, dut_asic, table, port):
        """
            Get ECN/WRED parameters from Redis db

            Args:
                dut_asic (SonicAsic): Device Under Test (DUT)
                table (str): Redis table name
                port (str): DUT port alias

            Returns:
                wredProfile (dict): Map of ECN/WRED attributes
        """
        if check_qos_db_fv_reference_with_table(dut_asic):
            out = dut_asic.run_redis_cmd(
                argv=[
                    "redis-cli", "-n", "4", "HGET",
                    "{0}|{1}|{2}".format(table, port, self.TARGET_QUEUE_WRED),
                    "wred_profile"
                ]
            )[0]
            if six.PY2:
                wredProfileName = out.encode("utf-8").translate(None, "[]")
            else:
                wredProfileName = out.translate({ord(i): None for i in '[]'})
        else:
            wredProfileName = "WRED_PROFILE|" + six.text_type(dut_asic.run_redis_cmd(
                argv=[
                    "redis-cli", "-n", "4", "HGET",
                    "{0}|{1}|{2}".format(table, port, self.TARGET_QUEUE_WRED),
                    "wred_profile"
                ]
            )[0])

        result = dut_asic.run_redis_cmd(
            argv=["redis-cli", "-n", "4", "HGETALL", wredProfileName]
        )
        it = iter(result)
        wredProfile = dict(list(zip(it, it)))

        return wredProfile

    def __getWatermarkStatus(self, dut_asic):
        """
            Get watermark status from Redis db

            Args:
                dut_asic (SonicAsic): Device Under Test (DUT)

            Returns:
                watermarkStatus (str): Watermark status
        """
        watermarkStatus = six.text_type(dut_asic.run_redis_cmd(
            argv=[
                "redis-cli", "-n", "4", "HGET",
                "FLEX_COUNTER_TABLE|QUEUE_WATERMARK", "FLEX_COUNTER_STATUS"
            ]
        )[0])

        return watermarkStatus

    def __getSchedulerParam(self, dut_asic, port, queue):
        """
            Get scheduler parameters from Redis db

            Args:
                dut_asic (SonicAsic): Device Under Test (DUT)
                port (str): DUT port alias
                queue (str): QoS queue

            Returns:
                SchedulerParam (dict): Map of scheduler parameters
        """
        if check_qos_db_fv_reference_with_table(dut_asic):
            out = dut_asic.run_redis_cmd(
                argv=[
                    "redis-cli", "-n", "4", "HGET",
                    "QUEUE|{0}|{1}".format(port, queue), "scheduler"
                ]
            )[0]
            if six.PY2:
                schedProfile = out.encode("utf-8").translate(None, "[]")
            else:
                schedProfile = out.translate({ord(i): None for i in '[]'})
        else:
            if dut_asic.sonichost.facts['switch_type'] == 'voq':
                # For VoQ chassis, the scheduler queues config is based on system port
                if dut_asic.sonichost.is_multi_asic:
                    schedProfile = "SCHEDULER|" + six.text_type(dut_asic.run_redis_cmd(
                        argv=[
                            "redis-cli", "-n", "4", "HGET",
                            "QUEUE|{0}|{1}|{2}|{3}"
                            .format(dut_asic.sonichost.hostname, dut_asic.namespace, port, queue), "scheduler"
                        ]
                    )[0])
                else:
                    schedProfile = "SCHEDULER|" + six.text_type(dut_asic.run_redis_cmd(
                        argv=[
                            "redis-cli", "-n", "4", "HGET",
                            "QUEUE|{0}|Asic0|{1}|{2}"
                            .format(dut_asic.sonichost.hostname, port, queue), "scheduler"
                        ]
                    )[0])
            else:
                schedProfile = "SCHEDULER|" + six.text_type(dut_asic.run_redis_cmd(
                    argv=[
                        "redis-cli", "-n", "4", "HGET",
                        "QUEUE|{0}|{1}".format(port, queue), "scheduler"
                    ]
                )[0])
        schedWeight = six.text_type(dut_asic.run_redis_cmd(
            argv=["redis-cli", "-n", "4", "HGET", schedProfile, "weight"]
        )[0])

        return {"schedProfile": schedProfile, "schedWeight": schedWeight}

    def __assignTestPortIps(self, mgFacts, topo):
        """
            Assign IPs to test ports of DUT host

            Args:
                mgFacts (dict): Map of DUT minigraph facts

            Returns:
                dutPortIps (dict): Map of port index to IPs
        """
        dutPortIps = {}
        if len(mgFacts["minigraph_vlans"]) > 0:
            # TODO: handle the case when there are multiple vlans
            vlans = iter(mgFacts["minigraph_vlans"])
            testVlan = next(vlans)
            testVlanMembers = mgFacts["minigraph_vlans"][testVlan]["members"]
            # To support t0-56-po2vlan topo, choose the Vlan with physical ports and remove the lag in Vlan members
            if topo == 't0-56-po2vlan':
                if len(testVlanMembers) == 1:
                    testVlan = next(vlans)
                    testVlanMembers = mgFacts["minigraph_vlans"][testVlan]["members"]
                for member in testVlanMembers:
                    if 'PortChannel' in member:
                        testVlanMembers.remove(member)
                        break

            testVlanIp = None
            for vlan in mgFacts["minigraph_vlan_interfaces"]:
                if mgFacts["minigraph_vlans"][testVlan]["name"] in vlan["attachto"]:
                    testVlanIp = ipaddress.ip_address(vlan["addr"])  # noqa F821
                    break
            pytest_assert(testVlanIp, "Failed to obtain vlan IP")

            vlan_id = None
            if 'type' in mgFacts["minigraph_vlans"][testVlan]:
                vlan_type = mgFacts["minigraph_vlans"][testVlan]['type']
                if vlan_type is not None and "Tagged" in vlan_type:
                    vlan_id = mgFacts["minigraph_vlans"][testVlan]['vlanid']

            for i in range(len(testVlanMembers)):
                portIndex = mgFacts["minigraph_ptf_indices"][testVlanMembers[i]]
                portIpMap = {'peer_addr': str(testVlanIp + portIndex + 1)}
                if vlan_id is not None:
                    portIpMap['vlan_id'] = vlan_id
                dutPortIps.update({portIndex: portIpMap})

        return dutPortIps

    @pytest.fixture(scope='class')
    def swapSyncd_on_selected_duts(self, request, duthosts, get_src_dst_asic_and_duts, creds, tbinfo, lower_tor_host): # noqa F811
        """
            Swap syncd on DUT host

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        swapSyncd = request.config.getoption("--qos_swap_syncd")
        public_docker_reg = request.config.getoption("--public_docker_registry")
        try:
            if swapSyncd:
                if public_docker_reg:
                    new_creds = copy.deepcopy(creds)
                    new_creds['docker_registry_host'] = new_creds['public_docker_registry_host']
                    new_creds['docker_registry_username'] = ''
                    new_creds['docker_registry_password'] = ''
                else:
                    new_creds = creds
                for duthost in get_src_dst_asic_and_duts["all_duts"]:
                    docker.swap_syncd(duthost, new_creds)
            yield
        finally:
            if swapSyncd:
                for duthost in get_src_dst_asic_and_duts["all_duts"]:
                    docker.restore_default_syncd(duthost, new_creds)

    @pytest.fixture(scope='class', name="select_src_dst_dut_and_asic",
                    params=("single_asic", "single_dut_multi_asic", "multi_dut"))
    def select_src_dst_dut_and_asic(self, duthosts, request, tbinfo, lower_tor_host): # noqa F811
        test_port_selection_criteria = request.param
        logger.info("test_port_selection_criteria is {}".format(test_port_selection_criteria))
        src_dut_index = 0
        dst_dut_index = 0
        src_asic_index = 0
        dst_asic_index = 0
        topo = tbinfo["topo"]["name"]
        if 'dualtor' in tbinfo['topo']['name']:
            # index of lower_tor_host
            for a_dut_index in range(len(duthosts)):
                if duthosts[a_dut_index] == lower_tor_host:
                    lower_tor_dut_index = a_dut_index
                    break

        duthost = duthosts.frontend_nodes[0]
        if test_port_selection_criteria == 'single_asic':
            # We should randomly pick a dut from duthosts.frontend_nodes and a random asic in that selected DUT
            # for now hard code the first DUT and the first asic
            if 'dualtor' in tbinfo['topo']['name']:
                src_dut_index = lower_tor_dut_index
            else:
                src_dut_index = 0
            dst_dut_index = src_dut_index
            src_asic_index = 0
            dst_asic_index = 0

        elif test_port_selection_criteria == "single_dut_multi_asic":
            if topo in self.SUPPORTED_T0_TOPOS or isMellanoxDevice(duthost):
                pytest.skip("single_dut_multi_asic is not supported on T0 topologies")
            found_multi_asic_dut = False
            for a_dut_index in range(len(duthosts.frontend_nodes)):
                a_dut = duthosts.frontend_nodes[a_dut_index]
                if a_dut.sonichost.is_multi_asic:
                    src_dut_index = a_dut_index
                    dst_dut_index = a_dut_index
                    src_asic_index = 0
                    dst_asic_index = 1
                    found_multi_asic_dut = True
                    logger.info("Using dut {} for single_dut_multi_asic testing".format(a_dut.hostname))
                    break
            if not found_multi_asic_dut:
                pytest.skip(
                    "Did not find any frontend node that is multi-asic - so can't run single_dut_multi_asic tests")
        else:
            # Dealing with multi-dut
            if topo in self.SUPPORTED_T0_TOPOS or isMellanoxDevice(duthost):
                pytest.skip("multi-dut is not supported on T0 topologies")
            elif topo in self.SUPPORTED_T1_TOPOS:
                pytest.skip("multi-dut is not supported on T1 topologies")

            if (len(duthosts.frontend_nodes)) < 2:
                pytest.skip("Don't have 2 frontend nodes - so can't run multi_dut tests")

            src_dut_index = 0
            dst_dut_index = 1
            src_asic_index = 0
            dst_asic_index = 0

        yield {
            "src_dut_index": src_dut_index,
            "dst_dut_index": dst_dut_index,
            "src_asic_index": src_asic_index,
            "dst_asic_index": dst_asic_index
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
            elif len(dst_test_port_ids) >= 4:
                dstPorts = [0, 2, 3]
                if (get_src_dst_asic_and_duts["src_asic"].sonichost.facts["asic_type"]
                        in ['cisco-8000']):
                    dstPorts = [2, 3, 4]
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
        if get_src_dst_asic_and_duts["src_asic"].sonichost.facts["hwsku"] == "Cisco-8101-O8C48":
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
                            get_src_dst_asic_and_duts["src_asic"].sonichost.facts["hwsku"] ==
                            "Cisco-8101-O8C48"):
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
            for iface, addr in active_ips.items():
                if iface.startswith("Ethernet") and ("Ethernet-Rec" not in iface):
                    portIndex = src_mgFacts["minigraph_ptf_indices"][iface]
                    portIpMap = {'peer_addr': addr["peer_ipv4"], 'port': iface}
                    dutPortIps[src_dut_index][src_asic_index].update({portIndex: portIpMap})
                    # Map port IDs to system port for dnx chassis
                    if 'platform_asic' in get_src_dst_asic_and_duts["src_dut"].facts and \
                            get_src_dst_asic_and_duts["src_dut"].facts['platform_asic'] == 'broadcom-dnx':
                        sys_key = src_asic.namespace + '|' + iface if src_asic.namespace else iface
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
                            sys_key = src_asic.namespace + '|' + portName if src_asic.namespace else portName
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
                    if 'platform_asic' in get_src_dst_asic_and_duts["src_dut"].facts and \
                            get_src_dst_asic_and_duts["src_dut"].facts['platform_asic'] == 'broadcom-dnx':
                        dst_system_port = dst_dut.config_facts(host=dst_dut.hostname, source='running')[
                            'ansible_facts']['SYSTEM_PORT'][dst_dut.hostname]
                else:
                    dst_mgFacts = src_mgFacts
                    dst_system_port = src_system_port
                dutPortIps[dst_dut_index][dst_asic_index] = {}
                sysPortMap[dst_dut_index][dst_asic_index] = {}
                active_ips = dst_asic.get_active_ip_interfaces(tbinfo)
                for iface, addr in active_ips.items():
                    if iface.startswith("Ethernet") and ("Ethernet-Rec" not in iface):
                        portIndex = dst_mgFacts["minigraph_ptf_indices"][iface]
                        portIpMap = {'peer_addr': addr["peer_ipv4"], 'port': iface}
                        dutPortIps[dst_dut_index][dst_asic_index].update({portIndex: portIpMap})
                        # Map port IDs to system port IDs
                        if 'platform_asic' in get_src_dst_asic_and_duts["src_dut"].facts and \
                                get_src_dst_asic_and_duts["src_dut"].facts['platform_asic'] == 'broadcom-dnx':
                            sys_key = dst_asic.namespace + '|' + iface if dst_asic.namespace else iface
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
                                sys_key = dst_asic.namespace + '|' + portName if dst_asic.namespace else portName
                                port_Index = dst_mgFacts["minigraph_ptf_indices"][portName]
                                if sys_key in dst_system_port:
                                    system_port = dst_system_port[sys_key]['system_port_id']
                                    sysPort = {'port': portName, 'system_port': system_port, 'port_type': iface}
                                    sysPortMap[dst_dut_index][dst_asic_index].update({port_Index: sysPort})

                testPortIds[dst_dut_index][dst_asic_index] = sorted(dutPortIps[dst_dut_index][dst_asic_index].keys())

            # restore currently assigned IPs
            testPortIps.update(dutPortIps)

        qosConfigs = {}
        with open(r"qos/files/qos.yml") as file:
            qosConfigs = yaml.load(file, Loader=yaml.FullLoader)
        # Assuming the same chipset for all DUTs so can use src_dut to get asic type
        vendor = src_dut.facts["asic_type"]
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
            "dualTorScenario": len(dualtor_ports_for_duts) != 0
        }

    @pytest.fixture(scope='class')
    def ssh_tunnel_to_syncd_rpc(self, duthosts, get_src_dst_asic_and_duts, swapSyncd_on_selected_duts, tbinfo, lower_tor_host): # noqa F811
        all_asics = get_src_dst_asic_and_duts['all_asics']

        for a_asic in all_asics:
            a_asic.create_ssh_tunnel_sai_rpc()

        yield

        for a_asic in all_asics:
            a_asic.remove_ssh_tunnel_sai_rpc()

    @pytest.fixture(scope='class')
    def updateIptables(self, duthosts, get_src_dst_asic_and_duts, swapSyncd_on_selected_duts, tbinfo, lower_tor_host): # noqa F811
        """
            Update iptables on DUT host with drop rule for BGP SYNC packets

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                swapSyncd (Fixture): swapSyncd fixture is required to run prior to updating iptables

            Returns:
                None
        """
        all_asics = get_src_dst_asic_and_duts['all_asics']

        ipVersions = [{"ip_version": "ipv4"}, {"ip_version": "ipv6"}]

        logger.info(
            "Add ip[6]tables rule to drop BGP SYN Packet from peer so that we do not ACK back")
        for ipVersion in ipVersions:
            for a_asic in all_asics:
                a_asic.bgp_drop_rule(state="present", **ipVersion)

        yield

        logger.info("Remove ip[6]tables rule to drop BGP SYN Packet from Peer")
        for ipVersion in ipVersions:
            for a_asic in all_asics:
                a_asic.bgp_drop_rule(state="absent", **ipVersion)

    @pytest.fixture(scope='class')
    def stopServices(
        self, duthosts, get_src_dst_asic_and_duts, dut_disable_ipv6,
        swapSyncd_on_selected_duts, enable_container_autorestart, disable_container_autorestart, get_mux_status, # noqa F811
        tbinfo, upper_tor_host, lower_tor_host, toggle_all_simulator_ports):  # noqa F811
        """
            Stop services (lldp-syncs, lldpd, bgpd) on DUT host prior to test start

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                swapSyncd (Fxiture): swapSyncd fixture is required to run prior to stopping services

            Returns:
                None
        """
        src_asic = get_src_dst_asic_and_duts['src_asic']
        src_dut = get_src_dst_asic_and_duts['src_dut']
        dst_asic = get_src_dst_asic_and_duts['dst_asic']
        dst_dut = get_src_dst_asic_and_duts['dst_dut']

        def updateDockerService(host, docker="", action="", service=""):  # noqa: F811
            """
                Helper function to update docker services

                Args:
                    host (AnsibleHost): Ansible host that is running docker
                    docker (str): docker container name
                    action (str): action to apply to service running within docker
                    service (str): service name running within docker

                Returns:
                    None
            """
            host.command(
                "docker exec {docker} supervisorctl {action} {service}".format(
                    docker=docker,
                    action=action,
                    service=service
                ),
                module_ignore_errors=True
            )
            logger.info("{}ed {}".format(action, service))

        """ Stop mux container for dual ToR """
        if 'dualtor' in tbinfo['topo']['name']:
            file = "/usr/local/bin/write_standby.py"
            backup_file = "/usr/local/bin/write_standby.py.bkup"
            toggle_all_simulator_ports(LOWER_TOR, retries=3)
            check_result = wait_until(
                120, 10, 10, check_mux_status, duthosts, LOWER_TOR)
            validate_check_result(check_result, duthosts, get_mux_status)

            try:
                lower_tor_host.shell("ls %s" % file)
                lower_tor_host.shell("sudo cp {} {}".format(file, backup_file))
                lower_tor_host.shell("sudo rm {}".format(file))
                lower_tor_host.shell("sudo touch {}".format(file))
            except Exception as e:
                pytest.skip('file {} not found. Exception {}'.format(file, str(e)))

            upper_tor_host.shell('sudo config feature state mux disabled')
            lower_tor_host.shell('sudo config feature state mux disabled')

        src_services = [
            {"docker": src_asic.get_docker_name("lldp"), "service": "lldp-syncd"},
            {"docker": src_asic.get_docker_name("lldp"), "service": "lldpd"},
            {"docker": src_asic.get_docker_name("bgp"),  "service": "bgpd"},
            {"docker": src_asic.get_docker_name("bgp"),  "service": "bgpmon"},
            {"docker": src_asic.get_docker_name("radv"), "service": "radvd"},
            {"docker": src_asic.get_docker_name("swss"), "service": "arp_update"}
        ]
        dst_services = []
        if src_asic != dst_asic:
            dst_services = [
                {"docker": dst_asic.get_docker_name("lldp"), "service": "lldp-syncd"},
                {"docker": dst_asic.get_docker_name("lldp"), "service": "lldpd"},
                {"docker": dst_asic.get_docker_name("bgp"), "service": "bgpd"},
                {"docker": dst_asic.get_docker_name("bgp"), "service": "bgpmon"},
                {"docker": dst_asic.get_docker_name("radv"), "service": "radvd"},
                {"docker": dst_asic.get_docker_name("swss"), "service": "arp_update"}
            ]

        feature_list = ['lldp', 'bgp', 'syncd', 'swss']
        if 'dualtor' in tbinfo['topo']['name']:
            disable_container_autorestart(
                upper_tor_host, testcase="test_qos_sai", feature_list=feature_list)

        disable_container_autorestart(src_dut, testcase="test_qos_sai", feature_list=feature_list)
        for service in src_services:
            updateDockerService(src_dut, action="stop", **service)
        if src_asic != dst_asic:
            disable_container_autorestart(dst_dut, testcase="test_qos_sai", feature_list=feature_list)
            for service in dst_services:
                updateDockerService(dst_dut, action="stop", **service)
        yield

        for service in src_services:
            updateDockerService(src_dut, action="start", **service)
        if src_asic != dst_asic:
            for service in dst_services:
                updateDockerService(dst_dut, action="start", **service)

        """ Start mux conatiner for dual ToR """
        if 'dualtor' in tbinfo['topo']['name']:
            try:
                lower_tor_host.shell("ls %s" % backup_file)
                lower_tor_host.shell("sudo cp {} {}".format(backup_file, file))
                lower_tor_host.shell("sudo chmod +x {}".format(file))
                lower_tor_host.shell("sudo rm {}".format(backup_file))
            except Exception as e:
                pytest.skip('file {} not found. Exception {}'.format(backup_file, str(e)))

            lower_tor_host.shell('sudo config feature state mux enabled')
            upper_tor_host.shell('sudo config feature state mux enabled')
            logger.info("Start mux container for dual ToR testbed")

        enable_container_autorestart(src_dut, testcase="test_qos_sai", feature_list=feature_list)
        if src_asic != dst_asic:
            enable_container_autorestart(dst_dut, testcase="test_qos_sai", feature_list=feature_list)
        if 'dualtor' in tbinfo['topo']['name']:
            enable_container_autorestart(
                upper_tor_host, testcase="test_qos_sai", feature_list=feature_list)

    @pytest.fixture(autouse=True)
    def updateLoganalyzerExceptions(self, get_src_dst_asic_and_duts, loganalyzer):
        """
            Update loganalyzer ignore regex list

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                loganalyzer (Fixture): log analyzer fixture

            Returns:
                None
        """
        if loganalyzer:
            ignoreRegex = [
                ".*ERR monit.*'lldpd_monitor' process is not running.*",
                ".*ERR monit.* 'lldp\\|lldpd_monitor' status failed.*-- 'lldpd:' is not running.*",

                ".*ERR monit.*'lldp_syncd' process is not running.*",
                ".*ERR monit.*'lldp\\|lldp_syncd' status failed.*-- 'python.* -m lldp_syncd' is not running.*",

                ".*ERR monit.*'bgpd' process is not running.*",
                ".*ERR monit.*'bgp\\|bgpd' status failed.*-- '/usr/lib/frr/bgpd' is not running.*",

                ".*ERR monit.*'bgpcfgd' process is not running.*",
                ".*ERR monit.*'bgp\\|bgpcfgd' status failed.*-- "
                "'/usr/bin/python.* /usr/local/bin/bgpcfgd' is not running.*",

                ".*ERR syncd#syncd:.*brcm_sai_set_switch_attribute:.*updating switch mac addr failed.*",

                ".*ERR monit.*'bgp\\|bgpmon' status failed.*'/usr/bin/python.* /usr/local/bin/bgpmon' is not running.*",
                ".*ERR monit.*bgp\\|fpmsyncd.*status failed.*NoSuchProcess process no longer exists.*",
                ".*WARNING syncd#SDK:.*check_attribs_metadata: Not implemented attribute.*",
                ".*WARNING syncd#SDK:.*sai_set_attribute: Failed attribs check, key:Switch ID.*",
                ".*WARNING syncd#SDK:.*check_rate: Set max rate to 0.*"
            ]
            for a_dut in get_src_dst_asic_and_duts['all_duts']:
                loganalyzer[a_dut.hostname].ignore_regex.extend(ignoreRegex)

        yield

    @pytest.fixture(scope='class', autouse=True)
    def disablePacketAging(
        self, duthosts, get_src_dst_asic_and_duts, stopServices
    ):
        """
            disable packet aging on DUT host

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                stopServices (Fxiture): stopServices fixture is required to run prior to disabling packet aging

            Returns:
                None
        """
        for duthost in get_src_dst_asic_and_duts['all_duts']:
            if isMellanoxDevice(duthost):
                logger.info("Disable Mellanox packet aging")
                duthost.copy(src="qos/files/mellanox/packets_aging.py", dest="/tmp")
                duthost.command("docker cp /tmp/packets_aging.py syncd:/")
                duthost.command("docker exec syncd python /packets_aging.py disable")

            yield

            if isMellanoxDevice(duthost):
                logger.info("Enable Mellanox packet aging")
                duthost.command("docker exec syncd python /packets_aging.py enable")
                duthost.command("docker exec syncd rm -rf /packets_aging.py")

    def dutArpProxyConfig(self, duthost):
        # so far, only record ARP proxy config to logging for debug purpose
        for a_asic in duthost.asics:
            vlanInterface = {}
            try:
                sonic_cfgen_cmd = 'sonic-cfggen {} -d --var-json "VLAN_INTERFACE"'.format(a_asic.cli_ns_option)
                vlanInterface = json.loads(duthost.shell(sonic_cfgen_cmd)['stdout'])
            except Exception as e:
                logger.info('Failed to read vlan interface config. Excpetion {}'.format(str(e)))
            if not vlanInterface:
                return
            for key, value in vlanInterface.items():
                if 'proxy_arp' in value:
                    logger.info('ARP proxy is {} on {}'.format(value['proxy_arp'], key))

    def dutBufferConfig(self, duthost, dut_asic):
        bufferConfig = {}
        try:
            ns_spec = ""
            ns = dut_asic.get_asic_namespace()
            if ns is not None:
                # multi-asic support
                ns_spec = " -n " + ns
            bufferConfig['BUFFER_POOL'] = json.loads(duthost.shell(
                'sonic-cfggen -d --var-json "BUFFER_POOL"' + ns_spec)['stdout'])
            bufferConfig['BUFFER_PROFILE'] = json.loads(duthost.shell(
                'sonic-cfggen -d --var-json "BUFFER_PROFILE"' + ns_spec)['stdout'])
            bufferConfig['BUFFER_QUEUE'] = json.loads(duthost.shell(
                'sonic-cfggen -d --var-json "BUFFER_QUEUE"' + ns_spec)['stdout'])
            bufferConfig['BUFFER_PG'] = json.loads(duthost.shell(
                'sonic-cfggen -d --var-json "BUFFER_PG"' + ns_spec)['stdout'])
        except Exception as err:
            logger.info(err)
        return bufferConfig

    @pytest.fixture(scope='class', autouse=True)
    def dutQosConfig(
        self, duthosts, get_src_dst_asic_and_duts,
        dutConfig, ingressLosslessProfile, ingressLossyProfile,
        egressLosslessProfile, egressLossyProfile, sharedHeadroomPoolSize,
        tbinfo, lower_tor_host # noqa F811
    ):
        """
            Prepares DUT host QoS configuration

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ingressLosslessProfile (Fxiture): ingressLosslessProfile fixture is required to run prior to collecting
                    QoS configuration

            Returns:
                QoSConfig (dict): Map containing DUT host QoS configuration
        """
        duthost = get_src_dst_asic_and_duts['src_dut']
        dut_asic = get_src_dst_asic_and_duts['src_asic']

        mgFacts = duthost.get_extended_minigraph_facts(tbinfo)
        pytest_assert("minigraph_hwsku" in mgFacts, "Could not find DUT SKU")

        profileName = ingressLosslessProfile["profileName"]
        logger.info(
            "Lossless Buffer profile selected is {}".format(profileName))

        if self.isBufferInApplDb(dut_asic):
            profile_pattern = "^BUFFER_PROFILE_TABLE\\:pg_lossless_(.*)_profile$"
        else:
            profile_pattern = "^BUFFER_PROFILE\\|pg_lossless_(.*)_profile"
        m = re.search(profile_pattern, profileName)
        pytest_assert(m.group(1), "Cannot find port speed/cable length")

        portSpeedCableLength = m.group(1)

        qosConfigs = dutConfig["qosConfigs"]
        dutAsic = dutConfig["dutAsic"]
        dutTopo = dutConfig["dutTopo"]

        self.dutArpProxyConfig(duthost)

        if isMellanoxDevice(duthost):
            current_file_dir = os.path.dirname(os.path.realpath(__file__))
            sub_folder_dir = os.path.join(current_file_dir, "files/mellanox/")
            if sub_folder_dir not in sys.path:
                sys.path.append(sub_folder_dir)
            # For Mellanox T1, if tunnel qos remap is enabled, we need to enable dualTor flag to cover
            # T1 in dualTor scenario
            if is_tunnel_qos_remap_enabled(duthost) and 't1' in tbinfo["topo"]["name"]:
                dualTor = True
            else:
                dualTor = dutConfig["dualTor"]
            import qos_param_generator
            dut_top = dutTopo if dutTopo in qosConfigs['qos_params']['mellanox'] else "topo-any"
            qpm = qos_param_generator.QosParamMellanox(qosConfigs['qos_params']['mellanox'][dut_top], dutAsic,
                                                       portSpeedCableLength,
                                                       dutConfig,
                                                       ingressLosslessProfile,
                                                       ingressLossyProfile,
                                                       egressLosslessProfile,
                                                       egressLossyProfile,
                                                       sharedHeadroomPoolSize,
                                                       dualTor,
                                                       get_src_dst_asic_and_duts['src_dut_index'],
                                                       get_src_dst_asic_and_duts['src_asic_index'],
                                                       get_src_dst_asic_and_duts['dst_dut_index'],
                                                       get_src_dst_asic_and_duts['dst_asic_index']
                                                       )
            qosParams = qpm.run()

        elif 'broadcom' in duthost.facts['asic_type'].lower():
            if 'platform_asic' in duthost.facts and duthost.facts['platform_asic'] == 'broadcom-dnx':
                logger.info("THDI_BUFFER_CELL_LIMIT_SP is not valid for broadcom DNX - ignore dynamic buffer config")
                qosParams = qosConfigs['qos_params'][dutAsic][dutTopo]
            else:
                bufferConfig = self.dutBufferConfig(duthost, dut_asic)
                pytest_assert(len(bufferConfig) == 4,
                              "buffer config is incompleted")
                pytest_assert('BUFFER_POOL' in bufferConfig,
                              'BUFFER_POOL is not exist in bufferConfig')
                pytest_assert('BUFFER_PROFILE' in bufferConfig,
                              'BUFFER_PROFILE is not exist in bufferConfig')
                pytest_assert('BUFFER_QUEUE' in bufferConfig,
                              'BUFFER_QUEUE is not exist in bufferConfig')
                pytest_assert('BUFFER_PG' in bufferConfig,
                              'BUFFER_PG is not exist in bufferConfig')

                current_file_dir = os.path.dirname(os.path.realpath(__file__))
                sub_folder_dir = os.path.join(current_file_dir, "files/brcm/")
                if sub_folder_dir not in sys.path:
                    sys.path.append(sub_folder_dir)
                import qos_param_generator
                qpm = qos_param_generator.QosParamBroadcom({'qos_params': qosConfigs['qos_params'][dutAsic][dutTopo],
                                                            'asic_type': dutAsic,
                                                            'speed_cable_len': portSpeedCableLength,
                                                            'dutConfig': dutConfig,
                                                            'ingressLosslessProfile': ingressLosslessProfile,
                                                            'ingressLossyProfile': ingressLossyProfile,
                                                            'egressLosslessProfile': egressLosslessProfile,
                                                            'egressLossyProfile': egressLossyProfile,
                                                            'sharedHeadroomPoolSize': sharedHeadroomPoolSize,
                                                            'dualTor': dutConfig["dualTor"],
                                                            'dutTopo': dutTopo,
                                                            'bufferConfig': bufferConfig,
                                                            'dutHost': duthost,
                                                            'testbedTopologyName': tbinfo["topo"]["name"],
                                                            'selected_profile': profileName})
                qosParams = qpm.run()
        elif is_cisco_device(duthost):
            bufferConfig = self.dutBufferConfig(duthost, dut_asic)
            pytest_assert('BUFFER_POOL' in bufferConfig,
                          'BUFFER_POOL does not exist in bufferConfig')
            pytest_assert('BUFFER_PROFILE' in bufferConfig,
                          'BUFFER_PROFILE does not exist in bufferConfig')
            pytest_assert('BUFFER_QUEUE' in bufferConfig,
                          'BUFFER_QUEUE does not exist in bufferConfig')
            pytest_assert('BUFFER_PG' in bufferConfig,
                          'BUFFER_PG does not exist in bufferConfig')
            current_file_dir = os.path.dirname(os.path.realpath(__file__))
            sub_folder_dir = os.path.join(current_file_dir, "files/cisco/")
            if sub_folder_dir not in sys.path:
                sys.path.append(sub_folder_dir)
            import qos_param_generator
            if (get_src_dst_asic_and_duts['src_dut_index'] ==
                    get_src_dst_asic_and_duts['dst_dut_index'] and
                get_src_dst_asic_and_duts['src_asic_index'] ==
                    get_src_dst_asic_and_duts['dst_asic_index']):
                dutTopo = "topo-any"
            qpm = qos_param_generator.QosParamCisco(
                      qosConfigs['qos_params'][dutAsic][dutTopo],
                      duthost,
                      dutAsic,
                      dutTopo,
                      bufferConfig,
                      portSpeedCableLength)

            qosParams = qpm.run()
        else:
            qosParams = qosConfigs['qos_params'][dutAsic][dutTopo]
        yield {
            "param": qosParams,
            "portSpeedCableLength": portSpeedCableLength,
        }

    @pytest.fixture(scope='class')
    def releaseAllPorts(
        self, duthosts, ptfhost, dutTestParams, updateIptables, ssh_tunnel_to_syncd_rpc
    ):
        """
            Release all paused ports prior to running QoS SAI test cases

            Args:
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                updateIptables (Fixture, dict): updateIptables to run prior to releasing paused ports

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        self.runPtfTest(
            ptfhost, testCase="sai_qos_tests.ReleaseAllPorts",
            testParams=dutTestParams["basicParams"]
        )

    def __loadSwssConfig(self, duthost):
        """
            Load SWSS configuration on DUT

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Raises:
                asserts if the load SWSS config failed

            Returns:
                None
        """
        duthost.docker_cmds_on_all_asics(
            "swssconfig /etc/swss/config.d/switch.json", "swss")

    def __deleteTmpSwitchConfig(self, duthost):
        """
            Delete temporary switch.json cofiguration files

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        result = duthost.find(path=["/tmp"], patterns=["switch.json*"])
        for file in result["files"]:
            duthost.file(path=file["path"], state="absent")

    @pytest.fixture(scope='class', autouse=True)
    def handleFdbAging(self, duthosts, get_src_dst_asic_and_duts):
        """
            Disable FDB aging and reenable at the end of tests

            Set fdb_aging_time to 0, update the swss configuration, and restore SWSS configuration afer
            test completes

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """
        fdbAgingTime = 0
        for duthost in get_src_dst_asic_and_duts['all_duts']:
            self.__deleteTmpSwitchConfig(duthost)
            duthost.docker_copy_from_asic("swss", "/etc/swss/config.d/switch.json", "/tmp")
            duthost.replace(
                dest='/tmp/switch.json',
                regexp='"fdb_aging_time": ".*"',
                replace='"fdb_aging_time": "{0}"'.format(fdbAgingTime),
                backup=True
            )
            duthost.docker_copy_to_all_asics("swss", "/tmp/switch.json", "/etc/swss/config.d/switch.json")
            self.__loadSwssConfig(duthost)

        yield
        for duthost in get_src_dst_asic_and_duts['all_duts']:
            result = duthost.find(path=["/tmp"], patterns=["switch.json.*"])
            if result["matched"] > 0:
                src = result["files"][0]["path"]
                duthost.docker_copy_to_all_asics("swss", src, "/etc/swss/config.d/switch.json")
                self.__loadSwssConfig(duthost)
            self.__deleteTmpSwitchConfig(duthost)

    @pytest.fixture(scope='function', autouse=True)
    def populateArpEntries_T2(
            self, duthosts, get_src_dst_asic_and_duts, ptfhost, dutTestParams, dutConfig):
        """
            Update ARP entries for neighbors for selected test ports for each test for T2 topology
            with broadcom-dnx asic. As Broadcom dnx asic has larger queue buffer size which takes longer time interval
            compared to other topology to fill up which leads to arp aging out intermittently as lag goes down due to
            voq credits getting exhausted during test runs.

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        testParams = dict()
        src_is_multi_asic = False
        dst_is_multi_asic = False
        if ('platform_asic' in dutTestParams["basicParams"] and
                dutTestParams["basicParams"]["platform_asic"] == "broadcom-dnx"):
            if get_src_dst_asic_and_duts['src_dut'].sonichost.is_multi_asic:
                src_is_multi_asic = True
            if get_src_dst_asic_and_duts['dst_dut'].sonichost.is_multi_asic:
                dst_is_multi_asic = True
            testParams.update(dutTestParams["basicParams"])
            testParams.update(dutConfig["testPorts"])
            testParams.update({
                "testPortIds": dutConfig["testPortIds"],
                "testPortIps": dutConfig["testPortIps"],
                "testbed_type": dutTestParams["topo"],
                "src_is_multi_asic": src_is_multi_asic,
                "dst_is_multi_asic": dst_is_multi_asic
            })
            self.runPtfTest(
                ptfhost, testCase="sai_qos_tests.ARPpopulate", testParams=testParams
            )

    @pytest.fixture(scope='class', autouse=True)
    def populateArpEntries(
        self, duthosts, get_src_dst_asic_and_duts,
        ptfhost, dutTestParams, dutConfig, releaseAllPorts, handleFdbAging, tbinfo, lower_tor_host # noqa F811
    ):
        """
            Update ARP entries of QoS SAI test ports

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                ptfhost (AnsibleHost): Packet Test Framework (PTF)
                dutTestParams (Fixture, dict): DUT host test params
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports
                releaseAllPorts (Fixture, dict): releaseAllPorts to run prior to updating ARP entries

            Returns:
                None

            Raises:
                RunAnsibleModuleFail if ptf test fails
        """
        # This is not needed in T2.
        if "t2" in dutTestParams["topo"]:
            yield
            return

        self.populate_arp_entries(
            get_src_dst_asic_and_duts, ptfhost, dutTestParams,
            dutConfig, releaseAllPorts, handleFdbAging, tbinfo, lower_tor_host)

        yield
        return

    @pytest.fixture(scope='class', autouse=True)
    def dut_disable_ipv6(self, duthosts, get_src_dst_asic_and_duts, tbinfo, lower_tor_host, # noqa F811
                         swapSyncd_on_selected_duts):
        for duthost in get_src_dst_asic_and_duts['all_duts']:
            docker0_ipv6_addr = \
                duthost.shell("sudo ip -6  addr show dev docker0 | grep global" + " | awk '{print $2}'")[
                    "stdout_lines"][0]
            duthost.shell("sysctl -w net.ipv6.conf.all.disable_ipv6=1")

        yield

        for duthost in get_src_dst_asic_and_duts['all_duts']:
            duthost.shell("sysctl -w net.ipv6.conf.all.disable_ipv6=0")
            logger.info("Adding docker0's IPv6 address since it was removed when disabing IPv6")
            duthost.shell("ip -6 addr add {} dev docker0".format(docker0_ipv6_addr))
            config_reload(duthost, config_source='config_db', safe_reload=True, check_intf_up_ports=True)

    @pytest.fixture(scope='class', autouse=True)
    def sharedHeadroomPoolSize(
        self, request, duthosts, get_src_dst_asic_and_duts, tbinfo, lower_tor_host): # noqa F811
        """
            Retreives shared headroom pool size

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                size: shared headroom pool size
                      none if it is not defined
        """
        yield self.__getSharedHeadroomPoolSize(
            request,
            get_src_dst_asic_and_duts['src_asic']
        )

    @pytest.fixture(scope='class', autouse=True)
    def ingressLosslessProfile(
        self, request, get_src_dst_asic_and_duts, dutConfig, tbinfo, lower_tor_host, dualtor_ports_for_duts # noqa F811
    ):
        """
            Retreives ingress lossless profile

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports

            Returns:
                ingressLosslessProfile (dict): Map of ingress lossless buffer profile attributes
        """

        dut_asic = get_src_dst_asic_and_duts['src_asic']
        duthost = get_src_dst_asic_and_duts['src_dut']
        srcport = dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]]

        if srcport in dualtor_ports_for_duts:
            pgs = "2-4"
        else:
            pgs = "3-4"

        yield self.__getBufferProfile(
            request,
            dut_asic,
            duthost.os_version,
            "BUFFER_PG_TABLE" if self.isBufferInApplDb(
                dut_asic) else "BUFFER_PG",
            srcport,
            pgs
        )

    @pytest.fixture(scope='class', autouse=True)
    def ingressLossyProfile(
        self, request, duthosts, get_src_dst_asic_and_duts, dutConfig, tbinfo, lower_tor_host # noqa F811
    ):
        """
            Retreives ingress lossy profile

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports

            Returns:
                ingressLossyProfile (dict): Map of ingress lossy buffer profile attributes
        """
        duthost = get_src_dst_asic_and_duts['src_dut']
        dut_asic = get_src_dst_asic_and_duts['src_asic']
        yield self.__getBufferProfile(
            request,
            dut_asic,
            duthost.os_version,
            "BUFFER_PG_TABLE" if self.isBufferInApplDb(
                dut_asic) else "BUFFER_PG",
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            "0"
        )

    @pytest.fixture(scope='class', autouse=True)
    def egressLosslessProfile(
        self, request, duthosts, get_src_dst_asic_and_duts, dutConfig, tbinfo, lower_tor_host, dualtor_ports_for_duts # noqa F811
    ):
        """
            Retreives egress lossless profile

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces, test port IDs, test port IPs,
                    and test ports

            Returns:
                egressLosslessProfile (dict): Map of egress lossless buffer profile attributes
        """
        duthost = get_src_dst_asic_and_duts['src_dut']
        dut_asic = get_src_dst_asic_and_duts['src_asic']

        srcport = dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]]

        if srcport in dualtor_ports_for_duts:
            queues = "2-4"
        else:
            queues = "3-4"

        yield self.__getBufferProfile(
            request,
            dut_asic,
            duthost.os_version,
            "BUFFER_QUEUE_TABLE" if self.isBufferInApplDb(
                dut_asic) else "BUFFER_QUEUE",
            srcport,
            queues
        )

    @pytest.fixture(scope='class', autouse=True)
    def egressLossyProfile(
        self, request, duthosts, get_src_dst_asic_and_duts, dutConfig, tbinfo, lower_tor_host, dualtor_ports_for_duts # noqa F811
    ):
        """
            Retreives egress lossy profile

            Args:
                request (Fixture): pytest request object
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces,
                test port IDs, test port IPs, and test ports

            Returns:
                egressLossyProfile (dict): Map of egress lossy buffer profile attributes
        """
        duthost = get_src_dst_asic_and_duts['src_dut']
        dut_asic = get_src_dst_asic_and_duts['src_asic']

        srcport = dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]]

        if srcport in dualtor_ports_for_duts:
            queues = "0-1"
        else:
            queues = "0-2"

        yield self.__getBufferProfile(
            request,
            dut_asic,
            duthost.os_version,
            "BUFFER_QUEUE_TABLE" if self.isBufferInApplDb(
                dut_asic) else "BUFFER_QUEUE",
            srcport,
            queues
        )

    @pytest.fixture(scope='class')
    def losslessSchedProfile(
            self, duthosts, get_src_dst_asic_and_duts, dutConfig, tbinfo, lower_tor_host  # noqa F811
    ):
        """
            Retreives lossless scheduler profile

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces,
                test port IDs, test port IPs, and test ports

            Returns:
                losslessSchedProfile (dict): Map of scheduler parameters
        """
        dut_asic = get_src_dst_asic_and_duts['src_asic']

        yield self.__getSchedulerParam(
            dut_asic,
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            self.TARGET_LOSSLESS_QUEUE_SCHED
        )

    @pytest.fixture(scope='class')
    def lossySchedProfile(
        self, duthosts, get_src_dst_asic_and_duts, dutConfig, tbinfo, lower_tor_host  # noqa F811
    ):
        """
            Retreives lossy scheduler profile

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                dutConfig (Fixture, dict): Map of DUT config containing dut interfaces,
                test port IDs, test port IPs, and test ports

            Returns:
                lossySchedProfile (dict): Map of scheduler parameters
        """
        dut_asic = get_src_dst_asic_and_duts['src_asic']

        yield self.__getSchedulerParam(
            dut_asic,
            dutConfig["dutInterfaces"][dutConfig["testPorts"]["src_port_id"]],
            self.TARGET_LOSSY_QUEUE_SCHED
        )

    @pytest.fixture
    def updateSchedProfile(
        self, duthosts, get_src_dst_asic_and_duts,
        dutQosConfig, losslessSchedProfile, lossySchedProfile, tbinfo, lower_tor_host  # noqa F811
    ):
        """
            Updates lossless/lossy scheduler profiles

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)
                dutQosConfig (Fixture, dict): Map containing DUT host QoS configuration
                losslessSchedProfile (Fixture, dict): Map of lossless scheduler parameters
                lossySchedProfile (Fixture, dict): Map of lossy scheduler parameters

            Returns:
                None
        """
        def updateRedisSchedParam(schedParam):
            """
                Helper function to updates lossless/lossy scheduler profiles

                Args:
                    schedParam (dict): Scheduler params to be set

                Returns:
                    None
            """
            for a_asic in get_src_dst_asic_and_duts['all_asics']:
                a_asic.run_redis_cmd(
                    argv=[
                        "redis-cli",
                        "-n",
                        "4",
                        "HSET",
                        schedParam["profile"],
                        "weight",
                        schedParam["qosConfig"]
                    ]
                )

        wrrSchedParams = [
            {
                "profile": lossySchedProfile["schedProfile"],
                "qosConfig": dutQosConfig["param"]["wrr_chg"]["lossy_weight"]
            },
            {
                "profile": losslessSchedProfile["schedProfile"],
                "qosConfig": dutQosConfig["param"]["wrr_chg"]["lossless_weight"]
            },
        ]

        for schedParam in wrrSchedParams:
            updateRedisSchedParam(schedParam)

        yield

        schedProfileParams = [
            {
                "profile": lossySchedProfile["schedProfile"],
                "qosConfig": lossySchedProfile["schedWeight"]
            },
            {
                "profile": losslessSchedProfile["schedProfile"],
                "qosConfig": losslessSchedProfile["schedWeight"]
            },
        ]

        for schedParam in schedProfileParams:
            updateRedisSchedParam(schedParam)

    @pytest.fixture
    def resetWatermark(
        self, duthosts, get_src_dst_asic_and_duts, tbinfo, lower_tor_host   # noqa F811
    ):
        """
            Reset queue watermark

            Args:
                duthost (AnsibleHost): Device Under Test (DUT)

            Returns:
                None
        """

        for dut_asic in get_src_dst_asic_and_duts['all_asics']:
            dut_asic.command("counterpoll watermark enable")
            dut_asic.command("counterpoll queue enable")

        time.sleep(70)
        for dut_asic in get_src_dst_asic_and_duts['all_asics']:
            dut_asic.command("counterpoll watermark disable")
            dut_asic.command("counterpoll queue disable")

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

    @pytest.fixture(scope='function', autouse=True)
    def set_static_route(
            self, get_src_dst_asic_and_duts, dutTestParams, dutConfig):
        # Get portchannels.
        # find the one that is backplane based.
        # set a static route through that portchannel.
        # remove when done.
        src_asic = get_src_dst_asic_and_duts['src_asic']
        dst_asic = get_src_dst_asic_and_duts['dst_asic']

        try:
            if not (
                src_asic.sonichost.facts['switch_type'] == "chassis-packet"
                    and dutTestParams['topo'] == 't2'):
                yield
                return
        except KeyError:
            yield
            return

        dst_keys = []
        for k in dutConfig["testPorts"].keys():
            if re.search("dst_port.*ip", k):
                dst_keys.append(k)

        for k in dst_keys:
            dst_asic.shell("ip netns exec asic{} ping -c 3 {}".format(
                dst_asic.asic_index,
                dutConfig["testPorts"][k]), module_ignore_errors=True)

        ip_address_mapping = self.get_interface_ip(dst_asic)
        for intf in ip_address_mapping.keys():
            if ip_address_mapping[intf]['peer_addr'] != '':
                dst_asic.shell("ip netns exec asic{} ping -c 3 {}".format(
                    dst_asic.asic_index,
                    ip_address_mapping[intf]['peer_addr']), module_ignore_errors=True)

        if src_asic == dst_asic:
            yield
            return

        portchannels = dst_asic.command(
            "show interface portchannel -n asic{} -d all".format(
                dst_asic.asic_index))['stdout']
        regx = re.compile("(PortChannel[0-9]+)")
        bp_portchannels = []
        for pc in portchannels.split("\n"):
            if "-BP" in pc:
                match = regx.search(pc)
                if match:
                    bp_portchannels.append(match.group(1))
        if not bp_portchannels:
            raise RuntimeError(
                "Couldn't find the backplane porchannels from {}".format(
                    bp_portchannels))

        non_bp_intfs = set(list(ip_address_mapping.keys())) \
            - set(bp_portchannels)
        addresses_to_ping = []
        for dst_key in dst_keys:
            addresses_to_ping.append(dutConfig["testPorts"][dst_key])

        for dst_intf in non_bp_intfs:
            if ip_address_mapping[dst_intf]['peer_addr'] != '':
                addresses_to_ping.append(
                    ip_address_mapping[dst_intf]['peer_addr'])

        addresses_to_ping = list(set(addresses_to_ping))
        no_of_bp_pcs = len(bp_portchannels)

        for dst_index in range(len(addresses_to_ping)):
            gw = ip_address_mapping[
                bp_portchannels[dst_index % no_of_bp_pcs]]['addr']
            src_asic.shell("ip netns exec asic{} ping -c 1 {}".format(
                src_asic.asic_index, gw))
            src_asic.shell("ip netns exec asic{} route add {} gw {}".format(
                src_asic.asic_index,
                addresses_to_ping[dst_index],
                gw))
        yield
        for dst_index in range(len(addresses_to_ping)):
            gw = ip_address_mapping[
                bp_portchannels[dst_index % no_of_bp_pcs]]['addr']
            src_asic.shell("ip netns exec asic{} route del {} gw {}".format(
                src_asic.asic_index,
                addresses_to_ping[dst_index],
                gw))

    def get_interface_ip(self, dut_asic):
        """
            Parse the output of "show ip int -n asic0 -d all" into a dict:
            interface => ip address.
        """
        mapping = {}
        ip_address_out = dut_asic.command(
            "show ip interface -n asic{} -d all".format(
                dut_asic.asic_index))['stdout']
        re_pattern = re.compile(
            r"^([^ ]*) [ ]*([0-9\.]*)\/[0-9]*  *[^ ]*  *[^ ]*  *([0-9\.]*)")
        for line in ip_address_out.split("\n"):
            match = re_pattern.search(line)
            if match:
                mapping[match.group(1)] = {
                    'addr': match.group(2),
                    'peer_addr': match.group(3),
                }

        return mapping

    @pytest.fixture(autouse=False)
    def _check_ingress_speed_gte_400g(
            self,
            get_src_dst_asic_and_duts,
            dutQosConfig):
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        m = re.search("([0-9]+)_([0-9]+m)", portSpeedCableLength)
        if not m:
            raise RuntimeError(
                "Format error in portSpeedCableLength:{}".
                format(portSpeedCableLength))
        speed = int(m.group(1))
        if speed >= 400000:
            pytest.skip("PGDrop test is not supported for 400G port speed.")

    def select_port_ids_for_mellnaox_device(self, duthost, mgFacts, testPortIds, dualtor_dut_ports=None):
        """
        For Nvidia devices, the tested ports must have the same cable length and speed.
        Firstly, categorize the ports by the same cable length and speed.
        Secondly, select the port group with the largest number of ports as test ports from the above results.
        """
        ptf_port_dut_port_dict = dict(zip(mgFacts["minigraph_ptf_indices"].values(),
                                          mgFacts["minigraph_ptf_indices"].keys()))
        get_interface_cable_length_info = 'redis-cli -n 4 hgetall "CABLE_LENGTH|AZURE"'
        interface_cable_length_list = duthost.shell(get_interface_cable_length_info)['stdout_lines']
        interface_status = duthost.show_interface(command="status")["ansible_facts"]['int_status']

        cable_length_speed_interface_dict = {}
        for ptf_port in testPortIds:
            dut_port = ptf_port_dut_port_dict[ptf_port]
            # Always select dualtor ports if not None
            if dualtor_dut_ports and dut_port not in dualtor_dut_ports:
                continue
            if dut_port in interface_cable_length_list:
                cable_length = interface_cable_length_list[interface_cable_length_list.index(dut_port) + 1]
                speed = interface_status[dut_port]['speed']
                cable_length_speed = f"{cable_length}_{speed}"
                if cable_length_speed in cable_length_speed_interface_dict:
                    cable_length_speed_interface_dict[cable_length_speed].append(ptf_port)
                else:
                    cable_length_speed_interface_dict[cable_length_speed] = [ptf_port]
        max_port_num = 0
        test_port_ids = []
        # Find the port group with the largest number of ports as test ports
        for _, port_list in cable_length_speed_interface_dict.items():
            if max_port_num < len(port_list):
                test_port_ids = port_list
                max_port_num = len(port_list)
        logger.info(f"Test ports ids is{test_port_ids}")
        return test_port_ids

    @pytest.fixture(scope="function", autouse=False)
    def _skip_watermark_multi_DUT(
            self,
            get_src_dst_asic_and_duts,
            dutQosConfig):
        if not is_cisco_device(get_src_dst_asic_and_duts['src_dut']):
            yield
            return
        if (get_src_dst_asic_and_duts['src_dut'] !=
                get_src_dst_asic_and_duts['dst_dut']):
            pytest.skip(
                "All WM Tests are skipped for multiDUT for cisco platforms.")

        yield
        return

    @pytest.fixture(scope="function", autouse=False)
    def skip_src_dst_different_asic(self, dutConfig):
        if dutConfig['dutAsic'] != dutConfig['dstDutAsic']:
            pytest.skip(
                "This test is skipped since asic types of ingress and egress are different.")
        yield
        return

    @pytest.fixture(scope="function", autouse=False)
    def skip_pacific_dst_asic(self, dutConfig):
        if dutConfig.get('dstDutAsic', 'UnknownDstDutAsic') == "pac":
            pytest.skip(
                "This test is skipped since egress asic is cisco-8000 Q100.")
        yield
        return

    def populate_arp_entries(
        self, get_src_dst_asic_and_duts,
        ptfhost, dutTestParams, dutConfig, releaseAllPorts, handleFdbAging, tbinfo, lower_tor_host  # noqa F811
    ):
        """
        Update ARP entries of QoS SAI test ports
        """
        dut_asic = get_src_dst_asic_and_duts['src_asic']

        dut_asic.command('sonic-clear fdb all')
        dut_asic.command('sonic-clear arp')

        saiQosTest = None
        if dutTestParams["topo"] in self.SUPPORTED_T0_TOPOS:
            saiQosTest = "sai_qos_tests.ARPpopulate"
        elif dutTestParams["topo"] in self.SUPPORTED_PTF_TOPOS:
            saiQosTest = "sai_qos_tests.ARPpopulatePTF"
        else:
            for dut_asic in get_src_dst_asic_and_duts['all_asics']:
                result = dut_asic.command("arp -n")
                pytest_assert(result["rc"] == 0, "failed to run arp command on {0}".format(dut_asic.sonichost.hostname))
                if result["stdout"].find("incomplete") == -1:
                    saiQosTest = "sai_qos_tests.ARPpopulate"

        if saiQosTest:
            testParams = dutTestParams["basicParams"]
            testParams.update(dutConfig["testPorts"])
            testParams.update({
                "testPortIds": dutConfig["testPortIds"],
                "testPortIps": dutConfig["testPortIps"],
                "testbed_type": dutTestParams["topo"]
            })
            self.runPtfTest(
                ptfhost, testCase=saiQosTest, testParams=testParams
            )

    @pytest.fixture(scope="function", autouse=False)
    def set_static_route_ptf64(self, dutConfig, get_src_dst_asic_and_duts, dutTestParams, enum_frontend_asic_index):
        def generate_ip_address(base_ip, new_first_octet):
            octets = base_ip.split('.')
            if len(octets) != 4:
                raise ValueError("Invalid IP address format")
            octets[0] = str(new_first_octet)
            octets[2] = octets[3]
            octets[3] = '1'
            return '.'.join(octets)

        def combine_ips(src_ips, dst_ips, new_first_octet):
            combined_ips_map = {}

            for key, src_info in src_ips.items():
                src_ip = src_info['peer_addr']
                new_ip = generate_ip_address(src_ip, new_first_octet)
                combined_ips_map[key] = {'original_ip': src_ip, 'generated_ip': new_ip}

            for key, dst_info in dst_ips.items():
                dst_ip = dst_info['peer_addr']
                new_ip = generate_ip_address(dst_ip, new_first_octet)
                combined_ips_map[key] = {'original_ip': dst_ip, 'generated_ip': new_ip}

            return combined_ips_map

        def configRoutePrefix(add_route):
            action = "add" if add_route else "del"
            for port, entry in combined_ips_map.items():
                if enum_frontend_asic_index is None:
                    src_asic.shell("config route {} prefix {}.0/24 nexthop {}".format(
                        action, '.'.join(entry['generated_ip'].split('.')[:3]), entry['original_ip']))
                else:
                    src_asic.shell("ip netns exec asic{} config route {} prefix {}.0/24 nexthop {}".format(
                        enum_frontend_asic_index,
                        action, '.'.join(entry['generated_ip'].split('.')[:3]),
                        entry['original_ip'])
                      )

        if dutTestParams["basicParams"]["sonic_asic_type"] != "cisco-8000":
            pytest.skip("Traffic sanity test is not supported")

        if dutTestParams["topo"] != "ptf64":
            pytest.skip("Test not supported in {} topology. Use ptf64 topo".format(dutTestParams["topo"]))

        src_dut_index = get_src_dst_asic_and_duts['src_dut_index']
        dst_dut_index = get_src_dst_asic_and_duts['dst_dut_index']
        src_asic_index = get_src_dst_asic_and_duts['src_asic_index']
        dst_asic_index = get_src_dst_asic_and_duts['dst_asic_index']
        src_asic = get_src_dst_asic_and_duts['src_asic']

        src_testPortIps = dutConfig["testPortIps"][src_dut_index][src_asic_index]
        dst_testPortIps = dutConfig["testPortIps"][dst_dut_index][dst_asic_index]

        new_first_octet = 100
        combined_ips_map = combine_ips(src_testPortIps, dst_testPortIps, new_first_octet)

        configRoutePrefix(True)
        yield combined_ips_map
        configRoutePrefix(False)

    @pytest.fixture(scope="function", autouse=False)
    def skip_longlink(self, dutQosConfig):
        portSpeedCableLength = dutQosConfig["portSpeedCableLength"]
        match = re.search("_([0-9]*)m", portSpeedCableLength)
        if match and int(match.group(1)) > 2000:
            pytest.skip(
                "This test is skipped for longlink.")
        yield
        return
