import json
import pytest
import os
import logging
from tests.common.mellanox_data import is_mellanox_device
from .args.counterpoll_cpu_usage_args import add_counterpoll_cpu_usage_args
from tests.common.helpers.mellanox_thermal_control_test_helper import suspend_hw_tc_service, resume_hw_tc_service
from tests.common.platform.transceiver_utils import get_ports_with_flat_memory


@pytest.fixture(autouse=True, scope="module")
def skip_on_simx(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    platform = duthost.facts["platform"]
    hwsku = duthost.facts['hwsku']
    support_platform_simx_hwsku_list = ['ACS-MSN4700', 'ACS-SN4280']
    if "simx" in platform and hwsku not in support_platform_simx_hwsku_list:
        pytest.skip('skipped on this platform: {}'.format(platform))


@pytest.fixture(scope="module")
def xcvr_skip_list(duthosts, dpu_npu_port_list, tbinfo):
    intf_skip_list = {}
    for dut in duthosts:
        platform = dut.facts['platform']
        hwsku = dut.facts['hwsku']
        f_path = os.path.join('/usr/share/sonic/device',
                              platform, hwsku, 'hwsku.json')
        intf_skip_list[dut.hostname] = []
        dut.has_sku = True
        try:
            out = dut.command("cat {}".format(f_path))
            hwsku_info = json.loads(out["stdout"])
            for int_n in hwsku_info['interfaces']:
                if hwsku_info['interfaces'][int_n].get('port_type') == "RJ45":
                    intf_skip_list[dut.hostname].append(int_n)
            for int_n in dpu_npu_port_list[dut.hostname]:
                if int_n not in intf_skip_list[dut.hostname]:
                    intf_skip_list[dut.hostname].append(int_n)

        except Exception:
            # hwsku.json does not exist will return empty skip list
            dut.has_sku = False
            logging.debug(
                "hwsku.json absent or port_type for interfaces not included for hwsku {}".format(hwsku))

        # No hwsku.json for Arista-7050-QX-32S/Arista-7050QX-32S-S4Q31
        if hwsku in ['Arista-7050-QX-32S', 'Arista-7050QX-32S-S4Q31']:
            sfp_list = ['Ethernet0', 'Ethernet1', 'Ethernet2', 'Ethernet3']
            logging.debug('Skipping sfp interfaces: {}'.format(sfp_list))
            intf_skip_list[dut.hostname].extend(sfp_list)

        # For Mx topo, skip the SFP interfaces because they are admin down
        if tbinfo['topo']['name'] == "mx" and hwsku in ["Arista-720DT-G48S4", "Nokia-7215"]:
            sfp_list = ['Ethernet48', 'Ethernet49', 'Ethernet50', 'Ethernet51']
            logging.debug('Skipping sfp interfaces: {}'.format(sfp_list))
            intf_skip_list[dut.hostname].extend(sfp_list)

    return intf_skip_list


@pytest.fixture()
def bring_up_dut_interfaces(request, duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
    Bring up outer interfaces on the DUT.

    Args:
        request: pytest request object
        duthost: Fixture for interacting with the DUT.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    yield
    if request.node.rep_call.failed:
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        ports = list(mg_facts['minigraph_ports'].keys())

        # Enable outer interfaces
        for port in ports:
            namespace = mg_facts["minigraph_neighbors"][port]['namespace']
            namespace_arg = '-n {}'.format(namespace) if namespace else ''
            duthost.command("sudo config interface {} startup {}".format(namespace_arg, port))


@pytest.fixture()
def capture_interface_counters(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logging.info("Run commands to print logs")

    show_counter_cmds = [
        "show interfaces counters",
        "show interfaces counters rif",
        "show queue counters",
        "show pfc counters"
    ]
    clear_counter_cmds = [
        "sonic-clear counters",
        "sonic-clear queuecounters",
        "sonic-clear dropcounters",
        "sonic-clear rifcounters",
        "sonic-clear pfccounters"
    ]
    if duthost.facts["asic_type"] == "broadcom":
        bcm_show_cmds = [
            "bcmcmd 'show counters'",
            "bcmcmd 'cstat all'"
        ]
        bcm_clear_cmds = [
            "bcmcmd 'clear counters'"
        ]
        show_counter_cmds = show_counter_cmds + bcm_show_cmds
        clear_counter_cmds = clear_counter_cmds + bcm_clear_cmds
    duthost.shell_cmds(cmds=clear_counter_cmds,
                       module_ignore_errors=True, verbose=False)
    results = duthost.shell_cmds(
        cmds=show_counter_cmds, module_ignore_errors=True, verbose=False)['results']
    outputs = []
    for res in results:
        res.pop('stdout')
        res.pop('stderr')
        outputs.append(res)
    logging.debug("Counters before reboot test: dut={}, cmd_outputs={}".format(duthost.hostname,
                  json.dumps(outputs, indent=4)))

    yield

    results = duthost.shell_cmds(
        cmds=show_counter_cmds, module_ignore_errors=True, verbose=False)['results']
    outputs = []
    for res in results:
        res.pop('stdout')
        res.pop('stderr')
        outputs.append(res)
    logging.debug("Counters after reboot test: dut={}, cmd_outputs={}".format(duthost.hostname,
                  json.dumps(outputs, indent=4)))


@pytest.fixture()
def thermal_manager_enabled(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    thermal_manager_available = True
    if duthost.facts.get("chassis"):
        thermal_manager_available = duthost.facts.get(
            "chassis").get("thermal_manager", True)
    if not thermal_manager_available:
        pytest.skip("skipped as thermal manager is not available")


def pytest_generate_tests(metafunc):
    if 'power_off_delay' in metafunc.fixturenames:
        delays = metafunc.config.getoption('power_off_delay')
        default_delay_list = [5, 15]
        if not delays:
            # if power_off_delay option is not present, set it to default [5, 15] for backward compatible
            metafunc.parametrize('power_off_delay', default_delay_list)
        else:
            try:
                delay_list = [int(delay.strip())
                              for delay in delays.split(',')]
                metafunc.parametrize('power_off_delay', delay_list)
            except ValueError:
                metafunc.parametrize('power_off_delay', default_delay_list)


def pytest_addoption(parser):
    add_counterpoll_cpu_usage_args(parser)


@pytest.fixture(scope="function", autouse=False)
def suspend_and_resume_hw_tc_on_mellanox_device(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    suspend and resume hw thermal control service on mellanox device
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if is_mellanox_device(duthost) and duthost.is_host_service_running("hw-management-tc"):
        suspend_hw_tc_service(duthost)

    yield

    if is_mellanox_device(duthost) and duthost.is_host_service_running("hw-management-tc"):
        resume_hw_tc_service(duthost)


@pytest.fixture(scope="module")
def dpu_npu_port_list(duthosts):
    dpu_npu_port_list = {}
    cmd_get_config_db_port_key_list = 'redis-cli --raw -n 4 keys "PORT|Ethernet*"'
    cmd_dump_config_db = "sonic-db-dump -n CONFIG_DB -y"
    dpu_npu_role = 'Dpc'
    for dut in duthosts:
        dpu_npu_port_list[dut.hostname] = []
        port_key_list = dut.command(cmd_get_config_db_port_key_list)['stdout'].split('\n')
        config_db_res = json.loads(dut.command(cmd_dump_config_db)["stdout"])

        for port_key in port_key_list:
            if port_key in config_db_res:
                if dpu_npu_role == config_db_res[port_key].get('value').get('role'):
                    dpu_npu_port_list[dut.hostname].append(port_key.split("|")[-1])
    logging.info(f"dpu npu port list: {dpu_npu_port_list}")
    return dpu_npu_port_list


@pytest.fixture(scope="module")
def port_list_with_flat_memory(duthosts):
    ports_with_flat_memory = {}
    for dut in duthosts:
        ports_with_flat_memory.update({dut.hostname: get_ports_with_flat_memory(dut)})
    logging.info(f"port list with flat memory: {ports_with_flat_memory}")
    return ports_with_flat_memory
