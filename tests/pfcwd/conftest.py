import logging
import pytest
import os
import os.path

from tests.common.fixtures.conn_graph_facts import conn_graph_facts         # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa: F401
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode   # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # noqa: F401
from tests.common.fixtures.ptfhost_utils import pause_garp_service           # noqa: F401
from tests.common.fixtures.ptfhost_utils import ptf_test_port_map_active_active
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice
from tests.common.cisco_data import is_cisco_device, check_dshell_ready
from tests.common.utilities import str2bool, wait_until
from tests.common.helpers.pfcwd_helper import HARDWARE, SOFTWARE, get_pfcwd_recovery_mode
from tests.common.helpers.pfcwd_recovery import SOFTWARE_STATE, RecoveryModeUnsupported, \
    available_recovery_modes, native_recovery_mode, recovery_state, restore_recovery_mode, set_recovery_mode
from tests.common.helpers.sonic_db import redis_hdel

logger = logging.getLogger(__name__)

SET_PFC_TIME_SUCCESS_MSG = "PFC bit time set successful"
# --pfcwd-recovery-modes value: run the mechanism the DUT boots into, never switch, keep today's test ids.
NATIVE = "native"


def pytest_addoption(parser):
    """
    Command line args specific for the pfcwd test

    Args:
        parser: pytest parser object

    Returns:
        None

    """
    parser.addoption('--warm-reboot', action='store', type=bool, default=False,
                     help='Warm reboot needs to be enabled or not')
    parser.addoption('--restore-time', action='store', type=int, default=3000,
                     help='PFC WD storm restore interval')
    parser.addoption('--fake-storm', action='store', type=str2bool, default=True,
                     help='Fake storm for most ports instead of using pfc gen')
    parser.addoption('--two-queues', action='store_true', default=True,
                     help='Run test with sending traffic to both queues [3, 4]')
    parser.addoption('--save-timer-results', action='store_true', default=False,
                     help='Save results of pfc timer accuracy test to file')


def pytest_configure(config):
    """Parse --pfcwd-recovery-modes once into config.pfcwd_recovery_modes; reject unknown values."""
    option = config.getoption('--pfcwd-recovery-modes')
    requested = list(dict.fromkeys(m.strip().lower() for m in option.split(',') if m.strip()))
    if requested != [NATIVE] and (not requested or any(mode not in (HARDWARE, SOFTWARE) for mode in requested)):
        raise pytest.UsageError('--pfcwd-recovery-modes takes {!r} or a comma separated list of {} and {}, '
                                'got {!r}'.format(NATIVE, HARDWARE, SOFTWARE, option))
    config.pfcwd_recovery_modes = requested


@pytest.hookimpl(trylast=True)
def pytest_generate_tests(metafunc):
    """Parametrize over modes at session scope; native or hardware-only keeps ids unchanged; suffix stays last."""
    requested = metafunc.config.pfcwd_recovery_modes
    if 'pfcwd_recovery_mode' in metafunc.fixturenames and requested not in ([NATIVE], [HARDWARE]):
        metafunc.parametrize('pfcwd_recovery_mode', requested, indirect=True, scope='session',
                             ids=['recovery_{}'.format(mode) for mode in requested])


@pytest.fixture(scope="session")
def pfcwd_recovery_mode(request):
    """The recovery mechanism the current phase of the run covers, or NATIVE."""
    return getattr(request, "param", None) or request.config.pfcwd_recovery_modes[0]


@pytest.fixture(scope="session")
def pfcwd_recovery_session(duthosts, pfcwd_recovery_mode):
    """
    Per-DUT native mechanism (read once, after clearing any stale override), the
    DUTs switched in this session and the switches that failed. Restores the
    switched DUTs at session end. Reads nothing in a native run.
    """
    state = {"native": {}, "switched": set(), "failed": set(), "unsupported": {}}
    if pfcwd_recovery_mode == NATIVE:
        yield state
        return
    for duthost in duthosts.frontend_nodes:
        state["native"][duthost.hostname] = native_recovery_mode(duthost)
        logger.info("%s: native PFC watchdog recovery is %s", duthost.hostname, state["native"][duthost.hostname])

    yield state

    failures = []
    for duthost in duthosts.frontend_nodes:
        if duthost.hostname in state["switched"]:
            try:
                restore_recovery_mode(duthost)
            except Exception as exc:
                failures.append("{}: {}".format(duthost.hostname, exc))
    if failures:
        pytest.fail("PFC watchdog recovery mechanism not restored:\n" + "\n".join(failures))


@pytest.fixture(scope="module", autouse=True)
def pfcwd_recovery_mode_setup(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                              pfcwd_recovery_mode, pfcwd_recovery_session):
    """Put the DUT into this phase's mechanism, or skip the module if it cannot run it."""
    if pfcwd_recovery_mode == NATIVE:
        return
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    native = pfcwd_recovery_session["native"][duthost.hostname]
    if pfcwd_recovery_mode not in available_recovery_modes(duthost, native):
        pytest.skip("{} recovery is not available on {} (native: {})".format(
            pfcwd_recovery_mode, duthost.hostname, native))
    key = (duthost.hostname, pfcwd_recovery_mode)
    if key in pfcwd_recovery_session["unsupported"]:
        pytest.skip(pfcwd_recovery_session["unsupported"][key])
    if key in pfcwd_recovery_session["failed"]:
        pytest.fail("switching {} to {} recovery already failed in this session".format(*key))
    if pfcwd_recovery_mode != native:
        pfcwd_recovery_session["switched"].add(duthost.hostname)
        try:
            set_recovery_mode(duthost, pfcwd_recovery_mode)
        except RecoveryModeUnsupported as exc:
            pfcwd_recovery_session["unsupported"][key] = str(exc)
            pytest.skip(str(exc))
        except Exception:
            pfcwd_recovery_session["failed"].add(key)
            raise


@pytest.fixture(autouse=True)
def pfcwd_recovery_mode_check(duthosts, enum_rand_one_per_hwsku_frontend_hostname, pfcwd_recovery_mode,
                              pfcwd_recovery_session):
    """Keep the phase label honest across the config reloads and reboots the modules do."""
    if pfcwd_recovery_mode == NATIVE:
        return
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if pfcwd_recovery_mode == SOFTWARE and duthost.hostname in pfcwd_recovery_session["switched"]:
        # Forced software: the full read-back, so an unpublished mechanism or a return of DLR init fails too.
        state = recovery_state(duthost)
        if state != SOFTWARE_STATE:
            pytest.fail("{} is not running forced software recovery: {}".format(duthost.hostname, state))
        return
    running = get_pfcwd_recovery_mode(duthost)
    if running != pfcwd_recovery_mode:
        pytest.fail("{} is running {} recovery but this phase is {}".format(
            duthost.hostname, running, pfcwd_recovery_mode))


@pytest.fixture(scope="module")
def two_queues(request, duthosts, enum_rand_one_per_hwsku_frontend_hostname, fanouthosts):
    """
    Enable/Disable sending traffic to queues [4, 3]
    By default send to queue 4

    Args:
        request: pytest request object
        duthosts: AnsibleHost instance for multi DUT
        enum_rand_one_per_hwsku_frontend_hostname: hostname of DUT

    Returns:
        two_queues: False/True
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    dut_asic_type = duthost.facts["asic_type"].lower()
    # On Mellanox devices, if the leaf-fanout is running EOS, then only one queue is supported
    if dut_asic_type == "mellanox":
        for fanouthost in list(fanouthosts.values()):
            fanout_os = fanouthost.get_fanout_os()
            if fanout_os == "eos":
                return False
    return request.config.getoption("--two-queues")


@pytest.fixture(scope="module")
def fake_storm(request, duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Enable/disable fake storm based on platform and input parameters

    Args:
        request: pytest request object
        duthosts: AnsibleHost instance for multi DUT
        enum_rand_one_per_hwsku_frontend_hostname: hostname of DUT

    Returns:
        fake_storm: False/True
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    return False if (isMellanoxDevice(duthost) or
                     is_cisco_device(duthost) or
                     "7060X6" in duthost.facts['hwsku'].upper()) \
        else request.config.getoption('--fake-storm')


@pytest.fixture(scope="module")
def save_timer_results(request):
    """
    Save pfcwd_timer_accuracy test results to file.
    By default, the test results will not be persisted.

    Args:
        request: pytest request object

    Returns:
        save_timer_results: True/False
    """
    return request.config.getoption('--save-timer-results')


@pytest.fixture(scope="module")
def setup_dut_test_params(
    duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, conn_graph_facts, tbinfo,    # noqa: F811
):
    """
    Sets up all the parameters needed for the PFCWD tests

    Args:
        duthost: AnsibleHost instance for DUT
        ptfhost: AnsibleHost instance for PTF
        conn_graph_facts: fixture that contains the parsed topology info

    Yields:
        dut_info: dictionary containing dut information
    """
    dut_test_params = {"basicParams": {"is_dualtor": False}}
    if "dualtor" in tbinfo["topo"]["name"]:
        dut_test_params["basicParams"]["is_dualtor"] = True
        vlan_cfgs = tbinfo["topo"]["properties"]["topology"]["DUT"]["vlan_configs"]
        if vlan_cfgs and "default_vlan_config" in vlan_cfgs:
            default_vlan_name = vlan_cfgs["default_vlan_config"]
            if default_vlan_name:
                for vlan in list(vlan_cfgs[default_vlan_name].values()):
                    if "mac" in vlan and vlan["mac"]:
                        dut_test_params["basicParams"]["def_vlan_mac"] = vlan["mac"]
                        break

    logger.info("dut_test_params : {}".format(dut_test_params))
    yield dut_test_params


# icmp_responder need to be paused during the test because the test case
# configures static IP address on ptf host and sends ICMP reply to DUT.
@pytest.fixture(scope="module", autouse=True)
def pfcwd_pause_service(ptfhost):
    needs_resume = {"icmp_responder": False, "garp_service": False}

    out = ptfhost.shell("supervisorctl status icmp_responder", module_ignore_errors=True).get("stdout", "")
    if "RUNNING" in out:
        needs_resume["icmp_responder"] = True
        ptfhost.shell("supervisorctl stop icmp_responder")

    out = ptfhost.shell("supervisorctl status garp_service", module_ignore_errors=True).get("stdout", "")
    if "RUNNING" in out:
        needs_resume["garp_service"] = True
        ptfhost.shell("supervisorctl stop garp_service")

    logger.debug("pause_service needs_resume {}".format(needs_resume))

    yield

    if needs_resume["icmp_responder"]:
        ptfhost.shell("supervisorctl start icmp_responder")
        needs_resume["icmp_responder"] = False
    if needs_resume["garp_service"]:
        ptfhost.shell("supervisorctl start garp_service")
        needs_resume["garp_service"] = False

    logger.debug("pause_service needs_resume {}".format(needs_resume))


@pytest.fixture(scope="function", autouse=False)
def set_pfc_time_cisco_8000(
        duthosts,
        enum_rand_one_per_hwsku_frontend_hostname,
        setup_pfc_test):

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    test_ports = setup_pfc_test["test_ports"]

    # Lets limit this to cisco and T2 only.
    if duthost.facts["asic_type"] != "cisco-8000":
        yield
        return

    PFC_TIME_SET_SCRIPT = "pfcwd/cisco/set_pfc_time.py"
    PFC_TIME_RESET_SCRIPT = "pfcwd/cisco/default_pfc_time.py"

    # Construct a map of asic_id to list of ports for multi-asic devices
    # Recycle the keys from ports for single-asic devices

    if duthost.sonichost.is_multi_asic:
        asic_to_ports = dict()
        for port in test_ports.keys():
            asic_instance = duthost.get_port_asic_instance(port)
            if asic_instance:
                if asic_instance.asic_index not in asic_to_ports:
                    asic_to_ports[asic_instance.asic_index] = [port]
                else:
                    asic_to_ports[asic_instance.asic_index].append(port)
    else:
        asic_to_ports = list(test_ports.keys())

    set_pfc_timer_cisco_8000(duthost, PFC_TIME_SET_SCRIPT, asic_to_ports)

    yield

    set_pfc_timer_cisco_8000(duthost, PFC_TIME_RESET_SCRIPT, asic_to_ports)


def set_pfc_timer_cisco_8000(duthost, script, asic_to_ports):
    script_name = os.path.basename(script)

    def copy_and_run(dut_script_path, port_list, asic=None):
        duthost.copy(src=script, dest=dut_script_path)
        ports_as_str = "[" + ",".join([f'"{port}"' for port in port_list]) + "]"
        duthost.shell(f"sed -i 's/__PARAM_INTERFACES__/{ports_as_str}/' {dut_script_path}")
        duthost.shell(f"sed -i 's/__PARAM_SUCCESS__/\"{SET_PFC_TIME_SUCCESS_MSG}\"/' {dut_script_path}")
        asic_str = str(asic) if asic is not None else ""
        duthost.docker_copy_to_all_asics(container_name=f"syncd{asic_str}", src=dut_script_path, dst="/")
        container_script_path = "/" + os.path.basename(dut_script_path)
        asic_str = f"-n asic{asic}" if asic is not None else ""
        run_cmd = f"show platform npu script {asic_str} -s {container_script_path}"

        # dshell may still be initializing after a syncd lifecycle event; wait
        # for it to be ready before running the script.
        if not wait_until(300, 20, 0, check_dshell_ready, duthost, asic):
            assert False, f"Script {script_name} failed to execute correctly; dshell not ready on {duthost.hostname}"

        result = duthost.shell(run_cmd)
        success = SET_PFC_TIME_SUCCESS_MSG in result["stdout"]
        assert success, f"Script {script_name} failed to execute correctly, output: {result['stdout']}"

    if type(asic_to_ports) is dict:
        for asic_id, ports in asic_to_ports.items():
            dut_script_path = f"/tmp/asic{asic_id}_{script_name}"
            copy_and_run(dut_script_path, ports, asic=asic_id)
    elif type(asic_to_ports) is list:
        dut_script_path = f"/tmp/{script_name}"
        copy_and_run(dut_script_path, asic_to_ports)
    else:
        assert False, f"Invalid type of port info sent to PFC timer script: {type(asic_to_ports).__name__}."


@pytest.fixture(scope="module", autouse=True)
def save_and_restore_pfcwd_config(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                  pfcwd_recovery_mode_setup):
    """
    Fixture that saves PFCWD configuration before each test and restores it after

    Args:
        duthosts: AnsibleHost instance for multi DUT
        enum_rand_one_per_hwsku_frontend_hostname: hostname of DUT

    Yields:
        None
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Get current PFCWD configuration from config_db.json
    cmd = "jq '.PFC_WD' /etc/sonic/config_db.json"
    result = duthost.shell(cmd, module_ignore_errors=True)
    original_config = result.get("stdout", "{}")
    logger.info("Original PFCWD config before test: {}".format(original_config))

    # Parse the configuration to extract settings
    import json

    try:
        pfcwd_config = json.loads(original_config)
    except Exception as e:
        logger.warning("Failed to parse PFCWD config: {}".format(e))
        pfcwd_config = {}

    yield

    # Restore original PFCWD configuration
    logger.info("Restoring original PFCWD config after test")

    # Stop current PFCWD
    duthost.shell("pfcwd stop", module_ignore_errors=True)

    original_global = (pfcwd_config or {}).get('GLOBAL', {})
    if 'POLL_INTERVAL' in original_global:
        poll_interval = original_global['POLL_INTERVAL']
        cmd = "pfcwd interval {}".format(poll_interval)
        duthost.shell(cmd, module_ignore_errors=True)
        logger.info("Restored POLL_INTERVAL to {}".format(poll_interval))
    elif redis_hdel(duthost, "CONFIG_DB", "PFC_WD|GLOBAL", "POLL_INTERVAL").get("stdout", "").strip() == "1":
        # A software phase on a hardware-default device adds a POLL_INTERVAL the device never had.
        logger.info("Removed the POLL_INTERVAL this run introduced")

    if pfcwd_config:
        # Restore per-port PFCWD settings
        # Group ports by their configuration (action, detection_time, restoration_time)
        config_groups = {}
        for port, settings in pfcwd_config.items():
            if port == "GLOBAL":
                continue

            action = settings.get("action", "drop")
            detection_time = settings.get("detection_time", "200")
            restoration_time = settings.get("restoration_time", "200")

            key = (action, detection_time, restoration_time)
            if key not in config_groups:
                config_groups[key] = []
            config_groups[key].append(port)

        # Start PFCWD for each configuration group
        for (action, detection_time, restoration_time), ports in config_groups.items():
            ports_str = " ".join(ports)
            cmd = "pfcwd start --action {} --restoration-time {} {} {}".format(
                action, restoration_time, ports_str, detection_time
            )
            duthost.shell(cmd, module_ignore_errors=True)
            logger.info("Restored PFCWD for ports {} with action={}, detection_time={}, restoration_time={}".format(
                ports_str, action, detection_time, restoration_time
            ))


@pytest.fixture(autouse=True, scope="module")
def cleanup(duthosts, ptfhost, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Fixture that remove ip address of ethX interface at ptf and clear arp at dut
    :param duthosts: dut instance
    :param ptfhost: ptf instance
    :return: None
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    yield
    ptfhost.remove_ip_addresses()
    duthost.command("sonic-clear arp")


@pytest.fixture(scope="module", autouse=True)
def create_ptf_test_port_map(
    ptfhost, tbinfo, duthosts, mux_server_url, duts_running_config_facts, duts_minigraph_facts,
    mux_status_from_nic_simulator
):
    ptf_test_port_map_active_active(
        ptfhost, tbinfo, duthosts, mux_server_url, duts_running_config_facts, duts_minigraph_facts,
        mux_status_from_nic_simulator())
