"""
Tests for the `show platform npu...` PFC commands in SONiC
- show platform npu rx
- show platform npu tx
- show platform npu voq
- show platform npu global
"""
import time
import logging
import pytest
from tests.common.helpers.assertions import pytest_assert
import random
import re

random.seed(10)

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

chosen_duthost = None

@pytest.fixture(scope="module")
def cached_asic_facts(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    return get_asic_facts(duthost)


@pytest.fixture(autouse=True)
def run_around_tests(duthosts, enum_rand_one_per_hwsku_hostname, cached_asic_facts):
    """
    @summary: ensure that dshell_client is running
    """
    global chosen_duthost
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    chosen_duthost = duthost
    asic_facts = cached_asic_facts
    if duthost.is_multi_asic:
        asics = [asic.replace("asic","") for asic in list(asic_facts.keys())]
    else:
        asics = ['']
    for asic in asics:
        if not check_process_status(duthost, "dshell_client", "RUNNING", "syncd"+asic):
            result = duthost.command("docker exec -i syncd%s supervisorctl start dshell_client"%(asic))
        assert check_process_status(duthost, "dshell_client", "RUNNING", "syncd"+asic), \
            "Failed to enable dshell_client in container syncd{}".format(asic)

def check_process_status(duthost, process, status="RUNNING", container="syncd"):
    """
    @summary: verify status of a process is RUNNING, STOPPED or EXITED
    """
    try:
        running_processes = duthost.command("docker exec -i %s supervisorctl status %s" % (container, process))["stdout"]
    except:
        running_processes = ""
    return status in running_processes

def get_asic_facts(duthost):
    asic_ports_dict = {}

    def get_ports_with_status(config_facts):
        status_dict = {}
        for p, v in config_facts['PORT'].items():
            status = v.get('admin_status', None)
            if status not in status_dict.keys():
                status_dict[status] = []
            status_dict[status].append(p)
        return status_dict

    if duthost.is_multi_asic:
        for asic in duthost.frontend_asics + duthost.backend_asics:
            asic_cfg_facts = asic.config_facts(host=duthost.hostname, source="running", namespace=asic.namespace)['ansible_facts']
            asic_ports_dict[asic.namespace] = get_ports_with_status(asic_cfg_facts)
    else:
        cfg_facts = duthost.get_running_config_facts()
        asic_ports_dict['asic0'] = get_ports_with_status(cfg_facts)
    for asic in asic_ports_dict.keys():
        up_ports = asic_ports_dict[asic]['up']
        intf_facts = duthost.interface_facts(up_ports=up_ports)['ansible_facts']
        up_ports = filter(lambda p: p not in intf_facts['ansible_interface_link_down_ports'], up_ports)
        assert up_ports, "No ports with admin_status=up and link state UP found on {}".format(asic)
    return asic_ports_dict

def test_show_platform_npu_tx(duthosts, enum_rand_one_per_hwsku_hostname, request, cached_asic_facts):
    """
    @summary: Verify output of `show platform npu tx`
    """
    global chosen_duthost
    duthost = chosen_duthost
    asic_facts = cached_asic_facts
    asic_namespace_string = ""
    asics = []
    if duthost.is_multi_asic:
        asics = list(asic_facts.keys())
    else:
        asics = ['']
    all_ports = request.config.getoption("--all_ports")
    options = ["cgm_state", "cgm_global"]
    for option in options:
        for asic in asics:
            if not asic:
                asic_namespace_string = asic
                asic = 'asic0'
            else:
                asic_namespace_string = " -n " + str(asic)

            up_ports = asic_facts[asic]['up']
            if all_ports:
                selected_up_ports = up_ports
            else:
                selected_up_ports = [up_ports[random.randint(0, len(up_ports) - 1)]]

            selected_down_ports = None
            if None in asic_facts[asic].keys():
                down_ports = asic_facts[asic][None]
                if all_ports:
                    selected_down_ports = down_ports
                elif down_ports:
                    selected_down_ports = [down_ports[random.randint(0, len(down_ports) - 1)]]

            show_command = "sudo show platform npu tx {} -i {} {}"

            logging.info("Checking Up Port{} : ".format("s" if all_ports else ""))
            for port in selected_up_ports:
                cmd = show_command.format(option, port, asic_namespace_string)
                result = duthost.command(cmd)
                traceback_found = "Traceback" in result["stdout"]
                assert not traceback_found, \
                    "Traceback found in 'npu tx {opt}' for UP port {port} on {asic}.\nCommand: {cmd}\nOutput:\n{out}".format(
                        opt=option, port=port, asic=asic, cmd=cmd, out=result["stdout"])
                assert result["stdout"], \
                    "Empty output for 'npu tx {opt}' on UP port {port}, {asic}.\nCommand: {cmd}".format(
                        opt=option, port=port, asic=asic, cmd=cmd)

            if selected_down_ports:
                logging.info("Checking Down Port{} : ".format("s" if all_ports else ""))
                for port in selected_down_ports:
                    cmd = show_command.format(option, port, asic_namespace_string)
                    result = duthost.command(cmd)
                    traceback_found = "Traceback" in result["stdout"]
                    assert not traceback_found, \
                        "Traceback found in 'npu tx {opt}' for DOWN port {port} on {asic}.\nCommand: {cmd}\nOutput:\n{out}".format(
                            opt=option, port=port, asic=asic, cmd=cmd, out=result["stdout"])
                    assert result["stdout"], \
                        "Empty output for 'npu tx {opt}' on DOWN port {port}, {asic}.\nCommand: {cmd}".format(
                            opt=option, port=port, asic=asic, cmd=cmd)

def test_show_platform_npu_rx(enum_rand_one_per_hwsku_hostname, request, cached_asic_facts):
    """
    @summary: Verify output of `show platform npu rx`
    """
    global chosen_duthost
    duthost = chosen_duthost
    asic_facts = cached_asic_facts
    asic_namespace_string = ""
    asics = []
    if duthost.is_multi_asic:
        asics = list(asic_facts.keys())
    else:
        asics = ['']
    all_ports = request.config.getoption("--all_ports")
    options = ["interface_cgm", "cgm_profile", "cgm_global", "punt"]
    for option in options:
        for asic in asics:
            if not asic:
                asic_namespace_string = asic
                asic = 'asic0'
            else:
                asic_namespace_string = " -n " + str(asic)

            up_ports = asic_facts[asic]['up']
            if all_ports:
                selected_up_ports = up_ports
            else:
                selected_up_ports = [up_ports[random.randint(0, len(up_ports) - 1)]]

            selected_down_ports = None
            if None in asic_facts[asic].keys():
                down_ports = asic_facts[asic][None]
                if all_ports:
                    selected_down_ports = down_ports
                elif down_ports:
                    selected_down_ports = [down_ports[random.randint(0, len(down_ports) - 1)]]

            show_command = "sudo show platform npu rx {} -i {} -t {}{}"

            for t in range(8):
                logging.info("Checking Up Port{} : ".format("s" if all_ports else ""))
                for port in selected_up_ports:
                    cmd = show_command.format(option, port, t, asic_namespace_string)
                    result = duthost.command(cmd)
                    traceback_found = "Traceback" in result["stdout"]
                    assert not traceback_found, \
                        "Traceback found in 'npu rx {opt}' for UP port {port} tc {t} on {asic}.\nCommand: {cmd}\nOutput:\n{out}".format(
                            opt=option, port=port, t=t, asic=asic, cmd=cmd, out=result["stdout"])
                    assert result["stdout"], \
                        "Empty output for 'npu rx {opt}' on UP port {port} tc {t}, {asic}.\nCommand: {cmd}".format(
                            opt=option, port=port, t=t, asic=asic, cmd=cmd)

                if selected_down_ports:
                    logging.info("Checking Down Port{} : ".format("s" if all_ports else ""))
                    for port in selected_down_ports:
                        cmd = show_command.format(option, port, t, asic_namespace_string)
                        result = duthost.command(cmd)
                        traceback_found = "Traceback" in result["stdout"]
                        assert not traceback_found, \
                            "Traceback found in 'npu rx {opt}' for DOWN port {port} tc {t} on {asic}.\nCommand: {cmd}\nOutput:\n{out}".format(
                                opt=option, port=port, t=t, asic=asic, cmd=cmd, out=result["stdout"])
                        assert result["stdout"], \
                            "Empty output for 'npu rx {opt}' on DOWN port {port} tc {t}, {asic}.\nCommand: {cmd}".format(
                                opt=option, port=port, t=t, asic=asic, cmd=cmd)

                # Check internal ports "CPU" and "RECYCLE" for cgm_profile option
                if option == "cgm_profile":
                    internal_ports = ["CPU", "RECYCLE"]
                    logging.info("Checking Internal Ports for cgm_profile: {}".format(internal_ports))
                    for port in internal_ports:
                        cmd = show_command.format(option, port, t, asic_namespace_string)
                        result = duthost.command(cmd)
                        traceback_found = "Traceback" in result["stdout"]
                        assert not traceback_found, \
                            "Traceback found in 'npu rx {opt}' for internal port {port} tc {t} on {asic}.\nCommand: {cmd}\nOutput:\n{out}".format(
                                opt=option, port=port, t=t, asic=asic, cmd=cmd, out=result["stdout"])
                        assert result["stdout"], \
                            "Empty output for 'npu rx {opt}' on internal port {port} tc {t}, {asic}.\nCommand: {cmd}".format(
                                opt=option, port=port, t=t, asic=asic, cmd=cmd)

def test_show_platform_npu_voq(duthosts, enum_rand_one_per_hwsku_hostname, request, cached_asic_facts):
    """
    @summary: Verify output of `show platform npu voq`
    """
    global chosen_duthost
    duthost = chosen_duthost
    asic_facts = cached_asic_facts
    asic_namespace_string = ""
    asics = []
    if duthost.is_multi_asic:
        asics = list(asic_facts.keys())
    else:
        asics = ['']
    all_ports = request.config.getoption("--all_ports")
    options = ["cgm_profile", "voq_globals", "queue_counters", "stats"]
    for option in options:
        for asic in asics:
            if not asic:
                asic_namespace_string = asic
                asic = 'asic0'
            else:
                asic_namespace_string = " -n " + str(asic)

            up_ports = asic_facts[asic]['up']
            if all_ports:
                selected_up_ports = up_ports
            else:
                selected_up_ports = [up_ports[random.randint(0, len(up_ports) - 1)]]

            selected_down_ports = None
            if None in asic_facts[asic].keys():
                down_ports = asic_facts[asic][None]
                if all_ports:
                    selected_down_ports = down_ports
                elif down_ports:
                    selected_down_ports = [down_ports[random.randint(0, len(down_ports) - 1)]]
            src = ""
            if option == "stats":
                selected_src_port = up_ports[random.randint(0, len(up_ports) - 1)]
                src = " -s " + str(selected_src_port)

            show_command = "sudo show platform npu voq {} -i {} -t {}{}{}"

            for t in range(8):
                logging.info("Checking Up Port{} : ".format("s" if all_ports else ""))
                for port in selected_up_ports:
                    cmd = show_command.format(option, port, t, src, asic_namespace_string)
                    result = duthost.command(cmd)
                    traceback_found = "Traceback" in result["stdout"]
                    assert not traceback_found, \
                        "Traceback found in 'npu voq {opt}' for UP port {port} tc {t} on {asic}.\nCommand: {cmd}\nOutput:\n{out}".format(
                            opt=option, port=port, t=t, asic=asic, cmd=cmd, out=result["stdout"])
                    assert result["stdout"], \
                        "Empty output for 'npu voq {opt}' on UP port {port} tc {t}, {asic}.\nCommand: {cmd}".format(
                            opt=option, port=port, t=t, asic=asic, cmd=cmd)

                if selected_down_ports:
                    logging.info("Checking Down Port{} : ".format("s" if all_ports else ""))
                    for port in selected_down_ports:
                        cmd = show_command.format(option, port, t, src, asic_namespace_string)
                        result = duthost.command(cmd)
                        traceback_found = "Traceback" in result["stdout"]
                        assert not traceback_found, \
                            "Traceback found in 'npu voq {opt}' for DOWN port {port} tc {t} on {asic}.\nCommand: {cmd}\nOutput:\n{out}".format(
                                opt=option, port=port, t=t, asic=asic, cmd=cmd, out=result["stdout"])
                        assert result["stdout"], \
                            "Empty output for 'npu voq {opt}' on DOWN port {port} tc {t}, {asic}.\nCommand: {cmd}".format(
                                opt=option, port=port, t=t, asic=asic, cmd=cmd)

def test_show_platform_npu_global(duthosts, enum_rand_one_per_hwsku_hostname, request):
    """
    @summary: Verify output of `show platform npu global`
    """
    global chosen_duthost
    duthost = chosen_duthost
    namespace_list = duthost.get_asic_namespace_list() if duthost.is_multi_asic else ['']
    for namespace in  namespace_list:
        show_command = "sudo show platform npu global -n '{}'"
        cmd = show_command.format(namespace)
        result = duthost.command(cmd)
        logging.info(result)
        traceback_found = "Traceback" in result["stdout"]
        assert not traceback_found, \
            "Traceback found in 'npu global' for namespace '{ns}'.\nCommand: {cmd}\nOutput:\n{out}".format(
                ns=namespace, cmd=cmd, out=result["stdout"])
        assert result["stdout"], \
            "Empty output for 'npu global' on namespace '{ns}'.\nCommand: {cmd}".format(
                ns=namespace, cmd=cmd)

def test_config_platform_cisco_voq_watchdog(duthosts, enum_rand_one_per_hwsku_hostname, request):
    """
    @summary: Verify output of `config platform cisco voq-watchdog`
    """
    global chosen_duthost
    duthost = chosen_duthost
    help_command = "config platform cisco -h"
    result = duthost.command(help_command)
    if "voq-watchdog" not in result["stdout"]:
        pytest.skip("This test is skipped since voq-watchdog CLI is not supported.")

    namespace_option = "-n asic0" if duthost.facts.get("modular_chassis") else ""
    show_command = "show platform npu global {}".format(namespace_option)
    result = duthost.command(show_command)
    pattern = r"voq_watchdog_enabled +: +True"
    match = re.search(pattern, result["stdout"])
    if match:
        options = ["disable", "enable"]
    else:
        options = ["enable", "disable"]

    for option in options:
        config_command = "config platform cisco voq-watchdog {}".format(option)
        result = duthost.command(config_command)
        traceback_found = "Traceback" in result["stdout"]
        assert not traceback_found, \
            "Traceback found in 'config platform cisco voq-watchdog {opt}'.\nCommand: {cmd}\nOutput:\n{out}".format(
                opt=option, cmd=config_command, out=result["stdout"])
        assert "Successfully" in result["stdout"], \
            "'config platform cisco voq-watchdog {opt}' did not report success.\nCommand: {cmd}\nOutput:\n{out}".format(
                opt=option, cmd=config_command, out=result["stdout"])
