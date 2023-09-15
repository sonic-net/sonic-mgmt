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


pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

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
        for asic in duthost.frontend_asics:
            asic_cfg_facts = asic.config_facts(host=duthost.hostname, source="running", namespace=asic.namespace)['ansible_facts']
            asic_ports_dict[asic.namespace] = get_ports_with_status(asic_cfg_facts)
    else:
        cfg_facts = duthost.get_running_config_facts()
        asic_ports_dict['asic0'] = get_ports_with_status(cfg_facts)
    
    for asic in asic_ports_dict.keys():
        up_ports = asic_ports_dict[asic]['up']
        intf_facts = duthost.interface_facts(up_ports=up_ports)['ansible_facts']
        up_ports = filter(lambda p: p not in intf_facts['ansible_interface_link_down_ports'], up_ports)
        assert up_ports, "No ports with Admin, Open state UP found"
    return asic_ports_dict

def test_show_platform_npu_tx(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu tx`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    asic_facts = get_asic_facts(duthost)
    asic_namespace_string = ""
    asics = []
    if duthost.is_multi_asic:
        asics = list(asic_facts.keys())
    else:
        asics = ['']

    options = ["cgm_state", "cgm_global"]
    for option in options:
        for asic in asics:
            if not asic:
                asic_namespace_string = asic
                asic = 'asic0'
            else:
                asic_namespace_string = " -n " + str(asic)

            up_ports = asic_facts[asic]['up']
            assert len(up_ports) > 0, "No ports with admin UP found"
            selected_up_port = up_ports[random.randint(0, len(up_ports) - 1)]

            down_ports = asic_facts[asic][None]
            selected_down_port = down_ports[random.randint(0, len(down_ports) - 1)]

            logging.info("Checking Up Port : ")
            result = duthost.command("sudo show platform npu tx {} -i {} {}".format(option, selected_up_port, asic_namespace_string))
            traceback_found = "Traceback" in result["stdout"]
            assert not traceback_found, "Traceback found in show platform npu tx for UP Port"                
            assert result["stdout"], "No ouput for this CLI"

            logging.info("\nChecking Down Port : ")
            result = duthost.command("sudo show platform npu tx {} -i {} {}".format(option, selected_down_port, asic_namespace_string))
            traceback_found = "Traceback" in result["stdout"]
            assert not traceback_found, "Traceback found in show platform npu tx for DOWN Port"
            assert result["stdout"], "No ouput for this CLI"

def test_show_platform_npu_rx(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu rx`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    asic_facts = get_asic_facts(duthost)
    asic_namespace_string = ""
    asics = []
    if duthost.is_multi_asic:
        asics = list(asic_facts.keys())
    else:
        asics = ['']

    options = ["interface_cgm", "cgm_profile", "cgm_global", "punt"]
    for option in options:
        for asic in asics:
            if not asic:
                asic_namespace_string = asic
                asic = 'asic0'
            else:
                asic_namespace_string = " -n " + str(asic)

            up_ports = asic_facts[asic]['up']
            assert len(up_ports) > 0, "No ports with admin UP found"
            selected_up_port = up_ports[random.randint(0, len(up_ports) - 1)]

            down_ports = asic_facts[asic][None]
            selected_down_port = down_ports[random.randint(0, len(down_ports) - 1)]

            for t in range(8):
                logging.info("Checking Up Port : ")
                result = duthost.command("sudo show platform npu rx {} -i {} -t {}{}".format(option, selected_up_port, t, asic_namespace_string))
                traceback_found = "Traceback" in result["stdout"]
                assert not traceback_found, "Traceback found in show platform npu rx for UP Port"
                assert result["stdout"], "No ouput for this CLI"

                logging.info("\nChecking Down Port : ")
                result = duthost.command("sudo show platform npu rx {} -i {} -t {}{}".format(option, selected_down_port, t, asic_namespace_string))
                traceback_found = "Traceback" in result["stdout"]
                assert not traceback_found, "Traceback found in show platform npu rx for DOWN Port"
                assert result["stdout"], "No ouput for this CLI"

def test_show_platform_npu_voq(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu voq`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    asic_facts = get_asic_facts(duthost)
    asic_namespace_string = ""
    asics = []
    if duthost.is_multi_asic:
        asics = list(asic_facts.keys())
    else:
        asics = ['']

    options = ["cgm_profile", "voq_globals", "queue_counters", "stats"]
    for option in options:
        for asic in asics:
            if not asic:
                asic_namespace_string = asic
                asic = 'asic0'
            else:
                asic_namespace_string = " -n " + str(asic)
            src = ""
            up_ports = asic_facts[asic]['up']
            assert len(up_ports) > 0, "No ports with admin UP found"
            selected_up_port = up_ports[random.randint(0, len(up_ports) - 1)]

            down_ports = asic_facts[asic][None]
            selected_down_port = down_ports[random.randint(0, len(down_ports) - 1)]
            
            if option == "stats":
                selected_src_port = up_ports[random.randint(0, len(up_ports) - 1)]
                src = " -s " + str(selected_src_port)

            for t in range(8):
                logging.info("Checking Up Port : ")
                result = duthost.command("sudo show platform npu voq {} -i {} -t {}{}{}".format(option, selected_up_port, t, src, asic_namespace_string))
                traceback_found = "Traceback" in result["stdout"]
                assert not traceback_found, "Traceback found in show platform npu voq for UP Port"
                assert result["stdout"], "No ouput for this CLI"

                logging.info("\nChecking Down Port : ")
                result = duthost.command("sudo show platform npu voq {} -i {} -t {}{}{}".format(option, selected_down_port, t, src, asic_namespace_string))
                traceback_found = "Traceback" in result["stdout"]
                assert not traceback_found, "Traceback found in show platform npu voq for DOWN Port"
                assert result["stdout"], "No ouput for this CLI"

def test_show_platform_npu_global(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu global`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo show platform npu global")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu global"
    assert result["stdout"], "No ouput for this CLI"
