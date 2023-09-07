"""
Tests for the `show platform npu...` commands in SONiC
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
            status_dict[status].setdefault(p, [p])
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
        if len(intf_facts['ansible_interface_link_down_ports']) != 0:
            raise Exception("Interface Status issue - {} : Admin UP ports {} are Oper DOWN".format(asic, up_ports))
    return asic_ports_dict

def test_disable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `sudo config platform cisco sdk-debug disable"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo config platform cisco sdk-debug disable")
    logging.info(result)
    assert "dshell_client: stopped" in result["stdout"], "dshell_client is not stopped"

def test_enable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `sudo config platform cisco sdk-debug enable"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo config platform cisco sdk-debug enable")
    logging.info(result)
    time.sleep(360)
    assert "dshell_client: started" in result["stdout"], "dshell_client not started"

def test_check_dshell_client_after_enable(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `docker exec -it syncd ps -efl "`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("docker exec -it syncd ps -efl")
    logging.info(result)
    assert "/usr/bin/dshell_client.py" in result["stdout"], "dshell_client is not running"


def test_show_platform_npu_lpts(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu lpts`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo show platform npu lpts")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu lpts output"
    assert result["stdout"], "No ouput for this CLI"

def test_show_platform_npu_counters(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu counters`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo show platform npu counters")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu counters output"
    assert result["stdout"], "No ouput for this CLI"

def test_show_platform_npu_ecmp(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu ecmp`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo show platform npu ecmp")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu ecmp output"
    assert result["stdout"], "No ouput for this CLI"

def test_show_platform_npu_event_trap(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu event-trap`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo show platform npu event-trap")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu event-trap"
    assert result["stdout"], "No ouput for this CLI"

def test_show_platform_npu_trap(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu trap`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo show platform npu trap")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu trap"
    assert result["stdout"], "No ouput for this CLI"

def test_show_platform_npu_temperatures(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu temperature`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo show platform npu temperatures")
    logging.info(result)
    traceback_found = "Traceback" in result["stdout"]
    assert not traceback_found, "Traceback found in show platform npu trap"
    assert result["stdout"], "No ouput for this CLI"
    assert "Sensor" in result["stdout"], "No Sensor found!"

def test_show_platform_npu_tx(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu tx`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    asic_facts = get_asic_facts(duthost)
    asic_namespace_string = ""
    if duthost.is_multi_asic:
        asics = list(asic_facts.keys())
        selected_asic = asics[random.randint(0, len(asics))]
        asic_namespace_string = " -n " + str(selected_asic)
    else:
        selected_asic = 'asic0'

    up_ports = asic_facts[selected_asic]['up']
    assert len(up_ports) > 0, "No ports with admin UP found"
    selected_up_port = up_ports[random.randint(0, len(up_ports))]

    down_ports = asic_facts[selected_asic]['down']
    selected_down_port = down_ports[random.randint(0, len(down_ports))]

    options = ["cgm_state", "cgm_global"]
    for option in options:
        logging.info("Checking Up Port : ")
        result = duthost.command("sudo show platform npu tx {} -i {}{}".format(option, selected_up_port, asic_namespace_string))
        traceback_found = "Traceback" in result["stdout"]
        assert not traceback_found, "Traceback found in show platform npu tx for UP Port"
        assert result["stdout"], "No ouput for this CLI"

        logging.info("\nChecking Down Port : ")
        result = duthost.command("sudo show platform npu tx {} -i {}{}".format(option, selected_down_port, asic_namespace_string))
        traceback_found = "Traceback" in result["stdout"]
        assert not traceback_found, "Traceback found in show platform npu tx for DOWN Port"
        assert result["stdout"], "No ouput for this CLI"

def test_show_platform_npu_rx(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu tx`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    asic_facts = get_asic_facts(duthost)
    asic_namespace_string = ""
    if duthost.is_multi_asic:
        asics = list(asic_facts.keys())
        selected_asic = asics[random.randint(0, len(asics))]
        asic_namespace_string = " -n " + str(selected_asic)
    else:
        selected_asic = 'asic0'

    up_ports = asic_facts[selected_asic]['up']
    assert len(up_ports) > 0, "No ports with admin UP found"
    selected_up_port = up_ports[random.randint(0, len(up_ports))]

    down_ports = asic_facts[selected_asic]['down']
    selected_down_port = down_ports[random.randint(0, len(down_ports))]

    options = ["interface_cgm", "cgm_profile", "cgm_global"]
    for option in options:
        for t in range(8):
            logging.info("Checking Up Port : ")
            result = duthost.command("sudo show platform npu rx {} -i {} -t {}{}".format(option, selected_up_port, asic_namespace_string))
            traceback_found = "Traceback" in result["stdout"]
            assert not traceback_found, "Traceback found in show platform npu rx for UP Port"
            assert result["stdout"], "No ouput for this CLI"

            logging.info("\nChecking Down Port : ")
            result = duthost.command("sudo show platform npu rx {} -i {} -t {}{}".format(option, selected_down_port, asic_namespace_string))
            traceback_found = "Traceback" in result["stdout"]
            assert not traceback_found, "Traceback found in show platform npu rx for DOWN Port"
            assert result["stdout"], "No ouput for this CLI"

def test_show_platform_npu_voq(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform npu tx`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    asic_facts = get_asic_facts(duthost)
    asic_namespace_string = ""
    if duthost.is_multi_asic:
        asics = list(asic_facts.keys())
        selected_asic = asics[random.randint(0, len(asics))]
        asic_namespace_string = " -n " + str(selected_asic)
    else:
        selected_asic = 'asic0'

    up_ports = asic_facts[selected_asic]['up']
    assert len(up_ports) > 0, "No ports with admin UP found"
    selected_up_port = up_ports[random.randint(0, len(up_ports))]

    down_ports = asic_facts[selected_asic]['down']
    selected_down_port = down_ports[random.randint(0, len(down_ports))]

    options = ["cgm_profile", "voq_globals", "queue_counters", "stats"] #have to add stats
    for option in options:
        for t in range(8):
            logging.info("Checking Up Port : ")
            result = duthost.command("sudo show platform npu voq {} -i {} -t {}{}".format(option, selected_up_port, asic_namespace_string))
            traceback_found = "Traceback" in result["stdout"]
            assert not traceback_found, "Traceback found in show platform npu voq for UP Port"
            assert result["stdout"], "No ouput for this CLI"

            logging.info("\nChecking Down Port : ")
            result = duthost.command("sudo show platform npu voq {} -i {} -t {}{}".format(option, selected_down_port, asic_namespace_string))
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

def test_disable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `sudo config platform cisco sdk-debug disable"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    result = duthost.command("sudo config platform cisco sdk-debug disable")
    logging.info(result)
    assert "dshell_client: stopped" in result["stdout"], "dshell_client is not stopped"
