"""
Tests for the `show platform npu...` commands in SONiC
"""
import time
import logging
import re
import pytest
import re
from tests.common.helpers.assertions import pytest_assert
from tests.cisco.common.utils import CheckEnvironment

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

SCRIPT_FILE = "/opt/cisco/silicon-one/res/script.txt"

# List of commands allowed in non-sudo user mode
npu_cli_dict_usr_mode = {
        #feature cli keyword : list of options under the cli (for all topologies)
        "packet-debug": ["capture", "status"],
        "next-hop": ["usage"],
        "router": ["entries", "ports"],
        "event-trap": " ",
        "trap": " ",
        "global": " ",
        "resource": " "
}

npu_cli_dict_general = {
        #feature cli keyword : list of options under the cli (for all topologies)
        "acl" : ["summary"],
        "asic-errors": " ",
        "bfd" : ["summary"],
        "counters": " ",
        "ecmp": " ",
        "hash" : " ",
        "l3-interface": " ",
        "l3-table" : " ",
        "lag": ["entries", "members"],
        #"lpts": " ", # commented out due to known issue with lpts cli in 25.11 SDK
        "multipath": " ",
        "next-hop": ["entries"],
        "port": ["counters", "entries"],
        "rate-check": " ",
        "router": ["route-table", "details"],
        "sdk-debug": ["status"],
        "switch": ["entries", "ports"],
        "trap-list": " ",
        "script": [f"-s {SCRIPT_FILE} -t 60"],
        #"ars": ["info","flows"]
}

npu_cli_dict_q200 = {
        #feature cli keyword : list of options under the cli (only for q200)
        "acl" : ["key-profile"],
        "router": ["port-counters"],
        "temperatures": " "
}

npu_cli_dict_t2 = {
        #feature cli keyword : list of options under the cli (only for t2 topology)
        "bp-interface-map" : " "
}

npu_cli_dict_hw = {
        #feature cli keyword : list of options under the cli (only for hardware)
        "cem-db" : " ",
        "lpm-db" : " "
}

def get_asic_str(duthost, asic):
    if duthost.is_multi_asic:
        return f" -n asic{asic}"
    else:
        return ""

def check_dshell_client(duthost, enabled=True, change=True):
    """
    @summary: This function can either modify the state of dshell_client or check it. 
    Args:
        @change : if set to true, dshell_client will either be enabled or disabled based on "enabled"
        @enabled : whether or not we expect dshell client to be enabled
    """
    asics = ['']
    if duthost.is_multi_asic:
        asics = duthost.get_asic_ids()
    result = True
    for asic in asics:
        check_dshell = duthost.command(f"docker exec syncd{asic} ps -efl")
        action = "start" if enabled else "stop"
        timeout = 0
        while timeout < 12 and ("dshell_client.py" in check_dshell["stdout"]) is not enabled:
            if timeout:
                time.sleep(15)
            if change:
                duthost.command(f"docker exec syncd{asic} supervisorctl " + action + " dshell_client")
            check_dshell = duthost.command(f"docker exec syncd{asic} ps -efl")
            timeout += 1
        result &= ("dshell_client.py" in check_dshell["stdout"]) is enabled
        if change:
            assert result, logging.error(f"Unable to {action} dshell client in syncd{asic}")
    return result

def test_check_dshell_enabled_default(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify dshell is enabled by default
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    assert check_dshell_client(duthost, True, False), "dshell_client not running by default"

def test_disable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `docker exec syncd supervisorctl stop dshell_client`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost)
    asics = ['']
    if duthost.is_multi_asic:
        asics = duthost.get_asic_ids()
    for asic in asics:
        result = duthost.command(f"docker exec syncd{asic} supervisorctl stop dshell_client")
        logging.info(result)
        assert "dshell_client: stopped" in result["stdout"], f"dshell_client stopped : expected output is missing for asic {asic}"
    assert check_dshell_client(duthost, False, False), "dshell_client still running"

def test_disable_sdk_debug(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `sudo config platform cisco sdk-debug disable"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost, False)
    result = duthost.command("sudo config platform cisco sdk-debug disable")
    logging.info(result)
    assert check_dshell_client(duthost, False, False), "dshell_client still running"
    assert "Disabling sdk-debug on all ASICs" in result["stdout"], "sdk-debug not disabled on all ASICS"
    assert "Disabling sdk-debug on syncd" in result["stdout"], "sdk-debug not disabled on syncd"
    assert "sdk-debug has been disabled on syncd" in result["stdout"], "sdk-debug not disabled on syncd"

def test_enable_dshell_client(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `docker exec syncd supervisorctl start dshell_client`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost, False)
    asics = ['']
    if duthost.is_multi_asic:
        asics = duthost.get_asic_ids()
    for asic in asics:
        result = duthost.command(f"docker exec syncd{asic} supervisorctl start dshell_client")
        logging.info(result)
        assert f"dshell_client: started" in result["stdout"], f"dshell_client started : expected output is missing for asic {asic}"
    assert check_dshell_client(duthost, True, False), "dshell_client not started"
    
def test_enable_sdk_debug(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `sudo config platform cisco sdk-debug enable"`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost, False)
    result = duthost.command("sudo config platform cisco sdk-debug enable")
    logging.info(result)
    assert check_dshell_client(duthost, True, False), "dshell_client not started"
    assert "Enabling sdk-debug on all ASICs" in result["stdout"], "sdk-debug not enabled on all ASICS"
    assert "Enabling sdk-debug on syncd" in result["stdout"], "sdk-debug not enabled on syncd"
    assert "sdk-debug has been enabled on syncd" in result["stdout"], "sdk-debug not enabled on syncd"


def test_show_platform_npu_all(duthosts, enum_rand_one_per_hwsku_hostname, tbinfo, enum_rand_one_asic_index):
    """
    @summary: Verify output of `show platform npu` , update the npu_cli_dict at the top for new platform npu command check.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    check_dshell_client(duthost)

    result = duthost.shell(f"sudo echo 'dapi.dump_router_ports()' > {SCRIPT_FILE}")

    result_list = []
    npu_cli_dict = npu_cli_dict_general.copy()

    if duthost.facts["platform"] in ["x86_64-8101_32h_o-r0",
            "x86_64-8102_64h_o-r0", "x86_64-8101_32fh_o-r0"]:
        npu_cli_dict.update(npu_cli_dict_q200)

    if 't2' in tbinfo['topo']['name']:
        npu_cli_dict.update(npu_cli_dict_t2)

    if not CheckEnvironment.is_sim(duthost):
        npu_cli_dict.update(npu_cli_dict_hw)
    
    for cli in npu_cli_dict:
        if duthost.is_multi_asic:
            asic = enum_rand_one_asic_index
        else:
            asic = ''
        for opt in npu_cli_dict[cli]:
            result = duthost.shell("sudo show platform npu {} {} {}".format(cli, opt, get_asic_str(duthost, asic)), module_ignore_errors=True)
            logging.info(result["stdout"])
            traceback_found = "Traceback" in result["stdout"]

            if traceback_found:
                result_list.append("Traceback found in show platform npu {} {}".format(cli, opt))
            elif result is None:
                result_list.append("No output for this CLI show platform npu {} {}".format(cli, opt))
            elif result["failed"]:
                result_list.append("Failed CLI show platform npu {} {}".format(cli, opt))

    for result in result_list:
        logging.error(result)

    assert not result_list, "One or more show platform npu commands failed {}".format(result_list)


def test_show_platform_npu_user_mode_cli(duthosts, enum_rand_one_per_hwsku_hostname, tbinfo, enum_rand_one_asic_index):
    """
    @summary: Verify output of `show platform npu` for user mode CLIs.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    check_dshell_client(duthost)

    result = duthost.shell(f"sudo echo 'dapi.dump_router_ports()' > {SCRIPT_FILE}")

    result_list = []
    npu_cli_dict = npu_cli_dict_usr_mode.copy()
    
    for cli in npu_cli_dict:
        if duthost.is_multi_asic:
            asic = enum_rand_one_asic_index
        else:
            asic = ''
        for opt in npu_cli_dict[cli]:
            result = duthost.shell("show platform npu {} {} {}".format(cli, opt, get_asic_str(duthost, asic)), module_ignore_errors=True)
            logging.info(result["stdout"])
            traceback_found = "Traceback" in result["stdout"]

            if traceback_found:
                result_list.append("Traceback found in show platform npu {} {}".format(cli, opt))
            elif result is None:
                result_list.append("No output for this CLI show platform npu {} {}".format(cli, opt))
            elif result["failed"]:
                result_list.append("Failed CLI show platform npu {} {}".format(cli, opt))

    for result in result_list:
        logging.error(result)

    assert not result_list, "One or more show platform npu commands failed {}".format(result_list)


def test_show_platform_npu_udump(duthosts, enum_rand_one_per_hwsku_hostname, enum_rand_one_asic_index):
    """
    @summary: Verify output of 'sudo udump --force -t <sw, full>'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost)
    
    if duthost.is_multi_asic:
        asic = enum_rand_one_asic_index
    else:
        asic = ''
    for dump_type in ['sw', 'full']:
        cmd = f"udump --force -t sw {get_asic_str(duthost, asic)}"
        result = duthost.shell(cmd, module_ignore_errors=True)
    
        logging.info(f"Command: {cmd}")
        logging.info(f"Result: {result}")
    
        assert result is not None, f"No output for CLI: {cmd}"
        assert "Traceback" not in result["stdout"], f"Traceback found in CLI: {cmd}"
        assert not result["failed"], f"CLI command failed: {cmd}"
    
        # Check for successful completion message
        assert "Udump generation completed successfully!" in result["stdout"], \
            f"Udump generation did not complete successfully for command: {cmd}"
    
        # Extract the udump filename to verify file creation
        match = re.search(r"Created udump\s+(\S+)", result['stdout'])
        pytest_assert(match, f"Udump filename not found in CLI output for command: {cmd}")

        udump_reference = match.group(1)
        filename = udump_reference.split('/')[-1]

        if '/' in udump_reference:
            file_check_path = udump_reference
        else:
            file_check_path = f"/var/dump/{filename}"

        exists = duthost.command(f"sudo ls {file_check_path}")
        if exists["rc"] == 0 and "No such file or directory" not in exists["stdout"]:
            logging.info(f"Successfully created udump file: {file_check_path}")
        else:
            logging.warning(f"Udump file verification failed at {file_check_path}, but CLI execution was successful")
            raise IOError(f"Udump file {file_check_path} was not created in specified path")

# Test for 'show platform npu packet-path CLI using pre-programmed IPv6 route'
def test_show_platform_npu_packet_path_ipv6(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of 'show platform npu packet-path -dip 20c1:bf8:0:80:: -sif PortChannel101 --ipv6'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost)
    # Check if the IPv6 route exists
    route_check_cmd = "ip -6 route show | grep '20c1:bf8:0:80::'"
    route_result = duthost.shell(route_check_cmd, module_ignore_errors=True)
    if not route_result["stdout"].strip():
        logging.info("IPv6 route 20c1:bf8:0:80:: not present on DUT, skipping CLI test.")
        return
    cmd = "sudo show platform npu packet-path -dip 20c1:bf8:0:80:: -sif PortChannel101 --ipv6"
    result = duthost.shell(cmd, module_ignore_errors=True)
    logging.info(result["stdout"])
    assert result is not None, f"No output for CLI: {cmd}"
    assert "Traceback" not in result["stdout"], f"Traceback found in CLI: {cmd}"

# Test for 'show platform npu packet-path CLI using pre-programmed IPv4 route'
def test_show_platform_npu_packet_path_ipv4(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of 'show platform npu packet-path -dip 193.11.32.128 -sif PortChannel101 --ipv4'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost)
    # Check if the IPv4 route exists
    route_check_cmd = "ip route show | grep '193.11.32.128'"
    route_result = duthost.shell(route_check_cmd, module_ignore_errors=True)
    if not route_result["stdout"].strip():
        logging.info("IPv4 route 193.11.32.128 not present on DUT, skipping CLI test.")
        return
    cmd = "sudo show platform npu packet-path -dip 193.11.32.128 -sif PortChannel101 --ipv4"
    result = duthost.shell(cmd, module_ignore_errors=True)
    logging.info(result["stdout"])
    assert result is not None, f"No output for CLI: {cmd}"
    assert "Traceback" not in result["stdout"], f"Traceback found in CLI: {cmd}"

def test_show_platform_npu_resource(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Validate that 'show platform npu resource' CLI output
    Checks: 1) State is Green/None, 2) All CLI resources are in SDK dump, 3) Max entries match resource usage totals.
    """
    script_content = (
        "import sdk\n"
        "la_device = sdk.la_get_device(0)\n"
        "for attr in dir(sdk.la_resource_descriptor):\n"
        "    if attr.startswith('type_e_'):\n"
        "        resource_id = getattr(sdk.la_resource_descriptor, attr)\n"
        "        try:\n"
        "            resource_usage_vect = la_device.get_resource_usage(resource_id)\n"
        "            for desc in resource_usage_vect:\n"
        "                print(f'{attr}: state={desc.state}, used={desc.used}, total={desc.total}')\n"
        "        except:\n"
        "            pass\n"
    )

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    check_dshell_client(duthost)
    
    asics = duthost.get_asic_ids() if duthost.is_multi_asic else ['']
    validation_errors = []
    row_re = re.compile(r"^\|(.+)\|$")

    for asic in asics:
        script_path = "/tmp/resource_usage.py"
        heredoc_cmd = f"cat <<EOF > {script_path}\n{script_content}\nEOF"
        duthost.shell(heredoc_cmd)
        container = f"syncd{asic}" if duthost.is_multi_asic else "syncd"
        duthost.shell(f"docker cp {script_path} {container}:/resource_usage.py")
        asic_str = get_asic_str(duthost, asic)
        script_result = duthost.shell(f"sudo show platform npu script{asic_str} -s /resource_usage.py", module_ignore_errors=True)
        
        # Parse dshell output into dict
        dshell_resources = {}
        for line in script_result["stdout"].splitlines():
            if ": state=" in line:
                parts = line.split(": state=")
                if len(parts) == 2:
                    resource_name = parts[0].replace("type_e_", "")
                    attrs = parts[1]
                    try:
                        state_val = attrs.split(", used=")[0]
                        used_val = attrs.split(", used=")[1].split(", total=")[0]
                        total_val = attrs.split(", total=")[1]
                        if resource_name not in dshell_resources:
                            dshell_resources[resource_name] = []
                        dshell_resources[resource_name].append({
                            'state': state_val,
                            'used': int(used_val),
                            'total': int(total_val)
                        })
                    except:
                        pass

        cli_result = duthost.shell(f"sudo show platform npu resource{asic_str}", module_ignore_errors=True)
        cli_output = cli_result["stdout"]
        
        if "Traceback" in cli_output:
            validation_errors.append(f"Traceback found in CLI output for asic{asic}")
            continue
        
        headers = None
        resource_idx, max_idx, state_idx = None, None, None
        cli_resources = {}

        for line in cli_output.splitlines():
            m = row_re.match(line.strip())
            if not m:
                continue
                
            cols = [x.strip() for x in m.group(1).split('|')]
            
            if headers is None:
                lower_cols = [c.lower() for c in cols]
                if 'resource' in lower_cols:
                    headers = lower_cols
                    for i, h in enumerate(headers):
                        if 'resource' in h:
                            resource_idx = i
                        if 'max entries' in h:
                            max_idx = i
                        if 'state' in h:
                            state_idx = i
                continue
            
            if len(cols) > max(resource_idx or 0, max_idx or 0, state_idx or 0):
                resource = cols[resource_idx] if resource_idx is not None else ""
                max_entries = cols[max_idx] if max_idx is not None else ""
                state = cols[state_idx] if state_idx is not None else ""
                
                if resource and max_entries:
                    if resource.startswith('-'):
                        continue
                    
                    if resource not in cli_resources:
                        cli_resources[resource] = []
                    cli_resources[resource].append({
                        'max': max_entries,
                        'state': state
                    })
                    
                    if state and state not in ['Green', 'None', '-']:
                        validation_errors.append(f"ASIC{asic} Resource '{resource}' has state '{state}' (expected Green or None)")

        for cli_resource in cli_resources.keys():
            if cli_resource not in dshell_resources:
                validation_errors.append(f"ASIC{asic} Resource '{cli_resource}' found in CLI but NOT in dshell output")
                logging.error(f"ASIC{asic} Missing resource in dshell: {cli_resource}")

        for resource_name in cli_resources.keys():
            if resource_name in dshell_resources:
                cli_entries = cli_resources[resource_name]
                dshell_entries = dshell_resources[resource_name]
                
                if len(cli_entries) != len(dshell_entries):
                    logging.info(f"ASIC{asic} Resource '{resource_name}': CLI has {len(cli_entries)} instances, dshell has {len(dshell_entries)} instances")
                
                cli_max_values = []
                for cli_entry in cli_entries:
                    max_str = cli_entry['max'].replace(',', '')
                    try:
                        cli_max_values.append(int(max_str))
                    except ValueError:
                        pass
                
                dshell_total_values = [entry['total'] for entry in dshell_entries]
                
                for cli_max in cli_max_values:
                    if cli_max not in dshell_total_values:
                        validation_errors.append(
                            f"ASIC{asic} Resource '{resource_name}': Max entries {cli_max} from CLI not found in dshell output "
                            f"(dshell totals: {dshell_total_values})"
                        )

        logging.info(f"ASIC{asic} validation complete: {len(cli_resources)} CLI resources checked, {len(dshell_resources)} dshell resources found")

    assert not validation_errors, f"NPU resource validation failed with {len(validation_errors)} errors:\n" + "\n".join(validation_errors)
