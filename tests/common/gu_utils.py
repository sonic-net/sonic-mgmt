import json
import logging
import pytest
import os
import time
import re
from jsonpointer import JsonPointer
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

CONTAINER_SERVICES_LIST = ["swss", "syncd", "radv", "lldp", "dhcp_relay", "teamd", "bgp", "pmon", "telemetry", "acms"]
DEFAULT_CHECKPOINT_NAME = "test"
GCU_FIELD_OPERATION_CONF_FILE = "gcu_field_operation_validators.conf.json"
GET_HWSKU_CMD = "sonic-cfggen -d -v DEVICE_METADATA.localhost.hwsku"
GCUTIMEOUT = 600

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")
TMP_DIR = '/tmp'
HOST_NAME = "localhost"
ASIC_PREFIX = "asic"


def generate_tmpfile(duthost):
    """Generate temp file
    """
    return duthost.shell('mktemp')['stdout']


def delete_tmpfile(duthost, tmpfile):
    """Delete temp file
    """
    duthost.file(path=tmpfile, state='absent')


def format_json_patch_for_multiasic(duthost, json_data,
                                    is_asic_specific=False,
                                    is_host_specific=False,
                                    asic_namespaces=None):
    """
    Formats a JSON patch for multi-ASIC platforms based on the specified scope.

    - Case 1: Apply changes only to /localhost namespace.
      example: format_json_patch_for_multiasic(duthost, json_data, is_host_specific=True)

    - Case 2: Apply changes only to all available ASIC namespaces (e.g., /asic0, /asic1).
      example: format_json_patch_for_multiasic(duthost, json_data, is_asic_specific=True)

    - Case 3: Apply changes to one specific ASIC namespace (e.g., /asic0).
      example: format_json_patch_for_multiasic(duthost, json_data, is_asic_specific=True, asic_namespaces='asic0')

    - Case 4: Apply changes to both /localhost and all ASIC namespaces.
      example: format_json_patch_for_multiasic(duthost, json_data)

    """
    json_patch = []
    asic_namespaces = asic_namespaces or []

    if duthost.is_multi_asic:
        num_asic = duthost.facts.get('num_asic')

        for operation in json_data:
            path = operation["path"]

            # Case 1: Apply only to localhost
            if is_host_specific:
                if path.startswith(f"/{HOST_NAME}"):
                    json_patch.append(operation)
                else:
                    template = operation.copy()
                    template["path"] = f"/{HOST_NAME}{path}"
                    json_patch.append(template)

            # Case 2: Apply only to all ASIC namespaces
            elif is_asic_specific and not asic_namespaces:
                for asic_index in range(num_asic):
                    asic_ns = f"{ASIC_PREFIX}{asic_index}"
                    template = operation.copy()
                    template["path"] = f"/{asic_ns}{path}"
                    json_patch.append(template)

            # Case 3: Apply to one specific ASIC namespace
            elif asic_namespaces:
                for asic_ns in asic_namespaces:
                    template = operation.copy()
                    template["path"] = f"/{asic_ns}{path}"
                    json_patch.append(template)

            # Case 4: Apply to both localhost and all ASIC namespaces
            else:
                # Add for localhost
                template = operation.copy()
                template["path"] = f"/{HOST_NAME}{path}"
                json_patch.append(template)

                # Add for all ASIC namespaces
                for asic_index in range(num_asic):
                    asic_ns = f"{ASIC_PREFIX}{asic_index}"
                    template = operation.copy()
                    template["path"] = f"/{asic_ns}{path}"
                    json_patch.append(template)

        json_data = json_patch
    logger.debug("format_json_patch_for_multiasic: {}".format(json_data))

    return json_data


def apply_patch(duthost, json_data, dest_file):
    """Run apply-patch on target duthost

    Args:
        duthost: Device Under Test (DUT)
        json_data: Source json patch to apply
        dest_file: Destination file on duthost
    """
    duthost.copy(content=json.dumps(json_data, indent=4), dest=dest_file)

    cmds = 'config apply-patch {}'.format(dest_file)

    logger.info("Commands: {}".format(cmds))
    start_time = time.time()
    output = duthost.shell(cmds, module_ignore_errors=True)
    elapsed_time = time.time() - start_time
    if duthost.facts['platform'] == 'armhf-nokia_ixs7215_52x-r0':
        GCUTIMEOUT = 1200
    if elapsed_time > GCUTIMEOUT:
        logger.error("Command took too long: {} seconds".format(elapsed_time))
        raise TimeoutError("Command execution timeout: {} seconds".format(elapsed_time))

    return output


def expect_op_success(duthost, output):
    """Expected success from apply-patch output
    """
    pytest_assert(not output['rc'], "Command is not running successfully")
    pytest_assert(
        "Patch applied successfully" in output['stdout'],
        "Please check if json file is validate"
    )


def expect_op_success_and_reset_check(duthost, output, service_name, timeout, interval, delay):
    """Add contianer reset check after op success

    Args:
        duthost: Device Under Test (DUT)
        output: Command couput
        service_name: Service to reset
        timeout: Maximum time to wait
        interval: Poll interval
        delay: Delay time
    """
    expect_op_success(duthost, output)
    if start_limit_hit(duthost, service_name):
        reset_start_limit_hit(duthost, service_name, timeout, interval, delay)


def expect_res_success(duthost, output, expected_content_list, unexpected_content_list):
    """Check output success with expected and unexpected content

    Args:
        duthost: Device Under Test (DUT)
        output: Command output
        expected_content_list: Expected content from output
        unexpected_content_list: Unexpected content from output
    """
    for expected_content in expected_content_list:
        pytest_assert(
            expected_content in output['stdout'],
            "{} is expected content".format(expected_content)
        )

    for unexpected_content in unexpected_content_list:
        pytest_assert(
            unexpected_content not in output['stdout'],
            "{} is unexpected content".format(unexpected_content)
        )


def expect_op_failure(output):
    """Expected failure from apply-patch output
    """
    logger.info("Return code: {}, error: {}".format(output['rc'], output['stderr']))
    pytest_assert(
        output['rc'],
        "The command should fail with non zero return code"
    )


def start_limit_hit(duthost, service_name):
    """If start-limit-hit is hit, the service will not start anyway.

    Args:
        service_name: Service to reset
    """
    service_status = duthost.shell("systemctl status {}.service | grep 'Active'".format(service_name))
    pytest_assert(
        not service_status['rc'],
        "{} service status cannot be found".format(service_name)
    )

    for line in service_status["stdout_lines"]:
        if "start-limit-hit" in line:
            return True

    return False


def reset_start_limit_hit(duthost, service_name, timeout, interval, delay):
    """Reset service if hit start-limit-hit

    Args:
        duthost: Device Under Test (DUT)
        service_name: Service to reset
        timeout: Maximum time to wait
        interval: Poll interval
        delay: Delay time
    """
    logger.info("Reset service '{}' due to start-limit-hit".format(service_name))

    service_reset_failed = duthost.shell("systemctl reset-failed {}.service".format(service_name))
    pytest_assert(
        not service_reset_failed['rc'],
        "{} systemctl reset-failed service fails"
    )

    service_start = duthost.shell("systemctl start {}.service".format(service_name))
    pytest_assert(
        not service_start['rc'],
        "{} systemctl start service fails"
    )

    if service_name not in CONTAINER_SERVICES_LIST:
        return

    reset_service = wait_until(timeout,
                               interval,
                               delay,
                               duthost.is_service_fully_started,
                               service_name)
    pytest_assert(
        reset_service,
        "Failed to reset service '{}' due to start-limit-hit".format(service_name)
    )


def list_checkpoints(duthost):
    """List checkpoint on target duthost

    Args:
        duthost: Device Under Test (DUT)
        cp: checkpoint filename
    """
    cmds = 'config list-checkpoints'

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    pytest_assert(
        not output['rc'],
        "Failed to list all checkpoint file"
    )

    return output


def verify_checkpoints_exist(duthost, cp):
    """Check if checkpoint file exist in duthost
    """
    output = list_checkpoints(duthost)
    return '"{}"'.format(cp) in output['stdout']


def create_checkpoint(duthost, cp=DEFAULT_CHECKPOINT_NAME):
    """Run checkpoint on target duthost

    Args:
        duthost: Device Under Test (DUT)
        cp: checkpoint filename
    """
    cmds = 'config checkpoint {}'.format(cp)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    pytest_assert(
        not output['rc']
        and "Checkpoint created successfully" in output['stdout']
        and verify_checkpoints_exist(duthost, cp),
        "Failed to config a checkpoint file: {}".format(cp)
    )


def delete_checkpoint(duthost, cp=DEFAULT_CHECKPOINT_NAME):
    """Run checkpoint on target duthost

    Args:
        duthost: Device Under Test (DUT)
        cp: checkpoint filename
    """
    pytest_assert(
        verify_checkpoints_exist(duthost, cp),
        "Failed to find the checkpoint file: {}".format(cp)
    )

    cmds = 'config delete-checkpoint {}'.format(cp)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    pytest_assert(
        not output['rc'] and "Checkpoint deleted successfully" in output['stdout'],
        "Failed to delete a checkpoint file: {}".format(cp)
    )


def rollback(duthost, cp=DEFAULT_CHECKPOINT_NAME):
    """Run rollback on target duthost

    Args:
        duthost: Device Under Test (DUT)
        cp: rollback filename
    """
    cmds = 'config rollback {}'.format(cp)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds, module_ignore_errors=True)

    return output


def rollback_or_reload(duthost, cp=DEFAULT_CHECKPOINT_NAME):
    """Run rollback on target duthost. config_reload if rollback failed.

    Args:
        duthost: Device Under Test (DUT)
    """
    output = rollback(duthost, cp)

    if output['rc'] or "Config rolled back successfully" not in output['stdout']:
        config_reload(duthost)
        pytest.fail("config rollback failed. Restored by config_reload")


def create_path(tokens):
    return JsonPointer.from_parts(tokens).path


def check_show_ip_intf(duthost, intf_name, expected_content_list, unexpected_content_list, is_ipv4=True):
    """Check lo interface status by show command

    Sample output:
    admin@vlab-01:~$ show ip interfaces  | grep -w Vlan1000
    Vlan1000                   192.168.0.1/21       up/up         N/A             N/A
    admin@vlab-01:~$ show ipv6 interfaces | grep -w Vlan1000
    Vlan1000                          fc02:1000::1/64                             up/up         N/A             N/A
                                      fe80::5054:ff:feda:c6af%Vlan1000/64                       N/A             N/A
    """
    address_family = "ip" if is_ipv4 else "ipv6"
    output = duthost.shell("show {} interfaces | grep -w {} || true".format(address_family, intf_name))

    expect_res_success(duthost, output, expected_content_list, unexpected_content_list)


def check_vrf_route_for_intf(duthost, vrf_name, intf_name, is_ipv4=True):
    """Check ip route for specific vrf

    Sample output:
    admin@vlab-01:~$ show ip route vrf Vrf_01 | grep -w Loopback0
    C>* 10.1.0.32/32 is directly connected, Loopback0, 00:00:13
    """
    address_family = "ip" if is_ipv4 else "ipv6"
    output = duthost.shell("show {} route vrf {} | grep -w {}".format(address_family, vrf_name, intf_name))

    pytest_assert(not output['rc'], "Route not found for {} in vrf {}".format(intf_name, vrf_name))


def get_gcu_field_operations_conf(duthost):
    get_gcu_dir_path_cmd = 'python3 -c \"import generic_config_updater ; print(generic_config_updater.__path__)\"'
    gcu_dir_path = duthost.shell("{}".format(get_gcu_dir_path_cmd))['stdout'].replace("[", "").replace("]", "")
    gcu_conf = duthost.shell('cat {}/{}'.format(gcu_dir_path, GCU_FIELD_OPERATION_CONF_FILE))['stdout']
    gcu_conf_json = json.loads(gcu_conf)
    return gcu_conf_json


def get_asic_name(duthost):
    asic_type = duthost.facts["asic_type"]
    asic = "unknown"
    gcu_conf = get_gcu_field_operations_conf(duthost)
    asic_mapping = gcu_conf["helper_data"]["rdma_config_update_validator"]

    def _get_asic_name(asic_type):
        cur_hwsku = duthost.shell(GET_HWSKU_CMD)['stdout'].rstrip('\n')
        # The key name is like "mellanox_asics" or "broadcom_asics"
        asic_key_name = asic_type + "_asics"
        if asic_key_name not in asic_mapping:
            return "unknown"
        asic_hwskus = asic_mapping[asic_key_name]
        for asic_name, hwskus in asic_hwskus.items():
            if cur_hwsku.lower() in [hwsku.lower() for hwsku in hwskus]:
                return asic_name
        return "unknown"

    if asic_type == 'cisco-8000':
        asic = "cisco-8000"
    elif asic_type in ('mellanox', 'broadcom'):
        asic = _get_asic_name(asic_type)
    elif asic_type == 'marvell-teralynx':
        asic = "marvell-teralynx"
    elif asic_type == 'vs':
        # We need to check both mellanox and broadcom asics for vs platform
        dummy_asic_list = ['broadcom', 'mellanox', 'cisco-8000']
        for dummy_asic in dummy_asic_list:
            tmp_asic = _get_asic_name(dummy_asic)
            if tmp_asic != "unknown":
                asic = tmp_asic
                break

    return asic


def is_valid_platform_and_version(duthost, table, scenario, operation, field_value=None):
    asic = get_asic_name(duthost)
    os_version = duthost.os_version
    if asic == "unknown":
        return False
    gcu_conf = get_gcu_field_operations_conf(duthost)

    if operation == "add":
        if field_value:
            operation = "replace"

    # Ensure that the operation is supported by comparing with conf
    try:
        valid_ops = gcu_conf["tables"][table]["validator_data"]["rdma_config_update_validator"][scenario]["operations"]
        if operation not in valid_ops:
            return False
    except KeyError:
        return False
    except IndexError:
        return False

    # Ensure that the version is suported by comparing with conf
    if "master" in os_version or "internal" in os_version:
        return True
    try:
        version_required = gcu_conf["tables"][table]["validator_data"]["rdma_config_update_validator"][scenario]["platforms"][asic] # noqa E501
        if version_required == "":
            return False
        # os_version is in format "20220531.04", version_required is in format "20220500"
        return os_version[0:8] >= version_required[0:8]
    except KeyError:
        return False
    except IndexError:
        return False


def apply_formed_json_patch(duthost, json_patch, setup):

    duts_to_apply = [duthost]
    outputs = []
    if setup["is_dualtor"]:
        duts_to_apply.append(setup["rand_unselected_dut"])

    for dut in duts_to_apply:
        tmpfile = generate_tmpfile(dut)
        logger.info("tmpfile {}".format(tmpfile))

        try:
            output = apply_patch(dut, json_data=json_patch, dest_file=tmpfile)
            outputs.append(output)
        finally:
            delete_tmpfile(dut, tmpfile)

    return outputs


def expect_acl_table_match_multiple_bindings(duthost,
                                             table_name,
                                             expected_first_line_content,
                                             expected_bindings,
                                             setup):
    """Check if acl table show as expected
    Acl table with multiple bindings will show as such

    Table_Name  Table_Type  Ethernet4   Table_Description   ingress
                            Ethernet8
                            Ethernet12
                            Ethernet16

    So we must have separate checks for first line and bindings
    """

    cmds = "show acl table {}".format(table_name)

    duts_to_check = [duthost]
    if setup["is_dualtor"]:
        duts_to_check.append(setup["rand_unselected_dut"])

    for dut in duts_to_check:

        output = dut.show_and_parse(cmds)
        pytest_assert(len(output) > 0, "'{}' is not a table on this device".format(table_name))

        first_line = output[0]
        pytest_assert(set(first_line.values()) == set(expected_first_line_content))
        table_bindings = [first_line["binding"]]
        for i in range(len(output)):
            table_bindings.append(output[i]["binding"])
        pytest_assert(set(table_bindings) == set(expected_bindings), "ACL Table bindings don't fully match")


def expect_acl_rule_match(duthost, rulename, expected_content_list, setup):
    """Check if acl rule shows as expected"""

    cmds = "show acl rule DYNAMIC_ACL_TABLE {}".format(rulename)

    duts_to_check = [duthost]
    if setup["is_dualtor"]:
        duts_to_check.append(setup["rand_unselected_dut"])

    for dut in duts_to_check:

        output = dut.show_and_parse(cmds)

        rule_lines = len(output)

        pytest_assert(rule_lines >= 1, "'{}' is not a rule on this device".format(rulename))

        first_line = output[0].values()

        pytest_assert(set(first_line) <= set(expected_content_list), "ACL Rule details do not match!")

        if rule_lines > 1:
            for i in range(1, rule_lines):
                pytest_assert(output[i]["match"] in expected_content_list,
                              "Unexpected match condition found: " + str(output[i]["match"]))


def expect_acl_rule_removed(duthost, rulename, setup):
    """Check if ACL rule has been successfully removed"""

    cmds = "show acl rule DYNAMIC_ACL_TABLE {}".format(rulename)

    duts_to_check = [duthost]
    if setup["is_dualtor"]:
        duts_to_check.append(setup["rand_unselected_dut"])

    for dut in duts_to_check:
        output = dut.show_and_parse(cmds)

        removed = len(output) == 0

        pytest_assert(removed, "'{}' showed a rule, this following rule should have been removed".format(cmds))


def get_bgp_speaker_runningconfig(duthost):
    """ Get bgp speaker config that contains src_address and ip_range

    Sample output in t0:
    ['\n neighbor BGPSLBPassive update-source 10.1.0.32',
     '\n neighbor BGPVac update-source 10.1.0.32',
     '\n bgp listen range 10.255.0.0/25 peer-group BGPSLBPassive',
     '\n bgp listen range 192.168.0.0/21 peer-group BGPVac']
    """
    cmds = "show runningconfiguration bgp"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    # Sample:
    # neighbor BGPSLBPassive update-source 10.1.0.32
    # bgp listen range 192.168.0.0/21 peer-group BGPVac
    bgp_speaker_pattern = r"\s+neighbor.*update-source.*|\s+bgp listen range.*"
    bgp_speaker_config = re.findall(bgp_speaker_pattern, output['stdout'])
    return bgp_speaker_config
