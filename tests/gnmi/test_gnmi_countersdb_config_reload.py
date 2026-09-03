import json
import logging
import pytest
import re

from .countersdb_helpers import countersdb_config_path, countersdb_prefix, iter_response_text, response_has_update
from tests.common import config_reload
from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.pygnmi_client import PygnmiClientCallError, PygnmiClientError
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

CFG_DB_BACKUP_SUFFIX = ".gnmi_countersdb_backup"

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "check_dut_timestamp"),
]


def _load_new_cfg(duthost, grpc_env, data, config_path):
    duthost.copy(content=json.dumps(data, indent=4), dest=config_path)
    config_reload(duthost, config_source='config_db', safe_reload=True, check_intf_up_ports=True,
                  wait_for_bgp=True, yang_validate=False)
    # Config reload restarts the gNMI container; restore managed TLS before the next RPC.
    grpc_env.reconfigure_after_reboot()


def _get_buffer_queues_cnt(duthost, client, iface):
    result = client.get(
        "COUNTERS_QUEUE_NAME_MAP",
        prefix=countersdb_prefix(duthost),
    )
    queue_pattern = re.compile(r'{}:\d+'.format(re.escape(iface)))
    queues = set()
    for text in iter_response_text(result):
        queues.update(queue_pattern.findall(text))
    return len(queues)


def _check_buffer_queues_cnt(duthost, client, iface):
    try:
        return _get_buffer_queues_cnt(duthost, client, iface) > 0
    except PygnmiClientError:
        return False


def test_gnmi_queue_buffer_cnt(rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    """
    Check number of queue counters
    """
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    if duthost.is_supervisor_node():
        pytest.skip("Skipping test as no Ethernet0 frontpanel port on supervisor")
    logger.info('start gnmi output testing')
    iface = "Ethernet0"
    namespace_name = None
    # Get UC for Ethernet0
    if duthost.is_multi_asic:
        namespace_name = duthost.get_port_asic_instance(iface).namespace
        dut_command = f"show queue counters {iface} -n {namespace_name}"
    else:
        dut_command = f"show queue counters {iface}"
    result = duthost.shell(dut_command, module_ignore_errors=True)
    uc_list = re.findall(r"UC(\d+)", result["stdout"])
    for i in uc_list:
        # Read UC
        path = "COUNTERS_QUEUE_NAME_MAP/" + iface + ":" + str(i)
        result = client.get(path, prefix=countersdb_prefix(duthost))
        pytest_assert(response_has_update(result, "oid"), (
            "OID not found in result. "
            "Result: {}"
        ).format(result))

    # Read invalid UC
    invalid_path = "COUNTERS_QUEUE_NAME_MAP/" + iface + ":abc"
    with pytest.raises(PygnmiClientCallError):
        client.get(invalid_path, prefix=countersdb_prefix(duthost))

    # Verify the "create_only_config_db_buffers" optimization: with it enabled,
    # removing a BUFFER_QUEUE entry must reduce the number of queue counters in
    # COUNTERS_QUEUE_NAME_MAP for that interface.
    # Covers https://github.com/sonic-net/sonic-buildimage/issues/17448
    interfaces = duthost.get_interfaces_status(namespace_name)
    pattern = re.compile(r'^Ethernet[0-9]{1,3}$')
    admin_up_interfaces = [i for i, info in interfaces.items()
                           if pattern.match(i) and info['admin'] == 'up' and info['oper'] == 'up']

    cfggen_namespace = "-n {} ".format(namespace_name) if namespace_name else ""
    data = json.loads(duthost.shell(
        "sonic-cfggen {}-d --print-data".format(cfggen_namespace), verbose=False
    )['stdout'])

    if 'BUFFER_QUEUE' not in data or not data['BUFFER_QUEUE']:
        pytest.skip("Skipping test as BUFFER_QUEUE table is not present in config db")

    buffer_queues = list(data['BUFFER_QUEUE'].keys())
    buffer_queues_interfaces = [bq.split('|')[0] for bq in buffer_queues]

    interface_to_check = None
    for bq in buffer_queues_interfaces:
        if bq in admin_up_interfaces:
            interface_to_check = bq
            break
    if interface_to_check is None:
        pytest.skip("Skipping test as there are no admin-up interfaces with buffer queues to check")

    interface_buffer_queues = [bq for bq in buffer_queues if bq.split('|')[0] == interface_to_check]
    if len(interface_buffer_queues) == 0:
        pytest.skip("No valid entry for any interface:queue entry")

    # If the interface has a single grouped queue entry (e.g. Ethernet0|0-9), split
    # off the first queue (Ethernet0|0) so there is a distinct entry to remove.
    is_single_queue = False
    bq_entry = interface_buffer_queues[0]
    if len(interface_buffer_queues) == 1:
        ifc, q_range = bq_entry.split('|')
        if '-' in q_range:
            start, end = map(int, q_range.split('-'))
            if start < end:
                single_queue_entry = f"{ifc}|{start}"
                remaining_queue_entry = f"{ifc}|{start + 1}-{end}"
                profile = data['BUFFER_QUEUE'][bq_entry]['profile']
                data['BUFFER_QUEUE'][remaining_queue_entry] = {"profile": profile}
                data['BUFFER_QUEUE'][single_queue_entry] = {"profile": profile}
                del data['BUFFER_QUEUE'][bq_entry]
                bq_entry = single_queue_entry
            else:
                pytest.skip("Invalid buffer queue range")
        else:
            is_single_queue = True

    config_path = countersdb_config_path(duthost, iface)
    config_backup = config_path + CFG_DB_BACKUP_SUFFIX
    duthost.shell("cp {} {}".format(config_path, config_backup))
    try:
        data['DEVICE_METADATA']["localhost"]["create_only_config_db_buffers"] = "true"
        _load_new_cfg(duthost, gnmi_tls, data, config_path)
        pytest_assert(wait_until(120, 20, 0, _check_buffer_queues_cnt, duthost, client, interface_to_check),
                      "Unable to get count of buffer queues from COUNTERS_QUEUE_NAME_MAP")
        pre_del_cnt = _get_buffer_queues_cnt(duthost, client, interface_to_check)

        # Remove a buffer queue, reload, and get the new number of queue counters.
        del data['BUFFER_QUEUE'][bq_entry]
        _load_new_cfg(duthost, gnmi_tls, data, config_path)
        if not is_single_queue:
            pytest_assert(wait_until(120, 20, 0, _check_buffer_queues_cnt, duthost, client, interface_to_check),
                          "Unable to get count of buffer queues from COUNTERS_QUEUE_NAME_MAP")
        post_del_cnt = _get_buffer_queues_cnt(duthost, client, interface_to_check)

        if duthost.facts.get("platform_asic") == "broadcom-dnx":
            pytest_assert(pre_del_cnt == post_del_cnt,
                          "Queue counter count changed on static-queue Broadcom-DNX")
        else:
            pytest_assert(pre_del_cnt > post_del_cnt,
                          "Number of queue counters count differs from expected")
    finally:
        duthost.shell("mv {} {}".format(config_backup, config_path))
        config_reload(duthost, config_source='config_db', safe_reload=True,
                      check_intf_up_ports=True, wait_for_bgp=True,
                      yang_validate=False)
