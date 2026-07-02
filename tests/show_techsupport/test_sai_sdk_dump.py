"""
Test that a SAI failure produces a SAI SDK failure dump on the DUT.

Background:
    Previously this test lived in test_auto_techsupport.py and verified the whole
    chain: SAI failure -> orchagent abort -> core dump -> auto-techsupport ->
    techsupport tarball contains sai_failure_dump/ (with sai_sdk_dump inside).

    After sonic-swss PR 4469, orchagent no longer aborts on caught SAI failures
    such as the one exercised here (create_router_interface on a port that is a
    PortChannel member). Consequently no core dump is generated and no
    auto-techsupport is triggered, so validating techsupport is no longer valid.

    However the SAI failure dump path is still exercised: orchagent tells syncd
    to invoke the SAI failure dump, and syncd writes it to
    /var/log/sai_failure_dump/ on the host (see
    sonic-net/SONiC:doc/SAI_failure_handling/dump_on_sai_failure.md).

    This test therefore only validates that /var/log/sai_failure_dump/ receives
    a new dump entry after triggering a SAI failure. It intentionally does NOT
    check techsupport, core dumps, or the auto-techsupport history.
"""
import logging
import os
import random
import re

import pytest

from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until

try:
    import allure
except ImportError:
    pytest.skip('Allure library not available. Skipping tests', allow_module_level=True)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'templates')
SAI_CALL_TEMPLATE_FILE_PATH = os.path.join(TEMPLATES_DIR, 'sai_call_fail_config.j2')
DUT_SAI_CALL_CONFIG_PATH = '/tmp/sai_call_fail_config.json'

# Directory (exposed from syncd to the host) where the SAI failure dump is placed.
SAI_FAILURE_DUMP_DIR = '/var/log/sai_failure_dump'

# Max seconds to wait for the SAI failure dump to appear after applying the
# faulty config. The dump is generated synchronously by syncd on receiving
# SAI_REDIS_NOTIFY_SYNCD_INVOKE_DUMP, but "config load" and orchagent processing
# add some latency, so allow a generous timeout.
SAI_DUMP_WAIT_SECONDS = 120


def _list_sai_failure_dumps(duthost):
    """
    List files currently under /var/log/sai_failure_dump/ on the DUT.

    :return: set of file names (may be empty).
    """
    result = duthost.shell(
        'sudo ls -1 {} 2>/dev/null || true'.format(SAI_FAILURE_DUMP_DIR),
        module_ignore_errors=True,
    )
    stdout = (result.get('stdout') or '').strip()
    if not stdout:
        return set()
    return set(line.strip() for line in stdout.splitlines() if line.strip())


def _get_random_physical_port_non_po_member(minigraph_facts):
    """
    Get a physical port which is not a member of any PortChannel.
    """
    po_members = []
    for _, po_data in minigraph_facts['minigraph_portchannels'].items():
        po_members += po_data['members']
    all_ports = list(minigraph_facts['minigraph_ports'].keys())
    non_po_ports = [port for port in all_ports if port not in po_members]
    if non_po_ports:
        return random.choice(non_po_ports)
    return None


def _get_port_vlan(minigraph_facts, port):
    for vlan in minigraph_facts.get('minigraph_vlans', []):
        if port in minigraph_facts['minigraph_vlans'][vlan]['members']:
            return vlan.split('Vlan')[1]
    return None


def _get_port_ips(minigraph_facts, port):
    iface_ips_data = []
    for iface_data in minigraph_facts.get('minigraph_interfaces', []):
        if iface_data['attachto'] == port:
            iface_ips_data.append((iface_data['addr'], iface_data['prefixlen']))
    return iface_ips_data


def _remove_port_from_vlan(duthost, minigraph_facts, test_port):
    test_port_vlan = _get_port_vlan(minigraph_facts, test_port)
    if test_port_vlan:
        with allure.step('Remove interface: {} from VLAN: {}'.format(test_port, test_port_vlan)):
            duthost.shell('sudo config vlan member del {} {}'.format(test_port_vlan, test_port))


def _remove_ips_from_port(duthost, minigraph_facts, test_port):
    for ip_addr, ip_mask in _get_port_ips(minigraph_facts, test_port):
        with allure.step('Remove IP: {}/{} from port: {}'.format(ip_addr, ip_mask, test_port)):
            duthost.shell('sudo config interface ip remove {} {}/{}'.format(test_port, ip_addr, ip_mask))


def _remove_acl_tables(duthost, failure_info):
    for acl_table in re.findall(r'ACL_TABLE\|(\w+)', failure_info):
        with allure.step('Remove ACL table: {}'.format(acl_table)):
            duthost.shell('sudo config acl remove table {}'.format(acl_table))


def _add_po_member(duthost, po_name, test_port, minigraph_facts):
    add_cmd = 'sudo config portchannel member add {} {}'.format(po_name, test_port)
    _remove_port_from_vlan(duthost, minigraph_facts, test_port)
    _remove_ips_from_port(duthost, minigraph_facts, test_port)

    result = duthost.shell(add_cmd, module_ignore_errors=True)
    if result['failed']:
        failure_info = result['stderr_lines'][-1] if result['stderr_lines'] else ''
        if 'is already bound to following ACL_TABLES' in failure_info:
            _remove_acl_tables(duthost, failure_info)
        duthost.shell(add_cmd)


@pytest.fixture()
def cleanup_list():
    cleanup = []
    yield cleanup
    for func, args, kwargs in cleanup:
        try:
            func(*args, **kwargs)
        except Exception as e:  # noqa: BLE001
            logger.warning('Cleanup step {} failed: {}'.format(func.__name__, e))


class TestSaiSdkDump:
    """
    Validate that a SAI programming failure results in a SAI failure dump being
    stored under /var/log/sai_failure_dump/ on the DUT.
    """

    @pytest.fixture(autouse=True)
    def _setup(self, duthosts, rand_one_dut_hostname):
        self.duthost = duthosts[rand_one_dut_hostname]

    @pytest.mark.disable_loganalyzer
    def test_sai_sdk_dump(self, tbinfo, cleanup_list):
        """
        Trigger a SAI programming failure by loading an INTERFACE config that
        targets a port which is a PortChannel member (create_router_interface
        will fail in SAI), and validate that a new dump file appears under
        /var/log/sai_failure_dump/ on the DUT.

        Note: post sonic-swss PR 4469 orchagent no longer aborts on this SAI
        failure, so this test intentionally does NOT check techsupport or core
        dumps.
        """
        duthost = self.duthost
        minigraph_facts = duthost.get_extended_minigraph_facts(tbinfo)
        po_name = 'PortChannel1234'

        with allure.step('Snapshot existing SAI failure dumps'):
            initial_dumps = _list_sai_failure_dumps(duthost)
            logger.info('Existing sai_failure_dump entries: {}'.format(sorted(initial_dumps)))

        with allure.step('Pick a physical port that is not a PortChannel member'):
            test_port = _get_random_physical_port_non_po_member(minigraph_facts)
            if not test_port:
                pytest.skip('Cannot find a physical port to build the stub PortChannel')
            logger.info('Using test port: {}'.format(test_port))

        with allure.step('Render config that will cause SAI failure'):
            duthost.host.options['variable_manager'].extra_vars.update({'test_port': test_port})
            duthost.template(src=SAI_CALL_TEMPLATE_FILE_PATH, dest=DUT_SAI_CALL_CONFIG_PATH)

        with allure.step('Create stub PortChannel: {}'.format(po_name)):
            duthost.shell('sudo config portchannel add {}'.format(po_name))
            # config_reload restores DUT config regardless of test outcome.
            cleanup_list.append((config_reload, (duthost,), {}))

        with allure.step('Add {} to {}'.format(test_port, po_name)):
            _add_po_member(duthost, po_name, test_port, minigraph_facts)

        with allure.step('Apply the SAI-failing config on the DUT'):
            duthost.shell('sudo config load -y {}'.format(DUT_SAI_CALL_CONFIG_PATH))

        with allure.step('Wait for a new dump under {}'.format(SAI_FAILURE_DUMP_DIR)):
            def _new_dump_appeared():
                current = _list_sai_failure_dumps(duthost)
                new_entries = current - initial_dumps
                if new_entries:
                    logger.info('New SAI failure dump entries: {}'.format(sorted(new_entries)))
                    return True
                return False

            appeared = wait_until(SAI_DUMP_WAIT_SECONDS, 5, 0, _new_dump_appeared)
            assert appeared, (
                'No new SAI failure dump appeared under {} within {}s after '
                'triggering a SAI failure. Existing entries: {}'.format(
                    SAI_FAILURE_DUMP_DIR, SAI_DUMP_WAIT_SECONDS, sorted(initial_dumps))
            )

        with allure.step('Validate the new dump file is non-empty'):
            current = _list_sai_failure_dumps(duthost)
            new_entries = sorted(current - initial_dumps)
            # Check size of every new dump; require at least one non-empty file.
            non_empty = []
            for name in new_entries:
                path = '{}/{}'.format(SAI_FAILURE_DUMP_DIR, name)
                size_out = duthost.shell(
                    "sudo stat -c '%s' {}".format(path), module_ignore_errors=True
                )['stdout'].strip()
                try:
                    size = int(size_out)
                except ValueError:
                    size = 0
                logger.info('SAI failure dump {} size={} bytes'.format(path, size))
                if size > 0:
                    non_empty.append(name)
            assert non_empty, (
                'New SAI failure dump entries {} are all empty under {}'.format(
                    new_entries, SAI_FAILURE_DUMP_DIR)
            )
