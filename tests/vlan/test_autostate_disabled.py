import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, delete_running_config


pytestmark = [
    pytest.mark.topology("t0", "m0", "mx")
]


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, rand_one_dut_hostname, loganalyzer):
    """
       Ignore expected errors in logs during test execution

       Args:
           loganalyzer: Loganalyzer utility fixture
           duthost: DUT host object
    """
    duthost = duthosts[rand_one_dut_hostname]
    if loganalyzer and duthost.facts["platform"] == "x86_64-cel_e1031-r0":
        loganalyzer_ignore_regex = [
            ".*ERR swss#orchagent:.*:- doPortTask: .*: autoneg is not supported.*",
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(loganalyzer_ignore_regex)

    yield


class TestAutostateDisabled:
    """
    This test case is used to verify that vlan interface autostate is **disabled** on SONiC.

    The autostate feature notifies a switch or routing module VLAN interface (Layer 3 interface) to transition to
    up/up status when at least one Layer 2 port becomes active in that VLAN.

    In SONiC, all vlans are bound to a single bridge interface, so the vlan interface will go down only if the bridge
    is down. Since bridge goes down when all the associated interfaces are down, if all the vlan members across all
    the vlans go down, the bridge will go down and the vlan interface will go down.

    For more information about autostate, see:
      * https://www.cisco.com/c/en/us/support/docs/switches/catalyst-6500-series-switches/41141-188.html
    """

    def test_autostate_disabled(self, duthosts, enum_frontend_dut_hostname):
        """
        Verify vlan interface autostate is disabled on SONiC.
        """
        pytest.skip("Temporarily skipped to let the sonic-swss submodule be updated.")

        duthost = duthosts[enum_frontend_dut_hostname]
        dut_hostname = duthost.hostname

        # Collect DUT configuration and status
        vlan_members_facts = duthost.get_running_config_facts().get('VLAN_MEMBER')
        if vlan_members_facts is None:
            pytest.skip('No vlan available on DUT {hostname}'.format(hostname=dut_hostname))
        ifs_status = duthost.get_interfaces_status()
        ip_ifs = duthost.show_ip_interface()['ansible_facts']['ip_interfaces']

        # Find out all vlans which meet the following requirements:
        #   1. The oper_state of vlan interface is 'up'
        #   2. The oper_state of at least one member in the vlan is 'up'
        vlan_available = []
        for vlan in vlan_members_facts:
            if ip_ifs.get(vlan, {}).get('oper_state') == 'up':
                for member in vlan_members_facts[vlan]:
                    if ifs_status.get(member, {}).get('oper') == 'up':
                        vlan_available.append(vlan)
                        break
        if len(vlan_available) == 0:
            pytest.skip('No applicable VLAN available on DUT {hostname} for this test case'.
                        format(hostname=dut_hostname))

        # Pick a vlan for test
        vlan = vlan_available[0]
        vlan_members = list(vlan_members_facts[vlan].keys())

        try:
            # Shutdown all the members in vlan.
            self.shutdown_multiple_with_confirm(duthost, vlan_members, err_handler=pytest.fail)

            # Check whether the oper_state of vlan interface is changed as expected.
            ip_ifs = duthost.show_ip_interface()['ansible_facts']['ip_interfaces']
            if len(vlan_available) > 1:
                # If more than one vlan comply with the above test requirements, then there are members in other vlans
                # that are still up. Therefore, the bridge is still up, and vlan interface should be up.
                pytest_assert(ip_ifs.get(vlan, {}).get('oper_state') == "up",
                              'vlan interface of {vlan} is not up as expected'.format(vlan=vlan))
            else:
                # If only one vlan comply with the above test requirements, then all the vlan members across all the
                # vlans are down. Therefore, the bridge is down, and vlan interface should be down.
                pytest_assert(ip_ifs.get(vlan, {}).get('oper_state') == "down",
                              'vlan interface of {vlan} is not down as expected'.format(vlan=vlan))
        finally:
            # Restore all interfaces to their original admin_state.
            self.restore_interface_admin_state(duthost, ifs_status)

    def restore_interface_admin_state(self, duthost, ifs_status):
        """
        Restore all interfaces to their original admin_state at the end of test.
        """
        ifs_up, ifs_down = [], []
        for interface in ifs_status:
            admin_state = ifs_status[interface].get('admin')
            if admin_state == 'up':
                ifs_up.append(interface)
            elif admin_state == 'down':
                ifs_down.append(interface)
        if len(ifs_up) > 0:
            self.startup_multiple_with_confirm(duthost, ifs_up)
        if len(ifs_down) > 0:
            self.shutdown_multiple_with_confirm(duthost, ifs_down)

    def check_interface_oper_state(self, duthost, interfaces, expected_state):
        """
        Check the oper_state of all interfaces are as expected.
        """
        ifs_status = duthost.get_interfaces_status()
        return all([ifs_status.get(x, {}).get('oper', '') == expected_state for x in interfaces])

    def shutdown_multiple_with_confirm(self, duthost, interfaces, err_handler=logging.error):
        """
        Shutdown multiple interfaces and confirm success.
        """
        res = duthost.shutdown_multiple(interfaces)
        if not res.is_successful:
            err_handler('shutdown "{interfaces}" failed'.format(interfaces=interfaces))
        logging.info('waiting for "{interfaces}" shutdown'.format(interfaces=interfaces))
        if not wait_until(60, 5, 0, self.check_interface_oper_state, duthost, interfaces, "down"):
            err_handler('shutdown "{interfaces}" failed'.format(interfaces=interfaces))

        config_entry = []
        config = {}
        config["PORT"] = {}

        for interface in interfaces:
            config["PORT"].update({interface: {"admin_status": "down"}})

        config_entry.append(config)

        delete_running_config(config_entry, duthost)

    def startup_multiple_with_confirm(self, duthost, interfaces, err_handler=logging.error):
        """
        Startup multiple interfaces and confirm success.
        """
        res = duthost.no_shutdown_multiple(interfaces)
        if not res.is_successful:
            err_handler('startup "{interfaces}" failed'.format(interfaces=interfaces))
        logging.info('waiting for "{interfaces}" startup'.format(interfaces=interfaces))
        if not wait_until(60, 5, 0, self.check_interface_oper_state, duthost, interfaces, "up"):
            err_handler('startup "{interfaces}" failed'.format(interfaces=interfaces))
