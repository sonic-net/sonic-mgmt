import logging
import pytest

from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("t0")
]


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

        duthost = duthosts[enum_frontend_dut_hostname]
        dut_hostname = duthost.hostname

        # Collect DUT configuration and status
        vlan_members_facts = duthost.get_running_config_facts().get('VLAN_MEMBER')
        if vlan_members_facts is None:
            pytest.skip('No vlan available on DUT {hostname}'.format(hostname=dut_hostname))
        ifs_status = self.get_interface_status(duthost)
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
            pytest.skip('No vlan available on DUT {hostname}'.format(hostname=dut_hostname))

        # Pick a vlan for test
        vlan = vlan_available[0]
        vlan_members = vlan_members_facts[vlan].keys()

        # Shutdown all the members in vlan.
        res = duthost.shutdown_multiple(vlan_members)
        if not res.is_successful:
            self.restore_interface_admin_state(duthost, ifs_status)
            pytest.fail('shutdown "{vlan_members}" in {vlan} failed'.format(vlan_members=vlan_members, vlan=vlan))
        logging.info('waiting for "{vlan_members}" shutdown in {vlan}'.format(vlan_members=vlan_members, vlan=vlan))
        if not wait_until(60, 5, 0, self.check_interface_oper_state, duthost, vlan_members, "down"):
            self.restore_interface_admin_state(duthost, ifs_status)
            pytest.fail('shutdown "{vlan_members}" in {vlan} failed'.format(vlan_members=vlan_members, vlan=vlan))

        # Check whether the oper_state of vlan interface is changed as expected.
        ip_ifs = duthost.show_ip_interface()['ansible_facts']['ip_interfaces']
        if len(vlan_available) > 1:
            # If more than one vlan comply with the above test requirements, then there are members in other vlans
            # that are still up. Therefore, the bridge is still up, and vlan interface should be up.
            if ip_ifs.get(vlan, {}).get('oper_state') != "up":
                self.restore_interface_admin_state(duthost, ifs_status)
                pytest.fail('vlan interface of {vlan} is not up as expected'.format(vlan=vlan))
        else:
            # If only one vlan comply with the above test requirements, then all the vlan members across all the vlans
            # are down. Therefore, the bridge is down, and vlan interface should be down.
            if ip_ifs.get(vlan, {}).get('oper_state') != "down":
                self.restore_interface_admin_state(duthost, ifs_status)
                pytest.fail('vlan interface of {vlan} is not down as expected'.format(vlan=vlan))

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
            res = duthost.no_shutdown_multiple(ifs_up)
            if not res.is_successful:
                logging.error('startup "{interfaces}" on DUT {hostname} failed'.
                              format(interfaces=ifs_up, hostname=duthost.hostname))
        if len(ifs_down) > 0:
            res = duthost.shutdown_multiple(ifs_down)
            if not res.is_successful:
                logging.error('shutdown "{interfaces}" on DUT {hostname} failed'.
                              format(interfaces=ifs_down, hostname=duthost.hostname))

    def get_interface_status(self, duthost):
        """
        Run 'show interfaces status' on DUT and parse the result into a dict
        """
        return {x.get('interface'): x for x in duthost.show_and_parse('show interfaces status')}

    def check_interface_oper_state(self, duthost, interfaces, expected_state):
        """
        Check the oper_state of all interfaces are as expected.
        """
        ifs_status = self.get_interface_status(duthost)
        return all([ifs_status.get(x, {}).get('oper', '') == expected_state for x in interfaces])
