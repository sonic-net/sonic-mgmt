# import pytest
# import logging
# import time
#
# from ndk_common import get_expecetd_data, generate_grpc_channel, get_ndk_cli_response
# from test_chassis import TestChassis
#
#
# pytestmark = [
#     pytest.mark.skip,
#     pytest.mark.sanity_check(skip_sanity=True),
#     pytest.mark.disable_loganalyzer,
# ]
#
#
# def modify_monitor_action_and_reboot(duthost, monitor_action=None):
#     """Modily /etc/sonic/platform_ndk.json file to edit monitor action and reboot the dut if needed"""
#     output = duthost.shell('cat /etc/sonic/platform_ndk.json | grep -A 2 monitor_action')
#     if monitor_action in output:
#         return
#     if monitor_action == 'reboot':
#         duthost.shell("sudo sed 's/warn/reboot/g' /etc/sonic/platform_ndk.json")
#         reboot(duthost, localhost)
#     else:
#         duthost.shell("sudo sed 's/reboot/warn/g' /etc/sonic/platform_ndk.json")
#         reboot(duthost, localhost)
#
#
# def modify_iptables_rules(sup_node, duthost, action=None):
#     """Modifies iptables rule on cpm"""
#     if action == 'add':
#         sup_node.shell('sudo iptables -A INPUT -s {} -j DROP'.format(duthost.mgmt_ip))
#     else:
#         sup_node.shell('sudo iptables -D INPUT -s {} -j DROP'.format(duthost.mgmt_ip))
#
#
# def test_linecard_not_reachable_to_cpm_action_reboot(duthosts,
#                                                      enum_rand_one_per_hwsku_frontend_hostname,
#                                                      enum_supervisor_dut_hostname):
#     """
#      Test to verify when Linecard is not reachable to cpm,
#       and '/etc/sonic/platform_ndk.json' file has monitor_action 'reboot' configured on linecard and cpm.
#       The Linecard should reboot after around 2 minutes.
#
#      Steps:
#          1. On linecard edit the platform_ndk.json file to set monitor_action as 'reboot'
#          2. Add iptables rule on the cpm to block the linecard
#          3. Verify logs on the linecard should have message 'cpm not reachable'
#          4. After around 2 minute linecard should reboot, to verify ping the linecard
#     """
#     duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
#     sup_node = duthosts[enum_supervisor_dut_hostname]
#     modify_platform_ndk_config_file(duthost, monitor_action='reboot')
#     modify_platform_ndk_config_file(duthost, monitor_action='reboot')
#
#     modify_iptables_rules(sup_node, duthost, action='add')
#
#
#
#
#
#
#
#
#
#
#
