"""
Cross check show sfp presence with qsfp_status
"""
import logging
import os
import json

from platform_fixtures import conn_graph_facts

def test_check_sfp_presence(testbed_devices, conn_graph_facts):
    """This test case is to check SFP presence status with CLI and sysfs.
    """
    ans_host = testbed_devices["dut"]
    ports_config = json.loads(ans_host.command("sudo sonic-cfggen -d --var-json PORT")["stdout"])
    check_qsfp_sysfs_command = 'cat /var/run/hw-management/qsfp/qsfp{}_status'
    check_intf_presence_command = 'show interface transceiver presence {}'

    logging.info("Use show interface status information")
    for intf in conn_graph_facts["device_conn"]:
        intf_lanes = ports_config[intf]["lanes"]
        sfp_id = int(intf_lanes.split(",")[0])/4 + 1

        check_presence_output = ans_host.command(check_intf_presence_command.format(intf))
        assert check_presence_output["rc"] == 0, "Failed to read interface %s transceiver presence" % intf
        logging.info(str(check_presence_output["stdout_lines"][2]))
        presence_list = check_presence_output["stdout_lines"][2].split()
        logging.info(str(presence_list))
        assert intf in presence_list, "Wrong interface name in the output %s" % str(presence_list)
        assert 'Present' in presence_list, "Status is not expected, output %s" % str(presence_list)

        check_sysfs_output = ans_host.command(check_qsfp_sysfs_command.format(str(sfp_id)))
        logging.info('output of check sysfs %s' % (str(check_sysfs_output)))
        assert check_sysfs_output["rc"] == 0, "Failed to read qsfp_status of sfp%s." % str(sfp_id)
        assert check_sysfs_output["stdout"] == '1', "Content of qsfp_status of sfp%s is not correct" % str(sfp_id)
