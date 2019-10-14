"""
Test SFP plug in/out behavior via simulation
"""
import logging
import os
import json
import time

from platform_fixtures import conn_graph_facts
from check_interface_status import parse_intf_status

ans_host = None


def teardown_module():
    logging.info("remove script to simulate sfp plug in/out from the DUT")
    file_path = os.path.join('/usr/share/sonic/device', ans_host.facts['platform'], 'plugins/sfpadminset.py')
    ans_host.file(path=file_path, state='absent')


def verify_interface_status(dut, mg_ports, intf, status_up_expected):
    shutdown_intf_command = 'config interface shutdown {}'
    startup_intf_command = 'config interface startup {}'

    if intf not in mg_ports:
        dut.command(startup_intf_command.format(intf))
        dut.command(shutdown_intf_command.format(intf))
    else:
        output = dut.command("intfutil description")
        intf_status = parse_intf_status(output["stdout_lines"][2:])
        if status_up_expected:
            expected_oper = "up"
            expected_admin = "up"
        else:
            expected_oper = "down"
            expected_admin = "up"
        assert intf in intf_status, "Missing status for interface %s" % intf
        assert intf_status[intf]["oper"] == expected_oper, \
            "Oper status of interface %s is %s, expected '%s'" % (intf, intf_status[intf]["oper"], expected_oper)
        assert intf_status[intf]["admin"] == expected_admin, \
            "Admin status of interface %s is %s, expected '%s'" % (intf, intf_status[intf]["admin"], expected_admin)


def verify_sfp_presence_status(dut, intf, presence_expected):
    check_intf_presence_command = 'show interface transceiver presence {}'
    check_presence_output = dut.command(check_intf_presence_command.format(intf))
    logging.info(str(check_presence_output["stdout_lines"][2]))
    presence_list = check_presence_output["stdout_lines"][2].split()
    logging.info(str(presence_list))
    assert intf in presence_list, "Wrong interface name in the output %s" % str(presence_list)
    if presence_expected:
        assert 'Present' in presence_list, "Status is not expected, output %s" % str(presence_list)
    else:
        assert 'Present' not in presence_list, "Status is not expected, output %s" % str(presence_list)


def verify_sfp_presence_sysfs_status(dut, sfp_id, presence_expected):
    check_qsfp_sysfs_command = 'cat /var/run/hw-management/qsfp/qsfp{}_status'
    check_sysfs_output = dut.command(check_qsfp_sysfs_command.format(str(sfp_id)))
    logging.info('output of check sysfs %s' % (str(check_sysfs_output)))
    if presence_expected:
        assert check_sysfs_output["stdout"] == '1', "Content of qsfp_status of sfp%s is not correct" % str(sfp_id)
    else:
        assert check_sysfs_output["stdout"] == '0', "Content of qsfp_status of sfp%s is not correct" % str(sfp_id)


def test_check_sfp_plug_in_out_sim(testbed_devices, conn_graph_facts):
    """This test case is to check SFP presence, sysfs status
       and interface status by simulating SFP plug in/out via PMAOS
    """
    global ans_host
    ans_host = testbed_devices["dut"]
    logging.debug('platform : %s, hwsku : %s, ASIC %s' % (ans_host.facts['platform'], ans_host.facts['hwsku'],
                                                          ans_host.facts['asic_type']))
    dest_path = os.path.join('/usr/share/sonic/device', ans_host.facts['platform'], 'plugins/sfpadminset.py')
    src_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'files/sfpadminset.py')
    logging.debug('src = %s, dest = %s' % (src_path, dest_path))
    ans_host.copy(src=src_path, dest=dest_path)

    mg_ports = ans_host.minigraph_facts(host=ans_host.hostname)["ansible_facts"]["minigraph_ports"]

    ports_config = json.loads(ans_host.command("sudo sonic-cfggen -d --var-json PORT")["stdout"])

    sfp_disconnect_command = \
        'docker exec syncd python /usr/share/sonic/platform/plugins/sfpadminset.py {} "disconnect"'
    sfp_connect_command = \
        'docker exec syncd python /usr/share/sonic/platform/plugins/sfpadminset.py {} "connect"'

    logging.info("Use show interface status information")
    for intf in mg_ports:
        intf_lanes = ports_config[intf]["lanes"]
        sfp_id = int(intf_lanes.split(",")[0])/4 + 1
        sdk_port_id = int(intf_lanes.split(",")[0])/4

        # Init check, expect port is up, SFP is presence
        verify_sfp_presence_sysfs_status(ans_host, sfp_id, True)
        verify_sfp_presence_status(ans_host, intf, True)
        verify_interface_status(ans_host, mg_ports, intf, True)

        # Disconnect SFP to simulate SFP plug out
        ans_host.command(sfp_disconnect_command.format(sdk_port_id))

        # Expecting port is down, SFP not presence
        verify_sfp_presence_status(ans_host, intf, False)
        verify_sfp_presence_sysfs_status(ans_host, sfp_id, False)
        verify_interface_status(ans_host, mg_ports, intf, False)

        # Connect SFP to simulate SFP plug in
        ans_host.command(sfp_connect_command.format(sdk_port_id))
        # It needs about 10s to have ports go up
        time.sleep(10)

        # Check again, expect SFP restored, and port become up again
        verify_sfp_presence_status(ans_host, intf, True)
        verify_sfp_presence_sysfs_status(ans_host, sfp_id, True)
        verify_interface_status(ans_host, mg_ports, intf, True)
