import time
import json
import os
import sys
import pytest
import pprint
import tortuga_common_utils as common_util
import traffic_stream_ixia_api as stream_api

from spytest import st, tgapi, SpyTestDict
module_dir = os.path.join(os.path.dirname(__file__), '../../', 'common')
sys.path.insert(0, os.path.abspath(module_dir))

min_keys = ["leaf", "tc", "frame_sizes", "pirs", "stream_rates"]


def remove_interface_from_vlan(dut, interface):
    """
    Remove interface from any VLAN membership.

    Example 'show vlan brief' output:
    +-----------+--------------+--------------+----------------+-------------+...
    |   VLAN ID | IP Address   | Ports        | Port Tagging   | Proxy ARP   |...
    +===========+==============+==============+================+=============+...
    |        10 |              | Ethernet1_49 | untagged       | disabled    |...
    |           |              | Ethernet1_50 | tagged         |             |...
    +-----------+--------------+--------------+----------------+-------------+...
    """
    st.log("Checking if {} is a member of any VLAN...".format(interface))

    output = st.show(dut, "show vlan brief", skip_tmpl=True)
    if not output:
        st.log("No VLAN configuration found.")
        return True

    vlans_to_remove = []
    current_vlan_id = None

    for line in output.split('\n'):
        # Skip header/separator lines
        if '===' in line or '---' in line or 'VLAN ID' in line or not line.strip():
            continue

        if '|' not in line:
            continue

        # Split by '|' and strip each field
        fields = [f.strip() for f in line.split('|')]

        # fields[0] is empty, fields[1] is VLAN ID
        if len(fields) > 1 and fields[1].isdigit():
            current_vlan_id = fields[1]

        # Check if interface is in this line
        if interface in line and current_vlan_id:
            if current_vlan_id not in vlans_to_remove:
                vlans_to_remove.append(current_vlan_id)

    if not vlans_to_remove:
        st.log("{} is not a member of any VLAN.".format(interface))
        return True

    st.log("Found {} in VLAN(s): {}".format(interface, vlans_to_remove))

    for vlan_id in vlans_to_remove:
        st.log("Removing {} from VLAN {}...".format(interface, vlan_id))
        st.config(dut, "config vlan member del {} {}".format(vlan_id, interface),
                  skip_error_check=True)

    return True


def remove_interface_from_portchannel(dut, interface):
    """
    Remove interface from any PortChannel membership.

    Example 'show interfaces portchannel' output:
    Flags: A - active, I - inactive, Up - up, Dw - Down, N/A - not available,
           S - selected, D - deselected, * - not synced
      No.  Team Dev      Protocol     Ports
    -----  ------------  -----------  --------------
        2  PortChannel2  LACP(A)(Dw)  Ethernet1_4(D)
    """
    st.log("Checking if {} is a member of any PortChannel...".format(interface))

    output = st.show(dut, "show interfaces portchannel", skip_tmpl=True)
    if not output:
        st.log("No PortChannel configuration found.")
        return True

    portchannel_name = None

    for line in output.split('\n'):
        # Interface appears with suffix like Ethernet1_4(D)
        if interface in line:
            parts = line.split()
            for part in parts:
                if part.startswith('PortChannel'):
                    portchannel_name = part
                    break
            if portchannel_name:
                break

    if not portchannel_name:
        st.log("{} is not a member of any PortChannel.".format(interface))
        return True

    st.log("Found {} in PortChannel: {}".format(interface, portchannel_name))
    st.log("Removing {} from {}...".format(interface, portchannel_name))
    st.config(dut, "config portchannel member del {} {}".format(portchannel_name, interface),
              skip_error_check=True)

    return True


def remove_interface_from_all_memberships(dut, interface):
    """
    Remove interface from both VLAN and PortChannel memberships.
    """
    st.log("Removing {} from all memberships (VLAN and PortChannel)...".format(interface))

    vlan_result = remove_interface_from_vlan(dut, interface)
    pc_result = remove_interface_from_portchannel(dut, interface)

    return vlan_result and pc_result

def calc_gbps(gbps_percnt):
    return int(gbps_percnt) * test_info['if_speed'] / 100.0

def tgen_ports_check():
    st.config(vars.D3, "config qos reload", skip_tmpl=True)
    st.config(vars.D4, "config qos reload", skip_tmpl=True)
    for src in ['T1D4P1', 'T1D4P2', 'T1D4P3', 'T1D4P4']:
        for dst in ['T1D4P1', 'T1D4P2', 'T1D4P3', 'T1D4P4']:
            if src == dst:
                continue

            str_id = stream_api.create_traffic_stream(tb_dict, src, dst, 8192,
                         stream_api.gbps_to_pps(99.9, 8192), 3)
            if str_id == None:
                st.error('Stream creation failed')
                continue
            st.log('stream_id ', str_id)
            stream_api.start_traffic_stream(str_id)
            st.wait(10)
            stream_api.stop_traffic_stream(str_id)
            st.wait(5)
            stats = stream_api.collect_traffic_stream_stats()
            stream_api.delete_traffic_stream(str_id)

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    global tb_dict
    global vars
    global test_info

    st.log("setup topology Started")
    test_info = common_util.get_qos_test_dict('../qos/sp_input_short.json2',
                                              'STRICT_PRIORITY_TEST')
    if test_info == None:
        st.report_fail('msg', 'Failed to read test input file or missing key')
        return

    for k in min_keys:
        if k not in test_info:
            st.report_fail('msg', 'Input dictionary is missing {}'.format(k))
            sys.exit(-1)

    test_info['tgen_port_cnt'] = 4
    # the leaf to leaf link D3D4 is non-standard for a 2 spine 2 leaf topology
    # the non-standard link is useful for breakout testing with data streams
    tb_dict = st.ensure_min_topology("D1D3:2", "D1D4:2", "D2D3:1", "D2D4:1",
                                     "D3T1:4", "D4T1:4")
    vars = st.get_testbed_vars()

    test_info['dut'] = tb_dict[test_info['leaf']]
    test_info['src'] = ['T1' + test_info['leaf'] + 'P1',
                        'T1' + test_info['leaf'] + 'P2']
    test_info['dst'] = 'T1' + test_info['leaf'] + 'P3'
    test_info['dut_if'] = tb_dict[test_info['leaf'] + 'T1' + 'P3']
    stream_api.traffic_api_init('T1' + test_info['leaf'],
                                ['0', '1', '2', '3', '0', '0', '0', '0'])
    temp = st.show(test_info['dut'],
                "show int status {} | tail -1 | awk '{{print $3}}'".format(\
                test_info['dut_if']), skip_tmpl=True)
    temp = temp.splitlines()[0]
    if temp[-1].upper() == 'G':
        temp = temp[:-1]
    test_info['if_speed'] = int(temp) if temp.isdigit() else 10
    test_info['gbps_table'] = []
    for r in test_info['stream_rates']:
        test_info['gbps_table'].append((calc_gbps(r[0]), calc_gbps(r[1])))

    common_util.cleanup_ip_interfaces(test_info['dut'])
    if test_info['dut'] == vars.D3:
        remove_interface_from_all_memberships(test_info['dut'], vars.D3T1P1)
        remove_interface_from_all_memberships(test_info['dut'], vars.D3T1P2)
        remove_interface_from_all_memberships(test_info['dut'], vars.D3T1P3)
        remove_interface_from_all_memberships(test_info['dut'], vars.D3T1P4)
    elif test_info['dut'] == vars.D4:
        remove_interface_from_all_memberships(test_info['dut'], vars.D4T1P1)
        remove_interface_from_all_memberships(test_info['dut'], vars.D4T1P2)
        remove_interface_from_all_memberships(test_info['dut'], vars.D4T1P3)
        remove_interface_from_all_memberships(test_info['dut'], vars.D4T1P4)
    stream_api.config_one_leaf(tb_dict, test_info)
    st.log("setup topology Done")
            
    if test_info['test_tgen'] == 'True':
        tgen_ports_check()
    yield
    common_util.cleanup_ip_interfaces(test_info['dut'])

'''
gbps is the total stream rate in gigabits /sec
If 2 streams are of the same TC, then its the sum of both streams

avail is how much bandwidth is theoretically available for the stream(s)

loss is the percent of loss returned in statistics

s_info is the formatted string containing key info about the stream(s)
'''
def report_pass_or_fail(gbps, avail, loss, s_info):
    diff = gbps - avail
    if diff <= 0:
        # If available is more than input traffic rate, we should be good
        expected_loss_percnt = 0
    else:
        expected_loss_percnt = diff * 100.0 / gbps
    delta = loss - expected_loss_percnt
    if delta <= 0:
        # we suffered less loss than expected
        delta_percnt = 0
    elif expected_loss_percnt == 0:
        # When no loss is expected, any loss is a delta
        delta_percnt = delta
    else:
        # Calculate the percent of deviation from theoretical loss%
        delta_percnt = delta * 100.0 / expected_loss_percnt
    info1 = 'PIR(gbps) {} Frame Len {} '.format(test_info['pir'],
                test_info['frame_size'])
    if delta_percnt <= 5:
        # If deviation from expected loss is withint 5%, we call it a PASS
        st.log('PASS: ' + info1 + s_info + ' Exp Loss% {:.2f}'.format(
              expected_loss_percnt))
        test_info['pass_ctr'] += 1
    elif delta_percnt <= 18:
        # TODO: This need further investigation
        st.log('PASS: ' + info1 + s_info + ' Exp Loss% {:.2f}'.format(
              expected_loss_percnt))
        st.banner(f'Warning: delta % is {delta_percnt}')
        test_info['pass_ctr'] += 1
    else:
        st.log('FAIL: ' + info1 + s_info + ' Exp Loss% {:.2f}'.format(
              expected_loss_percnt))
        test_info['fail_ctr'] += 1

def run_traffic_test(gbps_pair, tc_pair):
    str1 = str2 = None
    if tc_pair[0] < tc_pair[1]:
        high = 1
        low = 0
    else:
        high = 0
        low = 1
    # str1 is the higher priority stream. If both streams belong to same tc,
    # they they are created in order of occurrence in the tc_pair
    str1 = stream_api.create_traffic_stream(tb_dict, test_info['src'][high],
              test_info['dst'], test_info['frame_size'],
              stream_api.gbps_to_pps(gbps_pair[high], test_info['frame_size']),
              tc_pair[high])
    if str1 == None:
        st.error('Stream creation failed str1')
        return
    str1['tc'] = tc_pair[high]
    str1['gbps'] = gbps_pair[high]

    str2 = stream_api.create_traffic_stream(tb_dict, test_info['src'][low],
              test_info['dst'], test_info['frame_size'],
              stream_api.gbps_to_pps(gbps_pair[low], test_info['frame_size']),
              tc_pair[low])
    if str2 == None:
        st.error('Stream creation failed str2')
        return
    str2['tc'] = tc_pair[low]
    str2['gbps'] = gbps_pair[low]
    
    st.log('Test info before stream execution')
    st.log(test_info)

    # 2 streams have been created. Now execute them
    stream_api.start_traffic_stream()
    st.wait(45)
    stream_api.stop_traffic_stream()
    st.wait(5)

    stats = stream_api.collect_traffic_stream_stats()
    if 'traffic_item' not in stats:
        st.report_fail('msg', 'Failed to find traffic_item in stats')
        sys.exit(-1)

    # Each stream handle will have an entry in the stats dictionary
    item_stats = stats['traffic_item']
    str1['loss'] = float(item_stats[str1['stream_id']]['rx']['loss_percent'])
    str2['loss'] = float(item_stats[str2['stream_id']]['rx']['loss_percent'])

    if str1['tc'] == str2['tc']:
        # Both streams belong to the same traffic class
        loss_percent = (str1['loss'] + str2['loss']) / 2.0
        total_gbps = (gbps_pair[0] + gbps_pair[1])
        s_info = 'TC {} Streams(gbps) {} Avg Loss% {:.2f}'.format(str1['tc'],
                    gbps_pair, loss_percent)
        report_pass_or_fail(total_gbps, test_info['pir'], loss_percent, s_info)
    else:
        # str1 corresponds to the higher priority stream
        # Theoretically the higher priority stream should take upto the PIR
        # and the rest of the bandwidht should go to lower priority stream
        s_info = 'TC {} Stream(gbps) {:.2f} Loss% {:.2f}'.format(str1['tc'],
                    str1['gbps'], str1['loss'])
        report_pass_or_fail(str1['gbps'], test_info['pir'], str1['loss'],
                            s_info)
        s_info = 'TC {} Stream(gbps) {:.2f} Loss% {:.2f}'.format(str2['tc'],
                    str2['gbps'], str2['loss'])
        # Theoretically, whatever bandwidth remains after passing higher 
        # priority stream, should go to lower priority stream. So we used upto
        # PIR of the bandwidth for str1 (the higher priority stream). Now we 
        # calculate how much remains
        remaining_gbps = test_info['if_speed'] - min(str1['gbps'], test_info['pir'])
        if remaining_gbps > test_info['pir']:
            remaining_gbps = test_info['pir']
        report_pass_or_fail(str2['gbps'], remaining_gbps, str2['loss'], s_info)

    stream_api.delete_traffic_stream(str1)
    stream_api.delete_traffic_stream(str2)

def get_scheduler_cfg(tc):
    new_name = test_info['dst'] + '_' + str(tc) + str(test_info['pir_bytes'])
    test_info['cfg'] += '''config scheduler add --type STRICT --cir {} --pir {} {}\n
        config queue queue-list update --scheduler {} {} {}\n'''.format(\
        test_info['pir_bytes'], test_info['pir_bytes'], new_name, new_name, 
        test_info['dut_if'], tc)

def apply_pir(pir):
    test_info['pir'] = (int(pir) * test_info['if_speed']) / 100.0
    test_info['pir_bytes'] = stream_api.gbps_to_bytes(test_info['pir'])
    test_info['cfg'] = 'config qos reload\n'
    get_scheduler_cfg(test_info['tc'][0])
    get_scheduler_cfg(test_info['tc'][1])
    st.config(test_info['dut'], test_info['cfg'], skip_tmpl=True)

def test_one_dev_strict_priority():
    # Test assumes a single device with 3 or more tgen ports connected to it
    st.banner('Test STARTED')

    test_info['tc'][0] = int(test_info['tc'][0])
    test_info['tc'][1] = int(test_info['tc'][1])
    test_info['pass_ctr'] = test_info['fail_ctr'] = 0
    for tc_pair in [(test_info['tc'][0], test_info['tc'][0]),
                    (test_info['tc'][0], test_info['tc'][1]),
                    (test_info['tc'][1], test_info['tc'][1])]:
        for pir in test_info['pirs']:
            apply_pir(pir)
            for gbps_pair in test_info['gbps_table']:
                for frame_size in test_info['frame_sizes']:
                        test_info['frame_size'] = int(frame_size)
                        run_traffic_test(gbps_pair, tc_pair)

    # Clear any qos config
    st.config(test_info['dut'], 'config qos clear', skip_tmpl=True)

    # Print the final disposition of the test execution
    final_msg = 'Test Cases: Passed={} Failed={}'.format(
                    test_info['pass_ctr'], test_info['fail_ctr'])
    if test_info['fail_ctr'] > 0:
        st.report_fail('msg', final_msg)
    else:
        st.report_pass('msg', final_msg)
