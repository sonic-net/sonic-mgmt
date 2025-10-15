import os
import re
import yaml
import pytest
import threading
import paramiko
from scp import SCPClient
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac_obj
import apis.switching.portchannel as pc_obj
from spytest.tgen.tg import tgen_obj_dict
from spytest.tgen import tg
import vxlan_helper as vxlan_obj
import ipaddress
import apis.system.interface as intf_obj
import apis.system.basic as basic_obj
import apis.system.reboot as reboot_obj
from spytest.utils import poll_wait
from copy import deepcopy
import json
import pdb
import time
from itertools import combinations

from utilities.utils import get_intf_short_name

'''
This is to configure the config from cnest_solution_base_config.yaml and proceed to the testcases. 
./bin/spytest --testbed /data/cnest_solution_topo_hw_cluster3.yaml --device-feature-group master --module-init-max-timeout=28000 --tc-max-timeout=28000 /data/tests/cisco/tortuga/solution/test_cnest_solution.py --skip-init-checks --skip-init-config --logs-path /data/run_logs/load_config_30 --env "input_file=cnest_solution_input_file.yaml" --env "tb_cfg_file=cnest_solution_base_config.yaml"

This is to skip base config, use existing configuration the devices and proceed to the testcases. 
./bin/spytest --testbed /data/cnest_solution_topo_hw_cluster3.yaml --device-feature-group master --module-init-max-timeout=28000 --tc-max-timeout=28000 /data/tests/cisco/tortuga/solution/test_cnest_solution.py --skip-init-checks --skip-init-config --logs-path /data/run_logs/load_config_30 --env "input_file=cnest_solution_input_file.yaml" --env "tb_cfg_file=cnest_solution_base_config.yaml" --env "skip_cfg=True"

Author = Lenny Dontuboyina <ldontubo@cisco.com>
'''

@pytest.fixture(scope="module", autouse=True)
def initialize_variables():
    global vars, nodes, test_cfg, inputs_file, config_dict, topo_dict, g_res
    g_res = None
    inputs_file = st.getenv('input_file', None)

    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + inputs_file) as f:
        test_cfg = yaml.load(f, Loader=yaml.FullLoader)
    test_cfg['tb_cfg_file'] = st.getenv('tb_cfg_file', None)
    with open(dir_path + '/' + test_cfg['tb_cfg_file']) as c:
        config_dict = yaml.load(c, Loader=yaml.FullLoader)

    test_cfg['nodes'] = {'host': [], 'leaf': [], 'spine': [], 'be_leaf': [], 'fe_leaf': [], 'vast_leaf': [], 'mgmt_leaf': [], 'all': []}
    for dut in st.get_dut_names():
        if 'host' in dut:
            test_cfg['nodes']['host'].append(dut)
        if 'leaf' in dut:
            test_cfg['nodes']['leaf'].append(dut)
        if 'spine' in dut:
            test_cfg['nodes']['spine'].append(dut)
        if dut in ['leaf1','leaf2','leaf3','leaf4']:
            test_cfg['nodes']['be_leaf'].append(dut)
        if dut in ['leaf5','leaf6']:
            test_cfg['nodes']['fe_leaf'].append(dut)
        if dut in ['leaf7','leaf8']:
            test_cfg['nodes']['mgmt_leaf'].append(dut)
        if dut in ['leaf9','leaf10']:
            test_cfg['nodes']['vast_leaf'].append(dut)
        test_cfg['nodes']['all'].append(dut)
    if not test_cfg.get('testcases'): 
        test_cfg['testcases'] = dict()
    vars = st.get_testbed_vars()
    nodes = st.get_dut_names()
    
    # The following will be changed once found the method to get sys.argv of --testbed from command line. 
    # Currently sys.argv is getting modified and unable to get --testbed argument
    # Please consult Lenny Dontuboyina for more information
    tb_file = '/data/cnest_solution_topo_hw_cluster3.yaml'
    new_tb_file = '/data/filtered_topo.yaml'
    string_to_omit = '!include'
    with open(tb_file, 'r') as f:
        lines = f.readlines()
    filtered_lines = [line for line in lines if string_to_omit not in line]
    with open(new_tb_file, 'w') as f:
        f.writelines(filtered_lines)
    with open(new_tb_file) as c:
        topo_dict = yaml.load(c, Loader=yaml.FullLoader)
    os.system("rm /data/filtered_topo.yaml")

@pytest.fixture(scope="module", autouse=True)
def copy_default_config_db():
    cmd = "sudo cp /etc/sonic/config_db.json config_db.json.orig"
    for dut in st.get_dut_names():
        if 'leaf' in dut or 'spine' in dut:
            st.config(dut, cmd, skip_error_check=True)

@pytest.fixture(scope="function", autouse=True)
def check_for_cores(request):
    st.banner("Checking cores will done at the end of the testcase and fail the testcase if any cores present")
    yield
    cores = vxlan_obj.check_core()
    if cores:
        st.banner("Core was generated during the test, Core file is copied and failing the test")
        st.report_fail("test_case_failed")

@pytest.fixture(scope="function", autouse=False)
def pause_run(request):
    pause_before = st.getenv('pause_before', None)
    if pause_before == request.node.name or \
        pause_before == 'all':
        value = raw_input("Press return to continue...")

    yield
    pause_after = st.getenv('pause_after', None)
    if pause_after == request.node.name or \
        pause_after == 'all':
        value = raw_input("Press return to continue...")

def get_tc_params(tc_id):
    if tc_id not in test_cfg['testcases'].keys():
        test_cfg['testcases'][tc_id] = dict()
    return test_cfg['testcases'][tc_id]

def link_flap(node, link, start_delay=0):
    '''
    This is a helper function to perform a link flap
    '''
    st.log('Performing link flap on {}, interface: {}'.format(node, link))
    if start_delay:
        st.wait(start_delay)
    st.config(node, "sudo config interface shutdown {}".format(link))
    st.wait(5)
    st.config(node, "sudo config interface startup {}".format(link))
    st.wait(15)

def config_sonic_vty(node, sonic_cfg, vty_cfg):
    # This is a helper function to combine sonic and vty configs and push
    st.log("Configuring Sonic configuration on DUT {}".format(node))
    vxlan_obj.config_dut(node, 'sonic', sonic_cfg)
    st.log("Configuring FRR configuration on DUT {}".format(node))
    vxlan_obj.config_dut(node, 'bgp', vty_cfg)
    st.banner("Configuring SONIC and FRR on DUT {} is successfully done".format(node))
    
def static_config_push(config_file):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    st.banner("CONFIGURING DUTS")
    threads = list()
    with open(dir_path + '/' + config_file) as c:
        config_dict = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_dict.items():
            st.log("Pushing SONIC and VTYSH Configuration onto DUT {}".format(node))
            sonic_cfg = config['sonic']['config']
            vty_cfg = config['bgp']['config']
            thread = threading.Thread(target=config_sonic_vty, args=(node, sonic_cfg, vty_cfg), name="static_cfg_thread_{}".format(node))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
            st.banner('Thread {} completed'.format(thread.name))
    st.log("Pushing Configuration is done onto all DUTs")

def report_result(result, tc_id='', rc_msg=''):
    if result:
        st.banner('Testcase: {} :: Result: Pass'.format(tc_id))
        st.report_pass('test_case_passed')
    else:
        st.banner('Testcase: {} :: Result: Fail'.format(tc_id))
        st.banner('Testcase: {} :: Diags: {}'.format(tc_id, rc_msg))
        st.report_fail("test_case_failed")

def get_cli_out():
    sonic_cmds = ["docker ps -a", "show vlan brief", "show interface status", "show mac", "show arp","show vxlan tunnel",
            "show vxlan remotevtep", "show vxlan vlanvnimap","show vxlan vrfvnimap", "show vxlan counters",
            "show vxlan interface", "show vxlan remotevni all"]
    vtysh_cmds = ["show bgp summary","show bgp evpn summary", "show evpn vni detail", "show bgp l2vpn evpn",
            "show bgp l2vpn evpn route", "show ipv6 route vrf all"]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            st.log("Dumping Sonic show outputs from DUT: {}".format(dut))
            for cmd in sonic_cmds:
                output = st.show(dut, cmd, skip_tmpl=True)
                st.log(output)
            st.log("Dumping FRR/VTYSH show outputs from DUT: {}".format(dut))
            for cmd in vtysh_cmds:
                output = st.show(dut, cmd, type='vtysh', skip_tmpl=True)
                st.log(output)

def run_ssh_cmd(host, username, password, command):
    """
    Executes a command on a remote host using SSH.

    :param host: IP address or hostname of the remote host.
    :param username: SSH username.
    :param password: SSH password.
    :param command: Command to execute on the remote host.
    :return: Output of the command execution.
    """
    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to the remote host
        st.log("Connecting to host {}".format(host))
        ssh.connect(hostname=host, port=22, username=username, password=password)

        # Execute the command
        st.log("Executing command: {}".format(command))
        stdin, stdout, stderr = ssh.exec_command(command)

        # Read the output and error
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')

        # Close the SSH connection
        ssh.close()

        if error:
            raise Exception("Error executing command: {}".format(error))
        return output
    except Exception as e:
        st.log("Failed to execute command on host {}: {}".format(host, e))
        return None

def parse_iperf_output(iperf_output):
    """
    Parses the iperf output and compares the GBytes values from the sender and receiver lines.

    :param iperf_output: The raw iperf output as a string.
    :return: A dictionary with sender and receiver GBytes values and the comparison result.
    """
    try:
        # Extract the GBytes values for sender and receiver using regex
        st.log('IPERF3 Comparision checking....')
        sender_match = re.search(r"\[.*\]\s+.*\s+sec\s+(\d+(\.\d+)?)\s+GBytes\s+.*\s+sender", iperf_output)
        receiver_match = re.search(r"\[.*\]\s+.*\s+sec\s+(\d+(\.\d+)?)\s+GBytes\s+.*\s+receiver", iperf_output)

        if sender_match and receiver_match:
            sender_gbytes = float(sender_match.group(1))
            receiver_gbytes = float(receiver_match.group(1))

            # Compare the GBytes values
            if (sender_gbytes - receiver_gbytes) / sender_gbytes <= 0.01:
                st.log('IPERF3 Comparision check passed with Sender GBytes: {} and Receiver GBytes: {} '.format(sender_gbytes, receiver_gbytes))
                comparison_result = "Pass"
            else:
                st.log('IPERF3 Comparision check failed with Sender GBytes: {} and Receiver GBytes: {} '.format(sender_gbytes, receiver_gbytes))
                comparison_result = "Fail"
            return (comparison_result)
        else:
            st.log('IPERF3 Comparision checking errored out as parsing failed....')
            return('Fail')
    except Exception as e:
        st.error("Encountered exception error: \n {}".format(e))
        return('Fail')

def noshut_del_static(host, username, password, ens_intf, dest_ip, unshut=False):
    '''
    This helper will unshut the ens interface (ens_intf) and delete the static route to dest_ip.
    Unshut happens only if the unshut flag is True
    '''
    try:
        if unshut:
            noshut_cmd = "sudo ifconfig {} up".format(ens_intf)
            run_ssh_cmd(host, username, password, noshut_cmd)
        static_cmd = 'sudo ip route del {}'.format(dest_ip)
        st.wait(5)
        run_ssh_cmd(host, username, password, static_cmd)
        rt_cmd = 'route -n'
        route_output = run_ssh_cmd(host, username, password, rt_cmd)
        st.log('ROUTE OUTPUT after deleting the static route\n {}'.format(route_output))
    except Exception as e:
        st.error('Unable to un-shutdown and configure as {}'.format(e))

def link_flap_on_host(host, username, password, ens_intf):
    '''
    This is a helper function to flap a port on ubuntu host
    '''
    try:
        st.log('Shutting down and un-shutting down ens port {} on ubuntu host {}'.format(ens_intf, host))
        down_cmd = 'sudo ifconfig {} down'.format(ens_intf)
        up_cmd = 'sudo ifconfig {} up'.format(ens_intf)
        st.wait(20) # This is to allow trafffic to go through before the port flap
        op = run_ssh_cmd(host, username, password, down_cmd)
        st.wait(10)
        op = run_ssh_cmd(host, username, password, up_cmd)
    except Exception as e:
        st.error('Unable to flap the port {} on host {} as {}'.format(host, ens_intf, e))

def shut_add_static(host, username, password, dest_ip, local_intf, local_ip, shut=False):
    '''
    This helper will shutdown interface with dest_ip and add static route and return the
    local ens interafce correspoding to dest_ip_subnet. If shut flag is False, it doesnt shutdown the interface
    '''
    ens_intf = None
    try:
        m = re.search(r"(\d+\.\d+\.\d+)\.\d+", dest_ip)
        command = "sudo ifconfig | grep -B 1 {}".format(m.group(1))
        op = run_ssh_cmd(host, username, password, command)
        if_pattern = r"^\s*(\S+):"
        # Extract the interface name
        for line in op.split('\n'):
            match = re.match(if_pattern, line)
            if match:
                ens_intf = match.group(1)
        #Shutdown only if shut flag is True
        if shut:
            shut_cmd = 'sudo ifconfig {} down'.format(ens_intf)
            run_ssh_cmd(host, username, password, shut_cmd)
            st.wait(5)
        gw_ip = re.findall(r"^\d+\.\d+\.\d+\.", local_ip)[0]+'1'
        static_cmd = 'sudo ip route add {} via {} dev {}'.format(dest_ip, gw_ip, local_intf)
        run_ssh_cmd(host, username, password, static_cmd)
        rt_cmd = 'route -n'
        route_output = run_ssh_cmd(host, username, password, rt_cmd)
        st.log('ROUTE OUTPUT after adding the static route \n {}'.format(route_output))
    except Exception as e:
        st.error('Unable to shutdown and configure as {}'.format(e))

    return(ens_intf)

def check_iperf(server_endpoint, client_endpoint, traffic_endpoints, server_port=5201, duration=10):
    """
    Checks iperf performance between two hosts.
    :param server_host: IP address or hostname of the iperf server.
    :param server_username: SSH username for the iperf server.
    :param server_password: SSH password for the iperf server.
    :param client_host: IP address or hostname of the iperf client.
    :param client_username: SSH username for the iperf client.
    :param client_password: SSH password for the iperf client.
    :param server_port: Port on which the iperf server is listening (default: 5201).
    :param duration: Duration of the iperf test in seconds (default: 10).
    :return: Output of the iperf test.
    """

    try:
        #Getting IPERF3 details
        server_host = traffic_endpoints[server_endpoint]['host_ip']
        server_username = st.get_username(traffic_endpoints[server_endpoint]['host_name'])
        server_password = st.get_password(traffic_endpoints[server_endpoint]['host_name'])
        s_ip = traffic_endpoints[server_endpoint]['intf_ip']
        s_intf = traffic_endpoints[server_endpoint]['intf']
        client_host = traffic_endpoints[client_endpoint]['host_ip']
        client_username = st.get_username(traffic_endpoints[client_endpoint]['host_name'])
        client_password = st.get_password(traffic_endpoints[client_endpoint]['host_name'])
        c_ip = traffic_endpoints[client_endpoint]['intf_ip']
        c_intf = traffic_endpoints[client_endpoint]['intf']
        s_subnet = ipaddress.ip_network(u"{}/24".format(s_ip), strict=False)
        c_subnet = ipaddress.ip_network(u"{}/24".format(c_ip), strict=False)
        s_hostname = traffic_endpoints[server_endpoint]['host_name']
        c_hostname = traffic_endpoints[client_endpoint]['host_name']

        if c_subnet != s_subnet or s_hostname != c_hostname:
            st.log('Here are host {} s subnet {} and {} c subnet {} '.format(s_hostname, s_subnet, c_hostname, c_subnet))
            ens_on_server = shut_add_static(server_host, server_username, server_password, c_ip, s_intf, s_ip)
            ens_on_client = shut_add_static(client_host, client_username, client_password, s_ip, c_intf, c_ip)
        else:
            st.log('Host {} side s subnet: {} and {} c subnet: {} are same, So no route add'.format(s_hostname, s_subnet, c_hostname, c_subnet))
        # Start iperf server on the server host
        server_ifconfig_stats_pre = run_ssh_cmd(server_host, server_username, server_password,'ifconfig {}'.format(s_intf))
        #server_command = "iperf3 -s -p {} --bind {} --bind-dev {} -D".format(server_port, s_ip, s_intf)  # Run iperf server in daemon mode
        server_command = "iperf3 -s -p {} --bind {} -D".format(server_port, s_ip)  # Run iperf server in daemon mode
        st.log("Starting iperf server on {}".format(server_host))
        run_ssh_cmd(server_host, server_username, server_password, server_command)

        # Run iperf client on the client host
        client_ifconfig_stats_pre = run_ssh_cmd(client_host, client_username, client_password,'ifconfig {}'.format(c_intf))
        #client_command = "iperf3 -c {} -p {} -t {} --bind {} --bind-dev {}".format(s_ip, server_port, duration, c_ip, c_intf)
        client_command = "iperf3 -c {} -p {} -t {} --bind {}".format(s_ip, server_port, duration, c_ip)
        st.log("Running iperf client on {}".format(client_host))
        iperf_output = run_ssh_cmd(client_host, client_username, client_password, client_command)

        # Stop iperf server on the server host
        stop_server_command = "pkill -f 'iperf3 -s'"
        st.log("Stopping iperf server on {}".format(server_host))
        run_ssh_cmd(server_host, server_username, server_password, stop_server_command)

        if c_subnet != s_subnet or s_hostname != c_hostname:
            st.log('Host {} side s subnet: {} and {} c subnet: {}'.format(s_hostname, s_subnet, c_hostname, c_subnet))
            #Un-Shutting same subnet interfaces on servers/client and un-configuring static routes.
            noshut_del_static(server_host, server_username, server_password, ens_on_server, c_ip)
            noshut_del_static(client_host, client_username, client_password, ens_on_client, s_ip)
        else:
            st.log('Host {} side s subnet: {} and {} c subnet: {} are same, So no deleting route'.format(s_hostname, s_subnet, c_hostname, c_subnet))

        # getting host side ifconfig stats after perf test
        server_ifconfig_stats_post = run_ssh_cmd(server_host, server_username, server_password,'ifconfig {}'.format(s_intf))
        client_ifconfig_stats_post = run_ssh_cmd(client_host, client_username, client_password,'ifconfig {}'.format(c_intf))

        st.log('Here are the ifconfig stats Before perf test: \n {} \n {} \n After perf test: \n {} \n {}'.format(server_ifconfig_stats_pre, client_ifconfig_stats_pre, server_ifconfig_stats_post, client_ifconfig_stats_post, client_ifconfig_stats_post))

        #Parse iperf out to determine the result and return result Pass or Fail.
        result = parse_iperf_output(iperf_output)

        st.log('HERE IS THE IPERF3 OUTPUT from CLIENT side {}'.format(iperf_output))
        # Return the iperf result
        return result

    except Exception as e:
        #Cleaning up incase if iperf errored out
        if c_subnet != s_subnet or s_hostname != c_hostname:
            st.log('EXCEPTION BLOCK- Host {} side s subnet: {} and {} c subnet: {}'.format(s_hostname, s_subnet, c_hostname, c_subnet))
            #Un-Shutting same subnet interfaces on servers/client and un-configuring static routes.
            noshut_del_static(server_host, server_username, server_password, ens_on_server, c_ip)
            noshut_del_static(client_host, client_username, client_password, ens_on_client, s_ip)
        else:
            st.log('Exception block - Host {} side s subnet: {} and {} c subnet: {} are same, So no deleting route'.format(s_hostname, s_subnet, c_hostname, c_subnet))
        st.error("Failed to check iperf between {} and {} due to error: \n {}".format(server_host, client_host, e))
        return 'Fail'

def get_vlan(dut, interface, cfg_dict):
    '''
    This is a helper function to get vlan, given node and interface from config dict
    '''
    vlan_id = None
    try:
        for node, cfg in cfg_dict.items():
            if node == dut:
                config = cfg['sonic']['config'].split('\n')
                for line in config:
                    vlan_id_match = re.search(r"sudo config vlan member add -u (\d+) {}".format(interface), line)
                    if vlan_id_match:
                        vlan_id = vlan_id_match.group(1)
                        return int(vlan_id)
    except Exception as err:
        st.error("Unexpected error in get_vlan: {}".format(err))
        st.log('Unable to get vlan id from base configuration for the interface {} on node {}'.format(interface, dut))
    return vlan_id

def find_vlan_members(dut, vlan_id, cfg_dict):
    '''
    This is a helper function to get vlan members of a vlan_id
    '''
    vlan_mem_list = []
    try:
        for node, cfg in cfg_dict.items():
            if node == dut:
                config = cfg['sonic']['config'].split('\n')
                for line in config:
                    vlan_id_match = re.search(r"sudo config vlan member add -u {} (\w+)".format(vlan_id), line)
                    if vlan_id_match:
                        intf = vlan_id_match.group(1)
                        vlan_mem_list.append(intf)
    except Exception as err:
        st.error("Unexpected error in find_vlan_members: {}".format(err))
        st.log('Unable to get vlan members from vlan id from base configuration for the vlan {} on node {}'.format(vlan_id, dut))
    st.log('Here is the vlan {} and member list {}'.format(vlan_id, vlan_mem_list))
    return vlan_mem_list

def find_vnivrfip(dut, vlan_id, cfg_dict):
    '''
    This is a helper function to get vni, vrf and svi ip for a specific vlan
    '''
    vnivrfip_dict = {}
    try:
        for node, cfg in cfg_dict.items():
            if node == dut:
                config = cfg['sonic']['config'].split('\n')
                for line in config:
                    if re.search(r"sudo config vxlan map add VXLAN {} (\d+)".format(vlan_id), line):
                        vni_match = re.search(r"sudo config vxlan map add VXLAN {} (\d+)".format(vlan_id), line)
                        vni = vni_match.group(1)
                        vnivrfip_dict['vni'] = vni
                    elif re.search(r"sudo config interface vrf bind Vlan{} (\w+)".format(vlan_id), line):
                        vrf_match = re.search(r"sudo config interface vrf bind Vlan{} (\w+)".format(vlan_id), line)
                        vrf = vrf_match.group(1)
                        vnivrfip_dict['vrf'] = vrf
                    elif re.search(r"sudo config interface ip add Vlan{} ([\d\.\/]+)".format(vlan_id), line):
                        vlan_ip_match = re.search(r"sudo config interface ip add Vlan{} ([\d\.\/]+)".format(vlan_id), line)
                        ip = vlan_ip_match.group(1)
                        vnivrfip_dict['ip'] = ip
    except Exception as err:
        st.error("Unexpected error in find_vnivrfip: {}".format(err))
        st.log('Unable to get vni, vrf, ip from vlan id from base configuration for the vlan {} on node {}'.format(vlan_id, dut))
    return vnivrfip_dict

def get_expected_vrfvni_map(dut, cfg_dict):
    st.log("Fetching expected vrfvni_map on dut {} from base config".format(dut))
    ret_list = []
    try:
        for node, cfg in cfg_dict.items():
            if node == dut:
                config = cfg['sonic']['config'].split('\n')
                for line in config:
                    vrf_match = re.search(r"sudo config vrf add_vrf_vni_map (\w+) (\d+)", line)
                    if vrf_match:
                        vrfname = vrf_match.group(1)
                        vni_id = vrf_match.group(2)
                        mapping_dict = {'vni': vni_id, 'vrf': vrfname}
                        ret_list.append(mapping_dict)
        return ret_list
    except Exception as err:
        st.error("Unexpected error in get_expected_vrfvni_map: {}".format(err))
    return ret_list

def get_expected_vlanvni_map(dut, cfg_dict):
    st.log("Fetching expected vlanvni_map on dut {} from base config".format(dut))
    ret_list = []
    try:
        for node, cfg in cfg_dict.items():
            if node == dut:
                config = cfg['sonic']['config'].split('\n')
                for line in config:
                    vlan_match = re.search(r"sudo config vlan add (\d+)", line)
                    if vlan_match:
                        vlan_id = vlan_match.group(1)
                        mapping_dict = {'vlan': 'Vlan{}'.format(vlan_id)}
                        for linein in config:
                            vni_match = re.search(r"sudo config vxlan map add VXLAN {} (\d+)".format(vlan_id), linein)
                            if vni_match:
                                mapping_dict['vni'] = vni_match.group(1)
                                ret_list.append(mapping_dict)
        return ret_list
    except Exception as err:
        st.error("Unexpected error in get_expected_vlanvni_map: {}".format(err))
    return ret_list

def get_expected_remotevteps(dut, cfg_dict):
    st.log("Fetching expected remote vteps on dut {} from base config".format(dut))
    ret_list = []
    try:
        for node, cfg in cfg_dict.items():
            if node == dut:
                config_sonic = cfg['sonic']['config'].split('\n')
                config_vty = cfg['bgp']['config'].split('\n')
                for line in config_sonic:
                    srcvtep = re.search(r"sudo config vxlan add VXLAN ([\d:]+)", line)
                    if srcvtep:
                        src_vtep = srcvtep.group(1)
                        for linein in config_vty:
                            dstvtep = re.search(r"neighbor ([\d:]+) peer-group OVERLAY", linein)
                            if dstvtep:
                                remotevtep_dict = dict()
                                dst_vtep = dstvtep.group(1)
                                remotevtep_dict['src_vtep'] = src_vtep
                                remotevtep_dict['dst_vtep'] = dst_vtep
                                remotevtep_dict['tun_src'] = 'EVPN'
                                remotevtep_dict['tun_status'] = 'oper_up'
                                ret_list.append(remotevtep_dict)
        return ret_list
    except Exception as err:
        st.error("Unexpected error in get_expected_remotevteps: {}".format(err))
    return ret_list

def verify_vxlan_states(node, config_dict, mapping_type):
    '''
    This helper function is to check vxlan states on lead nodes.It checks vlan/vni, vrf/vni and
    remote vteps.
    '''
    try:
        st.log('Verifying vxlan states on DUT {} for {}'.format(node, mapping_type))
        if mapping_type == "vlanvni":
            exp_data = get_expected_vlanvni_map(node, config_dict)
            vxlan_obj.verify_vxlan_vlanvnimap(node, exp_data)
        elif mapping_type == "vrfvni":
            exp_data = get_expected_vrfvni_map(node, config_dict)
            vxlan_obj.verify_vxlan_vrfvnimap(node, exp_data)
        elif mapping_type == "remotevtep":
            exp_data = get_expected_remotevteps(node, config_dict)
            vxlan_obj.verify_vxlan_remotevtep(node, exp_data)
        st.log('{} mapping on {} is correct'.format(mapping_type, node))
        return True, ''
    except Exception as err:
        msg = 'Verify {} mapping on {}: Fail\n{}\n'.format(mapping_type, node, err)
        st.log(msg)
        return False, msg

def sonic_clear_counters(nodes):
    '''
    This is to clear sonic counters
    '''
    for node in nodes:
        st.show(node, " sonic-clear counters" , skip_tmpl=True)
        st.show(node, " sonic-clear tunnelcounters" , skip_tmpl=True)

def verify_data_plane(traffic_endpoints, endpoint_tupl, node_list, ping=False, iperf=True, perftest=False, test_time=10, tolerance=1):
    '''
    This helper function is to verify data plane on duts using all to all ping ping test, bidirectional iperf, and PERFTEST.
    '''
    msgs = ''
    result = True
    global g_res
    g_res = True #setting global variable for thread return value check

    if ping:
        try:
            # Verify ping traffic
            st.log('Verifying ping test between all hosts between nodes: {}'.format(node_list))
            if not verify_ping_traffic(traffic_endpoints):
                msg = 'All to all ping test failed in the testcase'
                st.log(msg)
                msgs += msg
                result = False
                g_res = False
        except Exception as err:
            msg = 'ALL TO ALL ping test verification is failed with :\n{}\n'.format(err)
            st.log(msg)
            msgs += msg
            result = False
            g_res = False
    else:
        st.log('All to all ping test is by-passed')

    if iperf:
        try:
            #Making iperf bidirectional
            st.log('Verifying iperf test between endpoints: {}'.format(endpoint_tupl))
            for p1, p2 in [endpoint_tupl, tuple(reversed(endpoint_tupl))]:
                srv_endpoint = p1
                clnt_endpoint = p2
                st.log("Checking iPERF3 test with server {} and client {}".format(srv_endpoint, clnt_endpoint))
                sonic_clear_counters(node_list)
                st.wait(10)
                if not check_iperf(srv_endpoint, clnt_endpoint, traffic_endpoints, server_port=5201, duration=test_time):
                    msg = 'Testcase IPERF check failed'
                    st.log(msg)
                    msgs += msg
                    result = False
                    g_res = False
                # Skip verify_interface_stats if srv_endpoint and clnt_endpoint have the same host part
                srv_host = traffic_endpoints[srv_endpoint]['host_name']
                clnt_host = traffic_endpoints[clnt_endpoint]['host_name']
                if srv_host != clnt_host:
                    # verify_interface_stats from srv_endpoint and clnt_endpoint
                    get_show_interface_counters(node_list)
                    if not verify_interface_stats(srv_endpoint, clnt_endpoint, traffic_endpoints, tolerance):
                        msg = 'Interface stats are not within the acceptable range for the Testcase'
                        st.log(msg)
                        msgs += msg
                        result = False
                        g_res = False
                    else:
                        st.log('Interface stats are within the acceptable range for the Testcase')
                else:
                    st.log('Server end point {} and Client end poit {} are on same node'.format(srv_host, clnt_host))
                    st.log('Bypassing verify_interface_stats from srv_endpoint and clnt_endpoint')
        except Exception as err:
            msg = 'Error found while in checking iperf with {}'.format(err)
            st.log(msg)
            msgs += msg
            result = False
            g_res = False
    else:
        st.log('iperf test is by-passed')

    if perftest:
        pass
    else:
        st.log('perftest test is by-passed')

    return(result, msgs)

def verify_control_plane(node, config_dict, mapping_types):
    '''
    This helper function is to verify control plane states on duts.
    '''
    result = True
    summary = ''
    for mapping_type in mapping_types:
        st.log('Checking control plane on the node {}'.format(node))
        success = False
        start_time = time.time()
        while success == False and (time.time() - start_time < 300):
            st.log('Checking vxlan control plane with {} at..... {} on node {}'.format(mapping_type, time.time(), node))
            success, msg = verify_vxlan_states(node, config_dict, mapping_type)
            st.wait(5)
        if not success:
            result = False
            summary += msg
            st.log('Control plane check on the node {} failed with \n {}'.format(node, summary))
    return result, summary

# Function to fetch EndDevice and EndPort details where EndDevice contains 'host'
def construct_traffic_endpoints(topo_dict, test_cfg, node_list):
    '''
        #Example endpt_dict
	endpt_dict = {leaf1:
         {'intf_type': host_int_type,
         'host_ip':host_mgmt_ip,
         'src_ip': host_endpoint_ip,
         'src_int': end_port}
	leaf2:{}}
    '''
    endpt_dict = dict()
    st.log('Constructing traffic end point dictionary for the node list of {}'.format(node_list))
    for leaf_name in node_list:
        interfaces = topo_dict['topology'].get(leaf_name, {}).get('interfaces', {})
        for interface, details in interfaces.items():
            if 'host' in details.get('EndDevice'):
                st.log('Constructing traffic end point dict for interface {} ====> details {} of node: {}'.format(interface, details, leaf_name))
                end_device = details.get('EndDevice')
                end_port = details.get('EndPort')
                host_mgmt_ip = test_cfg['endhosts'][end_device]['mgmt'][1]
                for int_type, detail in test_cfg['endhosts'][end_device].items():
                    if isinstance(detail, list) and detail[0] == end_port:
                        host_endpoint_ip = detail[1]
                        host_int_type = int_type
                        break
                endpt_dict[leaf_name+'_'+end_device+'_'+end_port] = {'intf_type': host_int_type, 
                                                                   'host_ip':host_mgmt_ip, 
                                                                   'intf_ip': host_endpoint_ip, 
                                                                   'intf': end_port,
                                                                   'node_intf': interface,
                                                                   'host_name': end_device}
    st.log('Successfully constructed traffic end points')
    return(endpt_dict)

def perform_all2all_ping(traffic_endpoints, bidir=False):
    st.log('Performing full to full ping test based on end points')
    res = True
    ping_result_dict = dict()
    ping_result_dict['failcount'] = 0
    ping_result_dict['passcount'] = 0
    ping_list = list(combinations(traffic_endpoints.keys(), 2))
    if bidir:
        for src_endpoint,dest_endpoint in ping_list:
            ping_list.append([dest_endpoint, src_endpoint])
    for src_endpoint,dest_endpoint in ping_list:
        hostip = traffic_endpoints[src_endpoint]['host_ip']
        uname = st.get_username(traffic_endpoints[src_endpoint]['host_name'])
        pw = st.get_password(traffic_endpoints[src_endpoint]['host_name'])
        dip = traffic_endpoints[dest_endpoint]['intf_ip']
        sint = traffic_endpoints[src_endpoint]['intf']
        sip = traffic_endpoints[src_endpoint]['intf_ip']
        try:
            pingresultkey = src_endpoint+'->'+dest_endpoint
            ping_result = ping_test(hostip, uname, pw, dip, sint, sip)
            st.banner('Here is the ping result output \n {}'.format(ping_result))
            if ping_result == 'Fail':
                ping_result_dict[pingresultkey] = 'FAIL'
                ping_result_dict['failcount'] += 1
                res_msg = "PING test failed between {} --> {} \n".format(src_endpoint, dest_endpoint)
                st.log(res_msg)
                res = False
            else:
                #ping_result_dict[pingresultkey] = 'PASS'
                ping_result_dict['passcount'] += 1
        except Exception as e:
            res_msg = "PING test failed between {} --> {} due to \n {}".format(src_endpoint, dest_endpoint, e)
            st.log(res_msg)
            res = False
    st.banner('HERE IS THE PING RESULT SUMMARY' )
    st.log('FAIL COUNT is : {}'.format(ping_result_dict['failcount']))
    st.log('PASS COUNT is : {}'.format(ping_result_dict['passcount']))
    for key, value in ping_result_dict.items():
        if value == 'FAIL':
            st.log('{}:{}'.format(key, value))
    return(res)

def parse_ping_output(ping_output):
    """
    Parses the ping output and determines if the packet loss is less than 60%.

    :param ping_output: The raw ping output as a string.
    :return: "Pass" if packet loss < 60%, otherwise "Fail".
    """
    try:
        # Extract the packet loss percentage using regex
        packet_loss_match = re.search(r"(\d+)% packet loss", ping_output)
        if packet_loss_match:
            packet_loss = int(packet_loss_match.group(1))
            # Check if packet loss is less than 60%
            if packet_loss < 60:
                return "Pass"
            else:
                return "Fail"
        else:
            return "Fail: Unable to parse packet loss percentage."
    except Exception as e:
        return "Error: {}".format(e)

def ping_test(host, username, password, destination_ip, source_interface, source_ip, size=512, count=5):
    """
    Performs a ping test to a destination IP using a specific source interface and source IP.

    :param host: IP address or hostname of the Linux machine.
    :param username: SSH username.
    :param password: SSH password.
    :param destination_ip: Destination IP to ping.
    :param source_interface: Source interface to use for the ping.
    :param source_ip: Source IP to use for the ping.
    :return: Ping command output.
    """
    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        st.log("Connecting host {}".format(host))
        
        # Connect to the Linux machine
        ssh.connect(hostname=host, port=22, username=username, password=password)
        
        st.log("Trying to do PING from host-port-ip {} - {} - {} to destination {}".format(host, source_interface, source_ip, destination_ip))
        # Construct the ping command
        #ping_command = "ping -I {} -s {} -c {} {}".format(source_interface, size, count, destination_ip)
        ping_command = "ping -I {} -s {} -c {} {}".format(source_ip, size, count, destination_ip)
        # Execute the ping command
        stdin, stdout, stderr = ssh.exec_command(ping_command)
        
        # Read the output and error
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        ping_res = parse_ping_output(output) 
        # Close the SSH connection
        ssh.close()
        
        if error:
            raise Exception("Error executing ping command: {}".format(error))
        if not ping_res:
            st.log("PING test failed with output: \n {}".format(output))
        return ping_res
    except Exception as e:
        st.log("Failed to perform ping test: {}".format(e))
        return('Fail')

def verify_ping_traffic(traffic_endpoints):
    '''
    ping test from each end point to all other end points
    '''
    res = True
    res_msg = ''
    st.log('Verifying ping test between traffic end points')
    try:
        perform_all2all_ping(traffic_endpoints, bidir=False)
        st.log('Successfully verified ping all-to-all test')
    except Exception as err:
        res_msg = 'Ping all-to-all test verification is failed with :\n{}\n'.format(err)
        st.log(res_msg)
        res = False
    return(res)

def lookup_traffic_endpoints(tc_dp_tr_ep, traffic_endpoints):
    '''
    This helper function gets end point details based on testcase endpoint 
    '''
    st.log('Look up traffic end points based on testcase data plane requiremenets')
    end_point_list = []
    for ept in tc_dp_tr_ep:
        ept = ept.split(':')
        for key in traffic_endpoints.keys():
            if ept[0] in key:
                if ept[1] == traffic_endpoints[key]['intf_type']:
                    end_point_list.append(key)
                    break
    st.log('test case data plane traffic end points are {}'.format(end_point_list))
    return tuple(end_point_list)

@pytest.fixture(scope="module", autouse=False)
def cnest_base_config():
    if st.getenv('skip_cfg', 'false') == 'false':
        # Push the config
        st.log('STATIC CONFIG PUSH....')
        static_config_push(test_cfg['tb_cfg_file'])

        # Save the configuration for the relevant nodes
        for node in test_cfg['nodes']['leaf'] + test_cfg['nodes']['spine']:
            st.log('Configuration is getting saved....')
            vxlan_obj.config_dut(node, 'sonic', "sudo config save -y")
            vxlan_obj.config_dut(node, "bgp", "do write")
            st.log('Configuration saved ....')

def get_interface_counters(dut, intf, counters):
    cli_output = st.show(dut, "show int counters", skip_tmpl=True)
    parsed_out = st.parse_show(dut, "show int counters",cli_output, "show_interfaces_counters.tmpl")
    ctr_dict = dict()
    for output in parsed_out:
        if output['iface'] == intf:
            for counter in counters:
                counter_uni = output[counter]
                ctr_dict[counter] = int(counter_uni.replace(',',''))
    return(ctr_dict)

def get_show_interface_counters(node_list):
    '''
    This is a helper function to get show interface counters from all nodes
    '''
    for node in node_list:
        cli_output = st.show(node, "show int counters | grep U", skip_tmpl=True)
        st.log('Interface counters: \n {}'.format(cli_output))

def verify_interface_stats(srv_endpoint, clnt_endpoint, traffic_endpoints, tol=1):
    '''
    This is a helper function to get tx/rx interfaces from lead nodes and and verify them 
    by comparing rx_ok, tx_ok counters from those interfaces
    '''
    result = True
    tx_node = clnt_endpoint.split('_')[0]
    tx_node_intf = traffic_endpoints[clnt_endpoint]['node_intf']
    rx_node = srv_endpoint.split('_')[0]
    rx_node_intf = traffic_endpoints[srv_endpoint]['node_intf']
    tx_node_counters = get_interface_counters(tx_node, tx_node_intf, ['rx_ok', 'tx_ok'])
    rx_node_counters = get_interface_counters(rx_node, rx_node_intf, ['rx_ok', 'tx_ok'])

    st.log('Here are the TX node/interface {} {} counters: {} \n RX node/interface {} {} counters: {}'.format(tx_node, tx_node_intf, tx_node_counters, rx_node, rx_node_intf, rx_node_counters))
    try:
        rxnode_drop_percent = (float(tx_node_counters['rx_ok'] - rx_node_counters['tx_ok']) / tx_node_counters['rx_ok']) * 100
        st.log('Traffic Drop or Duplicate percentage for RX node is : {}'.format(round(rxnode_drop_percent, 4)))
        st.log('Legend: Positive value represents Drop, Negetive value represents Duplcaition')
        rxnode_drop_percent = abs(round(rxnode_drop_percent,4))
        st.log('Absolute Traffic Drop or Duplicate percentage for RX node is : {}'.format(rxnode_drop_percent))
        if rxnode_drop_percent > tol:
            st.log('Interface TX counter: {} RX counter: {}'.format(rx_node_counters['tx_ok'], tx_node_counters['rx_ok']))
            result=False
    except Exception as err:
        msg = "Encountered exception while checking interface counters: {}".format(err)
        st.error(msg)
        result= False
    return(result)

def proc_restart_on_node(nodelist, proc_type):
    '''
    This is a helper function to restart process on a nodelist and check docker status
    '''
    doc_count_dict = {}
    g_res = True
    st.log('Here is the node list {} for the the process restart {}'.format(nodelist, proc_type))
    for node in nodelist:
        doc_count_dict[node] = basic_obj.get_and_match_docker_count(node)
        vxlan_obj.config_dut(node,'bgp', 'do write')
        restart_complete = basic_obj.systemctl_restart_service(node, proc_type)
        if not poll_wait(basic_obj.verify_docker_status, 180, node, 'Exited'):
            st.error("Post 'systemctl restart {} on {}', Docker(s) is/are not auto recovered.".format(proc_type,node))
            g_res = False
            report_result(g_res, tc_id, "Docker Status Failed")
        if not poll_wait(basic_obj.get_and_match_docker_count, 180, node, doc_count_dict[node]):
            st.error("Post 'systemctl restart {} on {}', Not all dockers are UP.".format(proc_type, node))
            g_res = False
            report_result(g_res, tc_id, "Docker Status Failed")
        st.log('Successfully restarted the process {} on node {}'.format(proc_type, node))
    st.log('Successfully restarted the process {} on nodes: {}'.format(proc_type, nodelist))

def restore_helper_file(dut):
    '''
    This is a helper function to set the spyte test helper files
    '''
    st.config(dut, "mkdir -p /etc/spytest/remote")
    st.config(dut, "cp /etc/sonic/spytest-helper.py /etc/spytest/remote/spytest-helper.py")
    st.config(dut, "ls -lrt /etc | grep spytest")

def reload_node(nodelist, reload_type):
    '''
    This is a helper function to perform a reload on a node.
    '''
    doc_count_dict = {}
    g_res = True
    st.log('Here is the node list {} for the the reload type of {}'.format(nodelist, reload_type))
    st.wait(15)
    for node in nodelist:
        doc_count_dict[node] = basic_obj.get_and_match_docker_count(node)
        reboot_obj.config_save(node)
        vxlan_obj.config_dut(node,"bgp", "do write")
        if reload_type == 'config':
            status = reboot_obj.config_reload(node)
            if not status:
                st.log("config reload trigger is failed on {}".format(node))
                g_res = False
                report_result(g_res, tc_id, "Config reload is Failed")
        elif reload_type == 'reboot':
            try:
                #status = st.reboot(node, clear_skipped_file=True)
                #cmd = "sudo -s reboot"
                #st.config(node, cmd)
                #st.wait(360)
                reboot_obj.dut_reboot(node)
                restore_helper_file(node)
            except Exception as e:
                st.log("Reboot failed on node {}".format(node))
                g_res = False
                report_result(g_res, tc_id, "Reboot is Failed")
            '''    
            if not status:
                st.log("Reboot trigger is failed on {}".format(node))
                g_res = False
                report_result(g_res, tc_id, "Reboot is Failed")
            '''
        elif reload_type == 'powerfail':
            try:
                st.log("Power-cycle the node: {} ".format(node))
                cmd = "sudo shutdown -r now"
                st.config(node, cmd)
                st.wait(360)
            except Exception as e:
                st.log("Power cycle failed on node {}".format(node))
                g_res = False
                report_result(g_res, tc_id, "Power Cycle is Failed")
        if not poll_wait(basic_obj.verify_docker_status, 180, node, 'Exited'):
            st.error("Post trigger {} on node {}, Docker(s) is/are not auto recovered.".format(reload_type,node))
            g_res = False
            report_result(g_res, tc_id, "Docker Status Failed")
        if not poll_wait(basic_obj.get_and_match_docker_count, 180, node, doc_count_dict[node]):
            st.error("Post trigger {} on {}, Not all dockers are UP.".format(reload_type, node))
            g_res = False
            report_result(g_res, tc_id, "Docker Status Failed")
        st.log('Successfully reloaded the node {} with reload type {}'.format(node, reload_type))
    st.log('Successfully reloaded nodes: {} with reload type: {}'.format(nodelist, reload_type))

def clear_trigger(nodelist, trigger):
    '''
    This is helper function to perform a clean trigger such as clear mac or clear bgp
    '''
    # wait for 15 seconds before trigger
    st.wait(15)
    for node in nodelist:
        if trigger == 'bgp':
            st.log('Executing the trigger {} on node: {}'.format(trigger, node))
            cmd = "do clear bgp *"
            vxlan_obj.config_dut(node, 'bgp', cmd, add=True)
        elif trigger == 'mac':
            st.show(node, "show mac", skip_tmpl=False)
            st.log('Executing the trigger {} on node: {}'.format(trigger, node))
            action = mac_obj.clear_mac(node)
            if action:
                st.log("mac/fdb clear successful on node: {}".format(node))
            else:
                st.log("mac/fdb clear is not successful on node: {}".format(node))
                g_res == False
        st.wait(5)

def addrem_trigger(node, endpoint_tupl, trigger, t_endpoints):
    '''
    This is a helper function to perform add remove configuration such vlan membership
    '''
    st.log('Checking add rem trigger for the node: {} and trigger type: {}'.format(node, trigger))
    st.wait(15)
    if trigger == 'vlan':
        intf = t_endpoints[endpoint_tupl[0]]['node_intf']
        vlan = get_vlan(node, intf, config_dict)
        st.config(node, 'sudo config vlan member del {} {}'.format(vlan, intf))
        st.wait(10)
        st.config(node, 'sudo config vlan member add -u {} {}'.format(vlan, intf))
        st.wait(10)
    elif trigger == 'interrail' or trigger == 'rail':
        intf = t_endpoints[endpoint_tupl[0]]['node_intf']
        vlan = get_vlan(node, intf, config_dict)
        interfaces = find_vlan_members(node, vlan, config_dict)
        vnivrfip_dict = find_vnivrfip(node, vlan, config_dict)
        for cfg in ['del','add']:
            if cfg == 'del':
                for intf in interfaces:
                    st.config(node, 'sudo config vlan member {} {} {}'.format(cfg, vlan, intf))
                st.config(node, 'sudo config vxlan map {} VXLAN {} {}'.format(cfg, vlan, vnivrfip_dict['vni']))
                st.config(node, 'sudo config interface vrf unbind Vlan{}'.format(vlan))
                st.config(node, 'sudo config interface ip rem Vlan{} {}'.format(vlan, vnivrfip_dict['ip']))
                st.config(node, 'sudo config vlan {} {}'.format(cfg, vlan))
                st.wait(10)
            else:
                st.config(node, 'sudo config vlan add {}'.format(vlan))
                for intf in interfaces:
                    st.config(node, 'sudo config vlan member {} -u {} {}'.format(cfg, vlan, intf))
                st.config(node, 'sudo config vxlan map add VXLAN {} {}'.format(vlan, vnivrfip_dict['vni']))
                st.config(node, 'sudo config interface vrf bind Vlan{} {}'.format(vlan, vnivrfip_dict['vrf']))
                st.config(node, 'sudo config interface ip add Vlan{} {}'.format(vlan, vnivrfip_dict['ip']))
                st.wait(10)

def get_all_links_on_node(node, nbr_type, topo_dict):
    '''
    This is a helper function that returns a list of links between node and nbr 
    '''
    links_list = list()
    st.log('Getting all links on {} connected to neighbor type of {}'.format(node, nbr_type))
    all_links = topo_dict['topology'].get(node, {}).get('interfaces', {})
    for link, details in all_links.items():
        if nbr_type in details.get('EndDevice'):
            links_list.append(link)
    return(links_list)

def get_nbr_node(node, local_link):
    '''
    This is a helper function to get a nbr node for a given link and node
    '''
    all_links = topo_dict['topology'].get(node, {}).get('interfaces', {})
    for link, details in all_links.items():
        if link == local_link:
            return(details.get('EndDevice'))
        else:
            return(None)

def get_loaded_link(target_node, links, key='max', direction='tx'):
    '''
    This helper function takes node, links and key such as high, low, random and return link
    '''
    st.log('GETTING ONE LINK BASED ON SELCTION')
    if key == 'random':
        return(links[random.randomint[0,len(links)-1]])
    link_info = {'rx_max':{}, 'rx_min':{},'tx_max':{},'tx_min':{}}
    st.log('Here are the links: {}'.format(links))
    for link in links:
        node_counters = get_interface_counters(target_node, link, ['rx_ok', 'tx_ok'])
        if link_info['rx_max'] == {}:
            link_info['rx_max'] = {'link': link, 'ctr': node_counters['rx_ok']}
        elif link_info['rx_max']['ctr'] < node_counters['rx_ok']:
            link_info['rx_max'] = {'link': link, 'ctr': node_counters['rx_ok']}
        if link_info['rx_min'] == {}:
            link_info['rx_min'] = {'link': link, 'ctr': node_counters['rx_ok']}
        elif link_info['rx_min']['ctr'] > node_counters['rx_ok']:
            link_info['rx_min'] = {'link': link, 'ctr': node_counters['rx_ok']}
        if link_info['tx_max'] == {}:
            link_info['tx_max'] = {'link': link, 'ctr': node_counters['tx_ok']}
        elif link_info['tx_max']['ctr'] < node_counters['tx_ok']:
            link_info['tx_max'] = {'link': link, 'ctr': node_counters['tx_ok']}
        if link_info['tx_min'] == {}:
            link_info['tx_min'] = {'link': link, 'ctr': node_counters['tx_ok']}
        elif link_info['tx_min']['ctr'] > node_counters['tx_ok']:
            link_info['tx_min'] = {'link': link, 'ctr': node_counters['tx_ok']}
    st.log('HERE IS THE LINK COUNTERS INFORMATION {}'.format(link_info))
    if key == 'max':
        if direction == 'rx':
            return(link_info['rx_max']['link'])
        else:
            return(link_info['tx_max']['link'])
    elif key == 'min':
        if direction == 'rx':
            return(link_info['rx_min']['link'])
        else:
            return(link_info['tx_min']['link'])

@pytest.mark.usefixtures('cnest_base_config')
class TestCrowsnestBackendLinkTriggers():
    
    def test_backend_spine_link_trigger(self, pause_run):
        """
        Testcase: Test spine link failure in the Backend Network.
        Description:
            1) Bring up the Cluster3 Corwsnest solution testbed configs, underlay and overlay
	    2) Bring up backend base profile
            3) verify all EVPN types are exchanged correctly
	    4) Verify vxlan tunnels are up
            5) After verifying conrol plane, perform iPerf traffic test to find out loaded spine link
            6) Shut the Spine link if the there are more than one spine link.
            7) Please make sure iperf traffic test passes, taking different spine link.
        """
        tc_id = "test_backend_spine_link_trigger"
        test_cfg['tc_id'] = tc_id
        tc_cfg = get_tc_params(tc_id)

        st.banner('Testcase:Test spine link failure in Backend Network ({})'.format(tc_id))
        result = True
        summ = ''
        #Test case verification
        st.log('Testcase verification is in progress....')
        # Getting common sonic and vtysh command outputs.
        #get_cli_out()

        #Checking expected vlan/vni mappings, remote vteps and verifying control plane
        mapping_types = ["vlanvni", "vrfvni", "remotevtep"]
        node_list = test_cfg['nodes']['be_leaf']
        for node in st.get_dut_names():
            if node in node_list:
                success, msg = verify_control_plane(node, config_dict, mapping_types)
                if not success:
                    result = False
                    summ += msg
                    report_result(result, tc_id, summ)

        traffic_endpoints = construct_traffic_endpoints(topo_dict, test_cfg, node_list)
        tc_dp_tr_ep = tuple(tc_cfg['tc_ep'])
        st.log('Here is the data plane traffic from {} to {}'.format(tc_dp_tr_ep[1], tc_dp_tr_ep[0]))
        endpoint_tupl = lookup_traffic_endpoints(tc_dp_tr_ep, traffic_endpoints)
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, node_list, ping=False, iperf=True, perftest=False)
        target_node = endpoint_tupl[0].split('_')[0]
        # Getting spine links 
        links = get_all_links_on_node(target_node, 'spine', topo_dict)
        target_link = get_loaded_link(target_node, links, 'max', 'tx')
        st.log('Here are the all the links on the node connected to spine \n {} \n and selected link is: {}'.format(links, target_link))

        # Creating threads to run traffic and link flap in parallel
        threads = list()
        st.banner("Starting dataplane traffic and interface flap trigger in parallel on {} for interface {}".format(target_node, target_link))
        thread1 = threading.Thread(target=verify_data_plane, args=(traffic_endpoints, endpoint_tupl, [target_node], False, True, False, 90, 1), name="verifydata_thread_{}".format(target_node))
        thread2 = threading.Thread(target=link_flap, args=(target_node, target_link, 20), name="link_flap_thread_{}".format(target_node))
        thread1.start() ; thread2.start()
        threads = [thread1, thread2]
        for thread in threads:
            thread.join()
            st.banner('Thread {} completed'.format(thread.name))

        #Checking result
        if not g_res or not dp_res:
            msg = 'Data Plane verification during link trigger testcase {} failed'.format(tc_id)
            st.log(msg)
            summ += msgs
            result = g_res
        #Report result
        report_result(result, tc_id, summ)

    def test_backend_host_facing_link_trigger(self, pause_run):
        """
        Testcase: Test Host facing link flap in the Backend Network.
        Description:
            1) Bring up the Cluster3 Corwsnest solution testbed configs, underlay and overlay
	    2) Bring up backend base profile
            3) verify all EVPN types are exchanged correctly
	    4) Verify vxlan tunnels are up
            5) After verifying conrol plane, perform iPerf traffic test to find out loaded spine link
            6) Shut and Un-Shut the host facing link.
            7) Please make sure iperf traffic test passes and recovers after link flap.
        """
        tc_id = "test_backend_host_facing_link_trigger"
        test_cfg['tc_id'] = tc_id
        tc_cfg = get_tc_params(tc_id)

        st.banner('Testcase: Test Host facing link failure in the Backend Network ({})'.format(tc_id))
        result = True
        summ = ''
        #Test case verification
        st.log('Testcase verification is in progress....')
        # Getting common sonic and vtysh command outputs.
        #get_cli_out()

        #Checking expected vlan/vni mappings, remote vteps and verifying control plane
        mapping_types = ["vlanvni", "vrfvni", "remotevtep"]
        node_list = test_cfg['nodes']['be_leaf']
        for node in st.get_dut_names():
            if node in node_list:
                success, msg = verify_control_plane(node, config_dict, mapping_types)
                if not success:
                    result = False
                    summ += msg
                    report_result(result, tc_id, summ)

        traffic_endpoints = construct_traffic_endpoints(topo_dict, test_cfg, node_list)
        tc_dp_tr_ep = tuple(tc_cfg['tc_ep'])
        endpoint_tupl = lookup_traffic_endpoints(tc_dp_tr_ep, traffic_endpoints)
        # Getting host facing link 
        target_link = traffic_endpoints[endpoint_tupl[0]]['node_intf']
        target_node = endpoint_tupl[0].split('_')[0]
        host_name = traffic_endpoints[endpoint_tupl[0]]['host_name']
        st.log('Here is the host facing link {} on the node {} connected to host {}'.format(target_link, target_node, host_name))
        st.log('Here is the data plane traffic from {} to {} before trigger'.format(tc_dp_tr_ep[1], tc_dp_tr_ep[0]))
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, node_list, ping=False, iperf=True, perftest=False)
        if not dp_res:
            msg = 'Data Plane verification before link trigger testcase {} failed'.format(tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
            #report_result(result, tc_id, summ)
        
        # Creating threads to run traffic and link flap in parallel
        threads = list()
        st.banner("Starting dataplane traffic and interface flap trigger in parallel on {} for interface {}".format(target_node, target_link))
        thread1 = threading.Thread(target=verify_data_plane, args=(traffic_endpoints, endpoint_tupl, [target_node], False, True, False, 60, 100), name="verifydata_thread_{}".format(target_node))
        thread2 = threading.Thread(target=link_flap, args=(target_node, target_link, 20), name="link_flap_thread_{}".format(target_node))
        thread1.start() ; thread2.start()
        threads = [thread1, thread2]
        for thread in threads:
            thread.join()
            st.banner('Thread {} completed'.format(thread.name))

        st.log('Here is the data plane traffic from {} to {} after trigger'.format(tc_dp_tr_ep[1], tc_dp_tr_ep[0]))
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, node_list, ping=False, iperf=True, perftest=False)

        #Checking result
        if not dp_res or not g_res:
            msg = 'Data Plane verification in host facing link trigger testcase {} failed'.format(tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
        #Report result
        report_result(result, tc_id, summ)

    def test_backend_host_side_link_trigger(self, pause_run):
        """
        Testcase: Test Host side link flap in the Backend Network.
        Description:
            1) Bring up the Cluster3 Corwsnest solution testbed configs, underlay and overlay
	    2) Bring up backend base profile
            3) verify all EVPN types are exchanged correctly
	    4) Verify vxlan tunnels are up
            5) After verifying conrol plane, perform iPerf traffic test to find out loaded spine link
            6) Shut and Un-Shut the host side link.
            7) Please make sure iperf traffic test passes and recovers after link flap.
        """
        tc_id = "test_backend_host_side_link_trigger"
        test_cfg['tc_id'] = tc_id
        tc_cfg = get_tc_params(tc_id)

        st.banner('Testcase: Test Host side link failure in the Backend Network ({})'.format(tc_id))
        result = True
        summ = ''
        #Test case verification
        st.log('Testcase verification is in progress....')
        # Getting common sonic and vtysh command outputs.
        #get_cli_out()

        #Checking expected vlan/vni mappings, remote vteps and verifying control plane
        mapping_types = ["vlanvni", "vrfvni", "remotevtep"]
        node_list = test_cfg['nodes']['be_leaf']
        for node in st.get_dut_names():
            if node in node_list:
                success, msg = verify_control_plane(node, config_dict, mapping_types)
                if not success:
                    result = False
                    summ += msg
                    report_result(result, tc_id, summ)

        traffic_endpoints = construct_traffic_endpoints(topo_dict, test_cfg, node_list)
        tc_dp_tr_ep = tuple(tc_cfg['tc_ep'])
        endpoint_tupl = lookup_traffic_endpoints(tc_dp_tr_ep, traffic_endpoints)
        # Getting host side link, host ip, username/passwords, and host name
        target_link = traffic_endpoints[endpoint_tupl[0]]['intf']
        hostip = traffic_endpoints[endpoint_tupl[0]]['host_ip']
        username = st.get_username(traffic_endpoints[endpoint_tupl[0]]['host_name'])
        password = st.get_password(traffic_endpoints[endpoint_tupl[0]]['host_name'])
        target_node = endpoint_tupl[0].split('_')[1]
        host_name = traffic_endpoints[endpoint_tupl[0]]['host_name']
        st.log('Here is the host side link {} on the host {}'.format(target_link, host_name))
        st.log('Here is the data plane traffic from {} to {} before trigger'.format(tc_dp_tr_ep[1], tc_dp_tr_ep[0]))
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, node_list, ping=False, iperf=True, perftest=False)
        if not dp_res:
            msg = 'Data Plane verification before link trigger testcase {} failed'.format(tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
            #report_result(result, tc_id, summ)
        # Creating threads to run traffic and link flap in parallel
        threads = list()
        st.banner("Starting dataplane traffic and interface flap trigger in parallel on {} for interface {}".format(target_node, target_link))
        thread1 = threading.Thread(target=verify_data_plane, args=(traffic_endpoints, endpoint_tupl, [target_node], False, True, False, 60, 100), name="verifydata_thread_{}".format(target_node))
        thread2 = threading.Thread(target=link_flap_on_host, args=(hostip, username, password, target_link), name="ensint_flap_thread_{}".format(target_node))
        thread1.start() ; thread2.start()
        threads = [thread1, thread2]
        for thread in threads:
            thread.join()
            st.banner('Thread {} completed'.format(thread.name))

        #Checking result
        if not dp_res or not g_res:
            msg = 'Data Plane verification in host side link trigger testcase {} failed'.format(tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
        #Report result
        report_result(result, tc_id, summ)

@pytest.mark.usefixtures('cnest_base_config')
class TestCrowsnestBackend():
    
    def test_bringup_backend_cp(self, pause_run):
        """
        Testcase: Bring up the Control Plane in Backend Network.
        Description:
            1) Bring up the Cluster3 Corwsnest solution testbed configs, underlay and overlay
	    2) Bring up backend base profile
            3) verify all EVPN types are exchanged correctly
	    4) Verify vxlan tunnels are up
        """
        tc_id = "test_bringup_backend_cp"
        test_cfg['tc_id'] = tc_id
        tc_cfg = get_tc_params(tc_id)

        st.banner('Testcase:Test the bring-up of Backend control plane ({})'.format(tc_id))
        result = True
        summ = ''
        #Test case verification
        st.log('Testcase verification is in progress....')
        # Getting common sonic and vtysh command outputs.
        #get_cli_out()

        #Checking expected vlan/vni mappings, remote vteps and verifying control plane
        mapping_types = ["vlanvni", "vrfvni", "remotevtep"]
        for node in st.get_dut_names():
            if node in test_cfg['nodes']['be_leaf']:
                success, msg = verify_control_plane(node, config_dict, mapping_types)
                if not success:
                    result = False
                    summ += msg
        #Report result
        report_result(result, tc_id, summ)

    def test_backend_dp_h1g0_h1g3_samenode(self, pause_run):
        """
        Testcase: Bring up the Data Plane in Backend Network.
        Description:
            1) Bring up the Cluster3 Corwsnest solution testbed configs, underlay and overlay
	    2) Bring up backend base profile
            3) verify all EVPN types are exchanged correctly
	    4) Verify vxlan tunnels are up
            5) After verifying conrol plane, Check ping test using prior to actual PerfTest traffic test
            6) Perform PerfTest or/and iPERF traffic test between GPU-to-GPU on same node in the diff rail
        """
        tc_id = "test_backend_dp_h1g0_h1g3_samenode"
        test_cfg['tc_id'] = tc_id
        tc_cfg = get_tc_params(tc_id)

        st.banner('Testcase:Test the Backend date plane for ({})'.format(tc_id))
        result = True
        summ = ''
        #Test case verification
        st.log('Testcase verification is in progress....')
        # Getting common sonic and vtysh command outputs.
        #get_cli_out()

        #Checking expected vlan/vni mappings, remote vteps and verifying control plane
        mapping_types = ["vlanvni", "vrfvni", "remotevtep"]
        node_list = test_cfg['nodes']['be_leaf']
        for node in st.get_dut_names():
            if node in node_list:
                success, msg = verify_control_plane(node, config_dict, mapping_types)
                if not success:
                    result = False
                    summ += msg
                    report_result(result, tc_id, summ)

        traffic_endpoints = construct_traffic_endpoints(topo_dict, test_cfg, node_list)
        tc_dp_tr_ep = tuple(tc_cfg['tc_ep'])
        st.log('Here is the data plane traffic from {} to {}'.format(tc_dp_tr_ep[1], tc_dp_tr_ep[0]))
        endpoint_tupl = lookup_traffic_endpoints(tc_dp_tr_ep, traffic_endpoints)
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, node_list, ping=False, iperf=True, perftest=False)
        if not dp_res:
            msg = 'Data Plane verification failed in the testcase {}'.format(tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
        #Report result
        report_result(result, tc_id, summ)

    def test_backend_dp_h1g0_h2g0_diffnode_samerail(self, pause_run):
        """
        Testcase: Bring up the Data Plane in Backend Network.
        Description:
            1) Bring up the Cluster3 Corwsnest solution testbed configs, underlay and overlay
	    2) Bring up backend base profile
            3) verify all EVPN types are exchanged correctly
	    4) Verify vxlan tunnels are up
            5) After verifying conrol plane, Check ping test using prior to actual PerfTest traffic test
            6) Perform PerfTest or/and iPERF traffic test between GPU-to-GPU on different node in the same rail
        """
        tc_id = "test_backend_dp_h1g0_h2g0_diffnode_samerail"
        test_cfg['tc_id'] = tc_id
        tc_cfg = get_tc_params(tc_id)

        st.banner('Testcase:Test the Backend date plane for ({})'.format(tc_id))
        result = True
        summ = ''
        #Test case verification
        st.log('Testcase verification is in progress....')
        # Getting common sonic and vtysh command outputs.
        #get_cli_out()

        #Checking expected vlan/vni mappings, remote vteps and verifying control plane
        mapping_types = ["vlanvni", "vrfvni", "remotevtep"]
        node_list = test_cfg['nodes']['be_leaf']
        for node in st.get_dut_names():
            if node in node_list:
                success, msg = verify_control_plane(node, config_dict, mapping_types)
                if not success:
                    result = False
                    summ += msg
                    report_result(result, tc_id, summ)

        traffic_endpoints = construct_traffic_endpoints(topo_dict, test_cfg, node_list)
        tc_dp_tr_ep = tuple(tc_cfg['tc_ep'])
        st.log('Here is the data plane traffic from {} to {}'.format(tc_dp_tr_ep[1], tc_dp_tr_ep[0]))
        endpoint_tupl = lookup_traffic_endpoints(tc_dp_tr_ep, traffic_endpoints)
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, node_list, ping=False, iperf=True, perftest=False)
        if not dp_res:
            msg = 'Data Plane verification failed in the testcase {}'.format(tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
        #Report result
        report_result(result, tc_id, summ)

    def test_backend_dp_h1g1_h4g7_diffnode_diffrail(self, pause_run):
        """
        Testcase: Bring up the Data Plane in Backend Network.
        Description:
            1) Bring up the Cluster3 Corwsnest solution testbed configs, underlay and overlay
	    2) Bring up backend base profile
            3) verify all EVPN types are exchanged correctly
	    4) Verify vxlan tunnels are up
            5) After verifying conrol plane, Check ping test using prior to actual PerfTest traffic test
            6) Perform PerfTest or/and iPERF traffic test between GPU-to-GPU on diff node in the diff rail
        """
        tc_id = "test_backend_dp_h1g1_h4g7_diffnode_diffrail"
        test_cfg['tc_id'] = tc_id
        tc_cfg = get_tc_params(tc_id)

        st.banner('Testcase:Test the Backend date plane for ({})'.format(tc_id))
        result = True
        summ = ''
        #Test case verification
        st.log('Testcase verification is in progress....')
        # Getting common sonic and vtysh command outputs.
        #get_cli_out()

        #Checking expected vlan/vni mappings, remote vteps and verifying control plane
        mapping_types = ["vlanvni", "vrfvni", "remotevtep"]
        node_list = test_cfg['nodes']['be_leaf']
        for node in st.get_dut_names():
            if node in node_list:
                success, msg = verify_control_plane(node, config_dict, mapping_types)
                if not success:
                    result = False
                    summ += msg
                    report_result(result, tc_id, summ)

        traffic_endpoints = construct_traffic_endpoints(topo_dict, test_cfg, node_list)
        tc_dp_tr_ep = tuple(tc_cfg['tc_ep'])
        st.log('Here is the data plane traffic from {} to {}'.format(tc_dp_tr_ep[1], tc_dp_tr_ep[0]))
        endpoint_tupl = lookup_traffic_endpoints(tc_dp_tr_ep, traffic_endpoints)
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, node_list, ping=False, iperf=True, perftest=False)
        if not dp_res:
            msg = 'Data Plane verification failed in the testcase {}'.format(tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
        #Report result
        report_result(result, tc_id, summ)

    def test_backend_dp_h2g4_h3g5_diffnode_samerail_diffvlan(self, pause_run):
        """
        Testcase: Bring up the Data Plane in Backend Network.
        Description:
            1) Bring up the Cluster3 Corwsnest solution testbed configs, underlay and overlay
	    2) Bring up backend base profile
            3) verify all EVPN types are exchanged correctly
	    4) Verify vxlan tunnels are up
            5) After verifying conrol plane, Check ping test using prior to actual PerfTest traffic test
            6) Perform PerfTesiiii/and iPERF traffic test between GPU-to-GPU on diff node in the same rail and in the diff vlan
        """
        tc_id = "test_backend_dp_h2g4_h3g5_diffnode_samerail_diffvlan"
        test_cfg['tc_id'] = tc_id
        tc_cfg = get_tc_params(tc_id)

        st.banner('Testcase:Test the Backend date plane for ({})'.format(tc_id))
        result = True
        summ = ''
        #Test case verification
        st.log('Testcase verification is in progress....')
        # Getting common sonic and vtysh command outputs.
        #get_cli_out()

        #Checking expected vlan/vni mappings, remote vteps and verifying control plane
        mapping_types = ["vlanvni", "vrfvni", "remotevtep"]
        node_list = test_cfg['nodes']['be_leaf']
        for node in st.get_dut_names():
            if node in node_list:
                success, msg = verify_control_plane(node, config_dict, mapping_types)
                if not success:
                    result = False
                    summ += msg
                    report_result(result, tc_id, summ)

        traffic_endpoints = construct_traffic_endpoints(topo_dict, test_cfg, node_list)
        tc_dp_tr_ep = tuple(tc_cfg['tc_ep'])
        st.log('Here is the data plane traffic from {} to {}'.format(tc_dp_tr_ep[1], tc_dp_tr_ep[0]))
        endpoint_tupl = lookup_traffic_endpoints(tc_dp_tr_ep, traffic_endpoints)
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, node_list, ping=False, iperf=True, perftest=False)
        if not dp_res:
            msg = 'Data Plane verification failed in the testcase {}'.format(tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
        #Report result
        report_result(result, tc_id, summ)

@pytest.mark.usefixtures('cnest_base_config')
class TestCrowsnestFrontend():
    
    def test_bringup_frontend_cp(self, pause_run):
        """
        Testcase: Bring up the Control Plane in Frontend Network.
        Description:
            1) Bring up the Cluster3 Corwsnest solution testbed configs, underlay and overlay
	    2) Bring up frontend base profile
            3) verify all EVPN types are exchanged correctly
	    4) Verify vxlan tunnels are up
        """
        tc_id = "test_bringup_frontend_cp"
        test_cfg['tc_id'] = tc_id
        tc_cfg = get_tc_params(tc_id)

        st.banner('Testcase:Test the bring-up of Frontend control plane ({})'.format(tc_id))
        result = True
        summ = ''
        #Test case verification
        st.log('Testcase verification is in progress....')
        # Getting common sonic and vtysh command outputs.
        #get_cli_out()

        #Checking expected vlan/vni mappings, remote vteps and verifying control plane
        mapping_types = ["vlanvni", "vrfvni", "remotevtep"]
        all_fe_leaf_nodes = test_cfg['nodes']['fe_leaf'] + test_cfg['nodes']['mgmt_leaf'] + test_cfg['nodes']['vast_leaf']
        for node in st.get_dut_names():
            if node in all_fe_leaf_nodes:
                success, msg = verify_control_plane(node, config_dict, mapping_types)
                if not success:
                    result = False
                    summ += msg
        #Report result
        report_result(result, tc_id, summ)

@pytest.mark.usefixtures('cnest_base_config')
class TestCrowsnestBackendRestartProcessTriggers():

    @pytest.mark.parametrize('restart_type', ["bgp", "swss", "syncd", "dhcp_relay"]) 
    def test_backend_restart_process_trigger(self, pause_run, restart_type):
        """
        Testcase: Test process restart trigger in the Backend Network node such as leaf,spine.
        Description:
            1) Bring up the Cluster3 Corwsnest solution testbed configs, underlay and overlay
	    2) Bring up backend base profile
            3) verify all EVPN types are exchanged correctly
	    4) Verify vxlan tunnels are up
            5) After verifying conrol plane, perform iPerf traffic test before the trigger
            6) Perform process restart and make sure check control plane and data plane is intact after process restart.
        """
        tc_id = "test_backend_restart_process_trigger_{}".format(restart_type)
        test_cfg['tc_id'] = tc_id
        tc_cfg = get_tc_params(tc_id)

        st.banner('Testcase:Test process restart of {} in the Backend Network ({})'.format(restart_type, tc_id))
        result = True
        summ = ''
        #Test case verification
        st.log('Testcase verification is in progress....')
        # Getting common sonic and vtysh command outputs.
        #get_cli_out()

        #Checking expected vlan/vni mappings, remote vteps and verifying control plane
        mapping_types = ["vlanvni", "vrfvni", "remotevtep"]
        node_list = test_cfg['nodes']['be_leaf']
        for node in node_list:
            success, msg = verify_control_plane(node, config_dict, mapping_types)
            if not success:
                result = False
                summ += msg
                report_result(result, tc_id, summ)

        traffic_endpoints = construct_traffic_endpoints(topo_dict, test_cfg, node_list)
        tc_dp_tr_ep = tuple(tc_cfg['tc_ep'])
        endpoint_tupl = lookup_traffic_endpoints(tc_dp_tr_ep, traffic_endpoints)
        target_node_list = [endpoint_tupl[0].split('_')[0], endpoint_tupl[1].split('_')[0]]
        st.log('Here is the data plane traffic check before process ({}) restart trigger'.format(restart_type))
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, target_node_list, ping=False, iperf=True, perftest=False)
        if not dp_res:
            msg = 'Data Plane verification before process restart trigger testcase {} failed'.format(tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
            #report_result(result, tc_id, summ)
        # Creating threads to run traffic and process restart in parallel
        threads = list()
        st.banner("Starting dataplane traffic and process ({}) restart trigger in parallel".format(restart_type))
        thread1 = threading.Thread(target=verify_data_plane, args=(traffic_endpoints, endpoint_tupl, target_node_list, False, True, False, 60, 0.001), name="verifydata_thread_{}".format(restart_type))
        thread2 = threading.Thread(target=proc_restart_on_node, args=(target_node_list, restart_type), name="restart_proc_thread_{}".format(restart_type))
        thread1.start() ; thread2.start()
        threads = [thread1, thread2]
        for thread in threads:
            thread.join()
            st.banner('Thread {} completed'.format(thread.name))

        #Checking control plane after process restart trigger
        for node in node_list:
            success, msg = verify_control_plane(node, config_dict, mapping_types)
            if not success:
                st.log('Control plane check failed after process {} restart trigger on node {}'.format(restart_type, node))
                result = False
                summ += msg
                report_result(result, tc_id, summ)
        st.log('Here is the data plane traffic check after process ({}) restart trigger'.format(restart_type))
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, target_node_list, ping=False, iperf=True, perftest=False)

        #Checking result
        if not dp_res or not g_res:
            msg = 'Data Plane verification after process restart trigger testcase {} failed'.format(tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
        #Report result
        report_result(result, tc_id, summ)

@pytest.mark.usefixtures('cnest_base_config')
class TestCrowsnestBackendLeafReloadTriggers():

    @pytest.mark.parametrize('reload_type', ["config", "reboot", "powerfail"]) 
    def test_backend_leaf_reload_trigger(self, pause_run, reload_type):
        """
        Testcase: Test node reload trigger in the Backend Network node such as leaf.
        Description:
            1) Bring up the Cluster3 Corwsnest solution testbed configs, underlay and overlay
	    2) Bring up backend base profile
            3) verify all EVPN types are exchanged correctly
	    4) Verify vxlan tunnels are up
            5) After verifying conrol plane, perform iPerf traffic test before the trigger
            6) Perform config reload or soft reload or hard failure 
            7) And then check control plane and data plane is intact after reload trigger.
        """
        tc_id = "test_backend_leaf_reload_trigger_{}".format(reload_type)
        test_cfg['tc_id'] = tc_id
        tc_cfg = get_tc_params(tc_id)

        st.banner('Testcase:Test Leaf node {} reload of in the Backend Network ({})'.format(reload_type, tc_id))
        result = True
        summ = ''
        #Test case verification
        st.log('Testcase verification is in progress....')
        # Getting common sonic and vtysh command outputs.
        #get_cli_out()

        #Checking expected vlan/vni mappings, remote vteps and verifying control plane
        mapping_types = ["vlanvni", "vrfvni", "remotevtep"]
        node_list = test_cfg['nodes']['be_leaf']
        for node in node_list:
            success, msg = verify_control_plane(node, config_dict, mapping_types)
            if not success:
                result = False
                summ += msg
                report_result(result, tc_id, summ)

        traffic_endpoints = construct_traffic_endpoints(topo_dict, test_cfg, node_list)
        tc_dp_tr_ep = tuple(tc_cfg['tc_ep'])
        endpoint_tupl = lookup_traffic_endpoints(tc_dp_tr_ep, traffic_endpoints)
        target_node_list = [endpoint_tupl[0].split('_')[0], endpoint_tupl[1].split('_')[0]]
        st.log('Here is the data plane traffic check before reload ({}) trigger'.format(reload_type))
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, target_node_list, ping=False, iperf=True, perftest=False)
        if not dp_res:
            msg = 'Data Plane verification before the trigger {}, testcase {} failed'.format(reload_type, tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
            #report_result(result, tc_id, summ)
        if reload_type == 'config':
            # Creating threads to run traffic and reload trigger in parallel
            threads = list()
            st.banner("Starting dataplane traffic and trigger ({}) in parallel".format(reload_type))
            thread1 = threading.Thread(target=verify_data_plane, args=(traffic_endpoints, endpoint_tupl, target_node_list, False, True, False, 90, 100), name="verifydata_thread_{}".format(reload_type))
            thread2 = threading.Thread(target=reload_node, args=(target_node_list, reload_type), name="reload_node_thread_{}".format(reload_type))
            thread1.start() ; thread2.start()
            threads = [thread1, thread2]
            for thread in threads:
                thread.join()
                st.banner('Thread {} completed'.format(thread.name))
        else:
            st.banner("Starting trigger for reload type: {} ".format(reload_type))
            reload_node(target_node_list, reload_type)
    
        #Checking control plane after reload trigger
        for node in node_list:
            success, msg = verify_control_plane(node, config_dict, mapping_types)
            if not success:
                st.log('Control plane check failed after {} trigger on node {}'.format(reload_type, node))
                result = False
                summ += msg
                report_result(result, tc_id, summ)
        st.log('Here is the data plane traffic check after ({}) trigger'.format(reload_type))
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, target_node_list, ping=False, iperf=True, perftest=False)

        #Checking result
        if not dp_res or not g_res:
            msg = 'Data Plane verification after {} trigger, testcase {} failed'.format(reload_type, tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
        #Report result
        report_result(result, tc_id, summ)

@pytest.mark.usefixtures('cnest_base_config')
class TestCrowsnestBackendSpineReloadTriggers():

    @pytest.mark.parametrize('reload_type', ["config", "reboot", "powerfail"]) 
    def test_backend_spine_reload_trigger(self, pause_run, reload_type):
        """
        Testcase: Test node reload trigger in the Backend Network node such as Spine.
        Description:
            1) Bring up the Cluster3 Corwsnest solution testbed configs, underlay and overlay
	    2) Bring up backend base profile
            3) verify all EVPN types are exchanged correctly
	    4) Verify vxlan tunnels are up
            5) After verifying conrol plane, perform iPerf traffic test before the trigger
            6) Perform config reload or soft reload or hard failure 
            7) And then check control plane and data plane is intact after reload trigger.
        """
        tc_id = "test_backend_spine_reload_trigger_{}".format(reload_type)
        test_cfg['tc_id'] = tc_id
        tc_cfg = get_tc_params(tc_id)

        st.banner('Testcase:Test Spine node {} reload of in the Backend Network ({})'.format(reload_type, tc_id))
        result = True
        summ = ''
        #Test case verification
        st.log('Testcase verification is in progress....')
        # Getting common sonic and vtysh command outputs.
        #get_cli_out()

        #Checking expected vlan/vni mappings, remote vteps and verifying control plane
        mapping_types = ["vlanvni", "vrfvni", "remotevtep"]
        node_list = test_cfg['nodes']['be_leaf']
        for node in node_list:
            success, msg = verify_control_plane(node, config_dict, mapping_types)
            if not success:
                result = False
                summ += msg
                report_result(result, tc_id, summ)

        traffic_endpoints = construct_traffic_endpoints(topo_dict, test_cfg, node_list)
        tc_dp_tr_ep = tuple(tc_cfg['tc_ep'])
        endpoint_tupl = lookup_traffic_endpoints(tc_dp_tr_ep, traffic_endpoints)
        target_node_list = [endpoint_tupl[0].split('_')[0], endpoint_tupl[1].split('_')[0]]
        st.log('Here is the data plane traffic check before reload ({}) trigger'.format(reload_type))
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, target_node_list, ping=False, iperf=True, perftest=False)
        if not dp_res:
            msg = 'Data Plane verification before the trigger {}, testcase {} failed'.format(reload_type, tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
            #report_result(result, tc_id, summ)

        #Find target spine node to reboot.
        links = get_all_links_on_node(endpoint_tupl[0].split('_')[0], 'spine', topo_dict)
        target_link = get_loaded_link(endpoint_tupl[0].split('_')[0], links, 'max', 'tx')
        target_spine = get_nbr_node(endpoint_tupl[0].split('_')[0], target_link)
        st.log('Here is the spine node selected for the trigger: {}'.format(target_spine))
        # Creating threads to run traffic and reload trigger in parallel
        threads = list()
        st.banner("Starting dataplane traffic and trigger ({}) in parallel".format(reload_type))
        thread1 = threading.Thread(target=verify_data_plane, args=(traffic_endpoints, endpoint_tupl, target_node_list, False, True, False, 60, 5), name="verifydata_thread_{}".format(reload_type))
        thread2 = threading.Thread(target=reload_node, args=([target_spine], reload_type), name="reload_node_thread_{}".format(reload_type))
        thread1.start() ; thread2.start()
        threads = [thread1, thread2]
        for thread in threads:
            thread.join()
            st.banner('Thread {} completed'.format(thread.name))
    
        #Checking control plane after reload trigger
        for node in node_list:
            success, msg = verify_control_plane(node, config_dict, mapping_types)
            if not success:
                st.log('Control plane check failed after {} trigger on node {}'.format(reload_type, node))
                result = False
                summ += msg
                report_result(result, tc_id, summ)
        st.log('Here is the data plane traffic check after ({}) trigger'.format(reload_type))
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, target_node_list, ping=False, iperf=True, perftest=False)

        #Checking result
        if not dp_res or not g_res:
            msg = 'Data Plane verification after {} trigger, testcase {} failed'.format(reload_type, tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
        #Report result
        report_result(result, tc_id, summ)

@pytest.mark.usefixtures('cnest_base_config')
class TestCrowsnestBackendAddRemoveTriggers():

    @pytest.mark.parametrize('trigger_type', ["rail", "interrail", "vlan", "mac", "bgp"]) 
    def test_backend_addremove_cfg_trigger(self, pause_run, trigger_type):
        """
        Testcase: Test add remove config trigger in the Backend Network node such as Leaf.
        Description:
            1) Bring up the Cluster3 Corwsnest solution testbed configs, underlay and overlay
	    2) Bring up backend base profile
            3) verify all EVPN types are exchanged correctly
	    4) Verify vxlan tunnels are up
            5) After verifying conrol plane, perform iPerf traffic test before the trigger
            6) Perform add/remove config triggers or clear mac, bgp  
            7) And then check control plane and data plane is intact after trigger.
        """
        tc_id = "test_backend_addremove_cfg_trigger_{}".format(trigger_type)
        test_cfg['tc_id'] = tc_id
        tc_cfg = get_tc_params(tc_id)

        st.banner('Testcase:add/remove/clear trigger {} in the Backend Network node ({})'.format(trigger_type, tc_id))
        result = True
        summ = ''
        #Test case verification
        st.log('Testcase verification is in progress....')
        # Getting common sonic and vtysh command outputs.
        #get_cli_out()

        #Checking expected vlan/vni mappings, remote vteps and verifying control plane
        mapping_types = ["vlanvni", "vrfvni", "remotevtep"]
        node_list = test_cfg['nodes']['be_leaf']
        for node in node_list:
            success, msg = verify_control_plane(node, config_dict, mapping_types)
            if not success:
                result = False
                summ += msg
                report_result(result, tc_id, summ)

        traffic_endpoints = construct_traffic_endpoints(topo_dict, test_cfg, node_list)
        tc_dp_tr_ep = tuple(tc_cfg['tc_ep'])
        endpoint_tupl = lookup_traffic_endpoints(tc_dp_tr_ep, traffic_endpoints)
        target_node_list = [endpoint_tupl[0].split('_')[0], endpoint_tupl[1].split('_')[0]]
        st.log('Here is the data plane traffic check before add_rem_cfg ({}) trigger'.format(trigger_type))
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, target_node_list, ping=False, iperf=True, perftest=False)

        # Checking dataplane before trigger
        if not dp_res:
            msg = 'Data Plane verification before the trigger {}, testcase {} failed'.format(trigger_type, tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
            #report_result(result, tc_id, summ)

        # Creating threads to run traffic and trigger in parallel
        threads = list()
        st.banner("Starting dataplane traffic and trigger ({}) in parallel".format(trigger_type))
        thread1 = threading.Thread(target=verify_data_plane, args=(traffic_endpoints, endpoint_tupl, target_node_list, False, True, False, 60, 100), name="verifydata_thread_{}".format(trigger_type))
        if trigger_type == 'bgp':
            thread2 = threading.Thread(target=clear_trigger, args=(target_node_list, trigger_type), name="thread_{}".format(trigger_type))
        elif trigger_type == 'mac':
            thread2 = threading.Thread(target=clear_trigger, args=(target_node_list, trigger_type), name="thread_{}".format(trigger_type))
        elif trigger_type == 'vlan':
            target_node = target_node_list[0]
            thread2 = threading.Thread(target=addrem_trigger, args=(target_node, endpoint_tupl, trigger_type, traffic_endpoints), name="thread_{}".format(trigger_type))
        elif trigger_type == 'rail':
            target_node = target_node_list[0]
            thread2 = threading.Thread(target=addrem_trigger, args=(target_node, endpoint_tupl, trigger_type, traffic_endpoints), name="thread_{}".format(trigger_type))
        elif trigger_type == 'interrail':
            target_node = target_node_list[0]
            thread2 = threading.Thread(target=addrem_trigger, args=(target_node, endpoint_tupl, trigger_type, traffic_endpoints), name="thread_{}".format(trigger_type))
        thread1.start() ; thread2.start()
        threads = [thread1, thread2]
        for thread in threads:
            thread.join()
            st.banner('Thread {} completed'.format(thread.name))
    
        #Checking control plane after the trigger
        for node in node_list:
            success, msg = verify_control_plane(node, config_dict, mapping_types)
            if not success:
                st.log('Control plane check failed after {} trigger on node {}'.format(trigger_type, node))
                result = False
                summ += msg
                report_result(result, tc_id, summ)

        #Checking dataplane after the trigger
        st.log('Here is the data plane traffic check after ({}) trigger'.format(trigger_type))
        dp_res, msgs = verify_data_plane(traffic_endpoints, endpoint_tupl, target_node_list, ping=False, iperf=True, perftest=False)

        #Checking result
        if not dp_res or not g_res:
            msg = 'Data Plane verification after {} trigger, testcase {} failed'.format(trigger_type, tc_id)
            st.log(msg)
            summ += msgs
            result = dp_res
        #Report result
        report_result(result, tc_id, summ)
