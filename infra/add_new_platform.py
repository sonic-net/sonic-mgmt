#!/usr/bin/env python3

"""
Script to add a new platform to the sonic test infrastructure.

Usage: python3 add_new_platform.py <new_platform_name> <hardware_sku> <topology>
Example: python3 add_new_platform.py titan Cisco-8223-64E-MO t0,t1
"""

import argparse
import os
import sys
import re
import shutil
from pathlib import Path

def update_create_sonic_topo(new_platform, topology_list):
    """Update create_sonic_topo.py to add support for the new platform."""
    script_path = "create_sonic_topo.py"
    
    if not os.path.exists(script_path):
        print("Error: {} not found!".format(script_path))
        return False
    
    # Read the file
    with open(script_path, 'r') as f:
        content = f.read()
    
    # 1. Update argument parser help text and choices
    # Find the device_type help text and add new platform
    help_pattern = r"(help='options are [^']+)'"
    help_match = re.search(help_pattern, content)
    if help_match:
        current_help = help_match.group(1)
        new_help = "{}, {}".format(current_help, new_platform)
        content = content.replace(help_match.group(0), "{}'".format(new_help))
    
    # Find device_type choices list and add new platform (look for the specific device_type argument)
    device_type_pattern = r"(parser\.add_argument\('-d', '--device_type'[^]]+choices=\[[^\]]+)(\])"
    device_type_match = re.search(device_type_pattern, content, re.DOTALL)
    if device_type_match:
        current_choices = device_type_match.group(1)
        new_choices = "{}, '{}']".format(current_choices, new_platform)
        content = content.replace(device_type_match.group(0), new_choices)
    
    # 2. Add device type return function
    return_pattern = r"(    elif device_type == '[^']+':[\s\S]*?return '[^']+')"
    return_matches = list(re.finditer(return_pattern, content))
    if return_matches:
        last_match = return_matches[-1]
        new_return = "\n    elif device_type == '{}':\n        return '{}'".format(new_platform, new_platform)
        insertion_point = last_match.end()
        content = content[:insertion_point] + new_return + content[insertion_point:]
    
    # 3. Add base topology file selection for t0 (only if t0 is requested)
    if 't0' in topology_list:
        # Look for the specific t0 section, not t0-64 or other variants
        t0_section_pattern = r"elif topo_type == 't0':([\s\S]*?)(?=elif topo_type == 't1':|$)"
        t0_section_match = re.search(t0_section_pattern, content)
        if t0_section_match:
            t0_section = t0_section_match.group(1)
            t0_section_start = t0_section_match.start(1)
            
            # Find the last elif device_type in the t0 section only
            t0_pattern = r"(        elif device_type == '[^']+':[\s\S]*?base_topo_file = 'testbed-[^']+-t0\.yaml')"
            t0_matches = list(re.finditer(t0_pattern, t0_section))
            if t0_matches:
                last_match = t0_matches[-1]
                new_t0 = "\n        elif device_type == '{}':\n            base_topo_file = 'testbed-{}-t0.yaml'".format(new_platform, new_platform)
                # Calculate the absolute position in the full content
                insertion_point = t0_section_start + last_match.end()
                content = content[:insertion_point] + new_t0 + content[insertion_point:]
    
    # 4. Add base topology file selection for t1 (only if t1 is requested)
    if 't1' in topology_list:
        # Look for the main t1 section, not t1-lag or other variants
        t1_section_pattern = r"elif topo_type == 't1':([\s\S]*?)(?=elif topo_type == 'dualtor':|$)"
        t1_section_match = re.search(t1_section_pattern, content)
        if t1_section_match:
            t1_section = t1_section_match.group(1)
            t1_section_start = t1_section_match.start(1)
            
            # Find the last elif device_type in the t1 section only
            t1_pattern = r"(        elif device_type == '[^']+':[\s\S]*?base_topo_file = 'testbed-[^']+-t1\.yaml')"
            t1_matches = list(re.finditer(t1_pattern, t1_section))
            if t1_matches:
                last_match = t1_matches[-1]
                new_t1 = "\n        elif device_type == '{}':\n            base_topo_file = 'testbed-{}-t1.yaml'".format(new_platform, new_platform)
                # Calculate the absolute position in the full content
                insertion_point = t1_section_start + last_match.end()
                content = content[:insertion_point] + new_t1 + content[insertion_point:]
    
    # 5. Add logging information section
    log_pattern = r"(    elif device_type == '[^']+':[\s\S]*?logging\.info\(\"[^\"]*bgp_fact\.log[^\"]*\"\))"
    log_matches = list(re.finditer(log_pattern, content))
    if log_matches:
        last_match = log_matches[-1]
        new_log = "\n    elif device_type == '{}':\n        logging.info(\"Device name is {}. To execute a pytest script:\\\\n\")\n        logging.info(\"./run_tests.sh -n docker-ptf -d {}-01 -O -u -l debug -e -s -e --disable_loganalyzer -m individual -p /data/tests/logs -c bgp/test_bgp_facts.py |& tee bgp_fact.log\\\\n\")".format(new_platform, new_platform, new_platform)
        insertion_point = last_match.end()
        content = content[:insertion_point] + new_log + content[insertion_point:]
    
    # Write the updated content back to the file
    with open(script_path, 'w') as f:
        f.write(content)
    
    print("✓ Updated {} with {} platform support".format(script_path, new_platform))
    return True

def create_testbed_file(new_platform, topology_type, hwsku):
    """Create a new testbed YAML file with a generic template."""
    new_file = "testbed-{}-{}.yaml".format(new_platform, topology_type)
    
    # Create a generic template based on the topology type
    if topology_type == "t0":
        template_content = """device_groups:
  fanout:
    children:
    - fanout_cisco
  fanout_cisco:
    host:
    - nexus-5
  lab:
    children:
    - sonic
    - fanout
    vars:
      mgmt_subnet_mask_length: '24'
  ptf:
    host:
    - docker-ptf
  sonic:
    children:
    - sonic_cisco
  sonic_cisco:
    host:
    - {}-01
    vars:
      hwsku: {}
      iface_speed: '400000'
devices:
  docker-ptf:
    ansible:
      ansible_host: 192.168.122.64/24
      ansible_hostv6: fc0b::1/64
      ansible_ssh_pass: root
      ansible_ssh_user: root
    credentials:
      password: root
      username: root
    device_type: blank
    hwsku: null
  nexus-5:
    alias: null
    ansible:
      ansible_host: 10.251.0.13/23
      ansible_ssh_pass: password
      ansible_ssh_user: user
      fanout_sonic_password: password
      fanout_sonic_user: admin
    credentials:
      password: null
      username: null
    device_type: FanoutLeaf
    hwsku: Arista-7260QX-64
  str-acs-serv-01:
    alias: null
    ansible:
      ansible_become_pass: cisco123
      ansible_host: 172.17.0.1/23
      ansible_ssh_pass: cisco123
      ansible_ssh_user: vxr
      sonicadmin_initial_password: cisco123
      sonicadmin_password: cisco123
      sonicadmin_user: cisco
    credentials:
      password: cisco123
      username: vxr
    device_type: server
    hwsku: TestServ
    mgmt_subnet_mask_length: '24'
  {}-01:
    alias: null
    ansible:
      ansible_host: 192.168.122.220
      ansible_ssh_pass: password
      ansible_ssh_user: admin
    credentials:
      enable_password: password
      password: password
      username: admin
    device_type: DevSonic
    hwsku: {}
    os: sonic
docker_registry:
  docker_registry_host: sonicdev-microsoft.azurecr.io:443
  docker_registry_password: sonic
  docker_registry_username: 1dafc8d7-d19c-4f58-8653-e8d904f30dab
host_vars:
  str-acs-serv-01:
    external_port: eth0
    mgmt_bridge: br1
    mgmt_gw: 172.17.0.1
    mgmt_prefixlen: 24
testbed:
  docker-ptf:
    ansible:
      ansible_host: 192.168.122.64/24
      ansible_hostv6: fc0b::1/64
      ansible_ssh_pass: root
      ansible_ssh_user: root
    comment: Test ptf {}
    credentials:
      password: root
      username: root
    dut: {}-01
    group-name: sonic_cisco
    ptf: docker-ptf
    ptf_image_name: docker-ptf-{}
    ptf_ip: 192.168.122.64/24
    ptf_ipv6: fc0b::1/64
    server: server_1
    topo: t0
    vm_base: VM0100
testbed_config:
  alias: {}topologyTestbed
  name: testbed-{}-t0
  type: Physical
topology:
  {}-01:
    interfaces:
      Ethernet0:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/0
        VlanID: 2000
        VlanMode: Access
      Ethernet100:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/25
        VlanID: 2025
        VlanMode: Access
      Ethernet104:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/26
        VlanID: 2026
        VlanMode: Access
      Ethernet108:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/27
        VlanID: 2027
        VlanMode: Access
      Ethernet112:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/28
        VlanID: 2028
        VlanMode: Access
      Ethernet116:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/29
        VlanID: 2029
        VlanMode: Access
      Ethernet12:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/3
        VlanID: 2003
        VlanMode: Access
      Ethernet120:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/30
        VlanID: 2030
        VlanMode: Access
      Ethernet124:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/31
        VlanID: 2031
        VlanMode: Access
      Ethernet128:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/32
        VlanID: 2032
        VlanMode: Access
      Ethernet132:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/33
        VlanID: 2033
        VlanMode: Access
      Ethernet136:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/34
        VlanID: 2034
        VlanMode: Access
      Ethernet140:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/35
        VlanID: 2035
        VlanMode: Access
      Ethernet144:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/36
        VlanID: 2036
        VlanMode: Access
      Ethernet148:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/37
        VlanID: 2037
        VlanMode: Access
      Ethernet152:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/38
        VlanID: 2038
        VlanMode: Access
      Ethernet156:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/39
        VlanID: 2039
        VlanMode: Access
      Ethernet16:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/4
        VlanID: 2004
        VlanMode: Access
      Ethernet160:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/40
        VlanID: 2040
        VlanMode: Access
      Ethernet164:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/41
        VlanID: 2041
        VlanMode: Access
      Ethernet168:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/42
        VlanID: 2042
        VlanMode: Access
      Ethernet172:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/43
        VlanID: 2043
        VlanMode: Access
      Ethernet176:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/44
        VlanID: 2044
        VlanMode: Access
      Ethernet180:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/45
        VlanID: 2045
        VlanMode: Access
      Ethernet184:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/46
        VlanID: 2046
        VlanMode: Access
      Ethernet188:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/47
        VlanID: 2047
        VlanMode: Access
      Ethernet192:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/48
        VlanID: 2048
        VlanMode: Access
      Ethernet196:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/49
        VlanID: 2049
        VlanMode: Access
      Ethernet20:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/5
        VlanID: 2005
        VlanMode: Access
      Ethernet200:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/50
        VlanID: 2050
        VlanMode: Access
      Ethernet204:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/51
        VlanID: 2051
        VlanMode: Access
      Ethernet208:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/52
        VlanID: 2052
        VlanMode: Access
      Ethernet212:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/53
        VlanID: 2053
        VlanMode: Access
      Ethernet216:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/54
        VlanID: 2054
        VlanMode: Access
      Ethernet220:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/55
        VlanID: 2055
        VlanMode: Access
      Ethernet224:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/56
        VlanID: 2056
        VlanMode: Access
      Ethernet228:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/57
        VlanID: 2057
        VlanMode: Access
      Ethernet232:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/58
        VlanID: 2058
        VlanMode: Access
      Ethernet236:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/59
        VlanID: 2059
        VlanMode: Access
      Ethernet24:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/6
        VlanID: 2006
        VlanMode: Access
      Ethernet240:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/60
        VlanID: 2060
        VlanMode: Access
      Ethernet244:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/61
        VlanID: 2061
        VlanMode: Access
      Ethernet248:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/62
        VlanID: 2062
        VlanMode: Access
      Ethernet252:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/63
        VlanID: 2063
        VlanMode: Access
      Ethernet28:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/7
        VlanID: 2007
        VlanMode: Access
      Ethernet32:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/8
        VlanID: 2008
        VlanMode: Access
      Ethernet36:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/9
        VlanID: 2009
        VlanMode: Access
      Ethernet4:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/1
        VlanID: 2001
        VlanMode: Access
      Ethernet40:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/10
        VlanID: 2010
        VlanMode: Access
      Ethernet44:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/11
        VlanID: 2011
        VlanMode: Access
      Ethernet48:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/12
        VlanID: 2012
        VlanMode: Access
      Ethernet52:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/13
        VlanID: 2013
        VlanMode: Access
      Ethernet56:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/14
        VlanID: 2014
        VlanMode: Access
      Ethernet60:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/15
        VlanID: 2015
        VlanMode: Access
      Ethernet64:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/16
        VlanID: 2016
        VlanMode: Access
      Ethernet68:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/17
        VlanID: 2017
        VlanMode: Access
      Ethernet72:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/18
        VlanID: 2018
        VlanMode: Access
      Ethernet76:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/19
        VlanID: 2019
        VlanMode: Access
      Ethernet8:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/2
        VlanID: 2002
        VlanMode: Access
      Ethernet80:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/20
        VlanID: 2020
        VlanMode: Access
      Ethernet84:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/21
        VlanID: 2021
        VlanMode: Access
      Ethernet88:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/22
        VlanID: 2022
        VlanMode: Access
      Ethernet92:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/23
        VlanID: 2023
        VlanMode: Access
      Ethernet96:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1/24
        VlanID: 2024
        VlanMode: Access
veos:
  cd_image_filename: Aboot-veos-serial-8.0.0.iso
  credentials:
    password: 123456
    username: admin
  eos_ansible:
    ansible_password: 123456
    ansible_user: admin
  hdd_image_filename: vEOS-lab-4.20.15M.vmdk
  max_fp_num: 4
  memory: 2097152
  proxy_env:
    http_proxy: http://173.36.224.108:80
    https_proxy: http://173.36.224.108:80
  root_path: /home/azure/veos-vm
  skip_image_downloading: false
  vm_console_base: 7000
  vm_host_1:
    STR-ACS-SERV-01:
      ansible_host: 10.88.23.66
  vm_host_ansible:
    ansible_password: cisco123
    ansible_sudo_pass: cisco123
    ansible_user: vxr
  vm_images_url: https://acsbe.blob.core.windows.net/vmimages
  vms_1:
    VM0100:
      ansible_host: 192.168.122.38
    VM0101:
      ansible_host: 192.168.122.134
    VM0102:
      ansible_host: 192.168.122.135
    VM0103:
      ansible_host: 192.168.122.167
veos_groups:
  eos:
    children:
    - vms_1
  server_1:
    children:
    - vm_host_1
    - vms_1
    vars:
      host_var_file: host_vars/STR-ACS-SERV-01.yml
  servers:
    children:
    - server_1
    vars:
      topologies:
      - t1
      - t1-lag
      - t1-64-lag
      - t1-64-lag-clet
      - t0
      - t0-56
      - t0-52
      - ptf32
      - ptf64
      - t0-64
      - t0-64-32
      - t0-116
  vm_host:
    children:
    - vm_host_1
  vm_host_1:
    host:
    - STR-ACS-SERV-01
  vms_1:
    host:
    - VM0100
    - VM0101
    - VM0102
    - VM0103
""".format(new_platform, hwsku, new_platform, hwsku, new_platform, new_platform, new_platform, new_platform, new_platform, new_platform)
    else:  # t1
        template_content = """device_groups:
  fanout:
    children:
    - fanout_cisco
  fanout_cisco:
    host:
    - nexus-5
  lab:
    children:
    - sonic
    - fanout
    vars:
      mgmt_subnet_mask_length: '24'
  ptf:
    host:
    - docker-ptf
  sonic:
    children:
    - sonic_cisco
  sonic_cisco:
    host:
    - {}-01
    vars:
      hwsku: {}
      iface_speed: '400000'
devices:
  docker-ptf:
    ansible:
      ansible_host: 192.168.122.183/24
      ansible_hostv6: fc0b::1/64
      ansible_ssh_pass: root
      ansible_ssh_user: root
    credentials:
      password: root
      username: root
    device_type: blank
    hwsku: null
  nexus-5:
    alias: null
    ansible:
      ansible_host: 10.251.0.13/23
      ansible_ssh_pass: password
      ansible_ssh_user: user
      fanout_sonic_password: password
      fanout_sonic_user: admin
    credentials:
      password: null
      username: null
    device_type: FanoutLeaf
    hwsku: Arista-7260QX-64
  str-acs-serv-01:
    alias: null
    ansible:
      ansible_become_pass: cisco123
      ansible_host: 172.17.0.1/23
      ansible_ssh_pass: cisco123
      ansible_ssh_user: vxr
      sonicadmin_initial_password: cisco123
      sonicadmin_password: cisco123
      sonicadmin_user: cisco
    credentials:
      password: cisco123
      username: vxr
    device_type: server
    hwsku: TestServ
    mgmt_subnet_mask_length: '24'
  {}-01:
    alias: null
    ansible:
      ansible_host: 192.168.122.33
      ansible_ssh_pass: password
      ansible_ssh_user: admin
    credentials:
      enable_password: password
      password: password
      username: admin
    device_type: DevSonic
    hwsku: {}
    os: sonic
docker_registry:
  docker_registry_host: sonicdev-microsoft.azurecr.io:443
  docker_registry_password: sonic
  docker_registry_username: 1dafc8d7-d19c-4f58-8653-e8d904f30dab
host_vars:
  str-acs-serv-01:
    external_port: eth0
    mgmt_bridge: br1
    mgmt_gw: 172.17.0.1
    mgmt_prefixlen: 24
testbed:
  docker-ptf:
    ansible:
      ansible_host: 192.168.122.183/24
      ansible_hostv6: fc0b::1/64
      ansible_ssh_pass: root
      ansible_ssh_user: root
    comment: Test ptf {}
    credentials:
      password: root
      username: root
    dut: {}-01
    group-name: sonic_cisco
    ptf: docker-ptf
    ptf_image_name: docker-ptf-{}
    ptf_ip: 192.168.122.183/24
    ptf_ipv6: fc0b::1/64
    server: server_1
    topo: t1
    vm_base: VM0100
testbed_config:
  alias: {}Testbed
  name: testbed-{}-t1
  type: Physical
topology:
  {}-01:
    interfaces:
      Ethernet0:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2000
        VlanMode: Access
      Ethernet100:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2025
        VlanMode: Access
      Ethernet104:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2026
        VlanMode: Access
      Ethernet108:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2027
        VlanMode: Access
      Ethernet112:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2028
        VlanMode: Access
      Ethernet116:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2029
        VlanMode: Access
      Ethernet12:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2003
        VlanMode: Access
      Ethernet120:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2030
        VlanMode: Access
      Ethernet124:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2031
        VlanMode: Access
      Ethernet16:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2004
        VlanMode: Access
      Ethernet20:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2005
        VlanMode: Access
      Ethernet24:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2006
        VlanMode: Access
      Ethernet28:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2007
        VlanMode: Access
      Ethernet32:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2008
        VlanMode: Access
      Ethernet36:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2009
        VlanMode: Access
      Ethernet4:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2001
        VlanMode: Access
      Ethernet40:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2010
        VlanMode: Access
      Ethernet44:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2011
        VlanMode: Access
      Ethernet48:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2012
        VlanMode: Access
      Ethernet52:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2013
        VlanMode: Access
      Ethernet56:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2014
        VlanMode: Access
      Ethernet60:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2015
        VlanMode: Access
      Ethernet64:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2016
        VlanMode: Access
      Ethernet68:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2017
        VlanMode: Access
      Ethernet72:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2018
        VlanMode: Access
      Ethernet76:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2019
        VlanMode: Access
      Ethernet8:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2002
        VlanMode: Access
      Ethernet80:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2020
        VlanMode: Access
      Ethernet84:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2021
        VlanMode: Access
      Ethernet88:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2022
        VlanMode: Access
      Ethernet92:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2023
        VlanMode: Access
      Ethernet96:
        Bandwidth: 400000
        EndDevice: nexus-5
        EndPort: Ethernet1
        VlanID: 2024
        VlanMode: Access
veos:
  cd_image_filename: Aboot-veos-serial-8.0.0.iso
  credentials:
    password: 123456
    username: admin
  eos_ansible:
    ansible_password: 123456
    ansible_user: admin
  hdd_image_filename: vEOS-lab-4.20.15M.vmdk
  max_fp_num: 4
  memory: 2097152
  proxy_env:
    http_proxy: http://173.36.224.108:80
    https_proxy: http://173.36.224.108:80
  root_path: /home/azure/veos-vm
  skip_image_downloading: false
  vm_console_base: 7000
  vm_host_1:
    STR-ACS-SERV-01:
      ansible_host: 10.89.172.177
  vm_host_ansible:
    ansible_password: cisco123
    ansible_sudo_pass: cisco123
    ansible_user: vxr
  vm_images_url: https://acsbe.blob.core.windows.net/vmimages
  vms_1:
    VM0100:
      ansible_host: 192.168.122.244
    VM0101:
      ansible_host: 192.168.122.178
    VM0102:
      ansible_host: 192.168.122.158
    VM0103:
      ansible_host: 192.168.122.117
    VM0104:
      ansible_host: 192.168.122.144
    VM0105:
      ansible_host: 192.168.122.47
    VM0106:
      ansible_host: 192.168.122.110
    VM0107:
      ansible_host: 192.168.122.25
    VM0108:
      ansible_host: 192.168.122.44
    VM0109:
      ansible_host: 192.168.122.236
    VM0110:
      ansible_host: 192.168.122.247
    VM0111:
      ansible_host: 192.168.122.148
    VM0112:
      ansible_host: 192.168.122.34
    VM0113:
      ansible_host: 192.168.122.184
    VM0114:
      ansible_host: 192.168.122.241
    VM0115:
      ansible_host: 192.168.122.66
    VM0116:
      ansible_host: 192.168.122.50
    VM0117:
      ansible_host: 192.168.122.6
    VM0118:
      ansible_host: 192.168.122.60
    VM0119:
      ansible_host: 192.168.122.12
    VM0120:
      ansible_host: 192.168.122.161
    VM0121:
      ansible_host: 192.168.122.26
    VM0122:
      ansible_host: 192.168.122.32
    VM0123:
      ansible_host: 192.168.122.61
    VM0124:
      ansible_host: 192.168.122.90
    VM0125:
      ansible_host: 192.168.122.196
    VM0126:
      ansible_host: 192.168.122.46
    VM0127:
      ansible_host: 192.168.122.89
    VM0128:
      ansible_host: 192.168.122.97
    VM0129:
      ansible_host: 192.168.122.173
    VM0130:
      ansible_host: 192.168.122.45
    VM0131:
      ansible_host: 192.168.122.35
veos_groups:
  eos:
    children:
    - vms_1
  server_1:
    children:
    - vm_host_1
    - vms_1
    vars:
      host_var_file: host_vars/STR-ACS-SERV-01.yml
  servers:
    children:
    - server_1
    vars:
      topologies:
      - t1
      - t1-lag
      - t1-64-lag
      - t1-64-lag-clet
      - t0
      - t0-56
      - t0-52
      - ptf32
      - ptf64
      - t0-64
      - t0-64-32
      - t0-116
  vm_host:
    children:
    - vm_host_1
  vm_host_1:
    host:
    - STR-ACS-SERV-01
  vms_1:
    host:
    - VM0100
    - VM0101
    - VM0102
    - VM0103
    - VM0104
    - VM0105
    - VM0106
    - VM0107
    - VM0108
    - VM0109
    - VM0110
    - VM0111
    - VM0112
    - VM0113
    - VM0114
    - VM0115
    - VM0116
    - VM0117
    - VM0118
    - VM0119
    - VM0120
    - VM0121
    - VM0122
    - VM0123
    - VM0124
    - VM0125
    - VM0126
    - VM0127
    - VM0128
    - VM0129
    - VM0130
    - VM0131
""".format(new_platform, hwsku, new_platform, hwsku, new_platform, new_platform, new_platform, new_platform, new_platform, new_platform)
    
    # Write the new file
    with open(new_file, 'w') as f:
        f.write(template_content)
    
    print("✓ Created {}".format(new_file))
    return True

def create_vxr_topo_file(new_platform, topology_type, hwsku):
    """Create a new VXR topology YAML file based on the topology type."""
    new_file = "../pyvxr_yaml_files/{}_sonic_{}_topo.yaml".format(new_platform, topology_type)
    
    # Remove "Cisco" keyword from hwsku for linecard_types
    linecard_type = hwsku
    if hwsku.startswith("Cisco-"):
        linecard_type = hwsku[6:]  # Remove "Cisco-" prefix
    elif "Cisco" in hwsku:
        linecard_type = hwsku.replace("Cisco-", "").replace("Cisco", "")
    
    # Determine the number of veos devices based on topology
    if topology_type == "t0":
        veos_range = "1..4"
        veos_count = 4
    else:  # t1
        veos_range = "1..32"
        veos_count = 32
    
    template_content = """simulation:
  no_image_copy: false
  slurm_flags:
    pending_timeout: 60
    hours: 20
    partition: regression
    cluster: rch-slurm-m1

devices:
  docker_ptf:
    platform: linux
    image: /auto/vxr/vxr_images/onie-sonic/ptf_docker_v4.qcow2
    linux_username: root
    linux_password: lab
    linux_prompt: root@docker-ptf:~#
    xr_port_redir: [22]
    extended_pci_bus: true
    vcpu: 4
    memory: '8G'
    mgmt_intf_name: mgmt
    data_ports:
      - eth[0..32]
      - backplane

  sonic_dut:
    platform: spitfire_f
    os_type: sonic
    pre_cli: |
      sudo bash -c "echo 'net.core.rmem_default = 16777216' >> /etc/sysctl.conf"
      sudo bash -c "echo 'net.core.wmem_default = 16777216' >> /etc/sysctl.conf"
      sudo sysctl -p
    xr_port_redir: [22]
    linux_username: "admin"
    linux_password: "password"
    vcpu: 10
    memory: '20G'
    linecard_types: ['{}']
    npu_asic_versions: [A0]
    image: /auto/vxr/images/onie-sonic/onie-recovery-x86_64-cisco_8000-r0-2020.11br.iso
    onie-install: /auto/vxr1/aaktiwar/sonic-cisco-8000_31324.bin
    port_breakout:
       lc0:
          0..63: 2x400

  sonic_mgmt:
    platform: linux
    xr_port_redir: [22]
    image: /globalnobackup/sonic/ubuntu1804_mgt.qcow2
    linux_username: 'vxr'
    linux_password: 'cisco123'
    linux_prompt: 'vxr@vxr-vm:~\\$'
    vcpu: 10
    memory: '20G'

device_groups:
  veos:
    devices:
      - "veos[{}]"
    platform: veos
    xr_port_redir: [22]
    image: /auto/vxr/images/veos/Aboot-veos-serial-8.0.0.iso
    disks:
      - hda:
          file: /auto/vxr/images/veos/vEOS-lab-4.24.1.1F.qcow2
          type: reference

connections:""".format(linecard_type, veos_range)
    
    if topology_type == "t0":
        # Add t0 specific connections (hubs + custom)
        template_content += """
   hubs:
    hub0_0:
    - docker_ptf.eth[0..1]
    - sonic_dut.Ethernet0/[0..1]
    hub0_1:
    - docker_ptf.eth[2..3]
    - sonic_dut.Ethernet1/[0..1]
    hub0_2:
    - docker_ptf.eth[4..5]
    - sonic_dut.Ethernet2/[0..1]
    hub0_3:
    - docker_ptf.eth[6..7]
    - sonic_dut.Ethernet3/[0..1]
    hub0_4:
    - docker_ptf.eth[8..9]
    - sonic_dut.Ethernet4/[0..1]
    hub0_5:
    - docker_ptf.eth[10..11]
    - sonic_dut.Ethernet5/[0..1]
    hub0_6:
    - docker_ptf.eth[12..13]
    - sonic_dut.Ethernet6/[0..1]
    hub0_7:
    - docker_ptf.eth[14..15]
    - sonic_dut.Ethernet7/[0..1]
    hub0_8:
    - docker_ptf.eth[16..17]
    - sonic_dut.Ethernet8/[0..1]
    hub0_9:
    - docker_ptf.eth[18..19]
    - sonic_dut.Ethernet9/[0..1]
    hub0_10:
    - docker_ptf.eth[20..21]
    - sonic_dut.Ethernet10/[0..1]
    hub0_11:
    - docker_ptf.eth[22..23]
    - sonic_dut.Ethernet11/[0..1]
    hub0_12:
    - docker_ptf.eth[24..25]
    - sonic_dut.Ethernet12/[0..1]
    hub0_13:
    - docker_ptf.eth[26..27]
    - sonic_dut.Ethernet13/[0..1]
   custom:
    ptf_injected29:
      ports:
      - docker_ptf.eth28
      - sonic_dut.Ethernet14/0
      - veos1.Ethernet1
    ptf_injected30:
      ports:
      - docker_ptf.eth29
      - sonic_dut.Ethernet14/1
      - veos2.Ethernet1
    ptf_injected31:
      ports:
      - docker_ptf.eth30
      - sonic_dut.Ethernet15/0
      - veos3.Ethernet1
    ptf_injected32:
      ports:
      - docker_ptf.eth31
      - sonic_dut.Ethernet15/1
      - veos4.Ethernet1
    backplane:
      ports:
      - veos[1..4].Ethernet9
      - docker_ptf.backplane
"""
    else:  # t1
        # Add t1 specific connections (only custom, no hubs)
        template_content += """
    custom:"""
        
        # Generate 32 ptf_injected connections for t1
        for i in range(1, 33):
            eth_num = i - 1
            ethernet_port = (i - 1) // 2
            sub_port = (i - 1) % 2
            template_content += """
      ptf_injected{}:
        ports:
        - docker_ptf.eth{}
        - sonic_dut.Ethernet{}/{}
        - veos{}.Ethernet1""".format(i, eth_num, ethernet_port, sub_port, i)
        
        template_content += """
      backplane:
        ports:
        - veos[1..32].Ethernet9
        - docker_ptf.backplane
"""
    
    # Write the new file
    with open(new_file, 'w') as f:
        f.write(template_content)
    
    print("✓ Created {}".format(new_file))
    return True

def validate_topology(topology_str):
    """Validate that the topology parameter is valid."""
    if not topology_str:
        return False, "Topology cannot be empty"
    
    # Split by comma and strip whitespace
    topologies = [t.strip() for t in topology_str.split(',')]
    
    # Check for valid topology types
    valid_topologies = ['t0', 't1']
    for topo in topologies:
        if topo not in valid_topologies:
            return False, "Invalid topology '{}'. Valid options are: {}".format(topo, ', '.join(valid_topologies))
    
    # Check for duplicates
    if len(topologies) != len(set(topologies)):
        return False, "Duplicate topology types are not allowed"
    
    if len(topologies) == 0:
        return False, "At least one topology type must be specified"
    
    return True, ""

def validate_platform_name(platform_name):
    """Validate that the platform name is valid."""
    if not platform_name:
        return False, "Platform name cannot be empty"
    
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]*$', platform_name):
        return False, "Platform name must start with a letter and contain only letters, numbers, hyphens, and underscores"
    
    if len(platform_name) > 50:
        return False, "Platform name must be 50 characters or less"
    
    return True, ""

def check_platform_exists(platform_name):
    """Check if the platform already exists in the system."""
    script_path = "create_sonic_topo.py"
    
    if not os.path.exists(script_path):
        return False
    
    with open(script_path, 'r') as f:
        content = f.read()
    
    # Check if platform is already in choices
    choices_pattern = r"choices=\[[^\]]*'" + re.escape(platform_name) + r"'[^\]]*\]"
    if re.search(choices_pattern, content):
        return True
    
    return False

def main():
    parser = argparse.ArgumentParser(
        description="Add a new platform to the sonic test infrastructure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 add_new_platform.py titan Cisco-8223-64E-MO t0
  python3 add_new_platform.py titan Cisco-8223-64E-MO t1
  python3 add_new_platform.py titan Cisco-8223-64E-MO t0,t1
        """
    )
    
    parser.add_argument(
        'platform_name',
        help='Name of the new platform to add'
    )
    
    parser.add_argument(
        'hwsku',
        help='Hardware SKU for the platform (e.g., Cisco-8223-64EF-MO, Cisco-8000-Series)'
    )
    
    parser.add_argument(
        'topology',
        help='Topology type(s) to create: t0, t1, or t0,t1 (comma-separated for multiple)'
    )
    
    args = parser.parse_args()
    
    # Validate platform name
    is_valid, error_msg = validate_platform_name(args.platform_name)
    if not is_valid:
        print("Error: {}".format(error_msg))
        sys.exit(1)
    
    # Validate topology
    is_valid, error_msg = validate_topology(args.topology)
    if not is_valid:
        print("Error: {}".format(error_msg))
        sys.exit(1)
    
    # Parse topology list
    topology_list = [t.strip() for t in args.topology.split(',')]
    
    # Check if platform already exists
    if check_platform_exists(args.platform_name):
        print("Error: Platform '{}' already exists.".format(args.platform_name))
        sys.exit(1)
    
    print("Adding new platform: {}".format(args.platform_name))
    print("Hardware SKU: {}".format(args.hwsku))
    print("Topology: {}".format(args.topology))
    print("-" * 50)
    
    success = True
    created_files = []
    
    # 1. Update create_sonic_topo.py
    try:
        if not update_create_sonic_topo(args.platform_name, topology_list):
            success = False
    except Exception as e:
        print("✗ Failed to update create_sonic_topo.py: {}".format(e))
        success = False
    else:
        created_files.append("create_sonic_topo.py (modified)")
    
    # 2. Create testbed files based on topology parameter
    if 't0' in topology_list:
        try:
            if not create_testbed_file(args.platform_name, "t0", args.hwsku):
                success = False
        except Exception as e:
            print("✗ Failed to create t0 testbed file: {}".format(e))
            success = False
        else:
            created_files.append("testbed-{}-t0.yaml (created)".format(args.platform_name))
    
    if 't1' in topology_list:
        try:
            if not create_testbed_file(args.platform_name, "t1", args.hwsku):
                success = False
        except Exception as e:
            print("✗ Failed to create t1 testbed file: {}".format(e))
            success = False
        else:
            created_files.append("testbed-{}-t1.yaml (created)".format(args.platform_name))
    
    # 3. Create VXR topology files based on topology parameter
    if 't0' in topology_list:
        try:
            if not create_vxr_topo_file(args.platform_name, "t0", args.hwsku):
                success = False
        except Exception as e:
            print("✗ Failed to create t0 VXR topology file: {}".format(e))
            success = False
        else:
            created_files.append("{}_sonic_t0_topo.yaml (created)".format(args.platform_name))
    
    if 't1' in topology_list:
        try:
            if not create_vxr_topo_file(args.platform_name, "t1", args.hwsku):
                success = False
        except Exception as e:
            print("✗ Failed to create t1 VXR topology file: {}".format(e))
            success = False
        else:
            created_files.append("{}_sonic_t1_topo.yaml (created)".format(args.platform_name))
    
    print("-" * 50)
    if success:
        print("✓ Successfully added platform '{}'!".format(args.platform_name))
        print("\nFiles created/modified:")
        for file_info in created_files:
            print("  - {}".format(file_info))
        print("\nNote: The generated testbed files contain basic templates.")
        print("You may need to customize them based on your specific hardware configuration.")
    else:
        print("✗ Some operations failed. Please check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
