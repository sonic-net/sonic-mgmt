#!/usr/bin/python

# When there're no enough space on the disk, libvirt pauses some VMs.
# This tool unpauses all paused VMs and rewire all connections back


from pprint import pprint
import subprocess
from collections import defaultdict
import re
import libvirt
import time
import sys


def resume_paused():
    MAX_ATTEMPTS = 10

    conn = libvirt.open("qemu:///system")
    if conn == None:
        print 'Failed to open connection to qemu:///system'
        exit(1)

    paused = [i.name() for i in conn.listAllDomains() if i.info()[0] == libvirt.VIR_DOMAIN_PAUSED]

    if len(paused) > 0:
        print "Following VM are paused"
        print "\n".join(paused)
        print

    for vm in paused:
        print "Resume VM: " + vm.name()
        vm.resume()

    for _ in range(MAX_ATTEMPTS):
        if len([i for i in conn.listAllDomains() if i.info()[0] == libvirt.VIR_DOMAIN_PAUSED]) == 0:
            break
        time.sleep(1)
    else:
        print "Can't resume VMs:%s" % ", ".join(i.name() for i in conn.listAllDomains() if i.info()[0] == libvirt.VIR_DOMAIN_PAUSED)
        paused = []

    conn.close()

    return paused

def cmd(cmdline):
    cmd = cmdline.split(' ')
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    ret_code = process.returncode

    if ret_code != 0:
        raise Exception("ret_code=%d, error message=%s. cmd=%s" % (ret_code, stderr, cmdline))

    return stdout

def get_list_of_bridges(vm):
    bridges = cmd("ovs-vsctl list-br")
    return [br for br in bridges.split("\n") if vm in br]

def get_list_of_ports(bridge):
    ports = cmd("ovs-vsctl list-ports %s" % bridge)
    return ports.split("\n")[:-1]

def extract_changing_ports(ports):
    result = {}
    for br in ports.keys():
        of_rules = cmd("ovs-ofctl dump-flows %s" % br)
        if "NORMAL" not in of_rules:
            result[br] = ports[br]
    return result

def get_port_id(ports):
    port_map = defaultdict(dict)
    port_re = re.compile(r"^\s*(\d+)\((\S+)\): .*$")
    for br in ports.keys():
        output = cmd("ovs-ofctl show %s" % br)
        for line in output.split("\n"):
            m = port_re.match(line)
            if m:
                port_map[br][m.group(2)] = m.group(1)

    return port_map

def cmd1(cmd):
    print cmd


def reassign_ports(port_map, vm):
    for br, mapping in port_map.items():
        pprint(mapping)
        injected_iface_id = None
        vm_iface_id = None
        vlan_iface_id = None
        for name, idx in mapping.items():
            if vm in name:
                vm_iface_id = idx
            if 'inje' in name:
                injected_iface_id = idx
            if '.' in name:
                vlan_iface_id = idx

        #assert(injected_iface_id is None or vm_iface_id is None or vlan_iface_id is None)
        #assert(injected_iface_id is None)
        #assert(vm_iface_id is None)
        #assert(vlan_iface_id is None)
        # clear old bindings
        cmd('ovs-ofctl del-flows %s' % br)

        # Add flow from a VM to an external iface
        cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s" % (br, vm_iface_id, vlan_iface_id))

        # Add flow from external iface to a VM and a ptf container
        cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s,%s" % (br, vlan_iface_id, vm_iface_id, injected_iface_id))

        # Add flow from a ptf container to an external iface
        cmd("ovs-ofctl add-flow %s table=0,in_port=%s,action=output:%s" % (br, injected_iface_id, vlan_iface_id))

    return


def main():
    vms = resume_paused()
    for vm in vms:
      bridges = get_list_of_bridges(vm)
      ports = {br:get_list_of_ports(br) for br in bridges}
      changing_ports = extract_changing_ports(ports)
      port_map = get_port_id(changing_ports)
      reassign_ports(port_map, vm)

    return

if __name__ == '__main__':
    main()
