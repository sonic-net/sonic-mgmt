import SocketServer
import pickle
import socket
import argparse
import yaml
import datetime
import os.path
from pprint import pprint


g_log_fp = None


def log(message, output_on_console=False):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if output_on_console:
        print "%s : %s" % (current_time, message)
    global g_log_fp
    if g_log_fp is not None:
        g_log_fp.write("%s : %s\n" % (current_time, message))
        g_log_fp.flush()


class TCPHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        data = pickle.load(self.rfile)
        log("Received request: %s" % str(data))
        key = self.client_address[0], data['intf']
        if key in self.server.x_table:
            value = self.server.x_table[key]
            conn = Conn(value[0])
            data['intf'] = value[1]
            log("Send data %s to %s" % (str(value[0]), str(data)))
            conn.write(data)
            data = conn.read()
            log("Received reply %s" % str(data))
        else:
            data = {'status': 'OK'}
        data = {'status': 'OK'}
        log("Send reply %s" % str(data))
        pickle.dump(data, self.wfile, pickle.HIGHEST_PROTOCOL)


class Conn(object):
    def __init__(self, ip):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((ip, 9876))

    def __del__(self):
        self.conn.close()

    def read(self):
        fp = self.conn.makefile('rb', 1024)
        data = pickle.load(fp)
        fp.close()
        return data

    def write(self, data):
        fp = self.conn.makefile('wb', 1024)
        pickle.dump(data, fp, pickle.HIGHEST_PROTOCOL)
        fp.close()


def parse_links(dut):
    candidates = ['sonic_str_links.csv', 'sonic_lab_links.csv']
    # find what files exists before opening
    target = None
    for filename in candidates:
        if os.path.exists(filename):
            target = filename
            break
    with open(target) as fp:
        all = fp.read()
    rows = all.split("\n")[1:]

    devices = []
    dut_ports = []
    mapping = {}

    for r in rows:
        if r == '':
            continue
        if dut not in r:
            continue
        values = r.split(',')
        target_device = values[0]
        target_port = values[1]
        fanout_device = values[2]
        fanout_port = values[3]
        if target_device == dut:
            devices.append(fanout_device)
            mapping[(fanout_device, fanout_port)] = target_port
            dut_ports.append(target_port)

    dut_ports = sorted(dut_ports, cmp=lambda x,y: cmp(int(x.replace('Ethernet', '')), int(y.replace('Ethernet', ''))))

    return devices, dut_ports, mapping

def parse_devices(device_names):
    ip_name = {}
    candidates = ['sonic_str_devices.csv', 'sonic_lab_devices.csv']
    # find what files exists before opening
    target = None
    for filename in candidates:
        if os.path.exists(filename):
            target = filename
            break
    with open(target) as fp:
        all = fp.read()
    rows = all.split("\n")
    for r in rows:
        if r == '':
            continue
        values = r.split(',')
        name = values[0]
        if name not in device_names:
            continue
        ip_prefix = values[1]
        ip_name[name] = ip_prefix.split('/')[0]

    return ip_name

def parse_veos(vms):
    mapping = {}
    with open('veos') as fp:
        all = fp.read()
    rows = all.split('\n')
    for r in rows:
        r = r.strip()
        if r == '':
            continue
        if not r.startswith('VM'):
            continue
        name, ansible_host = r.split(' ')
        if name not in vms:
            continue
        address = ansible_host.split('=')[1]
        mapping[name] = address 

    return mapping

def generate_vm_mappings(vms, base_vm, dut_ports, vm_2_ip):
    base_vm_id = int(base_vm[2:])
    required_ports = {}
    for vm_offset, ports in vms.items():
        vm = 'VM%04d' % (base_vm_id + vm_offset)
        vm_ip = vm_2_ip[vm] 
        p = {dut_ports[port]: (vm_ip, 'Ethernet%d' % (offset + 1)) for offset, port in enumerate(ports)}
        required_ports.update(p)

    return required_ports

def generate_vm_port_mapping(vm_base):
    with open('topo.yaml') as fp:
        data = yaml.load(fp)

    base = int(vm_base.replace("VM", ""))

    vm_ports = {v['vm_offset']:v['vlans'] for v in data['topology']['VMs'].values()}
    vm_list  = ["VM%04d" % (base + p) for p in sorted(vm_ports.keys())]

    return vm_ports, vm_list
           
def merge(fanout_mappings, fanout_name_2_ip, vm_mappings):
    return {(fanout_name_2_ip[fanout_name], fanout_port) : vm_mappings[dut_port]  for (fanout_name, fanout_port), dut_port in fanout_mappings.iteritems() if dut_port in vm_mappings}

def generate_x_table(base_vm, dut):
    devices, dut_ports, mapping = parse_links(dut)
    fanout_name_2_ip = parse_devices(devices)
    vm_ports, vm_list = generate_vm_port_mapping(base_vm)
    vm_2_ip = parse_veos(vm_list)
    vm_mappings = generate_vm_mappings(vm_ports, base_vm, dut_ports, vm_2_ip)
    target = merge(mapping, fanout_name_2_ip, vm_mappings)

    return target

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("vm_base", type=str, help="vm_base parameter")
    parser.add_argument("dut",     type=str, help="dut parameter")
    args = parser.parse_args()
    base_vm = args.vm_base
    dut = args.dut

    global g_log_fp
    g_log_fp = open("/tmp/ptf_proxy.log", "w")

    x_table = generate_x_table(base_vm, dut)

    server = SocketServer.TCPServer(("0.0.0.0", 9877), TCPHandler)
    server.request_queue_size = 64
    server.allow_reuse_address = True
    server.x_table = x_table
    server.serve_forever()

    return

if __name__ == '__main__':
    main()

