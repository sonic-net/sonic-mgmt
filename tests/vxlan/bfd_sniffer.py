"""
This bfd sniffer captures bfd packets on all PTF interfaces and
creates a json file for bfd_responder to use
"""
from scapy.all import *
import sys 
import json 
try:
    delete_member_a1 = sys.argv[1]
    delete_member_a2 = sys.argv[2]
except:
    print("Test will proceed even if we do not pass argument")
ifaces = get_if_list()
def return_bfd_interfaces():
    # Captures 5 BFD packets on every ptf port & returns a dictionary with interfaces & source address
    bfd_interfaces = {}
    for iface in ifaces:
        if iface.startswith("eth"):
            print(("Verification of BFD packets on interface - {}".format(iface)))
            output = sniff(iface=iface,filter="udp", count=5, timeout=5)
            for pkt in output:
                if pkt.haslayer(UDP):
                    if pkt.haslayer(IP): 
                        bfd_interfaces[pkt[IP].dst] = {"src":pkt[IP].src, "iface":iface}
                    elif pkt.haslayer(IPv6): 
                        bfd_interfaces[pkt[IPv6].dst] = {"src":pkt[IPv6].src, "iface":iface}
    return bfd_interfaces
bfd_interfaces = return_bfd_interfaces()
print(bfd_interfaces)
ptf_config = []
for key,value in list(bfd_interfaces.items()):
    ptf_config.append(
            {
                "neighbor_addr": value['src'],
                "local_addr" : key ,
                "multihop" : "true",
                "ptf_intf" : value['iface']
            }
        )
if delete_member_a1 is not None:
    for i in range(len(ptf_config)):
        if ptf_config[i]['local_addr'] == delete_member_a1:
            del ptf_config[i]
            break
if delete_member_a2 is not None:
    for i in range(len(ptf_config)):
        if ptf_config[i]['local_addr'] == delete_member_a2:
            del ptf_config[i]
            break
print(ptf_config)
with open("/tmp/ptf_config.json", "w") as f:
    json.dump(ptf_config, f)