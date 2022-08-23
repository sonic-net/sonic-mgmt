from scapy.all import *
import sys, json
ifaces = get_if_list()
def return_bfd_interfaces():
    bfd_interfaces = {}
    for iface in ifaces:
        if iface.startswith("eth"):
            print("Verification of BFD packets on interface - {}".format(iface))
            output = sniff(iface=iface,filter="udp", count=2, timeout=2)
            for pkt in output:
                if pkt.haslayer(UDP):
                    if pkt.haslayer(IP): 
                        bfd_interfaces[iface] = {"src":pkt[IP].src, "dest":pkt[IP].dst}
                    elif pkt.haslayer(IPv6): 
                        bfd_interfaces[iface] = {"src":pkt[IPv6].src, "dest":pkt[IPv6].dst}
    return bfd_interfaces
bfd_interfaces = return_bfd_interfaces()
ptf_config = []
for ptf_intf,ip_address in bfd_interfaces.items():
    ptf_config.append(
            {
                "neighbor_addr": ip_address['src'],
                "local_addr" :ip_address['dest'] ,
                "multihop" : "true",
                "ptf_intf" : ptf_intf
            }
        )
with open("/tmp/ptf_config.json", "w") as f:
    json.dump(ptf_config, f)
