from scapy.all import *
import sys, json
ifaces = get_if_list()
def return_bfd_interfaces():
    bfd_interfaces = {}
    for iface in ifaces:
        if iface.startswith("eth"):
            print("Verification of BFD packets on interface - {}".format(iface))
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
for key,value in bfd_interfaces.items():
    ptf_config.append(
            {
                "neighbor_addr": value['src'],
                "local_addr" : key ,
                "multihop" : "true",
                "ptf_intf" : value['iface']
            }
        )
with open("/tmp/ptf_config.json", "w") as f:
    json.dump(ptf_config, f)
