from ipaddress import ip_address, ip_network

class Fdb():
    def __init__(self, file_path):

        self._arp_dict = {}
        self._vlan_dict = {}

        with open(file_path, 'r') as f:
            for line in f.readlines():
                entry = line.split(' ', 1)
                prefix = ip_network(unicode(entry[0]))
                self._vlan_dict[prefix] = [int(i) for i in entry[1].split()]

    def insert(self, mac, member):
        self._arp_dict[member] = mac

    def get_vlan_table(self):
        return self._vlan_dict

    def get_arp_table(self):
        return self._arp_dict
