from tests.common.devices.base import AnsibleHostBase

CHANGE_MAC_ADDRESS_SCRIPT = "scripts/change_mac.sh"
REMOVE_IP_ADDRESS_SCRIPT = "scripts/remove_ip.sh"



class PTFHost(AnsibleHostBase):
    """
    @summary: Class for PTF

    Instance of this class can run ansible modules on the PTF host.
    """
    def __init__(self, ansible_adhoc, hostname):
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)

    def change_mac_addresses(self):
        self.script(CHANGE_MAC_ADDRESS_SCRIPT)

    def remove_ip_addresses(self):
        self.script(REMOVE_IP_ADDRESS_SCRIPT)

    # TODO: Add a method for running PTF script
