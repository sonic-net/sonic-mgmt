import logging
import pickle
import tempfile

from tests.common.devices.base import AnsibleHostBase
from tests.macsec.macsec_helper import load_macsec_info

logger = logging.getLogger(__name__)

CHANGE_MAC_ADDRESS_SCRIPT = "scripts/change_mac.sh"
REMOVE_IP_ADDRESS_SCRIPT = "scripts/remove_ip.sh"
MACSEC_INFO_FILE = "macsec_info.pickle"



class PTFHost(AnsibleHostBase):
    """
    @summary: Class for PTF

    Instance of this class can run ansible modules on the PTF host.
    """

    def __init__(self, ansible_adhoc, hostname, duthost, tbinfo, macsec_enabled=False):
        self.duthost = duthost
        self.tbinfo = tbinfo
        self.macsec_enabled = macsec_enabled
        AnsibleHostBase.__init__(self, ansible_adhoc, hostname)

    def change_mac_addresses(self):
        self.script(CHANGE_MAC_ADDRESS_SCRIPT)

    def remove_ip_addresses(self):
        self.script(REMOVE_IP_ADDRESS_SCRIPT)

    def create_macsec_info(self):
        macsec_info = {}
        for port_name, injected_port_id in self.duthost.get_extended_minigraph_facts(self.tbinfo)["minigraph_ptf_indices"].items():
            try:
                macsec_info[injected_port_id] = load_macsec_info(
                    self.duthost, port_name, force_reload=True)
            except KeyError:
                # If key error, It means the MACsec info isn't enabled in the specified port.
                logging.info(
                    "MACsec isn't enabled on the port {}".format(port_name))
                continue
        tf = tempfile.NamedTemporaryFile(delete=True)
        pickle.dump(macsec_info, tf)
        tf.flush()
        self.copy(src=tf.name, dest="/root/" + MACSEC_INFO_FILE)

    # TODO: Add a method for running PTF script
