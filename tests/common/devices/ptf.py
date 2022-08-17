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

    def add_ip_to_dev(self, dev, ip):
        """
        @summary: add ip to dev

        @param dev: device name
        @param ip: ip to be added
        """
        self.command("ip addr add {} dev {}".format(ip, dev))

    def create_lag(self, lag_name, lag_ip, lag_mode):
        """
        @summary: create a lag as intf, only if after running add_intf_to_lag and startup_lag the lag can work

        @param lag_name: name of lag
        @param lag_ip: ip of lag
        @param lag_mode: mode of lag
        """
        self.command("ip link add {} type bond".format(lag_name))
        self.command("ip link set {} type bond miimon 100 mode {}".format(lag_name, lag_mode))
        self.add_ip_to_dev(lag_name, lag_ip)

    def add_intf_to_lag(self, lag_name, intf_name):
        """
        @summary: set interface down and master lag

        @param lag_name: name of lag
        @param intf_name: mode of interface
        """
        self.set_dev_up_or_down(intf_name, False)
        self.command("ip link set {} master {}".format(intf_name, lag_name))

    def startup_lag(self, lag_name):
        """
        @summary: startup lag

        @param lag_name: name of lag
        """
        self.set_dev_up_or_down(lag_name, True)

    def set_dev_up_or_down(self, dev_name, is_up):
        """
        @summary: set device up or down

        @param dev_name: name of devices
        @param is_up: True -> set device up, False -> set device down
        """
        self.command("ip link set {} {}".format(dev_name, "up" if is_up else "down"))

    def set_dev_no_master(self, dev_name):
        """
        @summary: set device no master

        @param dev_name: name of device
        """
        self.command("ip link set {} nomaster".format(dev_name))

    def ptf_nn_agent(self):
        self.command("supervisorctl restart ptf_nn_agent")

    # TODO: Add a method for running PTF script
