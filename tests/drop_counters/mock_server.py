"""
Utilities for mocking a server using PTF.
"""

import logging
import time

from common.platform.device_utils import fanout_switch_port_lookup

class MockServer(object):
    """
    Mocks the presence of a server connected to the DUT.

    "Starting" the server will populate the FDB and ARP tables, allowing for realistic traffic
    forwarding behavior in the DUT.
    """
    def __init__(self, server_addr, server_prefix, neighbor_addr, neighbor_iface, neighbor_port,
                 ptfhost, fanouthosts):
        """
        Initializes the server.

        Args:
            server_addr (IPAddress): The IP address of the server.
            server_prefix (int): The network prefix of the server.
            neighbor_addr (IPAddress): The IP address of the device the server is connected to
                (typically an IP interface in SONiC).
            neighbor_iface (str): The interface associated with the `neighbor_addr`.
            neighbor_port (int): The port number associated with the `neighbor_iface`.
            ptfhost (PTFHost): The PTF host where the server is being mocked.
            fanouthosts (list[FanoutHost]): The fanouts that are connected to the PTF and DUT
                in this testbed setup.
        """
        self._ptf = ptfhost
        self._ptf_iface = "eth{}".format(neighbor_port)

        self._addr = server_addr
        self._subnet = server_prefix

        self._neighbor_iface = neighbor_iface
        self._neighbor_addr = neighbor_addr

        self._fanout_neighbor, self._fanout_iface = \
            fanout_switch_port_lookup(fanouthosts, neighbor_iface)

    def get_addr(self):
        """
        Fetches the IP address of the server.

        Returns:
            The IP address of the server.
        """

        return str(self._addr)

    def get_neighbor_iface(self):
        """
        Fetches the SONiC interface that is connected to the server.

        Returns:
            The SONiC interface that is connected to the server.
        """

        return self._neighbor_iface

    def start(self):
        """
        Starts the server.

        This will populate the FDB and ARP tables on the SONiC device.
        """

        try:
            self._ptf.command("ifconfig {} {}/{}".format(self._ptf_iface, self._addr, self._subnet))
            self._ptf.command("ping -c 1 -I {} {}".format(self._ptf_iface, self._neighbor_addr))
            time.sleep(1)
        except Exception:
            logging.exception("Error starting MockServer")
            self.shutdown()
            raise

    def shutdown(self):
        """
        Shuts down the server.

        This will remove the IP address from the PTF.
        """
        self._ptf.command("ifconfig {} 0".format(self._ptf_iface))
        time.sleep(1)

    def startup_link(self):
        """
        Starts up the link between the SONiC host and the server.

        This is done on the server side.
        """

        self._fanout_neighbor.no_shutdown(self._fanout_iface)
        time.sleep(1)

    def shutdown_link(self):
        """
        Shuts down the link between the SONiC host and the server.

        This is done on the server side.
        """
        self._fanout_neighbor.shutdown(self._fanout_iface)
        time.sleep(1)
