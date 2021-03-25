import nnpy
import ptf
import ptf.platforms.nn as nn
import ptf.ptfutils as ptfutils
import ptf.packet as scapy
import ptf.mask as mask

from ptf.base_tests import BaseTest
from ptf.dataplane import DataPlane, DataPlanePortNN
from tests.common.utilities import wait_until


class PtfAdapterNNConnectionError(Exception):

    def __init__(self, remote_sock_addr):
        super(PtfAdapterNNConnectionError, self).__init__(
            "Failed to connect to ptf_nn_agent('%s')" % remote_sock_addr
        )
        self.remote_sock_addr = remote_sock_addr


class PtfTestAdapter(BaseTest):
    """PtfTestAdapater class provides interface for pytest to use ptf.testutils functions """

    DEFAULT_PTF_QUEUE_LEN = 100000
    DEFAULT_PTF_TIMEOUT = 2
    DEFAULT_PTF_NEG_TIMEOUT = 0.1

    # the number of currently established connections
    NN_STAT_CURRENT_CONNECTIONS = 201

    def __init__(self, ptf_ip, ptf_nn_port, device_num, ptf_port_set):
        """ initialize PtfTestAdapter
        :param ptf_ip: PTF host IP
        :param ptf_nn_port: PTF nanomessage agent port
        :param device_num: device number
        :param ptf_port_set: PTF ports
        :return:
        """
        self.runTest = lambda : None # set a no op runTest attribute to satisfy BaseTest interface
        super(PtfTestAdapter, self).__init__()
        self.payload_pattern = ""
        self._init_ptf_dataplane(ptf_ip, ptf_nn_port, device_num, ptf_port_set)

    def __enter__(self):
        """ enter in 'with' block """

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """ exit from 'with' block """
        if exc_type != PtfAdapterNNConnectionError:
            self.kill()

    def _check_ptf_nn_agent_availability(self, socket_addr):
        """Verify the nanomsg socket address exposed by ptf_nn_agent is available."""
        sock = nnpy.Socket(nnpy.AF_SP, nnpy.PAIR)
        sock.connect(socket_addr)
        try:
            return wait_until(1, 0.2, lambda:sock.get_statistic(self.NN_STAT_CURRENT_CONNECTIONS) == 1)
        finally:
            sock.close()

    def _init_ptf_dataplane(self, ptf_ip, ptf_nn_port, device_num, ptf_port_set, ptf_config=None):
        """
        initialize ptf framework and establish connection to ptf_nn_agent
        running on PTF host
        :param ptf_ip: PTF host IP
        :param ptf_nn_port: PTF nanomessage agent port
        :param device_num: device number
        :param ptf_port_set: PTF ports
        :return:
        """
        self.ptf_ip = ptf_ip
        self.ptf_nn_port = ptf_nn_port
        self.device_num = device_num
        self.ptf_port_set = ptf_port_set

        ptfutils.default_timeout = self.DEFAULT_PTF_TIMEOUT
        ptfutils.default_negative_timeout = self.DEFAULT_PTF_NEG_TIMEOUT

        ptf_nn_sock_addr = 'tcp://{}:{}'.format(ptf_ip, ptf_nn_port)

        ptf.config.update({
            'platform': 'nn',
            'device_sockets': [
                (device_num, ptf_port_set, ptf_nn_sock_addr)
            ],
            'qlen': self.DEFAULT_PTF_QUEUE_LEN,
            'relax': True,
        })
        if ptf_config is not None:
            ptf.config.update(ptf_config)

        if not self._check_ptf_nn_agent_availability(ptf_nn_sock_addr):
            raise PtfAdapterNNConnectionError(ptf_nn_sock_addr)

        # update ptf.config based on NN platform and create dataplane instance
        nn.platform_config_update(ptf.config)
        ptf.dataplane_instance = DataPlane(config=ptf.config)

        # TODO: in case of multi PTF hosts topologies we'll have to provide custom platform that supports that
        # and initialize port_map specifying mapping between tcp://<host>:<port> and port tuple (device_id, port_id)
        for id, ifname in ptf.config['port_map'].items():
            device_id, port_id = id
            ptf.dataplane_instance.port_add(ifname, device_id, port_id)

        self.dataplane = ptf.dataplane_instance

    def kill(self):
        """ Close dataplane socket and kill data plane thread """
        self.dataplane.kill()

        for injector in DataPlanePortNN.packet_injecters.values():
            injector.socket.close()
        DataPlanePortNN.packet_injecters.clear()

    def reinit(self, ptf_config=None):
        """ reinitialize ptf data plane thread.
        In case if test changes PTF host network configuration (like MAC change on interfaces)
        reinit() method has to be called to restart data plane thread.
        Also if test wants to restart PTF data plane specifying non-default PTF configuration
        :param ptf_config: PTF configuration dictionary
        """
        self.kill()
        self._init_ptf_dataplane(self.ptf_ip, self.ptf_nn_port, self.device_num, self.ptf_port_set, ptf_config)

    def update_payload(self, pkt):
        """Update the payload of packet to the default pattern when certain conditions are met.

        The packet passed in could be a regular scapy packet or a masked packet. If it is a regular scapy packet and
        has UDP or TCP header, then update its TCP or UDP payload.

        If it is a masked packet, then its 'exp_pkt' is the regular scapy packet. Update the payload of its 'exp_pkt'
        properly.

        Args:
            pkt [scapy packet or masked packet]: The packet to be updated.

        Returns:
            [scapy packet or masked packet]: Returns the packet with payload part updated.
        """
        if isinstance(pkt, scapy.Ether):
            for proto in (scapy.UDP, scapy.TCP):
                if proto in pkt:
                    pkt[proto].load = self._update_payload(pkt[proto].load)
        elif isinstance(pkt, mask.Mask):
            for proto in (scapy.UDP, scapy.TCP):
                if proto in pkt.exp_pkt:
                    pkt.exp_pkt[proto].load = self._update_payload(pkt.exp_pkt[proto].load)
        return pkt

    def _update_payload(self, payload):
        """Update payload to the default_pattern if default_pattern is set.

        If length of the payload_pattern is longer payload, truncate payload_pattern to the length of payload.
        Otherwise, repeat the payload_pattern to reach the length of payload. Keep length of updated payload same
        as the original payload.

        Args:
            payload [string]: The payload to be updated.

        Returns:
            [string]: The updated payload.
        """
        if self.payload_pattern:
            len_old = len(payload)
            len_new = len(self.payload_pattern)
            if len_new >= len_old:
                return self.payload_pattern[:len_old]
            else:
                factor = len_old/len_new + 1
                new_payload = self.payload_pattern * factor
                return new_payload[:len_old]
        else:
            return payload
