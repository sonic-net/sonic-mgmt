import ptf
from ptf.base_tests import BaseTest
from ptf.dataplane import DataPlane
import ptf.platforms.nn as nn
import ptf.ptfutils as ptfutils


class PtfTestAdapter(BaseTest):
    """PtfTestAdapater class provides interface for pytest to use ptf.testutils functions """

    DEFAULT_PTF_QUEUE_LEN = 100000
    DEFAULT_PTF_TIMEOUT = 2
    DEFAULT_PTF_NEG_TIMEOUT = 0.1

    def __init__(self, ptf_ip, ptf_nn_port, device_num, ptf_ports_num):
        """ initialize PtfTestAdapter
        :param ptf_ip: PTF host IP
        :param ptf_nn_port: PTF nanomessage agent port
        :param device_num: device number
        :param ptf_ports_num: PTF ports count
        :return:
        """
        self.runTest = lambda : None # set a no op runTest attribute to satisfy BaseTest interface
        super(PtfTestAdapter, self).__init__()
        self._init_ptf_dataplane(ptf_ip, ptf_nn_port, device_num, ptf_ports_num)

    def __enter__(self):
        """ enter in 'with' block """

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """ exit from 'with' block """

        self.kill()

    def _init_ptf_dataplane(self, ptf_ip, ptf_nn_port, device_num, ptf_ports_num, ptf_config=None):
        """
        initialize ptf framework and establish connection to ptf_nn_agent
        running on PTF host
        :param ptf_ip: PTF host IP
        :param ptf_nn_port: PTF nanomessage agent port
        :param device_num: device number
        :param ptf_ports_num: PTF ports count
        :return:
        """
        self.ptf_ip = ptf_ip
        self.ptf_nn_port = ptf_nn_port
        self.device_num = device_num
        self.ptf_ports_num = ptf_ports_num

        ptfutils.default_timeout = self.DEFAULT_PTF_TIMEOUT
        ptfutils.default_negative_timeout = self.DEFAULT_PTF_NEG_TIMEOUT

        ptf.config.update({
            'platform': 'nn',
            'device_sockets': [
                (device_num, range(ptf_ports_num), 'tcp://{}:{}'.format(ptf_ip, ptf_nn_port))
            ],
            'qlen': self.DEFAULT_PTF_QUEUE_LEN,
            'relax': True,
        })
        if ptf_config is not None:
            ptf.config.update(ptf_config)

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
        """ kill data plane thread """
        self.dataplane.kill()

    def reinit(self, ptf_config=None):
        """ reinitialize ptf data plane thread.
        In case if test changes PTF host network configuration (like MAC change on interfaces)
        reinit() method has to be called to restart data plane thread.
        Also if test wants to restart PTF data plane specifying non-default PTF configuration
        :param ptf_config: PTF configuration dictionary
        """
        self.kill()
        self._init_ptf_dataplane(self.ptf_ip, self.ptf_nn_port, self.device_num, self.ptf_ports_num, ptf_config)

