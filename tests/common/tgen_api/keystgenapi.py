""" The IxNetwork Test Generator API implementation

    Note: Please note that some of these functions is implemented
        with the help of common/ixia/ixia_helpers.py for the demo
        purpose. 
"""
import json
from typing import Union, List, Dict
from common.reboot import logger

from tgenapi import TgenApi
from tgenmodels import Config
from ixnetwork_restpy import SessionAssistant
import common.ixia.ixia_helpers as helpers

class KeysTgenApi(TgenApi):
    def __init__(self, **kwargs):
        self._vports = None
        self.config = Config()  
        for key in kwargs.keys() :
            if (key == 'session') :
                self._assistant = kwargs['session']
                self._ixnetwork = self._assistant.Ixnetwork
            else :
                logger.info('invalid key %s in init' %(key))
                pytest_assert(0)

    def init_tgen(self, config = None) :
        """Staging repositary Initial configuration data
        """
        logger.info("Staging the initial configuration ....")
        if config is not None:
            self.config = config  

    def connect(self, host):
        if ']:' in host:
            address, port = host.split(']:')
        elif ':' in host:
            address, port = host.split(':')
        else:
            address = host
            port = None
        self._assistant = SessionAssistant(IpAddress=address, RestPort=port)
        self._ixnetwork = self._assistant.Ixnetwork
        self._port_map = self._assistant.PortMapAssistant()

    def configure(self):
        """
        restpy code goes here
        take the configuration objects and use restpy to configure the 
        test tool

        Note: We expect port list to be a list of dictionaries. 
        """

        self._vports = helpers.configure_ports(self._assistant, 
                                               self.config.ports._port_list)

        helpers.create_topology(
            self._assistant,
            self._vports, 
            name=self.config.topo._ip_address['topo_name'],
            ip_type='ipv4',
            ip_start=self.config.topo._ip_address['if_ip'],
            ip_incr_step=self.config.topo._ip_address['if_ip_step'],
            gw_start=self.config.topo._ip_address['gw_ip'],
            gw_incr_step=self.config.topo._ip_address['gw_ip_step'])

    def deconfigure(self):
        self._ixnetwork.NewConfig()

    def start(self):
        helpers.start_protocols(self._assistant)

    def stop(self):
        helpers.stop_protocols(self._assistant)
        pass

    def json_config(self):
        return json.dumps(self.config, default=lambda o: o.__dict__, indent=4)
