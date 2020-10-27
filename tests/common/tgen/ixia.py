# Ixia file to update ixia related variables 

import pytest

class IXIA():
    """
    IXIA Class to get ixia related variables
    """
    def __init__(self,testbed,duthost):
        """
        Args: 
        testbed (pytest fixture): The testbed fixture.
        duthost (pytest fixture): The duthost fixture.

        """

        self.testbed = testbed
        self.duthost = duthost

    @property
    def api_serv_ip(self):
        """ 
        In an Ixia testbed, there is no PTF docker. 
        Hence, we use ptf_ip field to store Ixia API server. 
        This fixture returns the IP address of the Ixia API server.

        Args: 
        testbed (pytest fixture): The testbed fixture.

        Returns:
            Ixia API server IP
        """
        return self.testbed['ptf_ip']


    @property
    def api_serv_user(self):
        """
        Return the username of Ixia API server.
    
        Returns:
            Ixia API server username.
        """
        return self.duthost.host.options['variable_manager']. \
              _hostvars[self.duthost.hostname]['secret_group_vars']['ixia_api_server']['user']


    @property
    def api_serv_passwd(self):
        """
        Return the password of Ixia API server.
    
        Returns:
            Ixia API server password.
        """
        return self.duthost.host.options['variable_manager']. \
               _hostvars[self.duthost.hostname]['secret_group_vars']['ixia_api_server']['password']


    @property
    def api_serv_port(self):
        """
        This fixture returns the TCP port for REST API of the ixia API server.
    
        Returns:
            Ixia API server REST port.
        """
        return self.duthost.host.options['variable_manager']. \
              _hostvars[self.duthost.hostname]['secret_group_vars']['ixia_api_server']['rest_port']


    @property
    def api_serv_session_id(self):
        """
        Ixia API server can spawn multiple session on the same REST port.
        Optional for LINUX, required for windows return the session ID.

        Returns:
            Ixia API server session id.
        """
        return self.duthost.host.options['variable_manager']. \
               _hostvars[self.duthost.hostname]['secret_group_vars']['ixia_api_server']['session_id']