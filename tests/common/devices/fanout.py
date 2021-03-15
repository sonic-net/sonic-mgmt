
import logging

from tests.common.devices.sonic import SonicHost
from tests.common.devices.onyx import OnyxHost
from tests.common.devices.ixia import IxiaHost
from tests.common.devices.eos import EosHost

logger = logging.getLogger(__name__)


class FanoutHost(object):
    """
    @summary: Class for Fanout switch

    For running ansible module on the Fanout switch
    """

    def __init__(self, ansible_adhoc, os, hostname, device_type, user, passwd, shell_user=None, shell_passwd=None):
        self.hostname = hostname
        self.type = device_type
        self.host_to_fanout_port_map = {}
        self.fanout_to_host_port_map = {}
        if os == 'sonic':
            self.os = os
            self.host = SonicHost(ansible_adhoc, hostname,
                                  shell_user=shell_user,
                                  shell_passwd=shell_passwd)
        elif os == 'onyx':
            self.os = os
            self.host = OnyxHost(ansible_adhoc, hostname, user, passwd)
        elif os == 'ixia':
            # TODO: add ixia chassis abstraction
            self.os = os
            self.host = IxiaHost(ansible_adhoc, os, hostname, device_type)
        else:
            # Use eos host if the os type is unknown
            self.os = 'eos'
            self.host = EosHost(ansible_adhoc, hostname, user, passwd, shell_user=shell_user, shell_passwd=shell_passwd)

    def __getattr__(self, module_name):
        return getattr(self.host, module_name)

    def get_fanout_os(self):
        return self.os

    def get_fanout_type(self):
        return self.type

    def shutdown(self, interface_name):
        return self.host.shutdown(interface_name)

    def no_shutdown(self, interface_name):
        return self.host.no_shutdown(interface_name)

    def __str__(self):
        return "{ os: '%s', hostname: '%s', device_type: '%s' }" % (self.os, self.hostname, self.type)

    def __repr__(self):
        return self.__str__()

    def add_port_map(self, host_port, fanout_port):
        """
            Fanout switch is build from the connection graph of the
            DUT. So each fanout switch instance is relevant to the
            DUT instance in the test. As result the port mapping is
            unique from the DUT perspective. However, this function
            need update when supporting multiple DUT

            host_port is a encoded string of <host name>|<port name>,
            e.g. sample_host|Ethernet0.
        """
        self.host_to_fanout_port_map[host_port]   = fanout_port
        self.fanout_to_host_port_map[fanout_port] = host_port

    def exec_template(self, ansible_root, ansible_playbook, inventory, **kwargs):
        return self.host.exec_template(ansible_root, ansible_playbook, inventory, **kwargs)
