
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
        """
        Shuts down the given interface.

        If a list of interfaces is provided, checks if the host object has
        a method that can shut down multiple interfaces at once. If no
        such method is found, an AttributeError is raised
        """
        if isinstance(interface_name, list):
            shutdown_multiple = getattr(self.host, "shutdown_multiple", None)
            if callable(shutdown_multiple):
                return shutdown_multiple(interface_name)
            else:
                raise AttributeError("Host of type {} does not contain a"
                                     "'shutdown_multiple' method"
                                     .format(type(self.host)))

        return self.host.shutdown(interface_name)

    def no_shutdown(self, interface_name):
        """
        Starts up the given interface.

        If a list of interfaces is provided, checks if the host object has
        a method that can startup multiple interfaces at once. If no
        such method is found, an AttributeError is raised
        """
        if isinstance(interface_name, list):
            no_shutdown_multiple = getattr(self.host, "no_shutdown_multiple", None)
            if callable(no_shutdown_multiple):
                return no_shutdown_multiple(interface_name)
            else:
                raise AttributeError("Host of type {} does not contain a"
                                     "'no_shutdown_multiple' method"
                                     .format(type(self.host)))

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

    def get_supported_speeds(self, interface_name):
        """Get supported speeds for a given interface

        Args:
            interface_name (str): Interface name

        Returns:
            list: A list of supported speed strings or None
        """
        return self.host.get_supported_speeds(interface_name)

    def set_auto_negotiation_mode(self, interface_name, mode):
        """Set auto negotiation mode for a given interface

        Args:
            interface_name (str): Interface name
            mode (boolean): True to enable auto negotiation else disable

        Returns:
            boolean: False if the operation is not supported else True
        """
        return self.host.set_auto_negotiation_mode(interface_name, mode)

    def get_auto_negotiation_mode(self, interface_name):
        """Get auto negotiation mode for a given interface

        Args:
            interface_name (str): Interface name

        Returns:
            boolean: True if auto negotiation mode is enabled else False. Return None if 
            the auto negotiation mode is unknown or unsupported.
        """
        return self.host.get_auto_negotiation_mode(interface_name)

    def set_speed(self, interface_name, speed):
        """Set interface speed according to the auto negotiation mode. When auto negotiation mode
        is enabled, set the advertised speeds; otherwise, set the force speed.

        Args:
            interface_name (str): Interface name
            speed (str): SONiC style interface speed. E.g, 1G=1000, 10G=10000, 100G=100000. If the speed
            is None and auto negotiation mode is enabled, it sets the advertised speeds to all supported
            speeds.

        Returns:
            boolean: True if success. Usually, the method return False only if the operation
            is not supported or failed.
        """
        return self.host.set_speed(interface_name, speed)

    def get_speed(self, interface_name):
        """Get interface speed

        Args:
            interface_name (str): Interface name

        Returns:
            str: SONiC style interface speed value. E.g, 1G=1000, 10G=10000, 100G=100000.
        """
        return self.host.get_speed(interface_name)
