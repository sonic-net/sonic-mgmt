import logging

from tests.common.devices.base import AnsibleHostBase

logger = logging.getLogger(__name__)


class IxiaHost (AnsibleHostBase):
    """ This class is a place-holder for running ansible module on Ixia
    fanout devices in future (TBD).
    """
    def __init__ (self, ansible_adhoc, os, hostname, device_type) :
        """ Initializing Ixia fanout host for using ansible modules.

        Note: Right now, it is just a place holder.

        Args:
            ansible_adhoc :The pytest-ansible fixture
            os (str): The os type of Ixia Fanout.
            hostname (str): The Ixia fanout host-name
            device_type (str): The Ixia fanout device type.
        """

        self.ansible_adhoc = ansible_adhoc
        self.os            = os
        self.hostname      = hostname
        self.device_type   = device_type
        super().__init__(IxiaHost, self)

    def get_host_name (self):
        """Returns the Ixia hostname

        Args:
            This function takes no argument.
        """
        return self.hostname

    def get_os (self) :
        """Returns the os type of the ixia device.

        Args:
            This function takes no argument.
        """
        return self.os

    def execute (self, cmd) :
        """Execute a given command on ixia fanout host.

        Args:
           cmd (str): Command to be executed.
        """
        if (self.os == 'ixia') :
            eval(cmd)
