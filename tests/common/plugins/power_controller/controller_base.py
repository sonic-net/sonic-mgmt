"""
Base class for controlling whole-device power of a DUT

This file defines the base class for whole-device power controllers. The base class
defines the basic interface of power controllers that can power-cycle the entire DUT.

The power controller for a DUT must be a subclass of the PowerControllerBase class and must
implement the methods defined in the base class.
"""


class PowerControllerBase():
    """
    @summary: Base class for whole-device power controller

    This base class defines the basic interface to be provided by a power controller.

    The power controller for a DUT must be a subclass of the PowerControllerBase class and must
    implement the methods defined in the base class.
    """
    def __init__(self, hostname=None):
        self.dut_hostname = hostname

    def power_off(self):
        """
        @summary: Turn off power for the whole DUT.

        @return: Returns True if operation is successful. Otherwise, returns False
        """
        raise NotImplementedError

    def power_on(self):
        """
        @summary: Turn on power for the whole DUT.

        @return: Returns True if operation is successful. Otherwise, returns False
        """
        raise NotImplementedError

    def get_power_state(self):
        """
        @summary: Get current power state of the DUT.

        @return: Returns "On", "Off", or "Unknown"
        """
        raise NotImplementedError

    def close(self):
        """
        @summary: Close the power controller to release resources.
        """
        raise NotImplementedError
