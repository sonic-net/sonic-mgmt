"""
Base class for controlling PSUs of DUT

This file defines the base class for controlling PSUs of DUT. The base class defined the basic interface of
PSU controllers.

The PSU controller for actually controlling PSUs must be a subclass of the PsuControllerBase class and must
implement the methods defined in the base class.
"""
import os
import sys
import subprocess


class PsuControllerBase():
    """
    @summary: Base class for PSU controller

    This base class defines the basic interface to be provided by PSU controller.

    The PSU controller for actually controlling PSUs must be a subclass of the PsuControllerBase class and must
    implement the methods defined in the base class.
    """
    def __init__(self):
        pass

    def turn_on_psu(self, psu_id):
        """
        @summary: Turn on power for specified PSU.

        @param psu_id: PSU ID, it could be integer of string digit. For example: 0 or '1'
        @return: Returns True if operation is successful. Otherwise, returns False
        """
        raise NotImplementedError

    def turn_off_psu(self, psu_id):
        """
        @summary: Turn off power for specified PSU.

        @param psu_id: PSU ID, it could be integer of string digit. For example: 0 or '1'
        @return: Returns True if operation is successful. Otherwise, returns False
        """
        raise NotImplementedError

    def get_psu_status(self, psu_id=None):
        """
        @summary: Get current power status of PSUs

        @param psu_id: Optional PSU ID, it could be integer or string digit. If no psu_id is specified, power status of
                       all PSUs should be returned
        @return: Returns a list of dictionaries. For example:
                     [{"psu_id": 0, "psu_on": True}, {"psu_id": 1, "psu_on": True}]
                 If getting PSU status failed, an empty list should be returned.
        """
        raise NotImplementedError

    def close(self):
        """
        @summary Close the PDU controller to release resources.
        """
        raise NotImplementedError


def run_local_cmd(cmd):
    """
    @summary: Helper function for running command on localhost -- the sonic-mgmt container
    @param cmd: Command to be executed
    @return: Returns whatever output to stdout by the command
    @raise: Raise an exception if the command return code is not 0.
    """
    process = subprocess.Popen(cmd.split(), shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    ret_code = process.returncode

    if ret_code != 0:
        raise Exception("ret_code=%d, error message=%s. cmd=%s" % (ret_code, stderr, ' '.join(cmd)))

    return stdout
