"""
Base class for controlling PDU(s) connected to DUT power supplies

This file defines the base class for controlling PDU outlets. The base class defined the basic interface of
PDU controllers.

The PDU controller for PDUs must be a subclass of the PduControllerBase class and must
implement the methods defined in the base class.
"""
import subprocess


class PduControllerBase():
    """
    @summary: Base class for PDU controller

    This base class defines the basic interface to be provided by PDU controller.

    The PDU controller for PDUs must be a subclass of the PduControllerBase class and must
    implement the methods defined in the base class.
    """
    def __init__(self):
        pass

    def turn_on_outlet(self, outlet):
        """
        @summary: Turn on power for specified PDU.

        @param outlet: PDU ID, it could be integer of string digit. For example: 0 or '1'
        @return: Returns True if operation is successful. Otherwise, returns False
        """
        raise NotImplementedError

    def turn_off_outlet(self, outlet):
        """
        @summary: Turn off power for specified PDU.

        @param outlet: PDU ID, it could be integer of string digit. For example: 0 or '1'
        @return: Returns True if operation is successful. Otherwise, returns False
        """
        raise NotImplementedError

    def get_outlet_status(self, outlet=None, hostname=None):
        """
        @summary: Get current power status of PDU outlets

        @param outlet: Optional outlet ID, it could be integer or string digit. If no outlet is specified, power status of
                       all PDU outlets should be returned
        @param hostname: Optional hostname used to partial match any label
        @return: Returns a list of dictionaries. For example:
                     [{"outlet_id": "0.0.1", "outlet_on": True}, {"outlet_id": "0.0.2", "outlet_on": True}]
                 If getting outlet(s) status failed, an empty list should be returned.
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
