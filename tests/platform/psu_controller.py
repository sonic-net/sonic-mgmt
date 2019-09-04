"""
Fixture for controlling PSUs of DUT

This file defines fixture psu_controller which is for controlling PSUs of DUT. The fixture uses factory design pattern
and returns a function for creating PSU controller instance. The function takes two arguments:
* hostname - hostname of the DUT
* asic_type - asic type of the DUT
Based on these two inputs, different PSU controller implemented by different vendors could be returned.

The PSU controller implemented by each vendor must be a subclass of the PsuControllerBase class and implements the
methods defined in the base class.
"""
import os
import sys

import pytest


class PsuControllerBase():
    """
    @summary: Base class for PSU controller

    This base class defines the basic interface to be provided by PSU controller. PSU controller implemented by each
    vendor must be a subclass of this base class.
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


@pytest.fixture
def psu_controller():
    """
    @summary: Fixture for controlling power supply to PSUs of DUT

    @returns: Returns a function for creating PSU controller object. The object must implement the PsuControllerBase
              interface.
    """
    # For holding PSU controller object to be used in fixture tear down section
    controllers = []

    def _make_psu_controller(hostname, asic_type):
        """
        @summary: Function for creating PSU controller object.
        @param hostname: Hostname of DUT
        @param asic_type: ASIC type of DUT, for example: 'mellanox'
        """
        controller = None

        # Create PSU controller object based on asic type and hostname of DUT
        if asic_type == "mellanox":
            current_file_dir = os.path.dirname(os.path.realpath(__file__))
            if current_file_dir not in sys.path:
                sys.path.append(current_file_dir)
            sub_folder_dir = os.path.join(current_file_dir, "mellanox")
            if sub_folder_dir not in sys.path:
                sys.path.append(sub_folder_dir)
            from mellanox_psu_controller import make_mellanox_psu_controller

            controller = make_mellanox_psu_controller(hostname)
            if controller:
                # The PSU controller object is returned to test case calling this fixture. Need to save the object
                # for later use in tear down section
                controllers.append(controller)

        return controller

    yield _make_psu_controller

    # Tear down section, ensure that all PSUs are turned on after test
    for controller in controllers:
        if controller:
            psu_status = controller.get_psu_status()
            if psu_status:
                for psu in psu_status:
                    if not psu["psu_on"]:
                        controller.turn_on_psu(psu["psu_id"])
            controller.close()
