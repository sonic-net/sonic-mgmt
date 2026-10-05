import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


def turn_on_all_outlets(pdu_controller):
    """Turns on all outlets through SNMP and confirms they are turned on successfully

    Args:
        pdu_controller (BasePduController): Instance of PDU controller

    Returns:
        None
    """
    logging.info("Turning on all outlets/PDUs")
    outlet_status = pdu_controller.get_outlet_status()
    for outlet in outlet_status:
        if not outlet['outlet_on']:
            pdu_controller.turn_on_outlet(outlet)

    for outlet in outlet_status:
        pytest_assert(wait_until(60, 5, 0, check_outlet_status,
                      pdu_controller, outlet, True),
                      "Outlet {} did not turn on".format(outlet['pdu_name']))


def check_outlet_status(pdu_controller, outlet, expect_status=True):
    """Check if a given PDU matches the expected status

    Args:
        pdu_controller (BasePduController): Instance of PDU controller
        outlet (RPS outlet): Outlet whose status is to be checked
        expect_status (boolean): Expected status in True/False (On/Off)

    Returns:
        boolean: True if the outlet matches expected status, False otherwise
    """
    status = pdu_controller.get_outlet_status(outlet)
    return 'outlet_on' in status[0] and status[0]['outlet_on'] == expect_status


def get_grouped_pdus_by_psu(pdu_controller):
    """Returns a grouping of PDUs associated with a PSU in dictionary form

    Args:
        pdu_controller (BasePduController): Instance of PDU controller

    Returns:
        dict: {PSU: array of PDUs} where PDUs are associated with PSU
    """
    # Group outlets/PDUs by PSU
    outlet_status = pdu_controller.get_outlet_status()
    psu_to_pdus = {}
    for outlet in outlet_status:
        if outlet['psu_name'] not in psu_to_pdus:
            psu_to_pdus[outlet['psu_name']] = [outlet]
        else:
            psu_to_pdus[outlet['psu_name']].append(outlet)

    return psu_to_pdus
