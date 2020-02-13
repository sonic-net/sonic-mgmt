"""
Helper script for checking all related information of interfaces

This script contains re-usable functions for checking status of interfaces on SONiC.
"""
import logging
from check_transceiver_status import all_transceivers_detected
from check_interface_status import check_interface_status


def check_interface_information(dut, interfaces):
    if not all_transceivers_detected(dut, interfaces):
        logging.info("Not all transceivers are detected")
        return False
    if not check_interface_status(dut, interfaces):
        logging.info("Not all interfaces are up")
        return False

    return True

