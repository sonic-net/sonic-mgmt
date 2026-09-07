"""
Adapter that exposes SNMP PDU outlet control as whole-device power operations.

PduWholeDeviceAdapter wraps an existing PduManager so that tests which only need
to power-cycle the entire DUT can use the PowerControllerBase interface without
depending on per-outlet PDU APIs.
"""
import logging

from .controller_base import PowerControllerBase

logger = logging.getLogger(__name__)


class PduWholeDeviceAdapter(PowerControllerBase):
    """
    @summary: Adapter that wraps PduManager as a whole-device power controller

    This adapter converts existing PDU outlet operations into PowerControllerBase
    methods so tests can power-cycle the entire DUT through a backend-neutral API.
    """

    def __init__(self, pdu_manager):
        """
        @summary: Create a whole-device adapter around an existing PduManager

        @param pdu_manager: PduManager instance that already knows the DUT outlets
        """
        super(PduWholeDeviceAdapter, self).__init__(pdu_manager.dut_hostname)
        self._pdu_manager = pdu_manager

    def power_off(self):
        """
        @summary: Turn off power for all PDU outlets connected to the DUT

        @return: Returns True if operation is successful. Otherwise, returns False
        """
        return self._pdu_manager.turn_off_outlet()

    def power_on(self):
        """
        @summary: Turn on power for all PDU outlets connected to the DUT

        @return: Returns True if operation is successful. Otherwise, returns False
        """
        return self._pdu_manager.turn_on_outlet()

    def get_power_state(self):
        """
        @summary: Get aggregated power state of all DUT PDU outlets

        @return: Returns "On" if all outlets are on, "Off" if all outlets are off,
                 otherwise returns "Unknown"
        """
        outlets = self._pdu_manager.get_outlet_status()
        if not outlets:
            return "Unknown"

        outlet_states = [bool(outlet.get("outlet_on")) for outlet in outlets]
        if all(outlet_states):
            return "On"
        if not any(outlet_states):
            return "Off"
        return "Unknown"

    def close(self):
        """
        @summary: Close the underlying PduManager to release resources.
        """
        self._pdu_manager.close()
