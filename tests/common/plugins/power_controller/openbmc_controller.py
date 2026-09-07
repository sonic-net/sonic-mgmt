"""
OpenBMC Redfish whole-device power controller for LD platforms.
This controller implements PowerControllerBase using the external OpenBMC Redfish API.
"""
import logging
import warnings

import requests
from urllib3.exceptions import InsecureRequestWarning

from .controller_base import PowerControllerBase

logger = logging.getLogger(__name__)

REDFISH_SYSTEMS_PATH = "/redfish/v1/Systems/System_0"
REDFISH_RESET_PATH = "/redfish/v1/Systems/System_0/Actions/ComputerSystem.Reset"
REDFISH_RESET_FORCE_OFF = "ForceOff"
REDFISH_RESET_ON = "On"
POWER_STATE_ON = "On"
POWER_STATE_OFF = "Off"
POWER_STATE_UNKNOWN = "Unknown"


class OpenBmcRedfishController(PowerControllerBase):
    """
    @summary: Control host power through external OpenBMC Redfish

    This controller issues Redfish ComputerSystem.Reset actions against the DUT BMC.
    """

    def __init__(self, hostname, bmc_ip, bmc_user, bmc_password):
        """
        @summary: Create an OpenBMC Redfish power controller

        @param hostname: DUT hostname associated with this controller
        @param bmc_ip: BMC management IP address
        @param bmc_user: BMC Redfish username
        @param bmc_password: BMC Redfish password
        """
        super(OpenBmcRedfishController, self).__init__(hostname)
        self._base_url = "https://{}".format(bmc_ip)
        self._auth = (bmc_user, bmc_password)

    def _request(self, method, url, **kwargs):
        """Issue an HTTPS request to the BMC, suppressing only this call's InsecureRequestWarning."""
        kwargs.setdefault("auth", self._auth)
        kwargs.setdefault("timeout", 30)
        kwargs.setdefault("verify", False)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InsecureRequestWarning)
            return requests.request(method, url, **kwargs)

    def _reset(self, reset_type):
        """
        @summary: Issue a Redfish ComputerSystem.Reset action

        @param reset_type: Redfish ResetType value, for example "ForceOff" or "On"
        @return: Returns True if operation is successful. Otherwise, returns False
        """
        url = self._base_url + REDFISH_RESET_PATH
        logger.info("BMC Redfish reset: POST %s ResetType=%s", url, reset_type)
        try:
            resp = self._request("POST", url, json={"ResetType": reset_type})
        except requests.exceptions.RequestException as exc:
            logger.error("BMC Redfish request failed: %s", exc)
            return False

        if resp.status_code not in (200, 204):
            logger.error("BMC Redfish reset returned HTTP %s: %s", resp.status_code, resp.text)
            return False

        logger.info("BMC Redfish reset %s accepted (HTTP %s)", reset_type, resp.status_code)
        return True

    def power_off(self):
        """
        @summary: Turn off host power using Redfish ForceOff

        @return: Returns True if operation is successful. Otherwise, returns False
        """
        return self._reset(REDFISH_RESET_FORCE_OFF)

    def power_on(self):
        """
        @summary: Turn on host power using Redfish On

        @return: Returns True if operation is successful. Otherwise, returns False
        """
        return self._reset(REDFISH_RESET_ON)

    def get_power_state(self):
        """
        @summary: Query host power state from Redfish Systems resource

        @return: Returns "On", "Off", or "Unknown"
        """
        url = self._base_url + REDFISH_SYSTEMS_PATH
        try:
            resp = self._request("GET", url)
            resp.raise_for_status()
            power_state = resp.json().get("PowerState")
            if power_state in (POWER_STATE_ON, POWER_STATE_OFF):
                return power_state
        except Exception as exc:
            logger.warning("BMC Redfish power state query failed: %s", exc)
        return POWER_STATE_UNKNOWN

    def close(self):
        """
        @summary: Close the power controller to release resources.

        OpenBMC Redfish requests are stateless, so there are no persistent
        resources to release.
        """
        pass
