"""
BMC PDU controller implementation using Redfish API.

This controller uses the Redfish ComputerSystem.Reset action exposed by
BMCs to perform power-off, power-on, and power-cycle
operations.  It implements the same PduControllerBase interface used by
SNMP-based controllers so that it can be used transparently by the
existing test infrastructure.

Inventory configuration example (INI format):
    [pdu]
    pdu-sn6600_ld-bmc  ansible_host=sn6600_ld-bmc  protocol=bmc  bmc_user=<user>  bmc_password=<password>

Inventory configuration example (YAML format):
    pdu:
      hosts:
        pdu-sn6600_ld-bmc:
          ansible_host: sn6600_ld-bmc
          protocol: bmc
          bmc_user: <user>
          bmc_password: <password>
"""

import logging

from .controller_base import PduControllerBase

logger = logging.getLogger(__name__)

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class BmcPduController(PduControllerBase):
    """
    PDU controller that drives power operations through an BMC Redfish interface.

    The controller discovers the system resource URI from the BMC at init time
    and uses the ComputerSystem.Reset action for turn_off / turn_on.
    """

    RESET_ACTION_SUFFIX = "/Actions/ComputerSystem.Reset"

    def __init__(self, bmc_host, bmc_user, bmc_password, dut_hostname):
        """
        @param bmc_host: BMC hostname or IP address.
        @param bmc_user: BMC username (e.g. "root").
        @param bmc_password: BMC password.
        """
        super().__init__()

        if not HAS_REQUESTS:
            raise RuntimeError("The 'requests' Python package is required for BmcPduController")

        self.bmc_host = bmc_host
        self.dut_hostname = dut_hostname
        self.base_url = f"https://{bmc_host}"  # noqa: E231
        self.auth = (bmc_user, bmc_password)

        # Discover the system resource URI (e.g. /redfish/v1/Systems/System_0)
        self.system_uri = self._discover_system_uri()
        self.reset_url = f"{self.base_url}{self.system_uri}{self.RESET_ACTION_SUFFIX}"

        logger.info(f"BmcPduController initialised for {bmc_host} (system URI: {self.system_uri})")

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def _discover_system_uri(self):
        """Query /redfish/v1/Systems/ and return the @odata.id of the first member."""
        url = f"{self.base_url}/redfish/v1/Systems/"
        try:
            resp = requests.get(url, auth=self.auth, verify=False, timeout=30)
            resp.raise_for_status()
            members = resp.json().get("Members", [])
            if not members:
                raise RuntimeError(f"No system members found at {url}")
            system_uri = members[0]["@odata.id"]
            logger.info(f"Discovered Redfish system URI: {system_uri}")
            return system_uri.rstrip("/")
        except Exception as e:
            logger.error(f"Failed to discover Redfish system URI from {url}: {e}")
            raise

    # ------------------------------------------------------------------
    # PduControllerBase interface
    # ------------------------------------------------------------------
    def turn_off_outlet(self, outlet=None):
        """
        Power off the system via Redfish ForceOff.

        @param outlet: Ignored -- BMC controls the whole system, not individual outlets.
        @return: True if the command succeeded, False otherwise.
        """
        return self._send_reset("ForceOff")

    def turn_on_outlet(self, outlet=None):
        """
        Power on the system via Redfish On.

        @param outlet: Ignored.
        @return: True if the command succeeded, False otherwise.
        """
        return self._send_reset("On")

    def get_outlet_status(self, outlet=None, hostname=None):
        """
        Query the BMC for the current PowerState and return a synthetic outlet list.

        @return: A list with a single dict: [{"outlet_id": "bmc", "outlet_on": True/False}]
        """
        url = f"{self.base_url}{self.system_uri}"
        try:
            resp = requests.get(url, auth=self.auth, verify=False, timeout=30)
            resp.raise_for_status()
            power_state = resp.json().get("PowerState", "Unknown")
            is_on = power_state.lower() == "on"
            logger.info(f"BMC {self.bmc_host} PowerState: {power_state}")
            return [{"outlet_id": "bmc", "outlet_on": is_on}]
        except Exception as e:
            logger.error(f"Failed to get power state from {self.bmc_host}: {e}")
            return []

    def close(self):
        """No persistent connection to close."""
        pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _send_reset(self, reset_type):
        """
        POST the ComputerSystem.Reset action with the given ResetType.

        @param reset_type: One of "ForceOff", "On", "ForceRestart", "PowerCycle", etc.
        @return: True on success, False on failure.
        """
        payload = {"ResetType": reset_type}
        logger.info(f"Sending Redfish Reset({reset_type}) to {self.bmc_host}")
        try:
            resp = requests.post(
                self.reset_url,
                auth=self.auth,
                json=payload,
                verify=False,
                timeout=30,
            )
            if resp.ok:
                logger.info(f"Redfish Reset({reset_type}) succeeded on {self.bmc_host}")
                return True
            else:
                logger.error(f"Redfish Reset({reset_type}) failed on {self.bmc_host}: "
                             f"HTTP {resp.status_code} - {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Redfish Reset({reset_type}) exception on {self.bmc_host}: {e}")
            return False


def get_bmc_controller(bmc_host, pdu_vars, dut_hostname):
    """
    Factory helper to create an BmcPduController from inventory variables.

    @param bmc_host: BMC hostname or IP (from ansible_host).
    @param pdu_vars: Dict of inventory variables for the PDU host.
    @return: An BmcPduController instance, or None on failure.
    """
    bmc_user = pdu_vars.get("bmc_user")
    bmc_password = pdu_vars.get("bmc_password")
    if not bmc_user or not bmc_password:
        logger.error(f"bmc_user and bmc_password must be set in inventory for BMC PDU host {bmc_host}")
        return None
    try:
        return BmcPduController(bmc_host, bmc_user, bmc_password, dut_hostname)
    except Exception as e:
        logger.error(f"Failed to create BmcPduController for {bmc_host}: {e}")
        return None
