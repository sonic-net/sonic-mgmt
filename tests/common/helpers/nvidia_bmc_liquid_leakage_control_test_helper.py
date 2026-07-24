import logging
import os
import shlex

from tests.common.helpers.sensor_control_test_helper import mocker
from tests.common.helpers.bmc_liquid_leakage_control_test_helper import LiquidLeakageMockerBMC

logger = logging.getLogger(__name__)

LEAKAGE_MOCKER_SCRIPT = 'sonic_bmc_nvidia_leakage_mocker.py'
LEAKAGE_MOCKER_SRC = os.path.join(
    'common', 'helpers', 'platform_api', 'scripts', LEAKAGE_MOCKER_SCRIPT)
DUT_LEAKAGE_MOCKER_PATH = os.path.join('/tmp', LEAKAGE_MOCKER_SCRIPT)

# Map the abstract leak states to the mocker script's --severity bands.
# The script drives the sensor's raw reading into the threshold band for the
# requested severity (see sonic_bmc_nvidia_leakage_mocker.py threshold model):
#   'ok'   -> reading in [min, max]     -> no leak      (state 'None')
#   'warn' -> reading in [lwarn, warn]  -> MINOR leak
#   'crit' -> reading in [lcrit, crit]  -> CRITICAL leak
STATE_TO_SEVERITY = {
    'None': 'ok',
    'MINOR': 'warn',
    'CRITICAL': 'crit',
    'FAULT': 'error'
}


@mocker('LiquidLeakageMockerBMC')
class LiquidLeakageMockerNvidiaBMC(LiquidLeakageMockerBMC):
    """
    NVIDIA BMC liquid leakage mocker.

    Drives leak readings on the BMC by deploying and invoking
    sonic_bmc_nvidia_leakage_mocker.py, which redirects each leakage channel's
    hw-management ``input`` symlink to a mock file.

    The mocker script addresses sensors by ``<a2d>/<channel>`` id rather than
    the sensor index, so the constructor lists the discovered sensors and maps
    each sensor name to its ``<a2d>/<channel>`` id.
    """

    def __init__(self, dut):
        super().__init__(dut)
        self.dut_script_path = DUT_LEAKAGE_MOCKER_PATH
        self._deploy_mocker_script()
        # Map sensor name -> mocker script '<a2d>/<channel>' id.
        self.name_to_sensor_id = self._list_sensor_ids_by_name()

    def _deploy_mocker_script(self):
        logger.info("Deploying %s to %s on %s",
                    LEAKAGE_MOCKER_SRC, self.dut_script_path, self.dut.hostname)
        self.dut.copy(src=LEAKAGE_MOCKER_SRC, dest=self.dut_script_path, mode='0755')

    def _run_mocker(self, *args):
        quoted_args = " ".join(shlex.quote(str(arg)) for arg in args)
        cmd = "python3 {} {}".format(shlex.quote(self.dut_script_path), quoted_args)
        return self.dut.shell(cmd)

    def _list_sensor_ids_by_name(self):
        """
        Parse the mocker 'list' output into a {sensor_name: '<a2d>/<channel>'} map.

        Each line looks like:
            1/1      name=Mngm_ADC0_Ch1_Flex_0
        """
        output = self._run_mocker('list')['stdout_lines']
        name_to_sensor_id = {}
        for line in output:
            parts = line.split()
            if len(parts) < 2 or not parts[1].startswith('name='):
                continue
            sensor_id = parts[0]
            name = parts[1].split('=', 1)[1]
            name_to_sensor_id[name] = sensor_id
        logger.info("Mocker sensor name-to-id map: %s", name_to_sensor_id)
        return name_to_sensor_id

    def get_sensor_id_by_name(self, name):
        """Return the mocker '<a2d>/<channel>' id for a sensor name, or raise if unknown."""
        if name not in self.name_to_sensor_id:
            raise ValueError(
                "Sensor name {!r} not found in mocker sensor map {}".format(
                    name, sorted(self.name_to_sensor_id)))
        return self.name_to_sensor_id[name]

    def restore_all_sensors(self):
        """Restore all mocked leak sensors to their original input link."""
        self._run_mocker('restore', '--all')

    def set_sensor_state(self, index, state):
        """
        Set a sensor by index to the requested leak state.

        The sensor index resolves to a sensor name, which is then mapped to the
        mocker script's ``<a2d>/<channel>`` id.

        :param index: Leak sensor index.
        :param state: One of 'None', 'MINOR', 'CRITICAL', or 'FAULT'.
        """
        self._validate_sensor_state(state)
        name = self.get_sensor_name(index)
        sensor_id = self.get_sensor_id_by_name(name)
        severity = STATE_TO_SEVERITY[state]
        self._run_mocker('mock', '--sensor', sensor_id, '--severity', severity)

    def deinit(self):
        """Restore sensors (via super class), then remove the mocker script from the DUT."""
        super().deinit()
        logger.info("Removing %s from %s", self.dut_script_path, self.dut.hostname)
        self.dut.file(path=self.dut_script_path, state='absent')
