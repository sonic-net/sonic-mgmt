import logging

from tests.common.helpers.mellanox_thermal_control_test_helper import MockerHelper

logger = logging.getLogger(__name__)


class PdbData(object):
    PDB_PRESENCE_FILE_CANDIDATES = [
        '/run/hw-management/system/pdb{}_status',
        '/run/hw-management/system/pdb{}_present'
    ]

    def __init__(self, mock_helper, index):
        self.helper = mock_helper
        self.index = index
        self.name = f'PDB {self.index}'
        self.presence_file = self._detect_presence_file()

    def _detect_presence_file(self):
        for file_path in [candidate.format(self.index) for candidate in self.PDB_PRESENCE_FILE_CANDIDATES]:
            out = self.helper.dut.stat(path=file_path)
            if out['stat']['exists']:
                logger.info("Detected PDB presence file '%s' for %s", file_path, self.name)
                return file_path
        logger.warning(
            "No PDB presence file found for %s. Checked candidates: %s",
            self.name,
            [candidate.format(self.index) for candidate in self.PDB_PRESENCE_FILE_CANDIDATES]
        )
        return None

    def mock_presence(self, status):
        if self.presence_file is None:
            logger.warning("Unable to mock presence for %s: no supported presence sysfs file detected", self.name)
            return False

        value = 1 if status else 0
        logger.info("Mocking %s presence via '%s' with value '%s'", self.name, self.presence_file, value)
        self.helper.mock_value(self.presence_file, str(value))
        return True

    def mock_status(self, status):
        value = 1 if status else 0
        power_status_file = f'/run/hw-management/system/pdb{self.index}_pwr_status'
        self.helper.mock_value(power_status_file, str(value))


class MellanoxPdbMocker(object):
    def __init__(self, dut):
        self.mock_helper = MockerHelper(dut)
        self.pdb_data = self._init_pdb_data()

    def _init_pdb_data(self):
        for i in range(1, 5):
            pdb_file = f'/run/hw-management/system/pdb{i}_pwr_status'
            out = self.mock_helper.dut.stat(path=pdb_file)
            if out['stat']['exists']:
                return PdbData(self.mock_helper, i)
        return None

    def deinit(self):
        self.mock_helper.deinit()

    def mock_pdb_status(self, status):
        if self.pdb_data is None:
            logger.warning(
                "Unable to mock PDB power status: no PDB data discovered on '%s'",
                self.mock_helper.dut.hostname
            )
            return False, None

        self.pdb_data.mock_status(status)
        logger.info("Mocked PDB power status for %s to '%s'", self.pdb_data.name, status)
        return True, self.pdb_data.name

    def mock_pdb_presence(self, status):
        if self.pdb_data is None:
            logger.warning(
                "Unable to mock PDB presence: no PDB data discovered on '%s'",
                self.mock_helper.dut.hostname
            )
            return False, None

        mock_result = self.pdb_data.mock_presence(status)
        if not mock_result:
            logger.warning(
                "PDB presence mock is not supported for %s on '%s'",
                self.pdb_data.name, self.mock_helper.dut.hostname
            )
            return False, self.pdb_data.name

        logger.info("Mocked PDB presence for %s to '%s'", self.pdb_data.name, status)
        return True, self.pdb_data.name


def create_pdb_mocker(dut):
    if 'mellanox' in dut.facts['asic_type']:
        return MellanoxPdbMocker(dut)
    return None
