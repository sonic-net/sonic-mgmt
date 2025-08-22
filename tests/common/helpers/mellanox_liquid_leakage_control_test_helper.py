import logging
import random
from tests.common.helpers.sensor_control_test_helper import mocker
from tests.common.helpers.liquid_leakage_control_test_helper import LiquidLeakageMocker
from tests.common.helpers.mellanox_sensor_control_test_helper import MockerBaseHelper
from tests.common.helpers.liquid_leakage_control_test_helper import verify_leakage_status, \
    verify_leakage_status_in_health_system, verify_leakage_status_in_state_db


LEAKAGE_STATUS_PATH = '/var/run/hw-management/system/'

class MockerHelper(MockerBaseHelper):
    """
    Mellanox specified mocker helper.
    """

    def __init__(self, dut):
        """
        Constructor of mocker helper.
        :param dut: DUT object representing a SONiC switch under test.
        """
        super().__init__(dut)
        self._extract_num_of_leakage_detection()

    def _extract_num_of_leakage_detection(self):
        """
        Get leakage number for this DUT.
        :return:
        """
        get_leakage_num_cmd = f'ls {LEAKAGE_STATUS_PATH}/leakage* | wc -l'
        output = self.dut.shell(get_leakage_num_cmd)
        content = output['stdout'].strip()
        if not content:
            return
        self.LEAKAGE_NUM = 2


@mocker('LiquidLeakageMocker')
class MlxLiquidLeakageMocker(LiquidLeakageMocker):
    """
    Mocker class to help generate liquid cooling leakage detection status and check it with actual data.
    """

    def __init__(self, dut):
        """
        Constructor of LiquidLeakageMocker.
        :param dut: DUT object representing a SONiC switch under test.
        """
        LiquidLeakageMocker.__init__(self, dut)
        self.mock_helper = MockerHelper(dut)
        self.test_leakage_num = random.randint(1, self.mock_helper.LEAKAGE_NUM)
        self.test_leakage_index_list = random.sample(
            list(range(1,self.mock_helper.LEAKAGE_NUM + 1)), k=self.test_leakage_num)
        logging.info(
            f"Test leakage num: {self.test_leakage_num}, test leakage index list: {self.test_leakage_index_list}")

    def deinit(self):
        """
        Destructor of LiquidLeakageMocker.
        :return:
        """
        self.mock_helper.deinit()

    def mock_leakage(self):
        """
        Change the mocked liquid leakage detection status to 'Leakage'.
        :return:
        """
        liquid_leak = 0
        for index in self.test_leakage_index_list:
            self.mock_helper.mock_value(f"{LEAKAGE_STATUS_PATH}/leakage{index}", liquid_leak)

    def mock_no_leakage(self):
        """
        Change the mocked liquid leakage detection status to 'No Leakage'.
        :return:
        """
        no_liquid_leak = 1
        for index in self.test_leakage_index_list:
            self.mock_helper.mock_value(f"{LEAKAGE_STATUS_PATH}/leakage{index}", no_liquid_leak)

    def check_result(self, actual_data):
        """
        Check the result of liquid cooling leakage detection.
        :param actual_data: Actual data of liquid cooling leakage detection.
        :return:
        """
        return self.mock_helper.read_value(self.LEAKAGE_STATUS_FILE) == 1

    def verify_leakage(self):
        """
        Verify the leakage status of the DUT.
        :param expected_status: Expected status of the DUT.
        :return:
        """
        verify_leakage_status_in_state_db(self.dut, self.test_leakage_index_list, "Yes")
        verify_leakage_status(self.dut, self.test_leakage_index_list, "YES")
        verify_leakage_status_in_health_system(self.dut, self.test_leakage_index_list, "Not OK")

        return True

    def verify_no_leakage(self):
        """
        Verify the leakage status of the DUT.
        :param expected_status: Expected status of the DUT.
        :return:
        """
        verify_leakage_status_in_state_db(self.dut, self.test_leakage_index_list, "No")
        verify_leakage_status(self.dut, self.test_leakage_index_list, "NO")
        verify_leakage_status_in_health_system(self.dut, self.test_leakage_index_list, "OK")

        return True
