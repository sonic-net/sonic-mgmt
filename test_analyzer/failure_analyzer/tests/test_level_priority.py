import unittest
import logging
import os, sys
sys.path.append("..")
from data_analyzer import DataAnalyzer
from datetime import datetime, timedelta
import pandas as pd
from unittest.mock import patch
from unittest.mock import Mock
from helper import load_config, check_next_level_data
import copy
from pandas.testing import assert_frame_equal
from unittest.mock import MagicMock


logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s :%(name)s:%(lineno)d %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)

current_file_path = os.path.abspath(__file__)
current_folder = os.path.dirname(current_file_path)

DF_FILE = f"{current_folder}/tests_df/test_topology_df.csv"

mock_current_time = datetime.fromisoformat("2025-01-06 03:44:26.785317+00:00")
mock_kusto_connector = MagicMock()
mock_kusto_connector.__getitem__.return_value = 0

# mock the analyze_active_icm function for DataAnalyzer initialization
with patch('data_analyzer.DataAnalyzer.analyze_active_icm', return_value=[None, None]), \
    patch('data_analyzer.timedelta', return_value=timedelta(days=7)):    # mock the self.search_start_time for data_analyzer.BasicAnalyzer
    general = DataAnalyzer(mock_kusto_connector, Mock(), mock_current_time)

t0_type = ["tgen-t0-3-32", "t0-standalone-32", "t0-backend", "t0-64", "t0-56-o8v48", "t0-120", "t0-118", "t0-116", "t0", "t0-56-po2vlan", "t0-8-lag", "t0-35", "t0-56-d48c8", "t0-56"]
t1_type = ["t1-lag", "t1-backend", "t1-64-lag", "t1-56-lag", "t1-32-lag", "t1", "tgen-t1-64-4", "t1-64-itpac", "t1-28-lag", "t1-be-64-lag", "t1-backend-64-lag"]
t2_type = ["t2_2lc_min_ports-masic", "t2", "t2_5lc-mixed-96"]
t2_ixia_type = ["t2-ixia-2lc-4"]
m0_mx_type = ["m0", "m0-2vlan", "mx"]
dualtor_type = ["dualtor-aa-64-breakout", "dualtor-aa-56", "dualtor-aa", "dualtor-120", "dualtor", "dualtor-64", "dualtor-56", "dualtor-mixed"]

class TestTopologyLevel(unittest.TestCase):

    def setUp(self):
        self.case_name_branch = "platform_tests.api.test_chassis.TestChassisApi.test_get_system_eeprom_info#20240510"
        self.history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '88%/215/245',
                'per_os_version_info': {
                    'success_rate': ['20240510.16 : 90%/18/25',
                                        '20240510.17 : 82%/14/17',
                                        '20240510.18 : 95%/70/74',
                                        '20240510.19 : 93%/68/73',
                                        '20240510.20 : 93%/26/28',
                                        '20240510.21 : 88%/15/17'
                                        ],
                    'consistent_failure_os_version': [],
                    'latest_failure_os_version': '20240510.21'
                },
                'latest_os_version': '20240510.21'
            },

        }
        # read the mock data, convert the column 'UploadTimestamp' to datetime type,
        # other columns to string type.
        self.history_case_branch_df = pd.read_csv(DF_FILE, dtype=object)
        self.history_case_branch_df['UploadTimestamp'] = pd.to_datetime(self.history_case_branch_df['UploadTimestamp'])

        self.kusto_row_data ={
            'failure_level_info': {

            }
        }
        self.case_info_dict = {
            'case_branch': 'platform_tests.api.test_chassis.TestChassisApi.test_get_system_eeprom_info#20240510',
            'is_module_path': False,
            'is_common_summary': False
        }
        self.prev_level_data = {
            'level_name': 'branch',
            'data': {
                '20240510': self.history_case_branch_df[self.history_case_branch_df['BranchName'] == '20240510']
            }
        }
        self.kusto_table = []

    def tearDown(self):
        del self.history_testcases
        del self.kusto_row_data
        del self.prev_level_data
        del self.kusto_table
        del self.history_case_branch_df

    @patch('data_analyzer.configuration', load_config('{}/configs/config_asic_before_topology.json'.format(current_folder)))
    def test_asic_before_topology(self):
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        actual_kusto_table = general.trigger_icm_new(self.case_name_branch, actual_history_testcases,
                                                             actual_case_df_after_filter, self.kusto_row_data, self.case_info_dict)
        expected_kusto_table = [
            {
                'failure_level_info': {
                    'topology': 'DUALTOR',
                    'asic': 'broadcom'
                },
                'trigger_icm': True,
                'subject': "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][broadcom][DUALTOR]",
            },
            {
                'failure_level_info': {
                    'topology': 'T2_IXIA',
                    'asic': 'cisco-8000'
                },
                'trigger_icm': True,
                'subject': "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][cisco-8000][T2_IXIA]",
            },
            {
                'failure_level_info': {
                    'topology': 'T2_IXIA',
                    'asic': 'mellanox'
                },
                'trigger_icm': True,
                'subject': "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][mellanox][T2_IXIA]",
            },
            {
                'failure_level_info': {
                    'topology': 'T2_IXIA',
                    'asic': 'broadcom',
                    'hwsku': 'Arista-7260CX3-D108C8'
                },
                'trigger_icm': True,
                'subject': "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][broadcom][T2_IXIA][Arista-7260CX3-D108C8]",
            }
        ]
        self.assertCountEqual(actual_kusto_table, expected_kusto_table)

    @patch('data_analyzer.configuration', load_config('{}/configs/config_hwsku_before_topology.json'.format(current_folder)))
    def test_hwsku_before_topology(self):
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        actual_kusto_table = general.trigger_icm_new(self.case_name_branch, actual_history_testcases,
                                                             actual_case_df_after_filter, self.kusto_row_data, self.case_info_dict)
        expected_kusto_table = [
            {
                'failure_level_info': {
                    'hwsku': 'Arista-7260CX3-D108C8'
                },
                'trigger_icm': True,
                'subject': "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][Arista-7260CX3-D108C8]",
            },
            {
                'failure_level_info': {
                    'topology': 'T2_IXIA',
                    'hwsku': 'Mellanox-SN4700-O8V48'
                },
                'trigger_icm': True,
                'subject': "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][Mellanox-SN4700-O8V48][T2_IXIA]",
            },
            {
                'failure_level_info': {
                    'topology': 'DUALTOR',
                    'hwsku': 'Arista-7260CX3-C64'
                },
                'trigger_icm': True,
                'subject': "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][Arista-7260CX3-C64][DUALTOR]",
            },
            {
                'failure_level_info': {
                    'topology': 'T2_IXIA',
                    'hwsku': 'Cisco-8101-O8C48'
                },
                'trigger_icm': True,
                'subject': "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][Cisco-8101-O8C48][T2_IXIA]",
            },
            {
                'failure_level_info': {
                    'topology': 'T2_IXIA',
                    'hwsku': 'Mellanox-SN4600C-C64'
                },
                'trigger_icm': True,
                'subject': "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][Mellanox-SN4600C-C64][T2_IXIA]",
            },
            {
                'failure_level_info': {
                    'hwsku': 'Mellanox-SN2700',
                    'topology': 'T2_IXIA'
                },
                'trigger_icm': True,
                'subject': '[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][Mellanox-SN2700][T2_IXIA]'
            }
        ]
        self.assertCountEqual(actual_kusto_table, expected_kusto_table)

