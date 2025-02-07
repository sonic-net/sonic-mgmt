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

TOPOLOGY_DF_FILE = f"{current_folder}/tests_df/test_topology_df.csv"

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
        self.history_case_branch_df = pd.read_csv(TOPOLOGY_DF_FILE, dtype=object)
        self.history_case_branch_df['UploadTimestamp'] = pd.to_datetime(self.history_case_branch_df['UploadTimestamp'])

        self.history_case_branch_df['HardwareSku_OSVersion'] = self.history_case_branch_df['HardwareSku'] + '_' + \
                                                                self.history_case_branch_df['OSVersion']
        self.history_case_branch_df['Topology_HardwareSku'] = self.history_case_branch_df['Topology'] + '_' + \
                                                                self.history_case_branch_df['HardwareSku']
        self.history_case_branch_df['BranchNameName'] = self.history_case_branch_df['BranchName']
        self.history_case_branch_df['OSVersionName'] = self.history_case_branch_df['OSVersion']
        self.history_case_branch_df['TopologyName'] = self.history_case_branch_df['Topology']
        self.history_case_branch_df.loc[:, 'TopologyName'] = self.history_case_branch_df['TopologyName'].replace(t0_type, 'T0')
        self.history_case_branch_df.loc[:, 'TopologyName'] = self.history_case_branch_df['TopologyName'].replace(t1_type, 'T1')
        self.history_case_branch_df.loc[:, 'TopologyName'] = self.history_case_branch_df['TopologyName'].replace(t2_type, 'T2')
        self.history_case_branch_df.loc[:, 'TopologyName'] = self.history_case_branch_df['TopologyName'].replace(dualtor_type, 'DUALTOR')
        self.history_case_branch_df.loc[:, 'TopologyName'] = self.history_case_branch_df['TopologyName'].replace(m0_mx_type, 'M0_MX')
        self.history_case_branch_df.loc[:, 'TopologyName'] = self.history_case_branch_df['TopologyName'].replace(t2_ixia_type, 'T2_IXIA')
        self.history_case_branch_df['AsicTypeName'] = self.history_case_branch_df['AsicType']
        self.history_case_branch_df['HardwareSkuName'] = self.history_case_branch_df['HardwareSku']
        self.history_case_branch_df['Topology_HardwareSku'] = self.history_case_branch_df['TopologyName'] + '_' + \
                                                                self.history_case_branch_df['HardwareSku']

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

    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_prev_level_data(self):
        """
            This test case is to check if the actual data filterd from previous level matches the expected prev_level_data
            The level priority is [branch, os_version, topology, asic, hwsku, hwsku_osversion, topology_hwsku]
        """
        actual_prev_level_data = {
            'level_name': None,
            'data': {}
        }
        actual_check_next_level, actual_prev_level_data = general.check_branch_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, actual_prev_level_data, self.kusto_table)
        actual_check_next_level, actual_prev_level_data = general.check_os_version_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, actual_prev_level_data, self.kusto_table)
        expected_check_next_level = True
        check_next_level_data(actual_prev_level_data['data'], self.prev_level_data['data'])
        self.assertEqual(actual_prev_level_data['level_name'], self.prev_level_data['level_name'])
        self.assertEqual(actual_check_next_level, expected_check_next_level)


    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_success_rate_less_than_threshold(self):
        """
            load the default configuration: enable_icm=true and threshold=50
            This test case is to test if a new IcM can be generated correctly when
            the success rate is lower than threshold.
        """
        actual_check_next_level, actual_next_level_data = general.check_topology_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])

        expected_icms = [
            "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][DUALTOR]",
            "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][T2_IXIA]",
        ]
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'topology',
            'data': {
                '20240510|T2': self.history_case_branch_df[self.history_case_branch_df['TopologyName'] == 'T2'],
                '20240510|T0': self.history_case_branch_df[self.history_case_branch_df['TopologyName'] == 'T0'],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_topology_threshold.json'.format(current_folder)))
    def test_different_threshold(self):
        """
            test with different threshold
            Set the threhold for t2 to 100 (greater than t2 success rate), an IcM should be generated
            Set the threshold for dualtor and t2_ixia to 30 (less than success rate), no IcM will be generated for this type
        """
        actual_check_next_level, actual_next_level_data = general.check_topology_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
        expected_icms = [
            "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][T2]"
        ]
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'topology',
            'data': {
                '20240510|DUALTOR': self.history_case_branch_df[self.history_case_branch_df['TopologyName'] == 'DUALTOR'],
                '20240510|T0': self.history_case_branch_df[self.history_case_branch_df['TopologyName'] == 'T0'],
                '20240510|T2_IXIA': self.history_case_branch_df[self.history_case_branch_df['TopologyName'] == 'T2_IXIA'],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_topology_enable_icm.json'.format(current_folder)))
    def test_enable_icm_false(self):
        """
            set the enable_icm=false for topology level
            The expected outcome is that no IcMs will be generated on this level,
            and all the data from previous level will be passed to next level.
        """
        actual_check_next_level, actual_next_level_data = general.check_topology_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
        expected_icms = []
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'branch',
            'data': {
                '20240510': self.history_case_branch_df[self.history_case_branch_df['BranchName'] == '20240510']
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_topology_included_types1.json'.format(current_folder)))
    def test_exclude_a_type(self):
        """
            set included=false for topology dualtor
            The expected outcome is that no IcM generated for topology dualtor
        """
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = self.history_case_branch_df[self.history_case_branch_df['TopologyName'] != 'DUALTOR']
        expected_history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '95%/199/209',
                'per_topology_info': {
                    'success_rate': [
                        'T2_IXIA : 36%/4/11',
                        'T2 : 82%/9/11',
                        'T0 : 98%/62/63',
                        'T1 : 100%/64/64',
                        'M0_MX : 100%/60/60'
                    ],
                    'consistent_failure_topology': [],
                    "latest_failure_topology": "t2-ixia-2lc-4"
                },
            },
        }
        self.assertEqual(actual_history_testcases[self.case_name_branch]['total_success_rate'],
                         expected_history_testcases[self.case_name_branch]['total_success_rate'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['per_topology_info'],
                         expected_history_testcases[self.case_name_branch]['per_topology_info'])
        assert_frame_equal(actual_case_df_after_filter, expected_case_df)
        self.prev_level_data = {
            'level_name': 'branch',
            'data': {
                '20240510': actual_case_df_after_filter
            }
        }
        actual_check_next_level, actual_next_level_data = general.check_topology_level(self.case_name_branch, actual_history_testcases,
                                                                       actual_case_df_after_filter, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
        expected_icms = [
            "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][T2_IXIA]"
        ]
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'topology',
            'data': {
                '20240510|T2': self.history_case_branch_df[self.history_case_branch_df['TopologyName'] == 'T2'],
                '20240510|T0': self.history_case_branch_df[self.history_case_branch_df['TopologyName'] == 'T0'],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_topology_included_types2.json'.format(current_folder)))
    def test_exclude_some_types(self):
        """
            set included=false for topology dualtor and t0
            This test case is to check if the data is correctly filtered.
        """
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = self.history_case_branch_df[(self.history_case_branch_df['TopologyName'] != 'DUALTOR') &
                                                       (self.history_case_branch_df['TopologyName'] != 'T0')]
        expected_history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '94%/137/146',
                'per_topology_info': {
                    'success_rate': [
                        'T2_IXIA : 36%/4/11',
                        'T2 : 82%/9/11',
                        'T1 : 100%/64/64',
                        'M0_MX : 100%/60/60'
                    ],
                    'consistent_failure_topology': [],
                    "latest_failure_topology": "t2-ixia-2lc-4"
                },
            },
        }
        self.assertEqual(actual_history_testcases[self.case_name_branch]['total_success_rate'],
                         expected_history_testcases[self.case_name_branch]['total_success_rate'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['per_topology_info'],
                         expected_history_testcases[self.case_name_branch]['per_topology_info'])
        assert_frame_equal(actual_case_df_after_filter, expected_case_df)
        self.prev_level_data = {
            'level_name': 'branch',
            'data': {
                '20240510': actual_case_df_after_filter
            }
        }
        actual_check_next_level, actual_next_level_data = general.check_topology_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
        expected_icms = [
            "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][T2_IXIA]"

        ]
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'topology',
            'data': {
                '20240510|T2': self.history_case_branch_df[self.history_case_branch_df['TopologyName'] == 'T2']
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

        # test trigger_icm_new function
        actual_kusto_table = general.trigger_icm_new(self.case_name_branch, actual_history_testcases,
                                                             actual_case_df_after_filter, self.kusto_row_data, self.case_info_dict)
        expected_kusto_table = [
            {
                'failure_level_info': {
                    'topology': 'T2_IXIA'
                },
                'trigger_icm': True,
                'subject': "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][T2_IXIA]",
            }
        ]
        self.assertEqual(actual_kusto_table, expected_kusto_table)

    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_results_older_than_7_days(self):
        mock_prev_level_data = {
            'level_name': 'branch',
            'data': {}
        }
        for level_value, df in self.prev_level_data['data'].items():
            df_copy = copy.deepcopy(df)
            df_copy.loc[df_copy['TopologyType']=='dualtor', 'UploadTimestamp'] = datetime.fromisoformat("2024-12-20 03:44:26.785317+00:00")
            mock_prev_level_data['data'][level_value] = df_copy
        actual_check_next_level, actual_next_level_data = general.check_topology_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, mock_prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
        expected_icms = [
            "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][T2_IXIA]"

        ]
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'topology',
            'data': {
                '20240510|T2': self.history_case_branch_df[self.history_case_branch_df['TopologyName'] == 'T2'],
                '20240510|T0': self.history_case_branch_df[self.history_case_branch_df['TopologyName'] == 'T0'],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_trigger_icm_new(self):
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        actual_kusto_table = general.trigger_icm_new(self.case_name_branch, actual_history_testcases,
                                                             actual_case_df_after_filter, self.kusto_row_data, self.case_info_dict)
        expected_kusto_table = [
            {
                'failure_level_info': {
                    'topology': 'T2_IXIA'
                },
                'trigger_icm': True,
                'subject': "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][T2_IXIA]",
            },
            {
                'failure_level_info': {
                    'topology': 'DUALTOR'
                },
                'trigger_icm': True,
                'subject':  "[platform_tests.api.test_chassis.TestChassisApi][test_get_system_eeprom_info][20240510][DUALTOR]",
            },
        ]
        self.assertEqual(actual_kusto_table, expected_kusto_table)


