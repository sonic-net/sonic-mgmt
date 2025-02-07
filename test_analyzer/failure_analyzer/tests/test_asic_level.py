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

ASIC_DF_FILE = f"{current_folder}/tests_df/test_asic_df.csv"

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

class TestAsicLevel(unittest.TestCase):

    def setUp(self):
        self.case_name_branch = "platform_tests.cli.test_show_platform.test_platform_serial_no#20230531"
        self.history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '73%/33/45',
                'per_os_version_info': {
                    'success_rate': ['20230531.40 : 73%/33/45'],
                    'consistent_failure_os_version': [],
                    'latest_failure_os_version': '20230531.40'
                },
                'latest_os_version': '20230513.40'
            },
        }
        # read the mock data, convert the column 'UploadTimestamp' to datetime type,
        # other columns to string type.
        self.history_case_branch_df = pd.read_csv(ASIC_DF_FILE, dtype=object)
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
            'case_branch': 'platform_tests.cli.test_show_platform.test_platform_serial_no#20230531',
            'is_module_path': False,
            'is_common_summary': False
        }
        self.prev_level_data = {
            'level_name': 'topology',
            'data': {
                '20230531|T0': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20230531') &
                                                           (self.history_case_branch_df['TopologyName'] == 'T0')]
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
        actual_check_next_level, actual_prev_level_data = general.check_topology_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, actual_prev_level_data, self.kusto_table)
        expected_check_next_level = True
        self.assertEqual(actual_prev_level_data['level_name'], self.prev_level_data['level_name'])
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        check_next_level_data(actual_prev_level_data['data'], self.prev_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_success_rate_less_than_threshold(self):
        """
            load the default configuration: enable_icm=true and threshold=50
            This test case is to test if new IcMs can be generated correctly when
            the success rate is lower than threshold.
        """
        actual_check_next_level, actual_next_level_data = general.check_asic_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])

        expected_icms = [
            "[platform_tests.cli.test_show_platform][test_platform_serial_no][20230531][T0][broadcom]"
        ]
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'asic',
            'data': {
                '20230531|T0|mellanox': self.history_case_branch_df[(self.history_case_branch_df['TopologyName'] == 'T0') &
                                                       (self.history_case_branch_df['AsicType'] == 'mellanox')],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_asic_threshold.json'.format(current_folder)))
    def test_different_threshold(self):
        """
            test with different threshold
            Set the threhold for mellanox to 100, an IcM should be generated
            Set the threshold for broadcom to 15, no IcM will be generated for this type
        """
        actual_check_next_level, actual_next_level_data = general.check_asic_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])

        expected_icms = [
            "[platform_tests.cli.test_show_platform][test_platform_serial_no][20230531][T0][mellanox]"
        ]
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'asic',
            'data': {
                '20230531|T0|broadcom': self.history_case_branch_df[(self.history_case_branch_df['TopologyName'] == 'T0') &
                                                       (self.history_case_branch_df['AsicType'] == 'broadcom')],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])


    @patch('data_analyzer.configuration', load_config('{}/configs/config_asic_enable_icm.json'.format(current_folder)))
    def test_enable_icm_false(self):
        """
            set the enable_icm=false for asic level
            The expected outcome is that no IcMs will be generated on this level,
            and all the data from previous level will be passed to next level.
        """
        actual_check_next_level, actual_next_level_data = general.check_asic_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])

        expected_icms = []
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'topology',
            'data': {
                '20230531|T0': self.history_case_branch_df[(self.history_case_branch_df['TopologyName'] == 'T0')],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_asic_included_types1.json'.format(current_folder)))
    def test_exclude_a_type(self):
        """
            set included=false for asic broadcom
            The expected outcome is that no IcMs generated for asic broadcom
        """
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = self.history_case_branch_df[self.history_case_branch_df['AsicType'] != 'broadcom']
        expected_history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '97%/29/30',
                'per_asic_info': {
                    'success_rate': [
                        'mellanox : 86%/6/7',
                        'cisco-8000 : 100%/23/23',
                    ],
                    'consistent_failure_asic': [],
                    "latest_failure_asic": "mellanox"
                },
            },
        }
        self.assertEqual(actual_history_testcases[self.case_name_branch]['total_success_rate'],
                         expected_history_testcases[self.case_name_branch]['total_success_rate'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['per_asic_info'],
                         expected_history_testcases[self.case_name_branch]['per_asic_info'])
        assert_frame_equal(actual_case_df_after_filter, expected_case_df)
        self.prev_level_data = {
            'level_name': 'topology',
            'data': {
                '20230531|T0': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20230531') &
                                              (self.history_case_branch_df['TopologyName'] == 'T0') &
                                              ((self.history_case_branch_df['AsicType'] != 'broadcom'))]
            }
        }
        actual_check_next_level, actual_next_level_data = general.check_asic_level(self.case_name_branch, actual_history_testcases,
                                                                       actual_case_df_after_filter, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])

        expected_icms = []
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'asic',
            'data': {
                '20230531|T0|mellanox': self.history_case_branch_df[(self.history_case_branch_df['TopologyName'] == 'T0') &
                                                       (self.history_case_branch_df['AsicType'] == 'mellanox')],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_asic_included_types2.json'.format(current_folder)))
    def test_exclude_some_types(self):
        """
            set included=false for asic broadcom and mellanox
            This test case is to check if the data is correctly filtered.
        """
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = self.history_case_branch_df[~self.history_case_branch_df['AsicType'].isin(['broadcom', 'mellanox'])]
        expected_history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '100%/23/23',
                'per_asic_info': {
                    'success_rate': [
                        'cisco-8000 : 100%/23/23',
                    ],
                    'consistent_failure_asic': [],
                },
            },
        }
        self.assertEqual(actual_history_testcases[self.case_name_branch]['total_success_rate'],
                         expected_history_testcases[self.case_name_branch]['total_success_rate'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['per_asic_info'],
                         expected_history_testcases[self.case_name_branch]['per_asic_info'])
        assert_frame_equal(actual_case_df_after_filter, expected_case_df)
        self.prev_level_data = {
            'level_name': 'topology',
            'data': {
                '20230531|T0': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20230531') &
                                              (self.history_case_branch_df['TopologyName'] == 'T0') &
                                              (~self.history_case_branch_df['AsicType'].isin(['broadcom', 'mellanox']))]
            }
        }
        actual_check_next_level, actual_next_level_data = general.check_asic_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])

        expected_icms = []
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'asic',
            'data': {}
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

        # test trigger_icm_function
        actual_kusto_table = general.trigger_icm_new(self.case_name_branch, actual_history_testcases,
                                                             actual_case_df_after_filter, self.kusto_row_data, self.case_info_dict)
        expected_kusto_table = []
        self.assertEqual(actual_kusto_table, expected_kusto_table)


    @patch('data_analyzer.configuration', load_config('{}/configs/config_asic_more_than_one_in_type_list.json'.format(current_folder)))
    def test_more_than_one_in_type_list(self):
        """
            treat mellanox and cisco-8000 as one type called mellanox&cisco-8000.
        """
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = copy.deepcopy(self.history_case_branch_df)
        expected_case_df.loc[:, 'AsicTypeName'] = expected_case_df['AsicTypeName'].replace(['mellanox', 'cisco-8000'], 'mellanox&cisco-8000')
        expected_history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '71%/32/45',
                'per_asic_info': {
                    'success_rate': [
                        'broadcom : 20%/3/15',
                        'mellanox&cisco-8000 : 97%/29/30'
                    ],
                    'consistent_failure_asic': [],
                    'latest_failure_asic': 'broadcom'
                },
            },
        }
        self.assertEqual(actual_history_testcases[self.case_name_branch]['total_success_rate'],
                         expected_history_testcases[self.case_name_branch]['total_success_rate'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['per_asic_info'],
                         expected_history_testcases[self.case_name_branch]['per_asic_info'])
        assert_frame_equal(actual_case_df_after_filter, expected_case_df)
        self.prev_level_data = {
            'level_name': 'topology',
            'data': {
                '20230531|T0': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20230531') &
                                              (actual_case_df_after_filter['TopologyName'] == 'T0')]
            }
        }
        actual_check_next_level, actual_next_level_data = general.check_asic_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])

        expected_icms = [
            "[platform_tests.cli.test_show_platform][test_platform_serial_no][20230531][T0][broadcom]"
        ]
        expected_check_next_level = True
        self.history_case_branch_df.loc[:, 'AsicTypeName'] = self.history_case_branch_df['AsicTypeName'].replace(['mellanox', 'cisco-8000'], 'mellanox&cisco-8000')
        excepted_next_level_data = {
            'level_name': 'asic',
            'data': {
                '20230531|T0|mellanox&cisco-8000': self.history_case_branch_df[(self.history_case_branch_df['TopologyName'] == 'T0') &
                                                       (self.history_case_branch_df['AsicTypeName'] == 'mellanox&cisco-8000')],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_asic_regex.json'.format(current_folder)))
    def test_regex_types(self):
        """
            Load the configuration from config_asic_regex.json
            Test regular expression
        """
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = copy.deepcopy(self.history_case_branch_df)
        expected_case_df.loc[:, 'AsicTypeName'] = expected_case_df['AsicTypeName'].replace(['mellanox', 'broadcom'], 'asic_with_no_numbers')
        expected_history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '71%/32/45',
                'per_asic_info': {
                    'success_rate': [
                        'asic_with_no_numbers : 41%/9/22',
                        'cisco-8000 : 100%/23/23'
                    ],
                    'consistent_failure_asic': [],
                    'latest_failure_asic': 'broadcom'
                },
            },
        }
        self.assertEqual(actual_history_testcases[self.case_name_branch]['total_success_rate'],
                         expected_history_testcases[self.case_name_branch]['total_success_rate'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['per_asic_info'],
                         expected_history_testcases[self.case_name_branch]['per_asic_info'])
        assert_frame_equal(actual_case_df_after_filter, expected_case_df)
        self.prev_level_data = {
            'level_name': 'topology',
            'data': {
                '20230531|T0': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20230531') &
                                              (actual_case_df_after_filter['TopologyName'] == 'T0')]
            }
        }
        actual_check_next_level, actual_next_level_data = general.check_asic_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])

        expected_icms = [
            "[platform_tests.cli.test_show_platform][test_platform_serial_no][20230531][T0][asic_with_no_numbers]"
        ]
        expected_check_next_level = True
        self.history_case_branch_df.loc[:, 'AsicType'] = self.history_case_branch_df['AsicType'].replace(['mellanox', 'broadcom'], 'asic_with_no_numbers')
        excepted_next_level_data = {
            'level_name': 'asic',
            'data': {}
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_results_older_than_7_days(self):
        mock_prev_level_data = {
            'level_name': 'topology',
            'data': {}
        }
        # set the 'UploadTimeStamp' for reults with TopologyType=t0 and AsicType=broadcom older than 7 days
        for level_value, df in self.prev_level_data['data'].items():
            df_copy = copy.deepcopy(df)
            df_copy.loc[
                (df_copy['TopologyName']=='T0') & (df_copy['AsicType']=='broadcom'),
                'UploadTimestamp'] = datetime.fromisoformat("2024-12-20 03:44:26.785317+00:00")
            mock_prev_level_data['data'][level_value] = df_copy

        actual_check_next_level, actual_next_level_data = general.check_asic_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, mock_prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])
        expected_icms = []
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'asic',
            'data': {
                '20230531|T0|mellanox': self.history_case_branch_df[(self.history_case_branch_df['TopologyName'] == 'T0') &
                                                       (self.history_case_branch_df['AsicType'] == 'mellanox')],
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
                    'topology': 'T0',
                    'asic': 'broadcom'
                },
                'trigger_icm': True,
                'subject': "[platform_tests.cli.test_show_platform][test_platform_serial_no][20230531][T0][broadcom]",
            }
        ]
        self.assertEqual(actual_kusto_table, expected_kusto_table)

