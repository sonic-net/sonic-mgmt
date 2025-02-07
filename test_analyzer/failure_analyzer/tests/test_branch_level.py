import unittest
import logging
import os, sys
sys.path.append("..")
from data_analyzer import DataAnalyzer
from kusto_connector import KustoConnector
from datetime import datetime, timedelta
import pandas as pd
from unittest.mock import patch
from unittest.mock import Mock
from helper import load_config
from unittest.mock import MagicMock
from pandas.testing import assert_frame_equal
import copy
from helper import load_config, check_next_level_data


logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s :%(name)s:%(lineno)d %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)

current_file_path = os.path.abspath(__file__)
current_folder = os.path.dirname(current_file_path)

BRANCH_DF_FILE = f"{current_folder}/tests_df/test_branch_df.csv"

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

class TestBranchLevel(unittest.TestCase):

    def setUp(self):
        self.case_name_branch = "bgp.test_bgp_bbr_default_state.test_bbr_disabled_constants_yml_default#20240510"
        self.history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '22%/17/79',
                'per_os_version_info': {
                    'success_rate': ['20240510.16 : 100%/3/3',
                                        '20240510.17 : 57%/4/7',
                                        '20240510.18 : 29%/5/17',
                                        '20240510.19 : 17%/5/29',
                                        '20240510.20 : 0%/0/19',
                                        '20240510.21 : 0%/0/4'
                                        ],
                    'consistent_failure_os_version': ['20240510.21', '20240510.20'],
                    'latest_failure_os_version': '20240510.21'
                }
            },

        }
        # read the mock data, convert the column 'UploadTimestamp' to datetime type,
        # other columns to string type.
        self.history_case_branch_df = pd.read_csv(BRANCH_DF_FILE, dtype=object)
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
            'case_branch': 'bgp.test_bgp_bbr_default_state.test_bbr_disabled_constants_yml_default#20240510',
            'is_module_path': False,
            'is_common_summary': False
            }
        self.prev_level_data = {
            'level_name': None,
            'data': {}
        }
        self.kusto_table = []

    def tearDown(self):
        del self.history_testcases
        del self.kusto_row_data
        del self.prev_level_data
        del self.kusto_table

    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_success_rate_less_than_threshold(self):
        """
            load the default configuration
            For branch 20240510, enable_icm=true and threshold=50
            This test case is to test if a new IcM can be generated correctly when
            the success rate (22) on branch 20240510 is lower than threshold (50).
        """
        actual_check_next_level, self.prev_level_data = general.check_branch_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])

        expected_icms = ["[bgp.test_bgp_bbr_default_state][test_bbr_disabled_constants_yml_default][20240510]"]
        expected_check_next_level = False

        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)

    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_success_rate_zero(self):
        """
            set the success rate on branch 20240510 to 0
            check if the failure_level_info has been updated when the success rate is zero
        """
        self.history_testcases[self.case_name_branch]['total_success_rate'] = '0%/0/79'
        actual_check_next_level, self.prev_level_data = general.check_branch_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertEqual(data['failure_level_info']['is_full_failure'], True)

        expected_icms = ["[bgp.test_bgp_bbr_default_state][test_bbr_disabled_constants_yml_default][20240510]"]
        expected_check_next_level = False
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)


    @patch('data_analyzer.configuration', load_config('{}/configs/config_branch_threshold.json'.format(current_folder)))
    def test_success_rate_greater_than_or_equal_to_threshold(self):
        """
            test with different threshold, load the configuration from config_branch_threshold.json
            Set the threhold for branch 20240510 to 20 (success_rate=22 > threshold=20)
            The expected outcome of this test case is that no IcM is generated at this level,
            and continue checking next level.
        """
        actual_check_next_level, actual_next_level_data = general.check_branch_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])

        expected_icms = []
        expected_check_next_level = True
        expected_next_level_data = {
            'level_name': 'branch',
            'data': {
                '20240510': self.history_case_branch_df[self.history_case_branch_df['BranchName'] == '20240510']
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], expected_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], expected_next_level_data['data'])


    @patch('data_analyzer.configuration', load_config('{}/configs/config_branch_enable_icm.json'.format(current_folder)))
    def test_exclude_types(self):
        """
            set enable_icm=false for branch 20240510.
        """
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            _, case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = self.history_case_branch_df[self.history_case_branch_df['BranchName'] != '20240510']
        assert_frame_equal(case_df_after_filter, expected_case_df)
        actual_check_next_level, _ = general.check_branch_level(self.case_name_branch, self.history_testcases,
                                                                       case_df_after_filter, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])

        expected_icms = []
        expected_check_next_level = False
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)

    @patch('data_analyzer.configuration', load_config('{}/configs/config_branch_enable_icm.json'.format(current_folder)))
    def test_exclude_types_trigger_icm(self):
        """
            set enable_icm=false for branch 20240510.
        """
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            _, case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = self.history_case_branch_df[self.history_case_branch_df['BranchName'] != '20240510']
        assert_frame_equal(case_df_after_filter, expected_case_df)
        actual_kusto_table = general.trigger_icm_new(self.case_name_branch, self.history_testcases,
                                                                       case_df_after_filter, self.kusto_row_data,
                                                                       self.case_info_dict)
        expected_kusto_table = []
        self.assertEqual(actual_kusto_table, expected_kusto_table)

    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_trigger_icm_new(self):
        actual_kusto_table = general.trigger_icm_new(self.case_name_branch, self.history_testcases,
                                                             self.history_case_branch_df, self.kusto_row_data, self.case_info_dict)
        expected_kusto_table = [
            {
                'failure_level_info': {
                },
                'trigger_icm': True,
                'subject': "[bgp.test_bgp_bbr_default_state][test_bbr_disabled_constants_yml_default][20240510]"
            }
        ]
        self.assertEqual(actual_kusto_table, expected_kusto_table)