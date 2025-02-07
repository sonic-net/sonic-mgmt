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

HWSKU_DF_FILE = f"{current_folder}/tests_df/test_hwsku_df.csv"

mock_current_time = datetime.fromisoformat("2025-01-06 03:44:26.785317+00:00")
mock_kusto_connector = MagicMock()
mock_kusto_connector.__getitem__.return_value = 0

with patch('data_analyzer.DataAnalyzer.analyze_active_icm', return_value=[None, None]), \
    patch('data_analyzer.timedelta', return_value=timedelta(days=7)):    # mock the self.search_start_time for data_analyzer.BasicAnalyzer
    general = DataAnalyzer(mock_kusto_connector, Mock(), mock_current_time)

t0_type = ["tgen-t0-3-32", "t0-standalone-32", "t0-backend", "t0-64", "t0-56-o8v48", "t0-120", "t0-118", "t0-116", "t0", "t0-56-po2vlan", "t0-8-lag", "t0-35", "t0-56-d48c8", "t0-56"]
t1_type = ["t1-lag", "t1-backend", "t1-64-lag", "t1-56-lag", "t1-32-lag", "t1", "tgen-t1-64-4", "t1-64-itpac", "t1-28-lag", "t1-be-64-lag", "t1-backend-64-lag"]
t2_type = ["t2_2lc_min_ports-masic", "t2", "t2_5lc-mixed-96"]
t2_ixia_type = ["t2-ixia-2lc-4"]
m0_mx_type = ["m0", "m0-2vlan", "mx"]
dualtor_type = ["dualtor-aa-64-breakout", "dualtor-aa-56", "dualtor-aa", "dualtor-120", "dualtor", "dualtor-64", "dualtor-56", "dualtor-mixed"]

class TestHwskuLevel(unittest.TestCase):

    def setUp(self):
        self.case_name_branch = "pfcwd.test_pfcwd_function.TestPfcwdFunc.test_pfcwd_multi_port#20240510"
        self.history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '73%/141/168',
                'per_os_version_info': {
                    'success_rate': ['20240510.16 : 69%/11/16',
                                        '20240510.17 : 92%/11/12',
                                        '20240510.18 : 93%/50/54',
                                        '20240510.19 : 83%/50/60',
                                        '20240510.20 : 73%/8/11',
                                        '20240510.21 : 73%/11/15'
                                        ],
                    'consistent_failure_os_version': [],
                    'latest_failure_os_version': '20240510.21'
                },
                'latest_os_version': '20240510.21'
            },
        }
        # read the mock data, convert the column 'UploadTimestamp' to datetime type,
        # other columns to string type.
        self.history_case_branch_df = pd.read_csv(HWSKU_DF_FILE, dtype=object)
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
            'case_branch': 'pfcwd.test_pfcwd_function.TestPfcwdFunc.test_pfcwd_multi_port#20240510',
            'is_module_path': False,
            'is_common_summary': False
        }
        self.prev_level_data = {
            'level_name': 'asic',
            'data': {
                '20240510|T0|broadcom': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'broadcom')],
                '20240510|T0|cisco-8000': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'cisco-8000')],
                '20240510|T0|mellanox': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'mellanox')],
                '20240510|T2|broadcom': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T2') & (self.history_case_branch_df['AsicType'] == 'broadcom')],
                '20240510|DUALTOR|broadcom': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'DUALTOR') & (self.history_case_branch_df['AsicType'] == 'broadcom')]
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
        actual_check_next_level, actual_prev_level_data = general.check_asic_level(self.case_name_branch, self.history_testcases,
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
        actual_check_next_level, actual_next_level_data = general.check_hwsku_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])
            self.assertIn(data['failure_level_info']['hwsku'], data['subject'])

        expected_icms = [
            "[pfcwd.test_pfcwd_function.TestPfcwdFunc][test_pfcwd_multi_port][20240510][DUALTOR][broadcom][Arista-7260CX3-C64]",
            "[pfcwd.test_pfcwd_function.TestPfcwdFunc][test_pfcwd_multi_port][20240510][DUALTOR][broadcom][Arista-7050CX3-32S-C32]"
        ]
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'hwsku',
            'data': {
                '20240510|T0|broadcom|Arista-7050CX3-32S-C32': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'broadcom') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Arista-7050CX3-32S-C32')],
                '20240510|T0|cisco-8000|Cisco-8122-O64S2': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'cisco-8000') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Cisco-8122-O64S2')],
                '20240510|T0|mellanox|Mellanox-SN4600C-C64': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'mellanox') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Mellanox-SN4600C-C64')],
                '20240510|T2|broadcom|Nokia-IXR7250E-SUP-10': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T2') & (self.history_case_branch_df['AsicType'] == 'broadcom') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Nokia-IXR7250E-SUP-10')],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_hwsku_threshold.json'.format(current_folder)))
    def test_different_threshold(self):
        """
            test with different threshold
            Set the threhold for Cisco-8122-O64S2 to 100. However, the results have timestamps older than 7 days, no
            IcM will be generated. This hwsku will be ignored.
            Set the threshold for Arista-7260CX3-C64 to 30, no IcM will be generated for this type
        """
        actual_check_next_level, actual_next_level_data = general.check_hwsku_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])
            self.assertIn(data['failure_level_info']['hwsku'], data['subject'])

        expected_icms = [
            "[pfcwd.test_pfcwd_function.TestPfcwdFunc][test_pfcwd_multi_port][20240510][DUALTOR][broadcom][Arista-7050CX3-32S-C32]"
        ]
        expected_check_next_level = True
        expected_next_level_data = {
            'level_name': 'hwsku',
            'data': {
                '20240510|T0|broadcom|Arista-7050CX3-32S-C32': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'broadcom') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Arista-7050CX3-32S-C32')],
                '20240510|T0|mellanox|Mellanox-SN4600C-C64': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'mellanox') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Mellanox-SN4600C-C64')],
                '20240510|T2|broadcom|Nokia-IXR7250E-SUP-10': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T2') & (self.history_case_branch_df['AsicType'] == 'broadcom') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Nokia-IXR7250E-SUP-10')],
                '20240510|DUALTOR|broadcom|Arista-7260CX3-C64': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'DUALTOR') & (self.history_case_branch_df['AsicType'] == 'broadcom') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Arista-7260CX3-C64')],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], expected_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], expected_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_hwsku_enable_icm.json'.format(current_folder)))
    def test_enable_icm_false(self):
        """
            set the enable_icm=false for hwsku level
            The expected outcome is that no IcMs will be generated on this level,
            and all the data from previous level will be passed to next level.
        """
        actual_check_next_level, actual_next_level_data = general.check_hwsku_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])
            self.assertIn(data['failure_level_info']['hwsku'], data['subject'])

        expected_icms = []
        expected_check_next_level = True
        excepted_next_level_data = self.prev_level_data
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_hwsku_included_types1.json'.format(current_folder)))
    def test_exclude_a_type(self):
        """
            set included=false for hwsku Arista-7260CX3-C64
            The expected outcome is that no IcMs generated for Arista-7260CX3-C64
        """
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = self.history_case_branch_df[self.history_case_branch_df['HardwareSku'] != 'Arista-7260CX3-C64']
        expected_history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '88%/126/143',
                'per_hwsku_info': {
                    'success_rate': [
                        'Nokia-IXR7250E-36x400G : 0%/0/2',
                        'Nokia-IXR7250E-SUP-10 : 50%/2/4',
                        'Arista-7050CX3-32S-C32 : 56%/14/25',
                        'Cisco-8122-O64S2 : 83%/5/6',
                        'Mellanox-SN4600C-C64 : 96%/23/24',
                        'Cisco-8101-O32 : 100%/2/2',
                        'Arista-7260CX3-D108C8 : 100%/10/10',
                        'Mellanox-SN2700-A1 : 100%/15/15',
                        'Arista-7060CX-32S-D48C8 : 100%/7/7',
                        'Mellanox-SN2700 : 100%/23/23',
                        'Cisco-8101-O8C48 : 100%/4/4',
                        'Arista-7060CX-32S-C32 : 100%/11/11',
                        'Arista-7800R3A-36DM2-D36 : 100%/4/4',
                        'Mellanox-SN4700-O32 : 100%/3/3',
                        'Mellanox-SN4700-O8C48 : 100%/1/1',
                        'Cisco-8102-C64 : 100%/1/1',
                        'Nokia-IXR7250E-36x100G : 100%/1/1'
                    ],
                    'consistent_failure_hwsku': ['Nokia-IXR7250E-36x400G'],
                    'latest_failure_hwsku': 'Arista-7050CX3-32S-C32'
                },
            },
        }
        self.assertEqual(actual_history_testcases[self.case_name_branch]['total_success_rate'],
                         expected_history_testcases[self.case_name_branch]['total_success_rate'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['per_hwsku_info'],
                         expected_history_testcases[self.case_name_branch]['per_hwsku_info'])
        assert_frame_equal(actual_case_df_after_filter, expected_case_df)
        self.prev_level_data = {
            'level_name': 'topology',
            'data': {
                '20240510|T0|broadcom': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'T0') & (actual_case_df_after_filter['AsicType'] == 'broadcom')],
                '20240510|T0|cisco-8000': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'T0') & (actual_case_df_after_filter['AsicType'] == 'cisco-8000')],
                '20240510|T0|mellanox': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'T0') & (actual_case_df_after_filter['AsicType'] == 'mellanox')],
                '20240510|T2|broadcom': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'T2') & (actual_case_df_after_filter['AsicType'] == 'broadcom')],
                '20240510|DUALTOR|broadcom': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'DUALTOR') & (actual_case_df_after_filter['AsicType'] == 'broadcom')]
            }
        }
        actual_check_next_level, actual_next_level_data = general.check_hwsku_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])
            self.assertIn(data['failure_level_info']['hwsku'], data['subject'])

        expected_icms = [
            "[pfcwd.test_pfcwd_function.TestPfcwdFunc][test_pfcwd_multi_port][20240510][DUALTOR][broadcom][Arista-7050CX3-32S-C32]"
        ]
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'hwsku',
            'data': {
                '20240510|T0|broadcom|Arista-7050CX3-32S-C32': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'broadcom') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Arista-7050CX3-32S-C32')],
                '20240510|T0|cisco-8000|Cisco-8122-O64S2': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'cisco-8000') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Cisco-8122-O64S2')],
                '20240510|T0|mellanox|Mellanox-SN4600C-C64': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'mellanox') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Mellanox-SN4600C-C64')],
                '20240510|T2|broadcom|Nokia-IXR7250E-SUP-10': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T2') & (self.history_case_branch_df['AsicType'] == 'broadcom') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Nokia-IXR7250E-SUP-10')],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_hwsku_included_types2.json'.format(current_folder)))
    def test_exclude_some_types(self):
        """
            set included=false for hwsku [Nokia-IXR7250E-SUP-10, Cisco-8122-O64S2, Mellanox-SN4600C-C64, Arista-7260CX3-C64]
            This test case is to check if the data is correctly filtered.
        """
        exlucded_list = ['Nokia-IXR7250E-SUP-10', 'Cisco-8122-O64S2', 'Mellanox-SN4600C-C64', 'Arista-7260CX3-C64']
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = self.history_case_branch_df[~self.history_case_branch_df['HardwareSku'].isin(exlucded_list)]
        expected_history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '88%/96/109',
                'per_hwsku_info': {
                    'success_rate': [
                        'Nokia-IXR7250E-36x400G : 0%/0/2',
                        'Arista-7050CX3-32S-C32 : 56%/14/25',
                        'Cisco-8101-O32 : 100%/2/2',
                        'Arista-7260CX3-D108C8 : 100%/10/10',
                        'Mellanox-SN2700-A1 : 100%/15/15',
                        'Arista-7060CX-32S-D48C8 : 100%/7/7',
                        'Mellanox-SN2700 : 100%/23/23',
                        'Cisco-8101-O8C48 : 100%/4/4',
                        'Arista-7060CX-32S-C32 : 100%/11/11',
                        'Arista-7800R3A-36DM2-D36 : 100%/4/4',
                        'Mellanox-SN4700-O32 : 100%/3/3',
                        'Mellanox-SN4700-O8C48 : 100%/1/1',
                        'Cisco-8102-C64 : 100%/1/1',
                        'Nokia-IXR7250E-36x100G : 100%/1/1'
                    ],
                    'consistent_failure_hwsku': ['Nokia-IXR7250E-36x400G'],
                    'latest_failure_hwsku': 'Arista-7050CX3-32S-C32'
                },
            },
        }
        self.assertEqual(actual_history_testcases[self.case_name_branch]['total_success_rate'],
                         expected_history_testcases[self.case_name_branch]['total_success_rate'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['per_hwsku_info'],
                         expected_history_testcases[self.case_name_branch]['per_hwsku_info'])
        assert_frame_equal(actual_case_df_after_filter, expected_case_df)
        self.prev_level_data = {
            'level_name': 'topology',
            'data': {
                '20240510|T0|broadcom': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'T0') & (actual_case_df_after_filter['AsicType'] == 'broadcom')],
                '20240510|T0|cisco-8000': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'T0') & (actual_case_df_after_filter['AsicType'] == 'cisco-8000')],
                '20240510|T0|mellanox': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'T0') & (actual_case_df_after_filter['AsicType'] == 'mellanox')],
                '20240510|T2|broadcom': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'T2') & (actual_case_df_after_filter['AsicType'] == 'broadcom')],
                '20240510|DUALTOR|broadcom': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'DUALTOR') & (actual_case_df_after_filter['AsicType'] == 'broadcom')]
            }
        }
        actual_check_next_level, actual_next_level_data = general.check_hwsku_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])

        expected_icms = [
            "[pfcwd.test_pfcwd_function.TestPfcwdFunc][test_pfcwd_multi_port][20240510][DUALTOR][broadcom][Arista-7050CX3-32S-C32]"
        ]
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'hwsku',
            'data': {
                '20240510|T0|broadcom|Arista-7050CX3-32S-C32': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'broadcom') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Arista-7050CX3-32S-C32')],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])

        # test trigger_icm_new function
        kusto_row_data = {
            'failure_level_info': {

            }
        }
        self.prev_level_data = {
            'level_name': None,
            'data': {}
        }
        actual_kusto_table = general.trigger_icm_new(self.case_name_branch, actual_history_testcases,
                                                             actual_case_df_after_filter, kusto_row_data, self.case_info_dict)
        expected_kusto_table = [
            {
                'failure_level_info': {
                    'topology': 'DUALTOR',
                    'asic': 'broadcom',
                    'hwsku': 'Arista-7050CX3-32S-C32'
                },
                'trigger_icm': True,
                'subject': "[pfcwd.test_pfcwd_function.TestPfcwdFunc][test_pfcwd_multi_port][20240510][DUALTOR][broadcom][Arista-7050CX3-32S-C32]"
            }
        ]
        self.assertEqual(actual_kusto_table, expected_kusto_table)

    @patch('data_analyzer.configuration', load_config('{}/configs/config_hwsku_regex.json'.format(current_folder)))
    def test_regex_types(self):
        """
            Load the configuration from config_hwsku_regex.json
            Test regular expression
        """
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = copy.deepcopy(self.history_case_branch_df)
        expected_case_df.loc[:, 'HardwareSkuName'] = expected_case_df['HardwareSkuName'].replace([
            'Arista-7050CX3-32S-C32', 'Arista-7060CX-32S-D48C8',
            'Arista-7800R3A-36DM2-D36', 'Arista-7060CX-32S-C32'], 'not-Arista-7260')
        expected_case_df.loc[:, 'HardwareSkuName'] = expected_case_df['HardwareSkuName'].replace([
            'Arista-7260CX3-D108C8', 'Arista-7260CX3-C64'], 'Arista-7260')
        expected_case_df.loc[:, 'HardwareSkuName'] = expected_case_df['HardwareSkuName'].replace([
            'Mellanox-SN2700-A1', 'Mellanox-SN2700', 'Mellanox-SN4600C-C64', 'Mellanox-SN4700-O32', 'Mellanox-SN4700-O8C48'], 'Mellanox')
        expected_case_df.loc[:, 'HardwareSkuName'] = expected_case_df['HardwareSkuName'].replace([
            'Cisco-8122-O64S2', 'Cisco-8101-O32', 'Cisco-8101-O8C48', 'Cisco-8102-C64'], 'Cisco')
        expected_case_df.loc[:, 'HardwareSkuName'] = expected_case_df['HardwareSkuName'].replace([
            'Nokia-IXR7250E-36x400G', 'Nokia-IXR7250E-36x100G', 'Nokia-IXR7250E-SUP-10'], 'Nokia')
        expected_case_df['HardwareSku_OSVersion'] = expected_case_df['HardwareSkuName'] + '_' + expected_case_df['OSVersion']
        expected_case_df['Topology_HardwareSku'] = expected_case_df['TopologyName'] + '_' + expected_case_df['HardwareSkuName']
        expected_history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '84%/141/168',
                'per_hwsku_info': {
                    'success_rate': [
                        'Nokia : 43%/3/7',
                        'Arista-7260 : 71%/25/35',
                        'not-Arista-7260 : 77%/36/47',
                        'Cisco : 92%/12/13',
                        'Mellanox : 98%/65/66'
                    ],
                    'consistent_failure_hwsku': [],
                    'latest_failure_hwsku': 'Arista-7050CX3-32S-C32'
                },
            },
        }
        self.assertEqual(actual_history_testcases[self.case_name_branch]['total_success_rate'],
                         expected_history_testcases[self.case_name_branch]['total_success_rate'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['per_hwsku_info'],
                         expected_history_testcases[self.case_name_branch]['per_hwsku_info'])
        assert_frame_equal(actual_case_df_after_filter, expected_case_df)
        self.prev_level_data = {
            'level_name': 'topology',
            'data': {
                '20240510|T0|broadcom': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'T0') & (actual_case_df_after_filter['AsicType'] == 'broadcom')],
                '20240510|T0|cisco-8000': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'T0') & (actual_case_df_after_filter['AsicType'] == 'cisco-8000')],
                '20240510|T0|mellanox': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'T0') & (actual_case_df_after_filter['AsicType'] == 'mellanox')],
                '20240510|T2|broadcom': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'T2') & (actual_case_df_after_filter['AsicType'] == 'broadcom')],
                '20240510|DUALTOR|broadcom': actual_case_df_after_filter[(actual_case_df_after_filter['BranchName'] == '20240510') &
                                            (actual_case_df_after_filter['TopologyName'] == 'DUALTOR') & (actual_case_df_after_filter['AsicType'] == 'broadcom')]
            }
        }
        actual_check_next_level, actual_next_level_data = general.check_hwsku_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])
        expected_icms = [
            "[pfcwd.test_pfcwd_function.TestPfcwdFunc][test_pfcwd_multi_port][20240510][DUALTOR][broadcom][not-Arista-7260]"

        ]
        expected_check_next_level = True
        self.history_case_branch_df.loc[:, 'HardwareSkuName'] = self.history_case_branch_df['HardwareSkuName'].replace([
            'Arista-7050CX3-32S-C32', 'Arista-7060CX-32S-D48C8',
            'Arista-7800R3A-36DM2-D36', 'Arista-7060CX-32S-C32'], 'not-Arista-7260')
        self.history_case_branch_df.loc[:, 'HardwareSkuName'] = self.history_case_branch_df['HardwareSkuName'].replace([
            'Arista-7260CX3-D108C8', 'Arista-7260CX3-C64'], 'Arista-7260')
        self.history_case_branch_df.loc[:, 'HardwareSkuName'] = self.history_case_branch_df['HardwareSkuName'].replace([
            'Mellanox-SN2700-A1', 'Mellanox-SN2700', 'Mellanox-SN4600C-C64'], 'Mellanox')
        self.history_case_branch_df.loc[:, 'HardwareSkuName'] = self.history_case_branch_df['HardwareSkuName'].replace(['Cisco-8122-O64S2'], 'Cisco')
        self.history_case_branch_df.loc[:, 'HardwareSkuName'] = self.history_case_branch_df['HardwareSkuName'].replace([
            'Nokia-IXR7250E-36x400G', 'Nokia-IXR7250E-36x100G', 'Nokia-IXR7250E-SUP-10'], 'Nokia')
        self.history_case_branch_df['HardwareSku_OSVersion'] = self.history_case_branch_df['HardwareSkuName'] + '_' + self.history_case_branch_df['OSVersion']
        self.history_case_branch_df['Topology_HardwareSku'] = self.history_case_branch_df['TopologyName'] + '_' + self.history_case_branch_df['HardwareSkuName']
        excepted_next_level_data = {
            'level_name': 'hwsku',
            'data': {
                '20240510|T0|broadcom|not-Arista-7260': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'broadcom') &
                                            (self.history_case_branch_df['HardwareSkuName'] == 'not-Arista-7260')],
                '20240510|T0|cisco-8000|Cisco': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'cisco-8000') &
                                            (self.history_case_branch_df['HardwareSkuName'] == 'Cisco')],
                '20240510|T0|mellanox|Mellanox': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'mellanox') &
                                            (self.history_case_branch_df['HardwareSkuName'] == 'Mellanox')],
                '20240510|DUALTOR|broadcom|Arista-7260': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'DUALTOR') & (self.history_case_branch_df['AsicType'] == 'broadcom') &
                                            (self.history_case_branch_df['HardwareSkuName'] == 'Arista-7260')],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])


    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_results_older_than_7_days(self):
        """
            check whether results that are older than 7 day can be ignored
        """
        mock_prev_level_data = {
            'level_name': 'asic',
            'data': {}
        }
        # set the 'UploadTimeStamp' for reults with hwsku Arista-7050CX3-32S-C32 older than 7 days
        for level_value, df in self.prev_level_data['data'].items():
            df_copy = copy.deepcopy(df)
            df_copy.loc[
                (df_copy['TopologyName']=='DUALTOR') & (df_copy['AsicType']=='broadcom') & (df_copy['HardwareSku']=='Arista-7050CX3-32S-C32'),
                'UploadTimestamp'] = datetime.fromisoformat("2024-12-20 03:44:26.785317+00:00")
            mock_prev_level_data['data'][level_value] = df_copy

        actual_check_next_level, actual_next_level_data = general.check_hwsku_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, mock_prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])
            self.assertIn(data['failure_level_info']['asic'], data['subject'])

        expected_icms = [
            "[pfcwd.test_pfcwd_function.TestPfcwdFunc][test_pfcwd_multi_port][20240510][DUALTOR][broadcom][Arista-7260CX3-C64]"
        ]
        expected_check_next_level = True
        excepted_next_level_data = {
            'level_name': 'hwsku',
            'data': {
                '20240510|T0|broadcom|Arista-7050CX3-32S-C32': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'broadcom') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Arista-7050CX3-32S-C32')],
                '20240510|T0|cisco-8000|Cisco-8122-O64S2': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'cisco-8000') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Cisco-8122-O64S2')],
                '20240510|T0|mellanox|Mellanox-SN4600C-C64': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T0') & (self.history_case_branch_df['AsicType'] == 'mellanox') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Mellanox-SN4600C-C64')],
                '20240510|T2|broadcom|Nokia-IXR7250E-SUP-10': self.history_case_branch_df[(self.history_case_branch_df['BranchName'] == '20240510') &
                                            (self.history_case_branch_df['TopologyName'] == 'T2') & (self.history_case_branch_df['AsicType'] == 'broadcom') &
                                            (self.history_case_branch_df['HardwareSku'] == 'Nokia-IXR7250E-SUP-10')],
            }
        }
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], excepted_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], excepted_next_level_data['data'])


    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_trigger_icm_new(self):
        actual_kusto_table = general.trigger_icm_new(self.case_name_branch, self.history_testcases,
                                                             self.history_case_branch_df, self.kusto_row_data, self.case_info_dict)
        expected_kusto_table = [
            {
                'failure_level_info': {
                    'topology': 'DUALTOR',
                    'asic': 'broadcom',
                    'hwsku': 'Arista-7260CX3-C64'
                },
                'trigger_icm': True,
                'subject':  "[pfcwd.test_pfcwd_function.TestPfcwdFunc][test_pfcwd_multi_port][20240510][DUALTOR][broadcom][Arista-7260CX3-C64]",
            },
            {
                'failure_level_info': {
                    'topology': 'DUALTOR',
                    'asic': 'broadcom',
                    'hwsku': 'Arista-7050CX3-32S-C32'
                },
                'trigger_icm': True,
                'subject': "[pfcwd.test_pfcwd_function.TestPfcwdFunc][test_pfcwd_multi_port][20240510][DUALTOR][broadcom][Arista-7050CX3-32S-C32]"
            }
        ]
        self.assertEqual(actual_kusto_table, expected_kusto_table)