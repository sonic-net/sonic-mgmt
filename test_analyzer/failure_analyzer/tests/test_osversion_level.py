import unittest
import logging
import os, sys
sys.path.append("..")
from data_analyzer import DataAnalyzer
from main import read_types_configuration
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

OSVERSION_DF_FILE = f"{current_folder}/tests_df/test_osversion_df.csv"

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

class TestOSVersionLevel(unittest.TestCase):

    def setUp(self):
        self.case_name_branch = "qos.test_qos_sai.TestQosSai.testQosSaiSeparatedDscpToPgMapping#20240510"
        self.history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '50%/54/108',
                'per_os_version_info': {
                    'success_rate': ['20240510.16 : 20%/4/20',
                                        '20240510.17 : 100%/8/8',
                                        '20240510.18 : 62%/16/26',
                                        '20240510.19 : 37%/14/38',
                                        '20240510.20 : 100%/10/10',
                                        '20240510.21 : 33%/2/6'
                                        ],
                    'consistent_failure_os_version': [],
                    'latest_failure_os_version': '20240510.21'
                },
                'latest_os_version': '20240510.21'
            },

        }
        # read the mock data, convert the column 'UploadTimestamp' to datetime type,
        # other columns to string type.
        self.history_case_branch_df = pd.read_csv(OSVERSION_DF_FILE, dtype=object)
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
            'case_branch': 'qos.test_qos_sai.TestQosSai.testQosSaiSeparatedDscpToPgMapping#20240510',
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

    def tearDown(self):
        del self.history_testcases
        del self.kusto_row_data

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
        expected_check_next_level = True
        check_next_level_data(actual_prev_level_data['data'], self.prev_level_data['data'])
        self.assertEqual(actual_prev_level_data['level_name'], self.prev_level_data['level_name'])
        self.assertEqual(actual_check_next_level, expected_check_next_level)

    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_success_rate_less_than_threshold(self):
        """
            load the default configuration
            For os_version 20240510.21, enable_icm=true and threshold=50
            This test case is to test if a new IcM can be generated correctly when
            the success rate (33) for os_version 20240510.21 is lower than threshold (50).
        """
        actual_check_next_level, actual_next_level_data = general.check_os_version_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])

        expected_icms = [
            "[qos.test_qos_sai.TestQosSai][testQosSaiSeparatedDscpToPgMapping][20240510]"
        ]
        expected_check_next_level = False
        expected_next_level_data = self.prev_level_data
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(self.kusto_table[0]['failure_level_info']['os_version'], '20240510.21')
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], expected_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], expected_next_level_data['data'])



    @patch('data_analyzer.configuration', load_config('{}/configs/config_osversion_threshold.json'.format(current_folder)))
    def test_success_rate_greater_than_or_equal_to_threshold(self):
        """
            test with different threshold, load the configuration from config_osversion_threshold.json
            Set the threhold for osversion 20240510.21 to 30 (success_rate=33 > threshold=30)
            The expected outcome of this test case is that no IcM is generated at this level,
            and continue checking next level.
        """
        actual_check_next_level, actual_next_level_data = general.check_os_version_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
        expected_icms = []
        expected_check_next_level = True
        expected_next_level_data = self.prev_level_data
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], expected_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], expected_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_osversion_case_num.json'.format(current_folder)))
    def test_case_number_threshold(self):
        """
            set the total_case_minimum_release_version to 10
            this test case should be able to ignore the latest osversion becase the total case number
            is lower than total_case_minimum_release_version threshold
        """
        actual_check_next_level, actual_next_level_data = general.check_os_version_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
        expected_icms = []
        expected_check_next_level = True
        expected_next_level_data = self.prev_level_data
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], expected_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], expected_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_osversion_enable_icm.json'.format(current_folder)))
    def test_enable_icm_false(self):
        """
            set the enable_icm=false for os_version level
            The expected outcome is that no IcMs will be generated on this level,
            and all the data from previous level will be passed to next level.
        """
        actual_check_next_level, actual_next_level_data = general.check_os_version_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
        expected_icms = []
        expected_check_next_level = True
        expected_next_level_data = self.prev_level_data
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], expected_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], expected_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_osversion_included_types1.json'.format(current_folder)))
    def test_exclude_latest_osversion(self):
        """
            set included=false for latest osversion.
        """
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = self.history_case_branch_df[self.history_case_branch_df['OSVersion'] != '20240510.21']
        expected_history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '51%/52/102',
                'per_os_version_info': {
                    'success_rate': ['20240510.16 : 20%/4/20',
                                        '20240510.17 : 100%/8/8',
                                        '20240510.18 : 62%/16/26',
                                        '20240510.19 : 37%/14/38',
                                        '20240510.20 : 100%/10/10',
                                        ],
                    'consistent_failure_os_version': [],
                    'latest_failure_os_version': '20240510.19'
                },
                'latest_os_version': '20240510.21'
            },
        }
        self.assertEqual(actual_history_testcases[self.case_name_branch]['total_success_rate'],
                         expected_history_testcases[self.case_name_branch]['total_success_rate'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['per_os_version_info'],
                         expected_history_testcases[self.case_name_branch]['per_os_version_info'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['latest_os_version'],
                         expected_history_testcases[self.case_name_branch]['latest_os_version'])
        assert_frame_equal(actual_case_df_after_filter, expected_case_df)
        self.prev_level_data = {
            'level_name': 'branch',
            'data': {
                '20240510': actual_case_df_after_filter
            }
        }
        actual_check_next_level, actual_next_level_data = general.check_os_version_level(self.case_name_branch, actual_history_testcases,
                                                                       actual_case_df_after_filter, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
        expected_icms = []
        expected_check_next_level = True
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        expected_next_level_data = {
            'level_name': 'branch',
            'data': {
                '20240510': self.history_case_branch_df[self.history_case_branch_df['OSVersion'] != '20240510.21']
            }
        }
        self.assertEqual(actual_next_level_data['level_name'], expected_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], expected_next_level_data['data'])


    @patch('data_analyzer.configuration', load_config('{}/configs/config_osversion_included_types2.json'.format(current_folder)))
    def test_exclude_some_types(self):
        """
            set the included=false for osversion 16, 17, 18, and 19
            This test case is to check whether the data for the next level is filtered correctly.
        """
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = self.history_case_branch_df[self.history_case_branch_df['OSVersion'].isin(['20240510.21', '20240510.20'])]
        expected_history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '75%/12/16',
                'per_os_version_info': {
                    'success_rate': [
                                        '20240510.20 : 100%/10/10',
                                        '20240510.21 : 33%/2/6'
                                        ],
                    'consistent_failure_os_version': [],
                    'latest_failure_os_version': '20240510.21'
                },
                'latest_os_version': '20240510.21'
            },
        }
        self.prev_level_data = {
            'level_name': 'branch',
            'data': {
                '20240510': actual_case_df_after_filter
            }
        }
        self.assertEqual(actual_history_testcases[self.case_name_branch]['total_success_rate'],
                         expected_history_testcases[self.case_name_branch]['total_success_rate'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['per_os_version_info'],
                         expected_history_testcases[self.case_name_branch]['per_os_version_info'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['latest_os_version'],
                         expected_history_testcases[self.case_name_branch]['latest_os_version'])
        assert_frame_equal(actual_case_df_after_filter, expected_case_df)
        actual_check_next_level, actual_next_level_data = general.check_os_version_level(self.case_name_branch, actual_history_testcases,
                                                                       actual_case_df_after_filter, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
        expected_icms = [
             "[qos.test_qos_sai.TestQosSai][testQosSaiSeparatedDscpToPgMapping][20240510]"
        ]
        expected_check_next_level = False
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        expected_next_level_data = {
            'level_name': 'branch',
            'data': {
                '20240510': self.history_case_branch_df[self.history_case_branch_df['OSVersion'].isin(['20240510.21', '20240510.20'])]
            }
        }
        self.assertEqual(actual_next_level_data['level_name'], expected_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], expected_next_level_data['data'])

        kusto_row_data = {
            'failure_level_info': {

            }
        }
        actual_kusto_table = general.trigger_icm_new(self.case_name_branch, actual_history_testcases,
                                                     actual_case_df_after_filter, kusto_row_data, self.case_info_dict)
        expected_kusto_table = [
            {
                'failure_level_info': {
                    'os_version': '20240510.21'
                },
                'trigger_icm': True,
                'subject': "[qos.test_qos_sai.TestQosSai][testQosSaiSeparatedDscpToPgMapping][20240510]"
            }
        ]
        self.assertEqual(actual_kusto_table, expected_kusto_table)


    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_results_older_than_7_days(self):
        mock_history_case_branch_df = copy.deepcopy(self.history_case_branch_df)
        mock_history_case_branch_df.loc[
            mock_history_case_branch_df['OSVersion']=='20240510.21',
            'UploadTimestamp'] = datetime.fromisoformat("2024-12-20 03:44:26.785317+00:00")   #
        actual_check_next_level, actual_next_level_data = general.check_os_version_level(self.case_name_branch, self.history_testcases,
                                                                       mock_history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
        expected_icms = []
        expected_check_next_level = True
        expected_next_level_data = self.prev_level_data
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(actual_next_level_data['level_name'], expected_next_level_data['level_name'])
        check_next_level_data(actual_next_level_data['data'], expected_next_level_data['data'])

    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_trigger_icm_new(self):
        actual_kusto_table = general.trigger_icm_new(self.case_name_branch, self.history_testcases,
                                                             self.history_case_branch_df, self.kusto_row_data, self.case_info_dict)
        expected_kusto_table = [
            {
                'failure_level_info': {
                    'os_version': '20240510.21'
                },
                'trigger_icm': True,
                'subject': "[qos.test_qos_sai.TestQosSai][testQosSaiSeparatedDscpToPgMapping][20240510]"
            }
        ]
        self.assertEqual(actual_kusto_table, expected_kusto_table)




