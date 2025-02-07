import unittest
import logging
import os, sys
sys.path.append("..")
from data_analyzer import DataAnalyzer
from datetime import datetime, timedelta
import pandas as pd
from unittest.mock import patch
from unittest.mock import Mock
from helper import load_config
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

TOPOLOGY_HWSKU_DF_FILE = f"{current_folder}/tests_df/test_topology_hwsku_df.csv"

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

class TestTopologyHwskuLevel(unittest.TestCase):

    def setUp(self):
        self.case_name_branch = "snmp.test_snmp_link_local.test_snmp_link_local_ip#20240510"
        self.history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '94%/47/50',
                'per_os_version_info': {
                    'success_rate': [
                                     '20240510.19 : 100%8/8'
                                     '20240510.20 : 88%/21/24',
                                     '20240510.21 : 100%/17/18'
                                    ],
                    'consistent_failure_os_version': [],
                    'latest_failure_os_version': '20240510.20'
                },
                'latest_os_version': '20240510.21'
            },
        }
        # read the mock data, convert the column 'UploadTimestamp' to datetime type,
        # other columns to string type.
        self.history_case_branch_df = pd.read_csv(TOPOLOGY_HWSKU_DF_FILE, dtype=object)
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
            'case_branch': 'snmp.test_snmp_link_local.test_snmp_link_local_ip#20240510',
            'is_module_path': False,
            'is_common_summary': False
        }
        self.prev_level_data = Mock()
        self.kusto_table = []


    def tearDown(self):
        del self.history_testcases
        del self.kusto_row_data
        del self.prev_level_data
        del self.kusto_table
        del self.history_case_branch_df

    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_not_empty_kusto_table(self):
        """
            IcMs have been generated at previous levels.
        """
        mock_kusto_table = ['mock_icms']
        actual_check_next_level, _ = general.check_topology_hwsku_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, mock_kusto_table)

        expected_check_next_level = False
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertEqual(mock_kusto_table, ['mock_icms'])     # check if kusto table has been updated

    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_success_rate_less_than_threshold(self):
        """
            load the default configuration: enable_icm=true and threshold=50
            This test case is to test if new IcMs can be generated correctly when
            the success rate is lower than threshold.
        """
        actual_check_next_level, _ = general.check_topology_hwsku_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['hwsku'], data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])

        expected_icms = []
        expected_check_next_level = True
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)

    @patch('data_analyzer.configuration', load_config('{}/configs/config_topology_hwsku_threshold.json'.format(current_folder)))
    def test_different_threshold(self):
        """
            test with different threshold
            Set the threshold for m0-mx_Nokia-M0-7215 to 100
        """
        actual_check_next_level, _ = general.check_topology_hwsku_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['hwsku'], data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])

        expected_icms = [
            '[snmp.test_snmp_link_local][test_snmp_link_local_ip][20240510][M0_MX_Nokia-M0-7215]'
        ]
        expected_check_next_level = False
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)


    @patch('data_analyzer.configuration', load_config('{}/configs/config_topology_hwsku_enable_icm.json'.format(current_folder)))
    def test_enable_icm_false(self):
        """
            set the enable_icm=false for hwsku_osversion level
            The expected outcome is that no IcMs will be generated on this level,
        """
        actual_check_next_level, _ = general.check_topology_hwsku_level(self.case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['hwsku'], data['subject'])

        expected_check_next_level = True
        expected_icms = []
        self.assertEqual(actual_check_next_level, expected_check_next_level)
        self.assertCountEqual(actual_generated_icms, expected_icms)     # check if kusto table has been updated

    @patch('data_analyzer.configuration', load_config('{}/configs/config_topology_hwsku_included_types.json'.format(current_folder)))
    def test_exclude_types(self):
        """
            set included=false for T2_Arista-7800R3A-36DM2-D36 and M0_MX_Nokia-7215
        """
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = self.history_case_branch_df[~self.history_case_branch_df['Topology_HardwareSku'].isin(["T2_Arista-7800R3A-36DM2-D36",  "M0_MX_Nokia-7215"])]
        expected_history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '98%/47/48',
                'per_topology_hwsku_info': {
                    'success_rate': [
                        'M0_MX_Nokia-M0-7215 : 80%/4/5',
                        'DUALTOR_Arista-7050CX3-32S-C32 : 100%/2/2',
                        'T1_Cisco-8101-O32 : 100%/1/1',
                        'DUALTOR_Arista-7260CX3-C64 : 100%/5/5',
                        'DUALTOR_Arista-7260CX3-D108C8 : 100%/1/1',
                        'DUALTOR_Mellanox-SN4700-V64 : 100%/1/1',
                        'T0_Mellanox-SN2700-A1 : 100%/2/2',
                        'M0_MX_Arista-720DT-G48S4 : 100%/4/4',
                        'T0_Mellanox-SN4600C-C64 : 100%/2/2',
                        'T0_Arista-7060CX-32S-D48C8 : 100%/3/3',
                        'T1_Mellanox-SN4600C-C64 : 100%/4/4',
                        'T1_Mellanox-SN2700 : 100%/1/1',
                        'T0_Mellanox-SN4700-O8V48 : 100%/2/2',
                        'T1_Cisco-8101-O8C48 : 100%/2/2',
                        'T0_Mellanox-SN2700 : 100%/3/3',
                        'T1_Arista-7260CX3-C64 : 100%/2/2',
                        'T1_Mellanox-SN2700-A1 : 100%/3/3',
                        'T1_Arista-7060CX-32S-C32 : 100%/4/4',
                        'T0_Arista-7050CX3-32S-C32 : 100%/1/1'
                    ],
                    'consistent_failure_topology_hwsku': [],
                    "latest_failure_topology_hwsku": "m0_Nokia-M0-7215"
                },
            },
        }
        self.assertEqual(actual_history_testcases[self.case_name_branch]['total_success_rate'],
                         expected_history_testcases[self.case_name_branch]['total_success_rate'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['per_topology_hwsku_info'],
                         expected_history_testcases[self.case_name_branch]['per_topology_hwsku_info'])
        assert_frame_equal(actual_case_df_after_filter, expected_case_df)
        actual_check_next_level, _ = general.check_topology_hwsku_level(self.case_name_branch, actual_history_testcases,
                                                                       actual_case_df_after_filter, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['hwsku'], data['subject'])

        expected_icms = []
        expected_check_next_level = True
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)

    @patch('data_analyzer.configuration', load_config('{}/configs/config_topology_hwsku_regex.json'.format(current_folder)))
    def test_regex_types(self):
        """
            regular expression: DUALTOR_Arista.*
            name: DUALTOR_Arista
        """
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        expected_case_df = copy.deepcopy(self.history_case_branch_df)
        expected_case_df.loc[:, 'Topology_HardwareSku'] = expected_case_df['Topology_HardwareSku'].replace(['DUALTOR_Arista-7050CX3-32S-C32', 'DUALTOR_Arista-7260CX3-C64', 'DUALTOR_Arista-7260CX3-D108C8'], 'DUALTOR_Arista')
        expected_history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '98%/49/50',
                'per_topology_hwsku_info': {
                    'success_rate': [
                        'M0_MX_Nokia-M0-7215 : 80%/4/5',
                        'DUALTOR_Arista : 100%/8/8',
                        'T1_Cisco-8101-O32 : 100%/1/1',
                        'DUALTOR_Mellanox-SN4700-V64 : 100%/1/1',
                        'T0_Mellanox-SN2700-A1 : 100%/2/2',
                        'M0_MX_Arista-720DT-G48S4 : 100%/4/4',
                        'T0_Mellanox-SN4600C-C64 : 100%/2/2',
                        'T0_Arista-7060CX-32S-D48C8 : 100%/3/3',
                        'T1_Mellanox-SN4600C-C64 : 100%/4/4',
                        'T1_Mellanox-SN2700 : 100%/1/1',
                        'T0_Mellanox-SN4700-O8V48 : 100%/2/2',
                        'T1_Cisco-8101-O8C48 : 100%/2/2',
                        'T0_Mellanox-SN2700 : 100%/3/3',
                        'T1_Arista-7260CX3-C64 : 100%/2/2',
                        'T1_Mellanox-SN2700-A1 : 100%/3/3',
                        'T1_Arista-7060CX-32S-C32 : 100%/4/4',
                        'T2_Arista-7800R3A-36DM2-D36 : 100%/2/2',
                        'T0_Arista-7050CX3-32S-C32 : 100%/1/1'
                    ],
                    'consistent_failure_topology_hwsku': [],
                    "latest_failure_topology_hwsku": "m0_Nokia-M0-7215"
                },
            },
        }
        self.assertEqual(actual_history_testcases[self.case_name_branch]['total_success_rate'],
                         expected_history_testcases[self.case_name_branch]['total_success_rate'])
        self.assertEqual(actual_history_testcases[self.case_name_branch]['per_topology_hwsku_info'],
                         expected_history_testcases[self.case_name_branch]['per_topology_hwsku_info'])
        assert_frame_equal(actual_case_df_after_filter, expected_case_df)
        actual_check_next_level, _ = general.check_topology_hwsku_level(self.case_name_branch, actual_history_testcases,
                                                                       actual_case_df_after_filter, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['os_version'], data['subject'])
            self.assertIn(data['failure_level_info']['hwsku'], data['subject'])

        expected_icms = []
        expected_check_next_level = True
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)

    @patch('data_analyzer.configuration', load_config('{}/configs/config_topology_hwsku_included_types.json'.format(current_folder)))
    def test_not_in_released_branch(self):
        """
            when the branch is not in the released brach list
        """
        mock_case_name_branch = 'dualtor.test_tunnel_memory_leak.test_tunnel_memory_leak#mock_branch'
        mock_case_info_dict = {
            'case_branch': 'dualtor.test_tunnel_memory_leak.test_tunnel_memory_leak#mock_branch',
            'is_module_path': False,
            'is_common_summary': False
        }
        actual_check_next_level, _ = general.check_topology_hwsku_level(mock_case_name_branch, self.history_testcases,
                                                                       self.history_case_branch_df, self.kusto_row_data,
                                                                       mock_case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])
            self.assertIn(data['failure_level_info']['hwsku'], data['subject'])

        expected_icms = []
        expected_check_next_level = True
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)


    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_results_older_than_7_days(self):
        """
            check whether results that are older than 7 day can be ignored
        """
        mock_history_case_branch_df = copy.deepcopy(self.history_case_branch_df)
        mock_history_case_branch_df.loc[
                (mock_history_case_branch_df['HardwareSku']=='Nokia-7215') & (mock_history_case_branch_df['TopologyName']=='M0_MX'),
                'UploadTimestamp'] = datetime.fromisoformat("2024-12-20 03:44:26.785317+00:00")
        actual_check_next_level, _ = general.check_topology_hwsku_level(self.case_name_branch, self.history_testcases,
                                                                       mock_history_case_branch_df, self.kusto_row_data,
                                                                       self.case_info_dict, self.prev_level_data, self.kusto_table)
        actual_generated_icms = []
        for data in self.kusto_table:
            actual_generated_icms.append(data['subject'])
            self.assertIn(data['failure_level_info']['hwsku'], data['subject'])
            self.assertIn(data['failure_level_info']['topology'], data['subject'])

        expected_icms = []
        expected_check_next_level = True
        self.assertCountEqual(actual_generated_icms, expected_icms)
        self.assertEqual(actual_check_next_level, expected_check_next_level)

    @patch('data_analyzer.configuration', load_config('{}/configs/config_topology_hwsku_threshold.json'.format(current_folder)))
    def test_trigger_icm_new(self):
        actual_kusto_table = general.trigger_icm_new(self.case_name_branch, self.history_testcases,
                                                             self.history_case_branch_df, self.kusto_row_data, self.case_info_dict)
        expected_kusto_table = [
            {
                'failure_level_info': {
                    'topology': 'M0_MX',
                    'hwsku': 'Nokia-M0-7215',
                    'is_combined': True
                },
                'trigger_icm': True,
                'subject': '[snmp.test_snmp_link_local][test_snmp_link_local_ip][20240510][M0_MX_Nokia-M0-7215]',
            }
        ]
        self.assertEqual(actual_kusto_table, expected_kusto_table)

