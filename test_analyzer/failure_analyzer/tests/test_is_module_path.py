import unittest
import logging
import os, sys
sys.path.append("..")
from data_analyzer import DataAnalyzer
from datetime import datetime, timedelta
import pandas as pd
from unittest.mock import patch
from unittest.mock import Mock
from unittest.mock import MagicMock
from helper import load_config

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s :%(name)s:%(lineno)d %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)

current_file_path = os.path.abspath(__file__)
current_folder = os.path.dirname(current_file_path)

DF_FILE = f"{current_folder}/tests_df/test_is_module_path_df.csv"

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

class TestIsModulePath(unittest.TestCase):

    def setUp(self):
        self.case_name_branch = "restapi.test_restapi#20240510"
        self.history_testcases = {
            self.case_name_branch: {
                'total_success_rate': '73%/33/45',
                'per_os_version_info': {
                    'success_rate': ['20240510.40 : 73%/33/45'],
                    'consistent_failure_os_version': [],
                    'latest_failure_os_version': '20240510.40'
                },
                'latest_os_version': '20240510.40'
            },
        }
        # read the mock data, convert the column 'UploadTimestamp' to datetime type,
        # other columns to string type.
        self.history_case_branch_df = pd.read_csv(DF_FILE, dtype=object)
        self.history_case_branch_df['UploadTimestamp'] = pd.to_datetime(self.history_case_branch_df['UploadTimestamp'])
        self.history_case_branch_df.loc[:, 'Topology'] = self.history_case_branch_df['Topology'].replace(t0_type, 'T0')
        self.history_case_branch_df.loc[:, 'Topology'] = self.history_case_branch_df['Topology'].replace(t1_type, 'T1')
        self.history_case_branch_df.loc[:, 'Topology'] = self.history_case_branch_df['Topology'].replace(t2_type, 'T2')
        self.history_case_branch_df.loc[:, 'Topology'] = self.history_case_branch_df['Topology'].replace(dualtor_type, 'DUALTOR')
        self.history_case_branch_df.loc[:, 'Topology'] = self.history_case_branch_df['Topology'].replace(m0_mx_type, 'M0_MX')
        self.history_case_branch_df['HardwareSku_OSVersion'] = self.history_case_branch_df['HardwareSku'] + '_' + \
                                                                self.history_case_branch_df['OSVersion']
        self.history_case_branch_df['Topology_HardwareSku'] = self.history_case_branch_df['Topology'] + '_' + \
                                                                self.history_case_branch_df['HardwareSku']
        self.kusto_row_data ={
            'failure_level_info': {

            }
        }
        self.case_info_dict = {
            'case_branch': 'restapi.test_restapi#20240510',
            'is_module_path': True,
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
    def test_trigger_icms_is_module_path(self):
        with patch('data_analyzer.dataframe_from_result_table', return_value=self.history_case_branch_df):
            actual_history_testcases, actual_case_df_after_filter = general.search_and_parse_history_results(self.case_info_dict)
        actual_kusto_table = general.trigger_icm_new(self.case_name_branch, actual_history_testcases,
                                                             actual_case_df_after_filter, self.kusto_row_data, self.case_info_dict)
        expected_kusto_table = [
            {
                'failure_level_info': {
                    'topology': 'T0',
                    'asic': 'mellanox',
                    'hwsku': 'Mellanox-SN2700'
                },
                'trigger_icm': True,
                'subject': '[restapi.test_restapi][20240510][T0][mellanox][Mellanox-SN2700]'
            }
        ]
        self.assertEqual(actual_kusto_table, expected_kusto_table)