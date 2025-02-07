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

DF1_FILE = f"{current_folder}/tests_df/test_branch_df.csv"
DF2_FILE = f"{current_folder}/tests_df/test_osversion_df.csv"
DF3_FILE = f"{current_folder}/tests_df/test_topology_df.csv"
HWSKU_OSVERSION_DF_FILE = f"{current_folder}/tests_df/test_hwsku_osversion_df.csv"
TOPOLOGY_HWSKU_DF_FILE = f"{current_folder}/tests_df/test_topology_hwsku_df.csv"

mock_current_time = datetime.fromisoformat("2025-01-06 03:44:26.785317+00:00")
mock_kusto_connector = MagicMock()
mock_kusto_connector.__getitem__.return_value = 0

# mock the analyze_active_icm function for DataAnalyzer initialization
with patch('data_analyzer.DataAnalyzer.analyze_active_icm', return_value=[None, None]), \
    patch('data_analyzer.timedelta', return_value=timedelta(days=7)):    # mock the self.search_start_time for data_analyzer.BasicAnalyzer
    general = DataAnalyzer(mock_kusto_connector, Mock(), mock_current_time)

df1 = pd.read_csv(DF1_FILE.format(current_folder), dtype=object)
df1['UploadTimestamp'] = pd.to_datetime(df1['UploadTimestamp'])
df1 = df1[df1['BranchName'] == '20240510']
df1_case_info_dict = {
    'case_branch': 'bgp.test_bgp_bbr_default_state.test_bbr_disabled_constants_yml_default#20240510',
    'is_module_path': False,
    'is_common_summary': False
}
with patch('data_analyzer.dataframe_from_result_table', return_value=df1), \
    patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder))):
    actual_history_testcases, df1 = general.search_and_parse_history_results(df1_case_info_dict)

df2 = pd.read_csv(DF2_FILE, dtype=object)
df2['UploadTimestamp'] = pd.to_datetime(df2['UploadTimestamp'])
df2_case_info_dict = {
    'case_branch': 'qos.test_qos_sai.TestQosSai.testQosSaiSeparatedDscpToPgMapping#20240510',
    'is_module_path': False,
    'is_common_summary': False
}
with patch('data_analyzer.dataframe_from_result_table', return_value=df2), \
    patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder))):
    actual_history_testcases, df2 = general.search_and_parse_history_results(df2_case_info_dict)

df3 = pd.read_csv(DF3_FILE, dtype=object)
df3['UploadTimestamp'] = pd.to_datetime(df3['UploadTimestamp'])
df3_case_info_dict = {
    'case_branch': 'platform_tests.api.test_chassis.TestChassisApi.test_get_system_eeprom_info#20240510',
    'is_module_path': False,
    'is_common_summary': False
}
with patch('data_analyzer.dataframe_from_result_table', return_value=df3), \
    patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder))):
    actual_history_testcases, df3 = general.search_and_parse_history_results(df3_case_info_dict)

hwsku_osversion_df = pd.read_csv(HWSKU_OSVERSION_DF_FILE, dtype=object)
hwsku_osversion_df['UploadTimestamp'] = pd.to_datetime(hwsku_osversion_df['UploadTimestamp'])

topology_hwsku_df = pd.read_csv(TOPOLOGY_HWSKU_DF_FILE, dtype=object)
topology_hwsku_df['UploadTimestamp'] = pd.to_datetime(topology_hwsku_df['UploadTimestamp'])

class TestSuccessRateCalculation(unittest.TestCase):

    def test_branch_success_rate(self):

        # on df1
        actual_success_rate_df1 = general.calculate_success_rate(df1, 'BranchName', 'branch')
        expected_actual_success_rate_df1 = {
            'success_rate': [
                '20240510 : 22%/17/79'],
            'consistent_failure_branch': []
        }
        self.assertEqual(actual_success_rate_df1, expected_actual_success_rate_df1)

        # on df2
        actual_success_rate_df2 = general.calculate_success_rate(df2, 'BranchName', 'branch')
        expected_actual_success_rate_df2 = {
            'success_rate': ['20240510 : 50%/54/108'],
            'consistent_failure_branch': []
        }
        self.assertEqual(actual_success_rate_df2, expected_actual_success_rate_df2)

        # on df3
        actual_success_rate_df3 = general.calculate_success_rate(df3, 'BranchName', 'branch')
        expected_actual_success_rate_df3 = {
            'success_rate': ['20240510 : 88%/215/245'],
            'consistent_failure_branch': []
        }
        self.assertEqual(actual_success_rate_df3, expected_actual_success_rate_df3)

    def test_osversion_success_rate(self):

        # on df1
        actual_success_rate_df1 = general.calculate_success_rate(df1, 'OSVersion', 'os_version')
        expected_actual_success_rate_df1 = {
            'success_rate': [
                '20240510.16 : 100%/3/3',
                '20240510.17 : 57%/4/7',
                '20240510.18 : 29%/5/17',
                '20240510.19 : 17%/5/29',
                '20240510.20 : 0%/0/19',
                '20240510.21 : 0%/0/4'
            ],
            'consistent_failure_os_version': ['20240510.21', '20240510.20']
        }
        self.assertEqual(actual_success_rate_df1, expected_actual_success_rate_df1)

        # on df2
        actual_success_rate_df2 = general.calculate_success_rate(df2, 'OSVersion', 'os_version')
        expected_actual_success_rate_df2 = {
            'success_rate': [
                '20240510.16 : 20%/4/20',
                '20240510.17 : 100%/8/8',
                '20240510.18 : 62%/16/26',
                '20240510.19 : 37%/14/38',
                '20240510.20 : 100%/10/10',
                '20240510.21 : 33%/2/6'
            ],
            'consistent_failure_os_version': []
        }
        self.assertEqual(actual_success_rate_df2, expected_actual_success_rate_df2)

        # on df3
        actual_success_rate_df3 = general.calculate_success_rate(df3, 'OSVersion', 'os_version')
        expected_actual_success_rate_df3 = {
            'success_rate': [
                '20240510.16 : 72%/18/25',
                '20240510.17 : 82%/14/17',
                '20240510.18 : 95%/70/74',
                '20240510.19 : 93%/68/73',
                '20240510.20 : 90%/26/29',
                '20240510.21 : 70%/19/27'
            ],
            'consistent_failure_os_version': []
        }
        self.assertEqual(actual_success_rate_df3, expected_actual_success_rate_df3)

    def test_topology_success_rate(self):

        # on df1
        actual_success_rate_df1 = general.calculate_success_rate(df1, 'Topology', 'topology')
        expected_actual_success_rate_df1 = {
            'success_rate': ['T1 : 22%/17/79'],
            'consistent_failure_topology': []
        }
        self.assertEqual(actual_success_rate_df1, expected_actual_success_rate_df1)

        # on df2
        actual_success_rate_df2 = general.calculate_success_rate(df2, 'Topology', 'topology')
        expected_actual_success_rate_df2 = {
            'success_rate': [
                'DUALTOR : 0%/0/4',
                'T2 : 0%/0/26',
                'T1 : 69%/54/78'],
            'consistent_failure_topology': ['DUALTOR', 'T2']
        }
        self.assertEqual(actual_success_rate_df2, expected_actual_success_rate_df2)

        # on df3
        actual_success_rate_df3 = general.calculate_success_rate(df3, 'Topology', 'topology')
        expected_actual_success_rate_df3 = {
            'success_rate': [
                'T2_IXIA : 36%/4/11',
                'DUALTOR : 44%/16/36',
                'T2 : 82%/9/11',
                'T0 : 98%/62/63',
                'T1 : 100%/64/64',
                'M0_MX : 100%/60/60'
            ],
            'consistent_failure_topology': []
        }
        self.assertEqual(actual_success_rate_df3, expected_actual_success_rate_df3)

    def test_asic_success_rate(self):

        # on df1
        actual_success_rate_df1 = general.calculate_success_rate(df1, 'AsicType', 'asic')
        expected_actual_success_rate_df1 = {
            'success_rate': [
                'mellanox : 3%/1/33',
                'cisco-8000 : 11%/1/9',
                'broadcom : 41%/15/37'],
            'consistent_failure_asic': []
        }
        self.assertEqual(actual_success_rate_df1, expected_actual_success_rate_df1)

        # on df2
        actual_success_rate_df2 = general.calculate_success_rate(df2, 'AsicType', 'asic')
        expected_actual_success_rate_df2 = {
            'success_rate': [
                'broadcom : 26%/16/62',
                'mellanox : 80%/24/30',
                'cisco-8000 : 88%/14/16'
            ],
            'consistent_failure_asic': []
        }
        self.assertEqual(actual_success_rate_df2, expected_actual_success_rate_df2)

        # on df3
        actual_success_rate_df3 = general.calculate_success_rate(df3, 'AsicType', 'asic')
        expected_actual_success_rate_df3 = {
            'success_rate': [
                'broadcom : 80%/94/117',
                'mellanox : 93%/75/81',
                'cisco-8000 : 94%/15/16',
                'marvell : 100%/31/31'
            ],
            'consistent_failure_asic': []
        }
        self.assertEqual(actual_success_rate_df3, expected_actual_success_rate_df3)

    def test_hwsku_success_rate(self):
        # on df1
        actual_success_rate_df1 = general.calculate_success_rate(df1, 'HardwareSku', 'hwsku')
        expected_actual_success_rate_df1 = {
            'success_rate': [
                'Cisco-8101-O32 : 0%/0/2',
                'Mellanox-SN2700 : 0%/0/10',
                'Cisco-8101-O8C48 : 0%/0/4',
                'Mellanox-SN2700-A1 : 0%/0/4',
                'Mellanox-SN4700-O32 : 0%/0/3',
                'Mellanox-SN4700-O8C48 : 0%/0/1',
                'Cisco-8122-O64S2 : 0%/0/1',
                'Mellanox-SN4600C-C64 : 7%/1/15',
                'Arista-7060CX-32S-C32 : 37%/7/19',
                'Arista-7260CX3-C64 : 41%/7/17',
                'Cisco-8102-C64 : 50%/1/2',
                'Arista-7050CX3-32S-C32 : 100%/1/1'
            ],
            'consistent_failure_hwsku': ['Cisco-8101-O32', 'Mellanox-SN2700', 'Cisco-8101-O8C48', 'Mellanox-SN2700-A1', 'Mellanox-SN4700-O32', 'Mellanox-SN4700-O8C48', 'Cisco-8122-O64S2']}
        self.assertEqual(actual_success_rate_df1, expected_actual_success_rate_df1)

        # on df2
        actual_success_rate_df2 = general.calculate_success_rate(df2, 'HardwareSku', 'hwsku')
        expected_actual_success_rate_df2 = {
            'success_rate': [
                'Mellanox-SN4700-V64 : 0%/0/4',
                'Nokia-IXR7250E-SUP-10 : 0%/0/10',
                'Nokia-IXR7250E-36x400G : 0%/0/16',
                'Arista-7260CX3-C64 : 44%/16/36',
                'Cisco-8101-O8C48 : 75%/6/8',
                'Mellanox-SN4600C-C64 : 92%/24/26',
                'Cisco-8102-C64 : 100%/8/8'
            ],
            'consistent_failure_hwsku': ['Mellanox-SN4700-V64', 'Nokia-IXR7250E-SUP-10', 'Nokia-IXR7250E-36x400G']}
        self.assertEqual(actual_success_rate_df2, expected_actual_success_rate_df2)

         # on df3
        actual_success_rate_df3 = general.calculate_success_rate(df3, 'HardwareSku', 'hwsku')
        expected_actual_success_rate_df3 = {
            'success_rate': [
                'Arista-7260CX3-D108C8 : 38%/9/24',
                'Mellanox-SN4700-O8V48 : 50%/2/4',
                'Nokia-IXR7250E-SUP-10 : 67%/4/6',
                'Arista-7260CX3-C64 : 71%/15/21',
                'Cisco-8101-O8C48 : 80%/4/5',
                'Mellanox-SN2700 : 92%/22/24',
                'Mellanox-SN4600C-C64 : 93%/27/29',
                'Cisco-8101-O32 : 100%/2/2',
                'Mellanox-SN4700-V64 : 100%/2/2',
                'Mellanox-SN2700-A1 : 100%/18/18',
                'Arista-720DT-G48S4 : 100%/30/30',
                'Nokia-M0-7215 : 100%/19/19',
                'Arista-7060CX-32S-D48C8 : 100%/8/8',
                'Arista-7060CX-32S-C32 : 100%/11/11',
                'Cisco-8102-C64 : 100%/3/3',
                'Arista-7800R3A-36DM2-D36 : 100%/3/3',
                'Nokia-7215 : 100%/12/12',
                'Arista-7050CX3-32S-C32 : 100%/12/12',
                'Mellanox-SN4700-O32 : 100%/3/3',
                'Mellanox-SN4700-O8C48 : 100%/1/1',
                'Nokia-IXR7250E-36x100G : 100%/2/2',
                'Cisco-8122-O64S2 : 100%/6/6'
            ],
            'consistent_failure_hwsku': []
        }
        self.assertEqual(actual_success_rate_df3, expected_actual_success_rate_df3)

    @patch('data_analyzer.configuration', load_config('{}/configs/config_more_than_one_in_type_list.json'.format(current_folder)))
    def test_success_rate_more_than_one_in_type_list(self):
        with patch('data_analyzer.dataframe_from_result_table', return_value=df3):
            _, data = general.search_and_parse_history_results(df3_case_info_dict)
        actual_osversion_success_rate = general.calculate_success_rate(data, 'OSVersion', 'os_version')
        expected_actual_osversion_success_rate_df = {
            'success_rate': [
                '20240510.1X : 90%/170/189',
                '20240510.2X : 80%/45/56'
            ],
            'consistent_failure_os_version': []
        }
        self.assertEqual(actual_osversion_success_rate, expected_actual_osversion_success_rate_df)


        actual_asic_success_rate = general.calculate_success_rate(data, 'AsicType', 'asic')
        expected_actual_asic_success_rate_df = {
            'success_rate': [
                'broadcom : 80%/94/117',
                'mellanox&cisco-8000 : 93%/90/97',
                'marvell : 100%/31/31'
            ],
            'consistent_failure_asic': []
        }
        self.assertEqual(actual_asic_success_rate, expected_actual_asic_success_rate_df)

        actual_hwsku_success_rate = general.calculate_success_rate(data, 'HardwareSku', 'hwsku')
        expected_actual_hwsku_success_rate_df = {
            'success_rate': [
                'Arista : 81%/88/109',
                'Mellanox : 93%/75/81',
                'Cisco : 94%/15/16',
                'Nokia : 95%/37/39'
            ],
            'consistent_failure_hwsku': []
        }
        self.assertEqual(actual_hwsku_success_rate, expected_actual_hwsku_success_rate_df)


    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_hwsku_osversion_success_rate(self):
        case_info_dict = {
            'case_branch': 'snmp.test_snmp_link_local.test_snmp_link_local_ip#20240510',
            'is_module_path': False,
            'is_common_summary': False
        }
        with patch('data_analyzer.dataframe_from_result_table', return_value=hwsku_osversion_df):
            actual_history_testcases, case_df_after_filter = general.search_and_parse_history_results(case_info_dict)
        actual_success_rate = general.calculate_combined_success_rate(case_df_after_filter, 'hwsku_osversion')
        expected_success_rate = {
            'success_rate': [
                'Arista-7260CX3-D108C8_20240510.21 : 0%/0/1',
                'Arista-7050CX3-32S-C32_20240510.21 : 50%/1/2',
                'Arista-7050CX3-32S-C32_20240510.19 : 100%/4/4',
                'Arista-7260CX3-D108C8_20240510.19 : 100%/1/1',
                'Arista-7260CX3-D108C8_20240510.18 : 100%/3/3',
                'Arista-7050CX3-32S-C32_20240510.18 : 100%/3/3',
                'Arista-7050CX3-32S-C32_20240510.16 : 100%/1/1'
            ],
            'consistent_failure_hwsku_osversion': ['Arista-7260CX3-D108C8_20240510.21']
        }
        self.assertEqual(actual_success_rate, expected_success_rate)

    @patch('data_analyzer.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_topology_hwsku_success_rate(self):
        case_info_dict = {
            'case_branch': 'snmp.test_snmp_link_local.test_snmp_link_local_ip#20240510',
            'is_module_path': False,
            'is_common_summary': False
        }
        with patch('data_analyzer.dataframe_from_result_table', return_value=topology_hwsku_df):
            actual_history_testcases, case_df_after_filter = general.search_and_parse_history_results(case_info_dict)
        actual_success_rate = general.calculate_combined_success_rate(case_df_after_filter, 'topology_hwsku')
        expected_success_rate = {
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
                'T2_Arista-7800R3A-36DM2-D36 : 100%/2/2',
                'T0_Arista-7050CX3-32S-C32 : 100%/1/1'],
            'consistent_failure_topology_hwsku': []
        }
        self.assertEqual(actual_success_rate, expected_success_rate)