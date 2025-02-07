import unittest
import logging
import os, sys
sys.path.append("..")
from data_deduplicator import DataDeduplicator
import pandas as pd
from unittest.mock import patch
from unittest.mock import Mock
from helper import load_config

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s :%(name)s:%(lineno)d %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)

ICM_PREFIX = '[SONiC_Nightly][Failed_Case]'

current_file_path = os.path.abspath(__file__)
current_folder = os.path.dirname(current_file_path)

class TestDeduplicator(unittest.TestCase):

    def setUp(self):
        with patch('data_deduplicator.configuration', load_config('{}/configs/config_default.json'.format(current_folder))):
            self.deduplicator = DataDeduplicator()

    def test_check_deduplicates_1(self):
        """
            check if [case_a][case_b][topology_a] is duplicated with [case_a][branch_b]
        """
        icm = {
            'subject': '[case_a][branch_a][topology_a]',
            'failure_level_info': {}
        }
        actual_duplicated_flag = self.deduplicator.check_duplicates(
            active_icm_title='{}[case_a][branch_a]'.format(ICM_PREFIX), icm=icm)
        expected_duplicated_flag = True
        self.assertEqual(actual_duplicated_flag, expected_duplicated_flag)

    def test_check_deduplicator_2(self):
        """
            check if [case_a][branch_a][hwskuA_20240510.16] is duplicated with [case_a][branch_a]
        """
        icm = {
            'subject': '[case_a][branch_a][hwskuA_20240510.16]',
            'failure_level_info': {
                'is_combined': True
            }
        }
        actual_duplicated_flag = self.deduplicator.check_duplicates(
            active_icm_title='{}[case_a][branch_a]'.format(ICM_PREFIX), icm=icm)
        expected_duplicated_flag = True
        self.assertEqual(actual_duplicated_flag, expected_duplicated_flag)

    @patch('data_deduplicator.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_check_deduplicator_3(self):
        """
            check if [case_a][branch_a][hwskuA_20240510.16] is duplicated with [case_a][branch_a][hwksuA]
        """
        icm = {
            'subject': '[case_a][branch_a][hwskuA_20240510.16]',
            'failure_level_info': {
                'is_combined': True
            }
        }
        actual_duplicated_flag = DataDeduplicator().check_duplicates(
            active_icm_title='{}[case_a][branch_a][hwskuA]'.format(ICM_PREFIX), icm=icm)
        expected_duplicated_flag = True
        self.assertEqual(actual_duplicated_flag, expected_duplicated_flag)

    @patch('data_deduplicator.configuration', load_config('{}/configs/config_default.json'.format(current_folder)))
    def test_check_deduplicator_4(self):
        """
            check if [case_a][20240510][hwskuA_20240510.16] is duplicated with [case_a][20240510]
        """
        icm = {
            'subject': '[case_a][20240510][hwskuA_20240510.16]',
            'failure_level_info': {
                'is_combined': True
            }
        }
        actual_duplicated_flag = self.deduplicator.check_duplicates(
            active_icm_title='{}[case_a][20240510]'.format(ICM_PREFIX), icm=icm)
        expected_duplicated_flag = True
        self.assertEqual(actual_duplicated_flag, expected_duplicated_flag)

    def test_check_deduplicator_5(self):
        """
            check if [case_a][20240510][hwskuA_20240510.16] is duplicated with [case_a][20240510][topologyA]
        """
        icm = {
            'subject': '[case_a][20240510][hwskuA_20240510.16]',
            'failure_level_info': {
                'is_combined': True
            }
        }
        actual_duplicated_flag = self.deduplicator.check_duplicates(
            active_icm_title='{}[case_a][20240510][topologyA]'.format(ICM_PREFIX), icm=icm)
        expected_duplicated_flag = False
        self.assertEqual(actual_duplicated_flag, expected_duplicated_flag)

    def test_check_deduplicator_6(self):
        """
            check if [case_a][20240510][topologyA_hwskuC] is duplicated with [case_a][20240510][topologyA][asicB]
        """
        icm = {
            'subject': '[case_a][20240510][hwskuA_20240510.16]',
            'failure_level_info': {
                'is_combined': True
            }
        }
        actual_duplicated_flag = self.deduplicator.check_duplicates(
            active_icm_title='{}[case_a][20240510][topologyA][asicB]'.format(ICM_PREFIX), icm=icm)
        expected_duplicated_flag = False
        self.assertEqual(actual_duplicated_flag, expected_duplicated_flag)

    def test_check_deduplicator_7(self):
        """
            check if [case_a][20240510][topologyA_hwskuC] is duplicated with [case_a][20240510][topologyA][asicB][hwskuC]
        """
        icm = {
            'subject': '[case_a][20240510][topologyA_hwskuC]',
            'failure_level_info': {
                'is_combined': True
            }
        }
        actual_duplicated_flag = self.deduplicator.check_duplicates(
            active_icm_title='{}[case_a][20240510][topologyA][asicB][hwskuC]'.format(ICM_PREFIX), icm=icm)
        expected_duplicated_flag = True
        self.assertEqual(actual_duplicated_flag, expected_duplicated_flag)

    def test_check_deduplicator_8(self):
        """
            check if [case_a][20240510][hwskuA_osversionB] is duplicated with [case_a][20240510][topologyA][asicB][hwskuA]
        """
        icm = {
            'subject': '[case_a][20240510][hwskuA_osversionB]',
            'failure_level_info': {
                'is_combined': True
            }
        }
        actual_duplicated_flag = self.deduplicator.check_duplicates(
            active_icm_title='{}[case_a][20240510][topologyA][asicB][hwskuA]'.format(ICM_PREFIX), icm=icm)
        expected_duplicated_flag = False
        self.assertEqual(actual_duplicated_flag, expected_duplicated_flag)

    def test_deduplicate_limit_with_active_icm_1(self):
        kusto_data_list = [
            {
                'trigger_icm': True,
                'testcase': 'test_bbr_disabled_constants_yml_default',
                'branch': '20240510',
                'module_path': 'bgp.test_bgp_bbr_default_state',
                'subject': '[bgp.test_bgp_bbr_default_state][test_bbr_disabled_constants_yml_default][20240510]',
                'failure_summary': '',
                'failure_level_info': {}
            }
        ]
        icm_count_dict = {'everflow_count': 3, 'qos_sai_count': 26, 'acl_count': 6}
        active_icm_df = pd.read_csv('{}/tests_df/active_icm_df_1.csv'.format(current_folder), dtype=object)
        actual_new_icm_list, actual_duplicated_icm_list, actual_updated_icm_count_dict = self.deduplicator.deduplicate_limit_with_active_icm(kusto_data_list, icm_count_dict, active_icm_df)
        expected_new_icm_list = []
        expected_duplicated_icm_list = kusto_data_list
        self.assertCountEqual(actual_new_icm_list, expected_new_icm_list)
        self.assertCountEqual(actual_duplicated_icm_list, expected_duplicated_icm_list)

    def test_deduplicate_limit_with_active_icm_2(self):
        kusto_data_list = [
            {
                'trigger_icm': True,
                'testcase': 'test_bbr_disabled_constants_yml_default',
                'branch': '20240510',
                'module_path': 'bgp.test_bgp_bbr_default_state',
                'subject': '[bgp.test_bgp_bbr_default_state][test_bbr_disabled_constants_yml_default][20240510]',
                'failure_summary': '',
                'failure_level_info': {}
            }
        ]
        icm_count_dict = {'everflow_count': 3, 'qos_sai_count': 26, 'acl_count': 6}
        active_icm_df = pd.read_csv('{}/tests_df/active_icm_df_1.csv'.format(current_folder), dtype=object)
        actual_new_icm_list, actual_duplicated_icm_list, actual_updated_icm_count_dict = self.deduplicator.deduplicate_limit_with_active_icm(kusto_data_list, icm_count_dict, active_icm_df)
        expected_new_icm_list = []
        expected_duplicated_icm_list = kusto_data_list
        self.assertCountEqual(actual_new_icm_list, expected_new_icm_list)
        self.assertCountEqual(actual_duplicated_icm_list, expected_duplicated_icm_list)

    def test_deduplicate_limit_with_active_icm_3(self):
        kusto_data_list = [
            {
                'trigger_icm': True,
                'testcase': 'test_soft_reboot',
                'branch': '20240510',
                'module_path': 'platform_tests.test_reboot',
                'subject': '[platform_tests.test_reboot][test_soft_reboot][20240510][Mellanox-SN4700-O8V48_20240510.23]',
                'failure_summary': '',
                'failure_level_info': {
                    'hwsku': 'Mellanox-SN4700-O8V48',
                    'os_version': '20240510.23',
                    'is_combined': True
                }
            }
        ]
        icm_count_dict = {'everflow_count': 3, 'qos_sai_count': 26, 'acl_count': 6}
        active_icm_df = pd.read_csv('{}/tests_df/active_icm_df_1.csv'.format(current_folder), dtype=object)
        actual_new_icm_list, actual_duplicated_icm_list, actual_updated_icm_count_dict = self.deduplicator.deduplicate_limit_with_active_icm(kusto_data_list, icm_count_dict, active_icm_df)
        expected_new_icm_list = []
        expected_duplicated_icm_list = kusto_data_list
        self.assertCountEqual(actual_new_icm_list, expected_new_icm_list)
        self.assertCountEqual(actual_duplicated_icm_list, expected_duplicated_icm_list)

    def test_deduplicate_limit_with_active_icm_4(self):
        kusto_data_list = [
            {
                'trigger_icm': True,
                'testcase': 'test_soft_reboot',
                'branch': '20240510',
                'module_path': 'platform_tests.test_reboot',
                'subject': '[platform_tests.test_reboot][test_soft_reboot][20240510][T2]',
                'failure_summary': '',
                'failure_level_info': {
                    'topology': 'T2',
                }
            }
        ]
        icm_count_dict = {'everflow_count': 3, 'qos_sai_count': 26, 'acl_count': 6}
        active_icm_df = pd.read_csv('{}/tests_df/active_icm_df_1.csv'.format(current_folder), dtype=object)
        actual_new_icm_list, actual_duplicated_icm_list, actual_updated_icm_count_dict = self.deduplicator.deduplicate_limit_with_active_icm(kusto_data_list, icm_count_dict, active_icm_df)
        expected_new_icm_list = []
        expected_duplicated_icm_list = kusto_data_list
        self.assertCountEqual(actual_new_icm_list, expected_new_icm_list)
        self.assertCountEqual(actual_duplicated_icm_list, expected_duplicated_icm_list)

    def test_deduplicate_limit_with_active_icm_5(self):
        kusto_data_list = [
            {
                'trigger_icm': True,
                'testcase': 'test_soft_reboot',
                'branch': '20240510',
                'module_path': 'platform_tests.test_reboot',
                'subject': '[platform_tests.test_reboot][test_soft_reboot][master]',
                'failure_summary': '',
                'failure_level_info': {}
            }
        ]
        icm_count_dict = {'everflow_count': 3, 'qos_sai_count': 26, 'acl_count': 6}
        active_icm_df = pd.read_csv('{}/tests_df/active_icm_df_1.csv'.format(current_folder), dtype=object)
        actual_new_icm_list, actual_duplicated_icm_list, actual_updated_icm_count_dict = self.deduplicator.deduplicate_limit_with_active_icm(kusto_data_list, icm_count_dict, active_icm_df)
        expected_new_icm_list = kusto_data_list
        expected_duplicated_icm_list = []
        self.assertCountEqual(actual_new_icm_list, expected_new_icm_list)
        self.assertCountEqual(actual_duplicated_icm_list, expected_duplicated_icm_list)


    def test_deduplication(self):
        setup_error_new_icm_table = []
        common_summary_new_icm_table = []
        original_failure_dict = [
            {'table': [
                {
                    'trigger_icm': True,
                    'testcase': 'test_soft_reboot',
                    'branch': '20240510',
                    'module_path': 'platform_tests.test_reboot',
                    'subject': '[platform_tests.test_reboot][test_soft_reboot][internal]',
                    'failure_summary': '',
                    'failure_level_info': {}
                },
                {
                    'trigger_icm': True,
                    'testcase': 'test_soft_reboot',
                    'branch': '20240510',
                    'module_path': 'platform_tests.test_reboot',
                    'subject': '[platform_tests.test_reboot][test_soft_reboot][20240510]',
                    'failure_summary': '',
                    'failure_level_info': {}
                },
                {
                    'trigger_icm': True,
                    'testcase': 'test_soft_reboot',
                    'branch': '20240510',
                    'module_path': 'platform_tests.test_reboot',
                    'subject': '[platform_tests.test_reboot][test_soft_reboot][master][toplogyA][asicA]',
                    'failure_summary': '',
                    'failure_level_info': {}
                },
                {
                    'trigger_icm': True,
                    'testcase': 'test_soft_reboot',
                    'branch': '20240510',
                    'module_path': 'platform_tests.test_reboot',
                    'subject': '[platform_tests.test_reboot][test_soft_reboot][master][toplogyA][asicB]',
                    'failure_summary': '',
                    'failure_level_info': {}
                },
                {
                    'trigger_icm': True,
                    'testcase': 'test_soft_reboot',
                    'branch': '20240510',
                    'module_path': 'platform_tests.test_reboot',
                    'subject': '[platform_tests.test_reboot][test_soft_reboot][internal][topologyB]',
                    'failure_summary': '',
                    'failure_level_info': {}
                },
                {
                    'trigger_icm': True,
                    'testcase': 'test_soft_reboot',
                    'branch': '20240510',
                    'module_path': 'platform_tests.test_reboot',
                    'subject': '[platform_tests.test_reboot][test_soft_reboot][20240510][hwskuA_20240510.21]',
                    'failure_summary': '',
                    'failure_level_info': {
                        'is_combined': True
                    }
                },
                {
                    'trigger_icm': True,
                    'testcase': 'test_soft_reboot',
                    'branch': '20240510',
                    'module_path': 'platform_tests.test_reboot',
                    'subject': '[platform_tests.test_reboot][test_soft_reboot][internal][hwskuA_internal.21]',
                    'failure_summary': '',
                    'failure_level_info':  {
                        'is_combined': True
                    }
                },
                {
                    'trigger_icm': True,
                    'testcase': 'test_soft_reboot',
                    'branch': '20240510',
                    'module_path': 'platform_tests.test_reboot',
                    'subject': '[case_a][20240510][topologyA_hwskuC]',
                    'failure_summary': '',
                    'failure_level_info': {
                    'is_combined': True
                    }
                },
                {
                    'trigger_icm': True,
                    'testcase': 'test_soft_reboot',
                    'branch': '20240510',
                    'module_path': 'platform_tests.test_reboot',
                    'subject': '[case_a][20240510][topologyB_hwskuC]',
                    'failure_summary': '',
                    'failure_level_info': {
                    'is_combined': True
                    }
                },
                {
                    'trigger_icm': True,
                    'testcase': 'test_soft_reboot',
                    'branch': '20240510',
                    'module_path': 'platform_tests.test_reboot',
                    'subject': '[case_a][20240510][topologyA][asicB][hwskuC]',
                    'failure_summary': '',
                    'failure_level_info': {}
                }
            ],
            'type': 'general'}
        ]
        branches = ['master', 'internal', '202012', '202205', '202305', '202311', '202405']
        _, actual_final_icm_list, actual_duplicated_icm_list = self.deduplicator.deduplication(setup_error_new_icm_table,
                                                                                 common_summary_new_icm_table,
                                                                                 original_failure_dict, branches)
        expected_final_icm_list = [
            {
                'trigger_icm': True,
                'testcase': 'test_soft_reboot',
                'branch': '20240510',
                'module_path': 'platform_tests.test_reboot',
                'subject': '[platform_tests.test_reboot][test_soft_reboot][internal]',
                'failure_summary': '',
                'failure_level_info': {}
            },
            {
                'trigger_icm': True,
                'testcase': 'test_soft_reboot',
                'branch': '20240510',
                'module_path': 'platform_tests.test_reboot',
                'subject': '[platform_tests.test_reboot][test_soft_reboot][20240510]',
                'failure_summary': '',
                'failure_level_info': {}
            },
            {
                'trigger_icm': True,
                'testcase': 'test_soft_reboot',
                'branch': '20240510',
                'module_path': 'platform_tests.test_reboot',
                'subject': '[platform_tests.test_reboot][test_soft_reboot][master][toplogyA][asicA]',
                'failure_summary': '',
                'failure_level_info': {}
            },
            {
                'trigger_icm': True,
                'testcase': 'test_soft_reboot',
                'branch': '20240510',
                'module_path': 'platform_tests.test_reboot',
                'subject': '[platform_tests.test_reboot][test_soft_reboot][master][toplogyA][asicB]',
                'failure_summary': '',
                'failure_level_info': {}
            },
            {
                'trigger_icm': True,
                'testcase': 'test_soft_reboot',
                'branch': '20240510',
                'module_path': 'platform_tests.test_reboot',
                'subject': '[case_a][20240510][topologyB_hwskuC]',
                'failure_summary': '',
                'failure_level_info': {
                'is_combined': True
                }
            },
            {
                'trigger_icm': True,
                'testcase': 'test_soft_reboot',
                'branch': '20240510',
                'module_path': 'platform_tests.test_reboot',
                'subject': '[case_a][20240510][topologyA][asicB][hwskuC]',
                'failure_summary': '',
                'failure_level_info': {}
            }
        ]
        expected_duplicated_icm_list = [
            {
                'trigger_icm': False,
                'testcase': 'test_soft_reboot',
                'branch': '20240510',
                'module_path': 'platform_tests.test_reboot',
                'subject': '[platform_tests.test_reboot][test_soft_reboot][internal][topologyB]',
                'failure_summary': '',
                'failure_level_info': {}
            },
            {
                'trigger_icm': False,
                'testcase': 'test_soft_reboot',
                'branch': '20240510',
                'module_path': 'platform_tests.test_reboot',
                'subject': '[platform_tests.test_reboot][test_soft_reboot][20240510][hwskuA_20240510.21]',
                'failure_summary': '',
                'failure_level_info': {
                    'is_combined': True
                }
            },
            {
                'trigger_icm': False,
                'testcase': 'test_soft_reboot',
                'branch': '20240510',
                'module_path': 'platform_tests.test_reboot',
                'subject': '[platform_tests.test_reboot][test_soft_reboot][internal][hwskuA_internal.21]',
                'failure_summary': '',
                'failure_level_info': {
                    'is_combined': True
                }
            },
            {
                'trigger_icm': False,
                'testcase': 'test_soft_reboot',
                'branch': '20240510',
                'module_path': 'platform_tests.test_reboot',
                'subject': '[case_a][20240510][topologyA_hwskuC]',
                'failure_summary': '',
                'failure_level_info': {
                'is_combined': True
                }
            },
        ]
        self.assertCountEqual(actual_final_icm_list, expected_final_icm_list)
        self.assertCountEqual(actual_duplicated_icm_list, expected_duplicated_icm_list)
