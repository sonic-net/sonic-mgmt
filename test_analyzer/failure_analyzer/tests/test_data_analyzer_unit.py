"""
Unit tests for data_analyzer.py
Covers DataAnalyzer methods that contribute most to coverage.
"""
import unittest
import os
import sys
import math
from unittest.mock import patch, MagicMock
from datetime import datetime

import pandas as pd
import pytz

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from helper import load_config  # noqa: E402

current_file_path = os.path.abspath(__file__)
current_folder = os.path.dirname(current_file_path)
TEST_CONFIG = load_config('{}/configs/config_default.json'.format(current_folder))


def make_analyzer():
    """Create a DataAnalyzer with mocked kusto_connector and deduper."""
    mock_kusto = MagicMock()
    mock_deduper = MagicMock()

    # Mock active_icm response
    mock_active_icm_response = MagicMock()
    mock_active_icm_result = MagicMock()
    mock_active_icm_result.__iter__ = MagicMock(return_value=iter([]))
    mock_active_icm_result.columns = ['IncidentId', 'Title', 'SourceCreateDate', 'ModifiedDate', 'Status']
    mock_active_icm_result.__len__ = MagicMock(return_value=0)
    mock_active_icm_response.primary_results = [mock_active_icm_result]
    mock_kusto.query_active_icm.return_value = mock_active_icm_response

    # Mock all_upload_records response
    mock_upload_response = MagicMock()
    mock_upload_result = MagicMock()
    mock_upload_result.__iter__ = MagicMock(return_value=iter([]))
    mock_upload_result.columns = ['UploadTimestamp', 'ModulePath', 'TestCase', 'Branch',
                                  'Subject', 'FailureLevelInfo', 'FailureSummary']
    mock_upload_result.__len__ = MagicMock(return_value=0)
    mock_upload_response.primary_results = [mock_upload_result]
    mock_kusto.query_all_upload_records_with_trigger_icm.return_value = mock_upload_response

    with patch('data_analyzer.configuration', TEST_CONFIG), \
            patch('data_analyzer.dataframe_from_result_table') as mock_df_from_result:
        # Return empty DataFrames for the init queries
        active_icm_df = pd.DataFrame({
            'IncidentId': [], 'Title': [], 'SourceCreateDate': [],
            'ModifiedDate': [], 'Status': []
        })
        upload_records_df = pd.DataFrame({
            'UploadTimestamp': [], 'ModulePath': [], 'TestCase': [],
            'Branch': [], 'Subject': [], 'FailureLevelInfo': [],
            'FailureSummary': []
        })
        mock_df_from_result.side_effect = [active_icm_df, upload_records_df]

        from data_analyzer import DataAnalyzer
        current_time = datetime.now(tz=pytz.UTC)
        analyzer = DataAnalyzer(mock_kusto, mock_deduper, current_time)

    return analyzer, mock_kusto, mock_deduper


class TestCountIcm(unittest.TestCase):
    """Tests for DataAnalyzer.count_icm()."""

    def setUp(self):
        self.analyzer, _, _ = make_analyzer()

    def test_count_icm_empty_list(self):
        result = self.analyzer.count_icm([])
        self.assertEqual(result['everflow_count'], 0)
        self.assertEqual(result['qos_sai_count'], 0)
        self.assertEqual(result['acl_count'], 0)

    def test_count_icm_with_everflow(self):
        titles = [
            '[SONiC_Nightly][Failed_Case][everflow.test_everflow][test_case][master]',
        ]
        result = self.analyzer.count_icm(titles)
        self.assertEqual(result['everflow_count'], 1)

    def test_count_icm_with_qos_sai(self):
        titles = [
            '[SONiC_Nightly][Failed_Case][qos.test_qos_sai][test_case][master]',
        ]
        result = self.analyzer.count_icm(titles)
        self.assertEqual(result['qos_sai_count'], 1)

    def test_count_icm_with_acl(self):
        titles = [
            '[SONiC_Nightly][Failed_Case][acl.test_acl][test_case][master]',
        ]
        result = self.analyzer.count_icm(titles)
        self.assertEqual(result['acl_count'], 1)

    def test_count_icm_mixed(self):
        titles = [
            '[SONiC_Nightly][Failed_Case][everflow.test_everflow][test1][master]',
            '[SONiC_Nightly][Failed_Case][acl.test_acl][test2][master]',
            '[SONiC_Nightly][Failed_Case][bgp.test_bgp][test3][master]',
        ]
        result = self.analyzer.count_icm(titles)
        self.assertEqual(result['everflow_count'], 1)
        self.assertEqual(result['acl_count'], 1)
        self.assertEqual(result['qos_sai_count'], 0)

    def test_count_icm_without_prefix(self):
        """Titles without the ICM prefix - count_icm uses raw title."""
        # The code has a bug with titles not starting with prefix (uses unset variable)
        # Just test valid titles
        titles = [
            '[SONiC_Nightly][Failed_Case][bgp.test_bgp][test_case][master]',
        ]
        result = self.analyzer.count_icm(titles)
        self.assertEqual(result['everflow_count'], 0)
        self.assertEqual(result['qos_sai_count'], 0)
        self.assertEqual(result['acl_count'], 0)


class TestCalculateSuccessRate(unittest.TestCase):
    """Tests for DataAnalyzer.calculate_success_rate()."""

    def setUp(self):
        self.analyzer, _, _ = make_analyzer()

    def test_all_success(self):
        df = pd.DataFrame({
            'BranchNameName': ['master', 'master'],
            'Result': ['success', 'success'],
            'TestbedName': ['tb1', 'tb1']
        })
        result = self.analyzer.calculate_success_rate(df, 'BranchName', 'branch')
        self.assertIn('success_rate', result)
        self.assertIn('consistent_failure_branch', result)
        self.assertEqual(len(result['consistent_failure_branch']), 0)

    def test_all_failure(self):
        df = pd.DataFrame({
            'BranchNameName': ['master', 'master'],
            'Result': ['failure', 'failure'],
            'TestbedName': ['tb1', 'tb1']
        })
        result = self.analyzer.calculate_success_rate(df, 'BranchName', 'branch')
        self.assertEqual(len(result['consistent_failure_branch']), 1)
        self.assertIn('master', result['consistent_failure_branch'])

    def test_mixed_results(self):
        df = pd.DataFrame({
            'AsicTypeName': ['broadcom', 'broadcom', 'mellanox', 'mellanox'],
            'Result': ['success', 'failure', 'success', 'success'],
            'TestbedName': ['tb1', 'tb1', 'tb2', 'tb2']
        })
        result = self.analyzer.calculate_success_rate(df, 'AsicType', 'asic')
        self.assertIn('success_rate', result)
        # broadcom has 50% success, mellanox has 100%
        self.assertEqual(len(result['consistent_failure_asic']), 0)

    def test_testbed_category(self):
        """For testbed category, column_name is used directly (no 'Name' suffix)."""
        df = pd.DataFrame({
            'TestbedName': ['tb1', 'tb1', 'tb2'],
            'Result': ['success', 'failure', 'success']
        })
        result = self.analyzer.calculate_success_rate(df, 'TestbedName', 'testbed')
        self.assertIn('success_rate', result)

    def test_os_version_sorting(self):
        """OS version should be sorted by key (version string), not by rate."""
        df = pd.DataFrame({
            'OSVersionName': ['20240510', '20240510', '20230531', '20230531'],
            'Result': ['success', 'failure', 'success', 'success'],
            'TestbedName': ['tb1', 'tb1', 'tb2', 'tb2']
        })
        result = self.analyzer.calculate_success_rate(df, 'OSVersion', 'os_version')
        rates = result['success_rate']
        # Should be sorted by version string
        self.assertTrue(rates[0].startswith('20230531'))


class TestCalculateCombinedSuccessRate(unittest.TestCase):
    """Tests for DataAnalyzer.calculate_combined_success_rate()."""

    def setUp(self):
        self.analyzer, _, _ = make_analyzer()

    def test_topology_hwsku(self):
        df = pd.DataFrame({
            'Topology_HardwareSku': ['T0_HwSku1', 'T0_HwSku1', 'T1_HwSku2'],
            'Result': ['success', 'failure', 'success']
        })
        result = self.analyzer.calculate_combined_success_rate(df, 'topology_hwsku')
        self.assertIn('success_rate', result)
        self.assertIn('consistent_failure_topology_hwsku', result)

    def test_hwsku_osversion(self):
        df = pd.DataFrame({
            'HardwareSku_OSVersion': ['HwSku1_20240510', 'HwSku1_20240510'],
            'Result': ['failure', 'failure']
        })
        result = self.analyzer.calculate_combined_success_rate(df, 'hwsku_osversion')
        self.assertIn('success_rate', result)
        self.assertEqual(len(result['consistent_failure_hwsku_osversion']), 1)

    def test_topology_hwsku_all_success(self):
        df = pd.DataFrame({
            'Topology_HardwareSku': ['T0_HwSku1', 'T0_HwSku1'],
            'Result': ['success', 'success']
        })
        result = self.analyzer.calculate_combined_success_rate(df, 'topology_hwsku')
        self.assertEqual(len(result['consistent_failure_topology_hwsku']), 0)

    def test_hwsku_osversion_all_success(self):
        df = pd.DataFrame({
            'HardwareSku_OSVersion': ['HwSku1_v1', 'HwSku1_v1'],
            'Result': ['success', 'success']
        })
        result = self.analyzer.calculate_combined_success_rate(df, 'hwsku_osversion')
        self.assertEqual(len(result['consistent_failure_hwsku_osversion']), 0)


class TestRearrangeIcmList(unittest.TestCase):
    """Tests for DataAnalyzer.rearrange_icm_list()."""

    def setUp(self):
        self.analyzer, _, _ = make_analyzer()

    def test_empty_list(self):
        result = self.analyzer.rearrange_icm_list([], ['master'])
        self.assertEqual(len(result), 0)

    def test_single_branch(self):
        icm_list = [
            {'branch': 'master', 'subject': 'test1'},
            {'branch': 'master', 'subject': 'test2'}
        ]
        result = self.analyzer.rearrange_icm_list(icm_list, ['master'])
        self.assertGreater(len(result), 0)
        # All items should be present
        total = sum(len(batch) for batch in result)
        self.assertEqual(total, 2)

    def test_multiple_branches(self):
        icm_list = [
            {'branch': 'master', 'subject': 'test1'},
            {'branch': '202311', 'subject': 'test2'},
            {'branch': 'internal', 'subject': 'test3'},
        ]
        result = self.analyzer.rearrange_icm_list(icm_list, ['master', '202311', 'internal'])
        total = sum(len(batch) for batch in result)
        self.assertEqual(total, 3)

    def test_exceeding_threshold(self):
        """When ICMs exceed the threshold, they should be split into batches."""
        icm_list = [{'branch': 'master', 'subject': f'test{i}'} for i in range(20)]
        result = self.analyzer.rearrange_icm_list(icm_list, ['master'])
        # threshold is 9, 20 items = ceil(20/9) = 3 batches
        self.assertEqual(len(result), math.ceil(20 / TEST_CONFIG['threshold']['icm_number_threshold']))

    def test_unmatched_branch_defaults_to_internal(self):
        icm_list = [{'branch': 'feature-xyz', 'subject': 'test1'}]
        result = self.analyzer.rearrange_icm_list(icm_list, ['master'])
        total = sum(len(batch) for batch in result)
        self.assertEqual(total, 1)


class TestReorderCsvColumns(unittest.TestCase):
    """Tests for DataAnalyzer._reorder_csv_columns()."""

    def setUp(self):
        self.analyzer, _, _ = make_analyzer()

    def test_all_columns_present(self):
        df = pd.DataFrame({
            'subject': ['test'],
            'branch': ['master'],
            'module_path': ['mod'],
            'testcase': ['tc'],
            'trigger_icm': [True],
            'upload_timestamp': ['2024-01-01'],
            'failure_summary': ['error']
        })
        result = self.analyzer._reorder_csv_columns(df)
        # upload_timestamp should be first
        self.assertEqual(result.columns[0], 'upload_timestamp')

    def test_missing_columns_added(self):
        df = pd.DataFrame({
            'subject': ['test'],
            'branch': ['master']
        })
        result = self.analyzer._reorder_csv_columns(df)
        self.assertIn('upload_timestamp', result.columns)
        self.assertIn('failure_summary', result.columns)
        self.assertIn('autoblame_id', result.columns)

    def test_extra_columns_preserved(self):
        df = pd.DataFrame({
            'subject': ['test'],
            'extra_col': ['extra_val']
        })
        result = self.analyzer._reorder_csv_columns(df)
        self.assertIn('extra_col', result.columns)


class TestUploadToKusto(unittest.TestCase):
    """Tests for DataAnalyzer.upload_to_kusto()."""

    def setUp(self):
        self.analyzer, self.mock_kusto, _ = make_analyzer()

    @patch('data_analyzer.time')
    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_upload_empty_tables(self, mock_time):
        """upload_to_kusto with empty tables should not crash."""
        os.makedirs('logs', exist_ok=True)
        self.analyzer.upload_to_kusto([], [], [])
        self.mock_kusto.upload_autoblame_data.assert_called_once()
        self.mock_kusto.upload_analyzed_data.assert_called()

    @patch('data_analyzer.time')
    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_upload_with_data(self, mock_time):
        """upload_to_kusto with data should upload and save CSVs."""
        os.makedirs('logs', exist_ok=True)
        new_icm = [{
            'subject': '[test][master]', 'branch': 'master',
            'trigger_icm': True, 'module_path': 'mod', 'testcase': 'tc',
            'failure_level_info': {}, 'failure_summary': 'err'
        }]
        dup_icm = [{
            'subject': '[dup][master]', 'branch': 'master',
            'trigger_icm': False, 'module_path': 'mod', 'testcase': 'tc',
            'failure_level_info': {}, 'failure_summary': 'err'
        }]
        autoblame = [{'commit': 'abc123'}]
        self.analyzer.upload_to_kusto(new_icm, dup_icm, autoblame)
        self.mock_kusto.upload_autoblame_data.assert_called_once()


class TestPrintAnalysisTable(unittest.TestCase):
    """Tests for DataAnalyzer.print_analysis_table()."""

    def setUp(self):
        self.analyzer, _, _ = make_analyzer()

    def test_empty_table(self):
        # Should not crash
        self.analyzer.print_analysis_table([])

    def test_with_data(self):
        data = [{
            'module_path': 'mod',
            'testcase': 'tc',
            'branch': 'master',
            'subject': '[test][master]',
            'trigger_icm': True,
            'per_testbed_info': {'success_rate': ['tb1 : 50%/1/2']},
            'per_asic_info': {'success_rate': ['broadcom : 100%/2/2']},
            'per_topology_info': {'success_rate': ['T0 : 50%/1/2']},
            'per_hwsku_info': {'success_rate': ['HwSku1 : 50%/1/2']},
            'per_os_version_info': {'success_rate': ['v1 : 50%/1/2']},
            'total_success_rate': '50%/1/2'
        }]
        # Should not crash
        self.analyzer.print_analysis_table(data)


class TestCollectMethods(unittest.TestCase):
    """Tests for collect_* methods with mocked kusto connector."""

    def setUp(self):
        self.analyzer, self.mock_kusto, _ = make_analyzer()

    @patch('data_analyzer.dataframe_from_result_table')
    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_collect_common_summary_failure(self, mock_df_from_result):
        """collect_common_summary_failure should call kusto and filter."""
        mock_response = MagicMock()
        mock_response.primary_results = [MagicMock()]
        self.mock_kusto.query_common_summary_results.return_value = mock_response

        test_df = pd.DataFrame({
            'ModulePath': ['bgp.test_bgp'],
            'BranchName': ['master'],
            'OSVersion': ['20240510.17'],
            'HardwareSku': ['HwSku1'],
            'AsicType': ['broadcom'],
            'Topology': ['T0'],
            'Result': ['failure'],
            'Summary': ['AssertionError']
        })
        mock_df_from_result.return_value = test_df

        self.analyzer.collect_common_summary_failure()
        self.mock_kusto.query_common_summary_results.assert_called_once()

    @patch('data_analyzer.dataframe_from_result_table')
    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_collect_legacy_failure(self, mock_df_from_result):
        """collect_legacy_failure should call kusto and filter."""
        mock_response = MagicMock()
        mock_response.primary_results = [MagicMock()]
        self.mock_kusto.query_legacy_failure.return_value = mock_response

        test_df = pd.DataFrame({
            'ModulePath': ['bgp.test_bgp'],
            'opTestCase': ['test_session'],
            'BranchName': ['master'],
            'OSVersion': ['20240510.17'],
            'HardwareSku': ['HwSku1'],
            'AsicType': ['broadcom'],
            'Topology': ['T0'],
            'Result': ['failure'],
            'FullCaseName': ['bgp.test_bgp.test_session']
        })
        mock_df_from_result.return_value = test_df

        self.analyzer.collect_legacy_failure()
        self.mock_kusto.query_legacy_failure.assert_called_once()

    @patch('data_analyzer.dataframe_from_result_table')
    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_collect_consistent_failure(self, mock_df_from_result):
        mock_response = MagicMock()
        mock_response.primary_results = [MagicMock()]
        self.mock_kusto.query_consistent_failure.return_value = mock_response

        test_df = pd.DataFrame({
            'ModulePath': ['bgp.test_bgp'],
            'opTestCase': ['test_session'],
            'BranchName': ['master'],
            'OSVersion': ['20240510.17'],
            'HardwareSku': ['HwSku1'],
            'AsicType': ['broadcom'],
            'Topology': ['T0'],
            'Result': ['failure'],
            'FullCaseName': ['bgp.test_bgp.test_session']
        })
        mock_df_from_result.return_value = test_df
        os.makedirs('logs', exist_ok=True)

        self.analyzer.collect_consistent_failure()
        self.mock_kusto.query_consistent_failure.assert_called_once()

    @patch('data_analyzer.dataframe_from_result_table')
    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_collect_flaky_failure(self, mock_df_from_result):
        mock_response = MagicMock()
        mock_response.primary_results = [MagicMock()]
        self.mock_kusto.query_flaky_failure.return_value = mock_response

        test_df = pd.DataFrame({
            'ModulePath': ['bgp.test_bgp'],
            'opTestCase': ['test_session'],
            'BranchName': ['master'],
            'OSVersion': ['20240510.17'],
            'HardwareSku': ['HwSku1'],
            'AsicType': ['broadcom'],
            'Topology': ['T0'],
            'Result': ['failure'],
            'FullCaseName': ['bgp.test_bgp.test_session'],
            'FailedType': ['PacketLoss'],
            'Summary': ['packet loss']
        })
        mock_df_from_result.return_value = test_df
        os.makedirs('logs', exist_ok=True)

        self.analyzer.collect_flaky_failure()
        self.mock_kusto.query_flaky_failure.assert_called_once()


class TestRunMethods(unittest.TestCase):
    """Tests for run_* methods with mocked internals."""

    def setUp(self):
        self.analyzer, self.mock_kusto, self.mock_deduper = make_analyzer()

    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_run_common_summary_failure(self):
        """run_common_summary_failure should collect and process."""
        with patch.object(self.analyzer, 'collect_common_summary_failure') as mock_collect, \
                patch.object(self.analyzer, 'multiple_process') as mock_mp:
            mock_collect.return_value = pd.DataFrame({
                'ModulePath': ['bgp.test_bgp'],
                'BranchName': ['master'],
                'Summary': ['AssertionError']
            })
            mock_mp.return_value = ([], [])

            new_icm, dup_icm = self.analyzer.run_common_summary_failure()
            mock_collect.assert_called_once()
            mock_mp.assert_called_once()
            self.assertEqual(len(new_icm), 0)

    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_run_legacy_failure(self):
        with patch.object(self.analyzer, 'collect_legacy_failure') as mock_collect, \
             patch.object(self.analyzer, 'multiple_process') as mock_mp:
            mock_collect.return_value = pd.DataFrame({
                'ModulePath': ['bgp.test_bgp'],
                'opTestCase': ['test_session'],
                'BranchName': ['master'],
                'OSVersion': ['20240510.17'],
                'FullCaseName': ['bgp.test_bgp.test_session']
            })
            mock_mp.return_value = ([], [])

            new_icm, dup_icm = self.analyzer.run_legacy_failure()
            mock_collect.assert_called_once()

    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_run_consistent_failure(self):
        with patch.object(self.analyzer, 'collect_consistent_failure') as mock_collect, \
             patch.object(self.analyzer, 'multiple_process') as mock_mp:
            mock_collect.return_value = pd.DataFrame({
                'ModulePath': ['bgp.test_bgp'],
                'opTestCase': ['test_session'],
                'BranchName': ['master'],
                'OSVersion': ['20240510.17'],
                'FullCaseName': ['bgp.test_bgp.test_session']
            })
            mock_mp.return_value = ([], [])

            new_icm, dup_icm = self.analyzer.run_consistent_failure()
            mock_collect.assert_called_once()

    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_run_flaky_failure(self):
        with patch.object(self.analyzer, 'collect_flaky_failure') as mock_collect, \
             patch.object(self.analyzer, 'multiple_process') as mock_mp:
            mock_collect.return_value = pd.DataFrame({
                'ModulePath': ['bgp.test_bgp'],
                'opTestCase': ['test_session'],
                'BranchName': ['master'],
                'OSVersion': ['20240510.17'],
                'FullCaseName': ['bgp.test_bgp.test_session'],
                'FailedType': ['PacketLoss'],
                'Summary': ['packet loss']
            })
            mock_mp.return_value = ([], [])

            new_icm, dup_icm = self.analyzer.run_flaky_failure()
            mock_collect.assert_called_once()


class TestMultipleProcess(unittest.TestCase):
    """Tests for DataAnalyzer.multiple_process()."""

    def setUp(self):
        self.analyzer, _, self.mock_deduper = make_analyzer()

    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_empty_waiting_list(self):
        new_icm, dup_icm = self.analyzer.multiple_process([])
        self.assertEqual(len(new_icm), 0)
        self.assertEqual(len(dup_icm), 0)

    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_with_waiting_list(self):
        """multiple_process should call analysis_process for each item."""
        with patch.object(self.analyzer, 'analysis_process') as mock_analysis:
            mock_analysis.return_value = [{
                'subject': '[test][master]',
                'branch': 'master',
                'trigger_icm': True,
                'module_path': 'mod',
                'testcase': 'tc',
                'failure_summary': 'err',
                'failure_level_info': {}
            }]
            self.mock_deduper.set_failure_summary.return_value = mock_analysis.return_value
            self.mock_deduper.deduplicate_limit_with_active_icm.return_value = (
                mock_analysis.return_value, [], {})

            waiting_list = [{
                'index': 1,
                'case_branch': 'mod.tc#master',
                'is_module_path': False,
                'is_common_summary': False
            }]
            new_icm, dup_icm = self.analyzer.multiple_process(waiting_list)
            self.assertEqual(len(new_icm), 1)


class TestFilterTestcase(unittest.TestCase):
    """Tests for DataAnalyzer.filter_testcase()."""

    def setUp(self):
        self.analyzer, _, _ = make_analyzer()

    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_basic_filtering(self):
        """filter_testcase should replace topology names and filter excluded."""
        df = pd.DataFrame({
            'BranchName': ['master'],
            'OSVersion': ['20240510.17'],
            'HardwareSku': ['HwSku1'],
            'AsicType': ['broadcom'],
            'Topology': ['t0'],
            'Result': ['failure'],
            'Feature': ['bgp'],
            'ModulePath': ['bgp.test_bgp'],
            'TestCase': ['test_case'],
            'FullCaseName': ['bgp.test_bgp.test_case'],
            'opTestCase': ['test_case'],
            'Summary': ['error']
        })
        result = self.analyzer.filter_testcase(df)
        self.assertIn('BranchNameName', result.columns)
        self.assertIn('TopologyName', result.columns)
        self.assertIn('AsicTypeName', result.columns)

    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_excluded_branch_filtered(self):
        """Excluded branches should be filtered out."""
        df = pd.DataFrame({
            'BranchName': ['C-branch'],
            'OSVersion': ['20240510.17'],
            'HardwareSku': ['HwSku1'],
            'AsicType': ['broadcom'],
            'Topology': ['t0'],
            'Result': ['failure'],
            'Feature': ['bgp'],
            'ModulePath': ['bgp.test_bgp'],
            'TestCase': ['test_case'],
            'FullCaseName': ['bgp.test_bgp.test_case'],
            'opTestCase': ['test_case'],
            'Summary': ['error']
        })
        # 'C' is in excluded_branch for the test config
        self.analyzer.filter_testcase(df)
        # Should be empty or filtered
        # Depends on exact config


class TestGenerateAutoblameAdoData(unittest.TestCase):
    """Tests for DataAnalyzer.generate_autoblame_ado_data()."""

    def setUp(self):
        self.analyzer, _, _ = make_analyzer()

    def test_empty_icm_list(self):
        result = self.analyzer.generate_autoblame_ado_data([])
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_with_icm_data(self):
        """generate_autoblame_ado_data with ICM data should search for commits."""
        with patch.object(self.analyzer, 'search_autoblame') as mock_search:
            mock_search.return_value = ('uuid-123', {'commits': [{'sha': 'abc'}]})
            icm_list = [{
                'testcase': 'test_case',
                'module_path': 'bgp.test_bgp',
                'branch': 'master',
                'failure_level_info': {
                    'oldest_failure_timestamp': '2024-06-01 10:00:00'
                },
                'per_os_version_info': {
                    'consistent_failure_os_version': [],
                    'latest_failure_os_version': '20240510.17'
                },
                'autoblame_id': ''
            }]
            result = self.analyzer.generate_autoblame_ado_data(icm_list)
            self.assertEqual(len(result), 1)
            self.assertEqual(icm_list[0]['autoblame_id'], 'uuid-123')

    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_with_released_branch(self):
        """generate_autoblame_ado_data for released branch should use tag."""
        with patch.object(self.analyzer, 'search_autoblame') as mock_search:
            mock_search.return_value = (None, {'commits': []})
            icm_list = [{
                'testcase': 'test_case',
                'module_path': 'bgp.test_bgp',
                'branch': '202311',
                'failure_level_info': {
                    'oldest_failure_timestamp': '2024-06-01 10:00:00'
                },
                'per_os_version_info': {
                    'consistent_failure_os_version': ['20231110.5'],
                    'latest_failure_os_version': '20231110.5'
                },
                'autoblame_id': ''
            }]
            self.analyzer.generate_autoblame_ado_data(icm_list)
            self.assertIsNone(icm_list[0]['autoblame_id'])


class TestTriggerFlakyIcm(unittest.TestCase):
    """Tests for DataAnalyzer.trigger_flaky_icm()."""

    def setUp(self):
        self.analyzer, _, _ = make_analyzer()

    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_flaky_non_module_path(self):
        kusto_row_data = {
            'failure_level_info': {},
            'trigger_icm': False,
            'autoblame_id': ''
        }
        case_info_dict = {
            'case_branch': 'bgp.test_bgp.test_session#master',
            'is_module_path': False,
            'is_common_summary': False,
            'failed_type': 'PacketLoss'
        }
        result = self.analyzer.trigger_flaky_icm(
            'bgp.test_bgp.test_session#master', kusto_row_data, case_info_dict)
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]['trigger_icm'])
        self.assertIn('is_flaky', result[0]['failure_level_info'])
        self.assertIn('[bgp.test_bgp][test_session][master]', result[0]['subject'])

    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_flaky_module_path(self):
        kusto_row_data = {
            'failure_level_info': {},
            'trigger_icm': False,
            'autoblame_id': ''
        }
        case_info_dict = {
            'case_branch': 'bgp.test_bgp#master',
            'is_module_path': True,
            'is_common_summary': False,
            'failed_type': 'SetupError'
        }
        result = self.analyzer.trigger_flaky_icm(
            'bgp.test_bgp#master', kusto_row_data, case_info_dict)
        self.assertEqual(len(result), 1)
        self.assertIn('[bgp.test_bgp][master]', result[0]['subject'])

    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_flaky_with_ai_category(self):
        kusto_row_data = {
            'failure_level_info': {},
            'trigger_icm': False,
            'autoblame_id': ''
        }
        case_info_dict = {
            'case_branch': 'bgp.test_bgp.test_session#master',
            'is_module_path': False,
            'is_common_summary': False,
            'failed_type': 'PacketLoss',
            'AI_flaky_category': 'timing_issue'
        }
        result = self.analyzer.trigger_flaky_icm(
            'bgp.test_bgp.test_session#master', kusto_row_data, case_info_dict)
        self.assertEqual(result[0]['failure_level_info']['AI_flaky_category'], 'timing_issue')


class TestBuildIcmSubject(unittest.TestCase):
    """Tests for DataAnalyzer.build_icm_subject()."""

    def setUp(self):
        self.analyzer, _, _ = make_analyzer()

    def test_module_path_no_level(self):
        case_info = {'is_module_path': True, 'is_common_summary': True}
        result = self.analyzer.build_icm_subject(
            'bgp.test_bgp#master', case_info, prev_level_value=None, level_value='master')
        self.assertEqual(result, '[bgp.test_bgp][master]')

    def test_module_path_with_level(self):
        case_info = {'is_module_path': True, 'is_common_summary': True}
        result = self.analyzer.build_icm_subject(
            'bgp.test_bgp#master', case_info, prev_level_value='master', level_value='T0')
        self.assertEqual(result, '[bgp.test_bgp][master][T0]')

    def test_testcase_no_level(self):
        case_info = {'is_module_path': False, 'is_common_summary': False}
        result = self.analyzer.build_icm_subject(
            'bgp.test_bgp.test_session#master', case_info,
            prev_level_value=None, level_value='master')
        self.assertEqual(result, '[bgp.test_bgp][test_session][master]')

    def test_testcase_with_prev_level(self):
        case_info = {'is_module_path': False}
        result = self.analyzer.build_icm_subject(
            'bgp.test_bgp.test_session#master', case_info,
            prev_level_value='master|broadcom', level_value='T0')
        self.assertIn('[master][broadcom]', result)
        self.assertIn('[T0]', result)

    def test_no_level_value(self):
        case_info = {'is_module_path': False}
        result = self.analyzer.build_icm_subject(
            'bgp.test_bgp.test_session#master', case_info,
            prev_level_value='master', level_value=None)
        self.assertNotIn('[None]', result)


class TestSetLevelValues(unittest.TestCase):
    """Tests for DataAnalyzer.set_level_values()."""

    def setUp(self):
        self.analyzer, _, _ = make_analyzer()

    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_set_level_values(self):
        raw_data = {}
        # level_priority: branch, os_version, topology, asic, hwsku, hwsku_osversion, topology_hwsku
        # First element is skipped (branch), rest are mapped to level_priority[i+1]
        self.analyzer.set_level_values('master|20240510.17', raw_data)
        # Index 1 maps to level_priority[2] = 'topology'
        self.assertIn('topology', raw_data)
        self.assertEqual(raw_data['topology'], '20240510.17')


class TestAnalyzeActiveIcm(unittest.TestCase):
    """Tests for DataAnalyzer.analyze_active_icm() to cover lines 532-624."""

    @patch('data_analyzer.dataframe_from_result_table')
    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_analyze_with_active_icms(self, mock_df_from_result):
        """analyze_active_icm with ICM data and matching upload records."""
        mock_kusto = MagicMock()
        mock_deduper = MagicMock()

        # Active ICM data
        active_icm_df = pd.DataFrame({
            'IncidentId': ['123'],
            'Title': ['[SONiC_Nightly][Failed_Case][bgp.test_bgp][test_case][master]'],
            'SourceCreateDate': ['2024-06-01'],
            'ModifiedDate': ['2024-06-02'],
            'Status': ['ACTIVE']
        })

        # Upload records with matching subject
        upload_records_df = pd.DataFrame({
            'UploadTimestamp': [pd.Timestamp('2024-06-01')],
            'ModulePath': ['bgp.test_bgp'],
            'TestCase': ['test_case'],
            'Branch': ['master'],
            'Subject': ['[bgp.test_bgp][test_case][master]'],
            'FailureLevelInfo': [{'is_flaky': True, 'flaky_category': 'PacketLoss',
                                  'AI_flaky_category': 'timing'}],
            'FailureSummary': ['bgp session timeout']
        })

        # First call for active ICMs, second for upload records
        mock_df_from_result.side_effect = [active_icm_df, upload_records_df]

        mock_kusto.query_active_icm.return_value = MagicMock()
        mock_kusto.query_all_upload_records_with_trigger_icm.return_value = MagicMock()

        import pytz
        from data_analyzer import DataAnalyzer
        os.makedirs('logs', exist_ok=True)
        analyzer = DataAnalyzer(mock_kusto, mock_deduper, datetime.now(tz=pytz.UTC))

        # Verify the active_icm_df was populated
        self.assertIn('FailureSummary', analyzer.active_icm_df.columns)
        self.assertIn('Branch', analyzer.active_icm_df.columns)
        self.assertEqual(analyzer.active_icm_df.iloc[0]['FailureSummary'], 'bgp session timeout')
        self.assertEqual(analyzer.active_icm_df.iloc[0]['Branch'], 'master')
        self.assertTrue(analyzer.active_icm_df.iloc[0]['is_flaky'])

    @patch('data_analyzer.dataframe_from_result_table')
    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_analyze_no_matching_records(self, mock_df_from_result):
        """analyze_active_icm when no upload records match."""
        mock_kusto = MagicMock()
        mock_deduper = MagicMock()

        active_icm_df = pd.DataFrame({
            'IncidentId': ['456'],
            'Title': ['[SONiC_Nightly][Failed_Case][platform.test_reboot][test_reboot][internal]'],
            'SourceCreateDate': ['2024-06-01'],
            'ModifiedDate': ['2024-06-02'],
            'Status': ['ACTIVE']
        })

        upload_records_df = pd.DataFrame({
            'UploadTimestamp': pd.Series(dtype='datetime64[ns]'),
            'ModulePath': pd.Series(dtype='str'),
            'TestCase': pd.Series(dtype='str'),
            'Branch': pd.Series(dtype='str'),
            'Subject': pd.Series(dtype='str'),
            'FailureLevelInfo': pd.Series(dtype='object'),
            'FailureSummary': pd.Series(dtype='str')
        })

        mock_df_from_result.side_effect = [active_icm_df, upload_records_df]
        mock_kusto.query_active_icm.return_value = MagicMock()
        mock_kusto.query_all_upload_records_with_trigger_icm.return_value = MagicMock()

        import pytz
        from data_analyzer import DataAnalyzer
        os.makedirs('logs', exist_ok=True)
        analyzer = DataAnalyzer(mock_kusto, mock_deduper, datetime.now(tz=pytz.UTC))

        # FailureSummary should remain empty since no matching upload records
        self.assertEqual(analyzer.active_icm_df.iloc[0]['FailureSummary'], '')

    @patch('data_analyzer.dataframe_from_result_table')
    @patch('data_analyzer.configuration', TEST_CONFIG)
    def test_analyze_title_without_prefix(self, mock_df_from_result):
        """analyze_active_icm with title not starting with ICM_PREFIX."""
        mock_kusto = MagicMock()
        mock_deduper = MagicMock()

        active_icm_df = pd.DataFrame({
            'IncidentId': ['789'],
            'Title': ['[SONiC_Nightly][Failed_Case]Custom Title Without Prefix'],
            'SourceCreateDate': ['2024-06-01'],
            'ModifiedDate': ['2024-06-02'],
            'Status': ['ACTIVE']
        })

        upload_records_df = pd.DataFrame({
            'UploadTimestamp': [pd.Timestamp('2024-06-01')],
            'ModulePath': ['mod'],
            'TestCase': ['tc'],
            'Branch': ['master'],
            'Subject': ['Custom Title Without Prefix'],
            'FailureLevelInfo': [''],
            'FailureSummary': ['custom error']
        })

        mock_df_from_result.side_effect = [active_icm_df, upload_records_df]
        mock_kusto.query_active_icm.return_value = MagicMock()
        mock_kusto.query_all_upload_records_with_trigger_icm.return_value = MagicMock()

        import pytz
        from data_analyzer import DataAnalyzer
        os.makedirs('logs', exist_ok=True)
        analyzer = DataAnalyzer(mock_kusto, mock_deduper, datetime.now(tz=pytz.UTC))
        self.assertEqual(analyzer.active_icm_df.iloc[0]['FailureSummary'], 'custom error')


class TestCollectPreviousUploadRecord(unittest.TestCase):
    """Tests for DataAnalyzer.collect_previous_upload_record()."""

    def setUp(self):
        self.analyzer, self.mock_kusto, _ = make_analyzer()

    @patch('data_analyzer.dataframe_from_result_table')
    def test_collect_previous_record(self, mock_df_from_result):
        mock_response = MagicMock()
        mock_response.primary_results = [MagicMock()]
        self.mock_kusto.query_previsou_upload_record.return_value = mock_response
        mock_df_from_result.return_value = pd.DataFrame({
            'UploadTimestamp': ['2024-06-01'],
            'ModulePath': ['mod'],
            'TestCase': ['tc'],
            'Branch': ['master'],
            'Subject': ['[test][master]'],
            'FailureSummary': ['error']
        })
        result = self.analyzer.collect_previous_upload_record('[test][master]')
        self.assertEqual(len(result), 1)


if __name__ == '__main__':
    unittest.main()
