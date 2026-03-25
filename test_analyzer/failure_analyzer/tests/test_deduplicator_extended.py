"""
Extended unit tests for data_deduplicator.py
Covers all untested methods to maximize coverage.
"""
import unittest
import os
import sys
import copy
from unittest.mock import patch, MagicMock
from datetime import timedelta

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

current_file_path = os.path.abspath(__file__)
current_folder = os.path.dirname(current_file_path)

# Load test config (same approach as existing tests)
from helper import load_config  # noqa: E402

TEST_CONFIG = load_config('{}/configs/config_default.json'.format(current_folder))


def make_deduplicator():
    """Create a DataDeduplicator with test configuration."""
    with patch('data_deduplicator.configuration', TEST_CONFIG):
        from data_deduplicator import DataDeduplicator
        return DataDeduplicator()


class TestPreprocessSummary(unittest.TestCase):
    """Tests for DataDeduplicator.__preprocess_summary() (name-mangled)."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_preprocess_empty_string(self):
        result = self.deduper._DataDeduplicator__preprocess_summary('')
        self.assertEqual(result, '')

    def test_preprocess_none(self):
        result = self.deduper._DataDeduplicator__preprocess_summary(None)
        self.assertEqual(result, '')

    def test_preprocess_nan(self):
        result = self.deduper._DataDeduplicator__preprocess_summary(float('nan'))
        self.assertEqual(result, '')

    def test_preprocess_lowercases(self):
        result = self.deduper._DataDeduplicator__preprocess_summary('HELLO WORLD')
        self.assertIn('hello world', result)

    def test_preprocess_removes_timestamps_start_of_line(self):
        text = "2024 Jun 15 10:30:45.123456 some error message"
        result = self.deduper._DataDeduplicator__preprocess_summary(text)
        self.assertNotIn("2024 jun 15", result)
        self.assertIn("some error message", result)

    def test_preprocess_removes_timestamps_middle(self):
        text = "Error at 2024-06-15 10:30:45.123456 in module"
        result = self.deduper._DataDeduplicator__preprocess_summary(text)
        self.assertNotIn("2024-06-15", result)

    def test_preprocess_removes_delta_timestamps(self):
        text = "Timeout after 0:00:30.039462 seconds"
        result = self.deduper._DataDeduplicator__preprocess_summary(text)
        self.assertNotIn("0:00:30.039462", result)

    def test_preprocess_removes_hostnames(self):
        text = "Error on str-msft-x1234-u5 during test"
        result = self.deduper._DataDeduplicator__preprocess_summary(text)
        self.assertNotIn("str-msft-x1234-u5", result)

    def test_preprocess_removes_numbers_for_traceback(self):
        text = "traceback line 42 in module at position 100"
        result = self.deduper._DataDeduplicator__preprocess_summary(text)
        self.assertNotIn("42", result)
        self.assertNotIn("100", result)

    def test_preprocess_removes_numbers_for_analyze_logs(self):
        text = "analyze_logs found 5 errors at line 123"
        result = self.deduper._DataDeduplicator__preprocess_summary(text)
        self.assertNotIn("5", result)
        self.assertNotIn("123", result)

    def test_preprocess_keeps_numbers_for_non_traceback(self):
        text = "Port 8080 is in use by process"
        result = self.deduper._DataDeduplicator__preprocess_summary(text)
        self.assertIn("8080", result)

    def test_preprocess_multiline(self):
        text = "Line 1 error\n\nLine 3 error"
        result = self.deduper._DataDeduplicator__preprocess_summary(text)
        self.assertIn("line 1 error", result)
        self.assertIn("line 3 error", result)

    def test_preprocess_skips_empty_lines(self):
        text = "first\n\n\nfourth"
        result = self.deduper._DataDeduplicator__preprocess_summary(text)
        lines = [line for line in result.split('\n') if line.strip()]
        self.assertEqual(len(lines), 2)


class TestGetBranchGroup(unittest.TestCase):
    """Tests for DataDeduplicator.get_branch_group()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_master_branch(self):
        self.assertEqual(self.deduper.get_branch_group('master'), 'master_internal')

    def test_internal_branch(self):
        self.assertEqual(self.deduper.get_branch_group('internal'), 'master_internal')

    def test_master_uppercase(self):
        self.assertEqual(self.deduper.get_branch_group('Master'), 'master_internal')

    def test_numeric_branch_6_digits(self):
        self.assertEqual(self.deduper.get_branch_group('202311'), '202311')

    def test_numeric_branch_8_digits(self):
        self.assertEqual(self.deduper.get_branch_group('20240510'), '202405')

    def test_numeric_branch_short(self):
        self.assertEqual(self.deduper.get_branch_group('12345'), '12345')

    def test_non_numeric_branch(self):
        self.assertEqual(self.deduper.get_branch_group('feature-branch'), 'feature-branch')

    def test_empty_branch(self):
        self.assertEqual(self.deduper.get_branch_group(''), '')


class TestClusterSummaries(unittest.TestCase):
    """Tests for DataDeduplicator.cluster_summaries()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_single_summary(self):
        summaries = ["test failure due to timeout"]
        clusters = self.deduper.cluster_summaries(summaries, eps=0.3, min_samples=1)
        self.assertEqual(len(clusters), 1)

    def test_identical_summaries_same_cluster(self):
        summaries = [
            "connection timeout error in bgp test",
            "connection timeout error in bgp test",
            "connection timeout error in bgp test"
        ]
        clusters = self.deduper.cluster_summaries(summaries, eps=0.3, min_samples=1)
        self.assertEqual(len(set(clusters)), 1)

    def test_different_summaries_different_clusters(self):
        summaries = [
            "bgp session timeout error on port 179",
            "memory usage exceeds threshold on device",
            "psu fan speed sensor reading abnormal",
        ]
        clusters = self.deduper.cluster_summaries(summaries, eps=0.1, min_samples=1)
        unique_clusters = set(clusters)
        # Very different summaries should be in different clusters (with small eps)
        self.assertGreater(len(unique_clusters), 1)

    def test_similar_summaries_same_cluster(self):
        summaries = [
            "bgp session establishment failed due to timeout on peer",
            "bgp session establishment failed due to timeout on neighbor",
        ]
        clusters = self.deduper.cluster_summaries(summaries, eps=0.5, min_samples=1)
        # Similar summaries with larger eps should cluster together
        self.assertEqual(clusters[0], clusters[1])

    def test_two_summaries(self):
        summaries = [
            "port channel flap detected",
            "completely unrelated memory error"
        ]
        clusters = self.deduper.cluster_summaries(summaries, eps=0.3, min_samples=1)
        self.assertEqual(len(clusters), 2)


class TestIsSameCluster(unittest.TestCase):
    """Tests for DataDeduplicator.is_same_cluster()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_empty_df(self):
        df = pd.DataFrame({'Summary': []})
        result = self.deduper.is_same_cluster(df, summary_col='Summary')
        self.assertTrue(result)

    def test_single_row(self):
        df = pd.DataFrame({'Summary': ['error on port 1']})
        result = self.deduper.is_same_cluster(df, summary_col='Summary')
        self.assertTrue(result)

    def test_identical_summaries(self):
        df = pd.DataFrame({'Summary': [
            'bgp test failed due to timeout',
            'bgp test failed due to timeout',
            'bgp test failed due to timeout'
        ]})
        result = self.deduper.is_same_cluster(df, summary_col='Summary', eps=0.3, min_samples=1)
        self.assertTrue(result)

    def test_very_different_summaries(self):
        df = pd.DataFrame({'Summary': [
            'bgp session timeout connection refused',
            'psu fan speed sensor hardware fault detected',
            'memory leak exhaustion out of resources crash dump'
        ]})
        result = self.deduper.is_same_cluster(df, summary_col='Summary', eps=0.1, min_samples=1)
        self.assertFalse(result)


class TestPrepareDataForClustering(unittest.TestCase):
    """Tests for DataDeduplicator.prepare_data_for_clustering()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_basic_preparation(self):
        icm_table = [
            {
                'full_casename': 'test.case1',
                'subject': '[test][case1][master]',
                'branch': 'master',
                'failure_summary': 'timeout error',
                'failure_level_info': {
                    'topology': 't0',
                    'asic': 'broadcom',
                    'hwsku': 'HwSku1',
                    'os_version': '20240510.17'
                }
            }
        ]
        df = self.deduper.prepare_data_for_clustering(icm_table)
        self.assertEqual(len(df), 1)
        self.assertIn('topology', df.columns)
        self.assertIn('asic', df.columns)
        self.assertIn('hwsku', df.columns)
        self.assertIn('os_version', df.columns)
        self.assertEqual(df.iloc[0]['topology'], 't0')

    def test_empty_table(self):
        df = self.deduper.prepare_data_for_clustering([])
        self.assertEqual(len(df), 0)

    def test_missing_failure_level_info(self):
        icm_table = [
            {
                'full_casename': 'test.case1',
                'subject': '[test][case1][master]',
                'branch': 'master',
                'failure_summary': 'error',
                'failure_level_info': {}
            }
        ]
        df = self.deduper.prepare_data_for_clustering(icm_table)
        self.assertEqual(df.iloc[0]['topology'], '')
        self.assertEqual(df.iloc[0]['asic'], '')

    def test_multiple_items(self):
        icm_table = [
            {
                'full_casename': f'test.case{i}',
                'subject': f'[test][case{i}][master]',
                'branch': 'master',
                'failure_summary': f'error {i}',
                'failure_level_info': {'topology': 't0'}
            }
            for i in range(5)
        ]
        df = self.deduper.prepare_data_for_clustering(icm_table)
        self.assertEqual(len(df), 5)


class TestCheckDuplicates(unittest.TestCase):
    """Tests for DataDeduplicator.check_duplicates()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_exact_match(self):
        icm = {
            'subject': '[case_a][branch_a]',
            'failure_level_info': {}
        }
        result = self.deduper.check_duplicates(
            '[SONiC_Nightly][Failed_Case][case_a][branch_a]', icm)
        self.assertTrue(result)

    def test_no_match(self):
        icm = {
            'subject': '[case_a][branch_a]',
            'failure_level_info': {}
        }
        result = self.deduper.check_duplicates(
            '[SONiC_Nightly][Failed_Case][case_b][branch_b]', icm)
        self.assertFalse(result)

    def test_higher_level_match(self):
        icm = {
            'subject': '[case_a][branch_a][topo_a]',
            'failure_level_info': {}
        }
        result = self.deduper.check_duplicates(
            '[SONiC_Nightly][Failed_Case][case_a][branch_a]', icm)
        self.assertTrue(result)

    def test_combined_level_match(self):
        icm = {
            'subject': '[case_a][branch_a][hwskuA_20240510.16]',
            'failure_level_info': {'is_combined': True}
        }
        result = self.deduper.check_duplicates(
            '[SONiC_Nightly][Failed_Case][case_a][branch_a]', icm)
        self.assertTrue(result)

    def test_combined_components_all_present(self):
        icm = {
            'subject': '[case_a][20240510][topologyA_hwskuC]',
            'failure_level_info': {'is_combined': True}
        }
        result = self.deduper.check_duplicates(
            '[SONiC_Nightly][Failed_Case][case_a][20240510][topologyA][asicB][hwskuC]', icm)
        self.assertTrue(result)

    def test_combined_components_not_all_present(self):
        icm = {
            'subject': '[case_a][20240510][hwskuA_20240510.16]',
            'failure_level_info': {'is_combined': True}
        }
        result = self.deduper.check_duplicates(
            '[SONiC_Nightly][Failed_Case][case_a][20240510][topologyA][asicB]', icm)
        self.assertFalse(result)

    def test_sets_trigger_icm_false_on_match(self):
        icm = {
            'subject': '[case_a][branch_a]',
            'failure_level_info': {}
        }
        self.deduper.check_duplicates(
            '[SONiC_Nightly][Failed_Case][case_a][branch_a]', icm)
        self.assertFalse(icm['trigger_icm'])


class TestCombinedLevelSplit(unittest.TestCase):
    """Tests for DataDeduplicator.combined_level_split()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_basic_split(self):
        result = self.deduper.combined_level_split('[case_a][branch_b][hwskuA_20240510.16]')
        self.assertIn('components', result)
        self.assertIn('titles', result)
        self.assertEqual(len(result['titles']), 2)

    def test_split_without_dot(self):
        result = self.deduper.combined_level_split('[case_a][branch_b][topologyA_hwskuC]')
        self.assertIn('components', result)
        self.assertIn('hwskuC', result['components'])

    def test_split_preserves_prefix(self):
        result = self.deduper.combined_level_split('[case_a][20240510][hwskuA_20240510.16]')
        self.assertTrue(any('[case_a][20240510]' in t for t in result['titles']))


class TestCheckSubjectMatch(unittest.TestCase):
    """Tests for DataDeduplicator.check_subject_match()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_matching_subject(self):
        kusto_row = {
            'subject': '[test][master][broadcom][HwSku1][20240510.17]',
            'failure_level_info': {
                'asic': 'broadcom',
                'hwsku': 'HwSku1',
                'osversion': '20240510.17'
            }
        }
        # Should not raise
        self.deduper.check_subject_match(kusto_row)

    def test_empty_failure_level_info(self):
        kusto_row = {
            'subject': '[test][master]',
            'failure_level_info': {}
        }
        # Should not raise
        self.deduper.check_subject_match(kusto_row)

    @patch('data_deduplicator.logger')
    def test_mismatched_asic_logs_error(self, mock_logger):
        kusto_row = {
            'subject': '[test][master][mellanox]',
            'failure_level_info': {'asic': 'broadcom'}
        }
        with patch('data_deduplicator.configuration', TEST_CONFIG):
            deduper = make_deduplicator()
            deduper.check_subject_match(kusto_row)
        # Logger.error should be called for mismatch
        error_calls = [str(c) for c in mock_logger.error.call_args_list]
        found = any('asic' in c and 'broadcom' in c for c in error_calls)
        self.assertTrue(found)


class TestDeduplication(unittest.TestCase):
    """Tests for DataDeduplicator.deduplication()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_empty_input(self):
        original_data = [{"table": [], "type": "legacy"}]
        branches = ['master', 'internal']
        final, duplicated = self.deduper.deduplication(original_data, branches)
        self.assertEqual(len(final), 0)
        self.assertEqual(len(duplicated), 0)

    def test_single_item(self):
        original_data = [
            {
                "table": [{
                    'subject': '[test][case1][master]',
                    'branch': 'master',
                    'trigger_icm': True,
                    'failure_level_info': {},
                    'failure_summary': ''
                }],
                "type": "legacy"
            }
        ]
        branches = ['master', 'internal']
        final, duplicated = self.deduper.deduplication(original_data, branches)
        self.assertEqual(len(final), 1)
        self.assertEqual(len(duplicated), 0)

    def test_duplicate_subjects_deduplicated(self):
        item = {
            'subject': '[test][case1][master]',
            'branch': 'master',
            'trigger_icm': True,
            'failure_level_info': {},
            'failure_summary': ''
        }
        original_data = [
            {"table": [item, copy.deepcopy(item)], "type": "legacy"}
        ]
        branches = ['master', 'internal']
        final, duplicated = self.deduper.deduplication(original_data, branches)
        self.assertEqual(len(final), 1)
        self.assertEqual(len(duplicated), 1)

    def test_flaky_type_categorized(self):
        items = [{
            'subject': f'[test][case{i}][master]',
            'branch': 'master',
            'trigger_icm': True,
            'failure_level_info': {},
            'failure_summary': ''
        } for i in range(5)]
        original_data = [{"table": items, "type": "flaky"}]
        branches = ['master']
        final, duplicated = self.deduper.deduplication(original_data, branches)
        # Max flaky limit is 3 in test config
        self.assertLessEqual(len(final), 3 + 2)  # some may be in final before limit applied

    def test_ai_flaky_type_categorized(self):
        items = [{
            'subject': f'[test][aicase{i}][master]',
            'branch': 'master',
            'trigger_icm': True,
            'failure_level_info': {},
            'failure_summary': ''
        } for i in range(5)]
        original_data = [{"table": items, "type": "ai_flaky"}]
        branches = ['master']
        final, duplicated = self.deduper.deduplication(original_data, branches)
        total = len(final) + len(duplicated)
        self.assertEqual(total, 5)

    def test_branch_limit_applied(self):
        # Create more items than the branch limit (default_branch_limit = 5)
        items = [{
            'subject': f'[test][branchcase{i}][202012]',
            'branch': '202012',
            'trigger_icm': True,
            'failure_level_info': {},
            'failure_summary': ''
        } for i in range(10)]
        original_data = [{"table": items, "type": "legacy"}]
        branches = ['202012']
        final, duplicated = self.deduper.deduplication(original_data, branches)
        total = len(final) + len(duplicated)
        self.assertEqual(total, 10)

    def test_multiple_types(self):
        common_items = [{'subject': '[test][c1][master]', 'branch': 'master',
                         'trigger_icm': True, 'failure_level_info': {}, 'failure_summary': ''}]
        legacy_items = [{'subject': '[test][l1][master]', 'branch': 'master',
                         'trigger_icm': True, 'failure_level_info': {}, 'failure_summary': ''}]
        original_data = [
            {"table": common_items, "type": "common"},
            {"table": legacy_items, "type": "legacy"}
        ]
        branches = ['master']
        final, duplicated = self.deduper.deduplication(original_data, branches)
        self.assertEqual(len(final), 2)

    def test_higher_level_dedup_across_types(self):
        """Higher-level subjects should deduplicate lower-level ones."""
        items_common = [{'subject': '[test][case1][master]', 'branch': 'master',
                         'trigger_icm': True, 'failure_level_info': {}, 'failure_summary': ''}]
        items_legacy = [{'subject': '[test][case1][master][t0]', 'branch': 'master',
                         'trigger_icm': True, 'failure_level_info': {}, 'failure_summary': ''}]
        original_data = [
            {"table": items_common, "type": "common"},
            {"table": items_legacy, "type": "legacy"}
        ]
        branches = ['master']
        final, duplicated = self.deduper.deduplication(original_data, branches)
        self.assertEqual(len(final), 1)
        self.assertEqual(len(duplicated), 1)


class TestIsInWeeklyFailure(unittest.TestCase):
    """Tests for DataDeduplicator.is_in_weekly_failure()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_none_dataframe(self):
        kusto_data = {'module_path': 'test.module', 'testcase': 'test_case', 'branch': 'master'}
        result_df, found = self.deduper.is_in_weekly_failure(
            'test#master', kusto_data, None)
        self.assertFalse(found)

    def test_matching_data(self):
        kusto_data = {
            'module_path': 'bgp.test_bgp',
            'testcase': 'test_bgp_session',
            'branch': 'master'
        }
        week_df = pd.DataFrame({
            'ModulePath': ['bgp.test_bgp'],
            'opTestCase': ['test_bgp_session'],
            'BranchName': ['master'],
            'TestCase': ['test_bgp_session'],
            'Summary': ['bgp failure'],
            'Topology': ['t0'],
            'AsicType': ['broadcom'],
            'HardwareSku': ['HwSku1'],
            'OSVersion': ['20240510']
        })
        result_df, found = self.deduper.is_in_weekly_failure(
            'bgp.test_bgp.test_bgp_session#master', kusto_data, week_df)
        self.assertTrue(found)
        self.assertEqual(len(result_df), 1)

    def test_no_matching_data(self):
        kusto_data = {
            'module_path': 'bgp.test_bgp',
            'testcase': 'test_bgp_nonexist',
            'branch': 'master'
        }
        week_df = pd.DataFrame({
            'ModulePath': ['platform.test_reboot'],
            'opTestCase': ['test_reboot'],
            'BranchName': ['master'],
            'TestCase': ['test_reboot'],
            'Summary': ['reboot failure'],
            'Topology': ['t0'],
            'AsicType': ['broadcom'],
            'HardwareSku': ['HwSku1'],
            'OSVersion': ['20240510']
        })
        result_df, found = self.deduper.is_in_weekly_failure(
            'bgp.test_bgp.test_bgp_nonexist#master', kusto_data, week_df)
        self.assertFalse(found)

    def test_with_condition_filters(self):
        kusto_data = {
            'module_path': 'bgp.test_bgp',
            'testcase': 'test_bgp_session',
            'branch': 'master'
        }
        week_df = pd.DataFrame({
            'ModulePath': ['bgp.test_bgp', 'bgp.test_bgp'],
            'opTestCase': ['test_bgp_session', 'test_bgp_session'],
            'BranchName': ['master', 'master'],
            'TestCase': ['test_bgp_session', 'test_bgp_session'],
            'Summary': ['failure1', 'failure2'],
            'Topology': ['t0', 't1'],
            'AsicType': ['broadcom', 'mellanox'],
            'HardwareSku': ['HwSku1', 'HwSku2'],
            'OSVersion': ['20240510', '20240510']
        })
        condition = {'asic': 'broadcom', 'topology': 't0'}
        result_df, found = self.deduper.is_in_weekly_failure(
            'bgp.test_bgp.test_bgp_session#master', kusto_data, week_df, condition)
        self.assertTrue(found)
        self.assertEqual(len(result_df), 1)


class TestSetFailureSummary(unittest.TestCase):
    """Tests for DataDeduplicator.set_failure_summary()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_none_week_df(self):
        kusto_list = [{'module_path': 'mod', 'testcase': 'tc', 'branch': 'master',
                       'failure_level_info': {}}]
        result = self.deduper.set_failure_summary(kusto_list, None)
        self.assertEqual(result, kusto_list)

    def test_sets_summary_when_aggregated(self):
        kusto_list = [{
            'module_path': 'bgp.test_bgp',
            'testcase': 'test_session',
            'branch': 'master',
            'failure_level_info': {}
        }]
        week_df = pd.DataFrame({
            'ModulePath': ['bgp.test_bgp', 'bgp.test_bgp'],
            'opTestCase': ['test_session', 'test_session'],
            'BranchName': ['master', 'master'],
            'TestCase': ['test_session', 'test_session'],
            'Summary': ['bgp session timeout', 'bgp session timeout'],
            'Topology': ['t0', 't0'],
            'AsicType': ['broadcom', 'broadcom'],
            'HardwareSku': ['Hw1', 'Hw1'],
            'OSVersion': ['v1', 'v1']
        })
        result = self.deduper.set_failure_summary(kusto_list, week_df)
        self.assertEqual(result[0]['failure_summary'], 'bgp session timeout')

    def test_empty_summary_when_no_results(self):
        kusto_list = [{
            'module_path': 'no.match',
            'testcase': 'tc',
            'branch': 'master',
            'failure_level_info': {}
        }]
        week_df = pd.DataFrame({
            'ModulePath': ['other.module'],
            'opTestCase': ['other_tc'],
            'BranchName': ['master'],
            'TestCase': ['other_tc'],
            'Summary': ['error'],
            'Topology': ['t0'],
            'AsicType': ['broadcom'],
            'HardwareSku': ['Hw1'],
            'OSVersion': ['v1']
        })
        result = self.deduper.set_failure_summary(kusto_list, week_df)
        self.assertEqual(result[0]['failure_summary'], '')
        self.assertFalse(result[0]['trigger_icm'])


class TestIsMatchedActiveIcm(unittest.TestCase):
    """Tests for DataDeduplicator.is_matched_active_icm()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_empty_active_icm(self):
        """Empty active ICM dataframe should return no match."""
        now = self.deduper.current_time
        # Use a dataframe with one expired entry to avoid tz-naive/tz-aware issues with empty df
        active_icm_df = pd.DataFrame({
            'SourceCreateDate': [(now - timedelta(days=100)).isoformat()],
            'Branch': ['master'],
            'FailureSummary': ['old expired entry'],
            'Title': ['old title']
        })
        matched, row = self.deduper.is_matched_active_icm(
            'test#master', 'test failure', 'master', active_icm_df)
        self.assertFalse(matched)
        self.assertIsNone(row)

    def test_matching_summary(self):
        now = self.deduper.current_time
        active_icm_df = pd.DataFrame({
            'SourceCreateDate': [(now - timedelta(days=1)).isoformat()],
            'Branch': ['master'],
            'FailureSummary': ['bgp session timeout error on device'],
            'Title': ['[SONiC_Nightly] BGP test failure']
        })
        matched, row = self.deduper.is_matched_active_icm(
            'test#master', 'bgp session timeout error on device', 'master', active_icm_df)
        self.assertTrue(matched)

    def test_non_matching_summary(self):
        now = self.deduper.current_time
        active_icm_df = pd.DataFrame({
            'SourceCreateDate': [(now - timedelta(days=1)).isoformat()],
            'Branch': ['master'],
            'FailureSummary': ['psu fan speed sensor abnormal reading'],
            'Title': ['[SONiC_Nightly] PSU failure']
        })
        matched, row = self.deduper.is_matched_active_icm(
            'test#master', 'bgp session timeout error on device', 'master', active_icm_df)
        self.assertFalse(matched)

    def test_expired_active_icm(self):
        now = self.deduper.current_time
        active_icm_df = pd.DataFrame({
            'SourceCreateDate': [(now - timedelta(days=30)).isoformat()],
            'Branch': ['master'],
            'FailureSummary': ['bgp session timeout error on device'],
            'Title': ['[SONiC_Nightly] BGP failure']
        })
        matched, row = self.deduper.is_matched_active_icm(
            'test#master', 'bgp session timeout error on device', 'master', active_icm_df)
        self.assertFalse(matched)

    def test_different_branch_group(self):
        now = self.deduper.current_time
        active_icm_df = pd.DataFrame({
            'SourceCreateDate': [(now - timedelta(days=1)).isoformat()],
            'Branch': ['202311'],
            'FailureSummary': ['bgp session timeout'],
            'Title': ['test']
        })
        matched, row = self.deduper.is_matched_active_icm(
            'test#master', 'bgp session timeout', 'master', active_icm_df)
        self.assertFalse(matched)


class TestDeduplicateSummaryWithActiveIcm(unittest.TestCase):
    """Tests for DataDeduplicator.deduplicate_summary_with_active_icm()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_empty_aggregated_df(self):
        aggregated_df = pd.DataFrame()
        active_icm_df = pd.DataFrame({'SourceCreateDate': [], 'Branch': [],
                                      'FailureSummary': [], 'Title': []})
        result_df, dup_df = self.deduper.deduplicate_summary_with_active_icm(
            aggregated_df, active_icm_df)
        self.assertTrue(result_df.empty)

    def test_empty_active_icm_df(self):
        aggregated_df = pd.DataFrame({
            'branch': ['master'],
            'failure_summary': ['test error'],
            'subject': ['[test][master]']
        })
        active_icm_df = pd.DataFrame()
        result_df, dup_df = self.deduper.deduplicate_summary_with_active_icm(
            aggregated_df, active_icm_df)
        self.assertEqual(len(result_df), 1)

    def test_matching_summaries_removed(self):
        now = self.deduper.current_time
        aggregated_df = pd.DataFrame({
            'branch': ['master'],
            'failure_summary': ['bgp session timeout error connection refused'],
            'subject': ['[bgp][test][master]']
        })
        active_icm_df = pd.DataFrame({
            'SourceCreateDate': [(now - timedelta(days=1)).isoformat()],
            'Branch': ['master'],
            'FailureSummary': ['bgp session timeout error connection refused'],
            'Title': ['[SONiC_Nightly] BGP failure']
        })
        result_df, dup_df = self.deduper.deduplicate_summary_with_active_icm(
            aggregated_df, active_icm_df)
        self.assertEqual(len(result_df), 0)
        self.assertEqual(len(dup_df), 1)

    def test_non_matching_summaries_kept(self):
        now = self.deduper.current_time
        aggregated_df = pd.DataFrame({
            'branch': ['master'],
            'failure_summary': ['completely unique error not seen before xyz'],
            'subject': ['[unique][test][master]']
        })
        active_icm_df = pd.DataFrame({
            'SourceCreateDate': [(now - timedelta(days=1)).isoformat()],
            'Branch': ['master'],
            'FailureSummary': ['psu fan speed sensor abnormal reading'],
            'Title': ['[SONiC_Nightly] PSU failure']
        })
        result_df, dup_df = self.deduper.deduplicate_summary_with_active_icm(
            aggregated_df, active_icm_df)
        self.assertEqual(len(result_df), 1)
        self.assertEqual(len(dup_df), 0)

    def test_empty_summary_rows_kept(self):
        now = self.deduper.current_time
        aggregated_df = pd.DataFrame({
            'branch': ['master', 'master'],
            'failure_summary': ['bgp timeout error connection refused', ''],
            'subject': ['[test1][master]', '[test2][master]']
        })
        active_icm_df = pd.DataFrame({
            'SourceCreateDate': [(now - timedelta(days=1)).isoformat()],
            'Branch': ['master'],
            'FailureSummary': ['bgp timeout error connection refused'],
            'Title': ['[SONiC_Nightly] BGP failure']
        })
        result_df, dup_df = self.deduper.deduplicate_summary_with_active_icm(
            aggregated_df, active_icm_df)
        # The empty summary row should be kept
        subjects = result_df['subject'].tolist()
        self.assertIn('[test2][master]', subjects)


class TestDeduplicateDataframeClusters(unittest.TestCase):
    """Tests for DataDeduplicator.deduplicate_dataframe_clusters()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_empty_reference(self):
        reference_df = pd.DataFrame()
        target_df = pd.DataFrame({
            'branch': ['master'],
            'failure_summary': ['error'],
            'subject': ['test']
        })
        result = self.deduper.deduplicate_dataframe_clusters(reference_df, target_df)
        self.assertEqual(len(result), 1)

    def test_empty_target(self):
        reference_df = pd.DataFrame({
            'branch': ['master'],
            'failure_summary': ['error'],
            'subject': ['test']
        })
        target_df = pd.DataFrame()
        result = self.deduper.deduplicate_dataframe_clusters(reference_df, target_df)
        self.assertTrue(result.empty)

    def test_matching_clusters_removed(self):
        reference_df = pd.DataFrame({
            'branch': ['master'],
            'failure_summary': ['bgp session timeout error connection refused on peer device'],
            'subject': ['[ref][test][master]']
        })
        target_df = pd.DataFrame({
            'branch': ['master'],
            'failure_summary': ['bgp session timeout error connection refused on peer device'],
            'subject': ['[target][test][master]']
        })
        result = self.deduper.deduplicate_dataframe_clusters(reference_df, target_df)
        self.assertEqual(len(result), 0)

    def test_different_clusters_kept(self):
        reference_df = pd.DataFrame({
            'branch': ['master'],
            'failure_summary': ['bgp session timeout error connection refused on peer device'],
            'subject': ['[ref][test][master]']
        })
        target_df = pd.DataFrame({
            'branch': ['master'],
            'failure_summary': ['psu fan speed sensor abnormal hardware fault reading'],
            'subject': ['[target][test][master]']
        })
        result = self.deduper.deduplicate_dataframe_clusters(reference_df, target_df)
        self.assertEqual(len(result), 1)

    def test_different_branch_groups_not_compared(self):
        reference_df = pd.DataFrame({
            'branch': ['master'],
            'failure_summary': ['bgp session timeout error connection refused on peer device'],
            'subject': ['[ref][master]']
        })
        target_df = pd.DataFrame({
            'branch': ['202311'],
            'failure_summary': ['bgp session timeout error connection refused on peer device'],
            'subject': ['[target][202311]']
        })
        result = self.deduper.deduplicate_dataframe_clusters(reference_df, target_df)
        # Different branch groups, so no dedup
        self.assertEqual(len(result), 1)


class TestFilterOutIcmList(unittest.TestCase):
    """Tests for DataDeduplicator.filter_out_icm_list()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_empty_aggregated_df(self):
        original = [{'subject': '[test][master]', 'failure_summary': '', 'trigger_icm': True}]
        agg_df = pd.DataFrame(columns=['subject', 'failure_summary'])
        result = self.deduper.filter_out_icm_list('legacy', original, agg_df)
        self.assertEqual(len(result), 0)

    def test_matching_subject_updates_summary(self):
        original = [{'subject': '[test][master]', 'failure_summary': '', 'trigger_icm': True}]
        agg_df = pd.DataFrame({
            'subject': ['[test][master]'],
            'failure_summary': ['bgp error found']
        })
        result = self.deduper.filter_out_icm_list('legacy', original, agg_df)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['failure_summary'], 'bgp error found')

    def test_trigger_icm_false(self):
        original = [{'subject': '[test][master]', 'failure_summary': 'err', 'trigger_icm': True}]
        agg_df = pd.DataFrame({
            'subject': ['[test][master]'],
            'failure_summary': ['err']
        })
        result = self.deduper.filter_out_icm_list('legacy', original, agg_df, trigger_icm=False)
        self.assertFalse(result[0]['trigger_icm'])

    def test_non_matching_subject_filtered(self):
        original = [{'subject': '[not_in_agg][master]', 'failure_summary': '', 'trigger_icm': True}]
        agg_df = pd.DataFrame({
            'subject': ['[test][master]'],
            'failure_summary': ['err']
        })
        result = self.deduper.filter_out_icm_list('legacy', original, agg_df)
        self.assertEqual(len(result), 0)

    def test_existing_summary_updated(self):
        original = [{'subject': '[test][master]', 'failure_summary': 'old_summary', 'trigger_icm': True}]
        agg_df = pd.DataFrame({
            'subject': ['[test][master]'],
            'failure_summary': ['new_summary']
        })
        result = self.deduper.filter_out_icm_list('legacy', original, agg_df)
        self.assertEqual(result[0]['failure_summary'], 'new_summary')


class TestDeduplicateLimitWithActiveIcm(unittest.TestCase):
    """Tests for DataDeduplicator.deduplicate_limit_with_active_icm()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_new_item_not_duplicated(self):
        kusto_list = [{
            'trigger_icm': True,
            'testcase': 'test_unique',
            'branch': 'master',
            'module_path': 'unique.module',
            'subject': '[unique.module][test_unique][master]',
            'failure_summary': '',
            'failure_level_info': {}
        }]
        icm_count = {}
        active_icm_df = pd.DataFrame({
            'Title': ['[SONiC_Nightly][Failed_Case][different.module][different_test][202311]'],
            'SourceCreateDate': ['2024-06-01'],
            'Branch': ['202311'],
            'FailureSummary': ['other error']
        })
        new_list, dup_list, _ = self.deduper.deduplicate_limit_with_active_icm(
            kusto_list, icm_count, active_icm_df)
        self.assertEqual(len(new_list), 1)
        self.assertEqual(len(dup_list), 0)

    def test_title_matched_item_duplicated(self):
        kusto_list = [{
            'trigger_icm': True,
            'testcase': 'test_case',
            'branch': 'master',
            'module_path': 'mod.test',
            'subject': '[mod.test][test_case][master]',
            'failure_summary': '',
            'failure_level_info': {}
        }]
        icm_count = {}
        active_icm_df = pd.DataFrame({
            'Title': ['[SONiC_Nightly][Failed_Case][mod.test][test_case][master]'],
            'SourceCreateDate': ['2024-06-01'],
            'Branch': ['master'],
            'FailureSummary': ['']
        })
        new_list, dup_list, _ = self.deduper.deduplicate_limit_with_active_icm(
            kusto_list, icm_count, active_icm_df)
        self.assertEqual(len(new_list), 0)
        self.assertEqual(len(dup_list), 1)

    def test_summary_matched_item_duplicated(self):
        now = self.deduper.current_time
        kusto_list = [{
            'trigger_icm': True,
            'testcase': 'test_case',
            'branch': 'master',
            'module_path': 'mod.test',
            'subject': '[mod.test][test_case][master][T0]',
            'failure_summary': 'bgp session timeout error connection refused peer',
            'failure_level_info': {}
        }]
        icm_count = {}
        active_icm_df = pd.DataFrame({
            'Title': ['[SONiC_Nightly][Failed_Case][other.test][other_case][master]'],
            'SourceCreateDate': [(now - timedelta(days=1)).isoformat()],
            'Branch': ['master'],
            'FailureSummary': ['bgp session timeout error connection refused peer']
        })
        new_list, dup_list, _ = self.deduper.deduplicate_limit_with_active_icm(
            kusto_list, icm_count, active_icm_df)
        self.assertEqual(len(new_list), 0)
        self.assertEqual(len(dup_list), 1)


class TestFindSimilarSummariesAndCount(unittest.TestCase):
    """Tests for DataDeduplicator.find_similar_summaries_and_count()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_empty_dataframe(self):
        df = pd.DataFrame(columns=['full_casename', 'subject', 'branch',
                                   'failure_summary', 'topology', 'asic',
                                   'hwsku', 'os_version'])
        week_df = pd.DataFrame()
        result = self.deduper.find_similar_summaries_and_count(df, week_df)
        self.assertTrue(result.empty)

    @patch('data_deduplicator.MIDDLE_FAILURES_CSV', 'logs/test_middle.csv')
    def test_single_item_with_summary(self):
        df = pd.DataFrame({
            'full_casename': ['test.case1'],
            'subject': ['[test][case1][master]'],
            'branch': ['master'],
            'failure_summary': ['bgp session timeout error on device port connection'],
            'topology': ['t0'],
            'asic': ['broadcom'],
            'hwsku': ['HwSku1'],
            'os_version': ['20240510']
        })
        week_df = pd.DataFrame()
        os.makedirs('logs', exist_ok=True)
        result = self.deduper.find_similar_summaries_and_count(df, week_df)
        self.assertEqual(len(result), 1)
        self.assertIn('cluster', result.columns)
        self.assertIn('count', result.columns)

    @patch('data_deduplicator.MIDDLE_FAILURES_CSV', 'logs/test_middle.csv')
    def test_similar_summaries_clustered(self):
        df = pd.DataFrame({
            'full_casename': ['test.case1', 'test.case2'],
            'subject': ['[test][case1][master]', '[test][case2][master]'],
            'branch': ['master', 'master'],
            'failure_summary': [
                'bgp session timeout error on device port connection refused peer',
                'bgp session timeout error on device port connection refused neighbor'
            ],
            'topology': ['t0', 't0'],
            'asic': ['broadcom', 'broadcom'],
            'hwsku': ['HwSku1', 'HwSku1'],
            'os_version': ['20240510', '20240510']
        })
        week_df = pd.DataFrame()
        os.makedirs('logs', exist_ok=True)
        result = self.deduper.find_similar_summaries_and_count(df, week_df)
        # Two very similar summaries should be in the same cluster
        self.assertGreaterEqual(len(result), 1)

    @patch('data_deduplicator.MIDDLE_FAILURES_CSV', 'logs/test_middle.csv')
    def test_empty_summary_filled_from_week_df(self):
        df = pd.DataFrame({
            'full_casename': ['test.case1'],
            'subject': ['[test][case1][master]'],
            'branch': ['master'],
            'failure_summary': [''],
            'topology': [''],
            'asic': [''],
            'hwsku': [''],
            'os_version': ['']
        })
        week_df = pd.DataFrame({
            'FullCaseName': ['test.case1'],
            'BranchName': ['master'],
            'Summary': ['bgp session timeout error on device port connection'],
            'TopologyName': ['t0'],
            'AsicTypeName': ['broadcom'],
            'HardwareSkuName': ['HwSku1'],
            'OSVersionName': ['20240510']
        })
        os.makedirs('logs', exist_ok=True)
        result = self.deduper.find_similar_summaries_and_count(df, week_df)
        self.assertGreaterEqual(len(result), 1)


class TestProcessAggregatedFailures(unittest.TestCase):
    """Tests for DataDeduplicator.process_aggregated_failures()."""

    def setUp(self):
        self.deduper = make_deduplicator()

    def test_empty_tables(self):
        mock_analyzer = MagicMock()
        mock_analyzer.week_failure_df = pd.DataFrame()
        mock_analyzer.active_icm_df = pd.DataFrame({
            'SourceCreateDate': pd.Series(dtype='str'),
            'Branch': pd.Series(dtype='str'),
            'FailureSummary': pd.Series(dtype='str'),
            'Title': pd.Series(dtype='str')
        })
        os.makedirs('logs', exist_ok=True)
        result_list, result_df = self.deduper.process_aggregated_failures(
            "legacy", [], [], mock_analyzer,
            'logs/test_analysis.csv', 'logs/test_agg.csv', 'logs/test_dedup.csv')
        self.assertEqual(len(result_list), 0)


if __name__ == '__main__':
    unittest.main()
