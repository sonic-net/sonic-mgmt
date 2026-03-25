"""
Unit tests for kusto_connector.py
Tests KustoConnector initialization, query methods, and upload methods with full mocking.
"""
import unittest
import os
import sys
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Build a mock configuration that matches the structure used in KustoConnector.__init__
MOCK_CONFIG = {
    "threshold": {
        "duration_days": 7,
        "history_days": 30,
        "flaky_case_query_days": 1.2,
        "eps": 0.3,
        "summary_expiration_days": 7
    },
    "branch": {
        "released_branch": ["202311"],
        "excluded_branch_setup_error": ["internal-202106"]
    },
    "testbeds": {
        "excluded_testbed_keywords_setup_error": ["ixia"]
    },
    "hwsku": {"excluded_hwsku": []},
    "topo": {"excluded_topo": []},
    "asic": {"excluded_asic": ["barefoot"]},
    "summary_white_list": ["AssertionError"],
    "upload": False
}


class TestKustoConnectorInit(unittest.TestCase):
    """Tests for KustoConnector.__init__"""

    @patch('kusto_connector.KustoClient')
    @patch('kusto_connector.KustoIngestClient')
    @patch('kusto_connector.KustoConnectionStringBuilder')
    @patch('kusto_connector.configuration', MOCK_CONFIG)
    def test_init_with_all_env_vars(self, mock_kcsb, mock_ingest_cls, mock_client_cls):
        """Init with all env vars set should create all clients."""
        mock_kcsb.with_aad_application_token_authentication.return_value = MagicMock()

        with patch.dict(os.environ, {
            'TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP': 'https://ingest-test.kusto.windows.net',
            'ACCESS_TOKEN': 'test_token',
            'ICM_KUSTO_CLUSTER': 'https://icm.kusto.windows.net',
            'ADO_KUSTO_CLUSTER': 'https://ado.kusto.windows.net'
        }):
            from kusto_connector import KustoConnector
            import pytz
            current_time = datetime.now(tz=pytz.UTC)
            connector = KustoConnector(current_time)

            self.assertEqual(connector.db_name, 'SonicTestData')
            self.assertEqual(connector.icm_db_name, 'IcMDataWarehouse')
            self.assertEqual(connector.ado_db_name, 'AzureDevOps')
            self.assertIsNotNone(connector._ingestion_client_backup)
            self.assertIsNotNone(connector.icm_client)
            self.assertIsNotNone(connector.ado_client)

    @patch('kusto_connector.KustoClient')
    @patch('kusto_connector.KustoIngestClient')
    @patch('kusto_connector.KustoConnectionStringBuilder')
    @patch('kusto_connector.configuration', MOCK_CONFIG)
    def test_init_without_ingest_cluster(self, mock_kcsb, mock_ingest_cls, mock_client_cls):
        """Init without ingest cluster env var should set _ingestion_client_backup to None."""
        mock_kcsb.with_aad_application_token_authentication.return_value = MagicMock()

        env = {
            'ACCESS_TOKEN': 'test_token',
            'ICM_KUSTO_CLUSTER': 'https://icm.kusto.windows.net',
            'ADO_KUSTO_CLUSTER': 'https://ado.kusto.windows.net'
        }
        with patch.dict(os.environ, env, clear=False):
            # Remove the var if present
            os.environ.pop('TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP', None)
            from kusto_connector import KustoConnector
            import pytz
            connector = KustoConnector(datetime.now(tz=pytz.UTC))
            self.assertIsNone(connector._ingestion_client_backup)

    @patch('kusto_connector.KustoClient')
    @patch('kusto_connector.KustoIngestClient')
    @patch('kusto_connector.KustoConnectionStringBuilder')
    @patch('kusto_connector.configuration', MOCK_CONFIG)
    def test_init_without_icm_cluster(self, mock_kcsb, mock_ingest_cls, mock_client_cls):
        """Init without ICM cluster env var should set _icm_client to None."""
        mock_kcsb.with_aad_application_token_authentication.return_value = MagicMock()

        env = {
            'TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP': 'https://ingest-test.kusto.windows.net',
            'ACCESS_TOKEN': 'test_token',
            'ADO_KUSTO_CLUSTER': 'https://ado.kusto.windows.net'
        }
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop('ICM_KUSTO_CLUSTER', None)
            from kusto_connector import KustoConnector
            import pytz
            connector = KustoConnector(datetime.now(tz=pytz.UTC))
            self.assertIsNone(connector._icm_client)

    @patch('kusto_connector.KustoClient')
    @patch('kusto_connector.KustoIngestClient')
    @patch('kusto_connector.KustoConnectionStringBuilder')
    @patch('kusto_connector.configuration', MOCK_CONFIG)
    def test_init_without_ado_cluster(self, mock_kcsb, mock_ingest_cls, mock_client_cls):
        """Init without ADO cluster env var should set _ado_client to None."""
        mock_kcsb.with_aad_application_token_authentication.return_value = MagicMock()

        env = {
            'TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP': 'https://ingest-test.kusto.windows.net',
            'ACCESS_TOKEN': 'test_token',
            'ICM_KUSTO_CLUSTER': 'https://icm.kusto.windows.net'
        }
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop('ADO_KUSTO_CLUSTER', None)
            from kusto_connector import KustoConnector
            import pytz
            connector = KustoConnector(datetime.now(tz=pytz.UTC))
            self.assertIsNone(connector._ado_client)

    @patch('kusto_connector.KustoClient')
    @patch('kusto_connector.KustoIngestClient')
    @patch('kusto_connector.KustoConnectionStringBuilder')
    @patch('kusto_connector.configuration', MOCK_CONFIG)
    def test_init_time_ranges(self, mock_kcsb, mock_ingest_cls, mock_client_cls):
        """Init should correctly compute search time ranges from configuration."""
        mock_kcsb.with_aad_application_token_authentication.return_value = MagicMock()

        with patch.dict(os.environ, {
            'TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP': 'https://ingest-test.kusto.windows.net',
            'ACCESS_TOKEN': 'test_token',
            'ICM_KUSTO_CLUSTER': 'https://icm.kusto.windows.net',
            'ADO_KUSTO_CLUSTER': 'https://ado.kusto.windows.net'
        }):
            from kusto_connector import KustoConnector
            import pytz
            current_time = datetime(2024, 6, 15, 12, 0, 0, tzinfo=pytz.UTC)
            connector = KustoConnector(current_time)

            expected_start = current_time - timedelta(days=7)
            expected_history = current_time - timedelta(days=30)
            expected_flaky = current_time - timedelta(days=1.2)

            self.assertEqual(connector.search_start_time, expected_start)
            self.assertEqual(connector.history_start_time, expected_history)
            self.assertEqual(connector.flaky_query_start_time, expected_flaky)
            self.assertEqual(connector.search_end_time, current_time)


def _make_connector():
    """Helper to create a KustoConnector with all clients mocked."""
    with patch('kusto_connector.KustoClient'), \
        patch('kusto_connector.KustoIngestClient'), \
        patch('kusto_connector.KustoConnectionStringBuilder') as mock_kcsb, \
        patch('kusto_connector.configuration', MOCK_CONFIG), \
        patch.dict(os.environ, {
             'TEST_REPORT_INGEST_KUSTO_CLUSTER_BACKUP': 'https://ingest-test.kusto.windows.net',
             'ACCESS_TOKEN': 'test_token',
             'ICM_KUSTO_CLUSTER': 'https://icm.kusto.windows.net',
             'ADO_KUSTO_CLUSTER': 'https://ado.kusto.windows.net'
         }):
        mock_kcsb.with_aad_application_token_authentication.return_value = MagicMock()
        from kusto_connector import KustoConnector
        import pytz
        connector = KustoConnector(datetime(2024, 6, 15, 12, 0, 0, tzinfo=pytz.UTC))
        # Replace clients with fresh mocks
        connector.client_backup = MagicMock()
        connector.icm_client = MagicMock()
        connector.ado_client = MagicMock()
        connector._ingestion_client_backup = MagicMock()
        return connector


class TestKustoConnectorQueryMethods(unittest.TestCase):
    """Tests for KustoConnector query methods."""

    def setUp(self):
        self.connector = _make_connector()

    def test_query_delegates_to_client(self):
        """query() should call client_backup.execute with db_name and query string."""
        self.connector.query("test query")
        self.connector.client_backup.execute.assert_called_once_with(
            self.connector.db_name, "test query")

    def test_icm_query_delegates_to_icm_client(self):
        """icm_query() should call icm_client.execute with icm_db_name."""
        self.connector.icm_query("icm test query")
        self.connector.icm_client.execute.assert_called_once_with(
            self.connector.icm_db_name, "icm test query")

    def test_ado_query_delegates_to_ado_client(self):
        """ado_query() should call ado_client.execute with ado_db_name."""
        self.connector.ado_query("ado test query")
        self.connector.ado_client.execute.assert_called_once_with(
            self.connector.ado_db_name, "ado test query")

    def test_query_active_icm_constructs_kql(self):
        """query_active_icm() should construct a valid KQL query and call icm_query."""
        self.connector.query_active_icm()
        call_args = self.connector.icm_client.execute.call_args
        query_str = call_args[0][1]
        self.assertIn("IncidentsSnapshotV2", query_str)
        self.assertIn("SONiCNightlyTest", query_str)
        self.assertIn("ACTIVE", query_str)

    def test_query_ado_constructs_kql(self):
        """query_ado() should construct a valid KQL query for work items."""
        self.connector.query_ado()
        call_args = self.connector.ado_client.execute.call_args
        query_str = call_args[0][1]
        self.assertIn("WorkItem", query_str)
        self.assertIn("sonic-nightly", query_str)
        self.assertIn("Product Backlog Item", query_str)

    def test_query_common_summary_results(self):
        """query_common_summary_results() should use search time range."""
        self.connector.query_common_summary_results()
        call_args = self.connector.client_backup.execute.call_args
        query_str = call_args[0][1]
        self.assertIn("TestReportUnionData", query_str)
        self.assertIn("SummaryWhileList", query_str)

    def test_query_flaky_failure_no_testbed(self):
        """query_flaky_failure(query_testbed=False) should query flaky cases."""
        self.connector.query_flaky_failure(query_testbed=False)
        call_args = self.connector.client_backup.execute.call_args
        query_str = call_args[0][1]
        self.assertIn("buildsWithRetry", query_str)
        self.assertIn("flakySummary", query_str)
        self.assertIn("hasFailure", query_str)

    def test_query_flaky_failure_with_testbed(self):
        """query_flaky_failure(query_testbed=True) should include FailedType."""
        self.connector.query_flaky_failure(query_testbed=True)
        call_args = self.connector.client_backup.execute.call_args
        query_str = call_args[0][1]
        self.assertIn("FailedType", query_str)
        self.assertIn("buildsWithRetry", query_str)

    def test_query_consistent_failure(self):
        """query_consistent_failure() should query consistently failing cases."""
        self.connector.query_consistent_failure()
        call_args = self.connector.client_backup.execute.call_args
        query_str = call_args[0][1]
        self.assertIn("consistentFailures", query_str)
        self.assertIn("totalAttempts == failedAttempts", query_str)

    def test_query_legacy_failure(self):
        """query_legacy_failure() should query legacy (no retry) failures."""
        self.connector.query_legacy_failure()
        call_args = self.connector.client_backup.execute.call_args
        query_str = call_args[0][1]
        self.assertIn("buildsWithoutRetry", query_str)
        self.assertIn("maxAttempt == 0", query_str)

    def test_query_history_results_common(self):
        """query_history_results with is_common=True should use SummaryWhileList."""
        self.connector.query_history_results("test_case", "module.path", is_common=True)
        call_args = self.connector.client_backup.execute.call_args
        query_str = call_args[0][1]
        self.assertIn("SummaryWhileList", query_str)
        self.assertIn("module.path", query_str)

    def test_query_history_results_legacy(self):
        """query_history_results with is_legacy=True should query builds without retry."""
        self.connector.query_history_results("test_case", "module.path", is_legacy=True)
        call_args = self.connector.client_backup.execute.call_args
        query_str = call_args[0][1]
        self.assertIn("buildsWithoutRetry", query_str)
        self.assertIn("test_case", query_str)
        self.assertIn("module.path", query_str)

    def test_query_history_results_consistent(self):
        """query_history_results with is_consistent=True should query builds with retry."""
        self.connector.query_history_results("test_case", "module.path", is_consistent=True)
        call_args = self.connector.client_backup.execute.call_args
        query_str = call_args[0][1]
        self.assertIn("buildsWithRetry", query_str)
        self.assertIn("test_case", query_str)

    def test_query_history_results_flaky(self):
        """query_history_results with is_flaky=True should use same query as consistent."""
        self.connector.query_history_results("test_case", "module.path", is_flaky=True)
        call_args = self.connector.client_backup.execute.call_args
        query_str = call_args[0][1]
        self.assertIn("buildsWithRetry", query_str)

    def test_query_history_results_no_flags(self):
        """query_history_results with no flags should return None."""
        result = self.connector.query_history_results("test_case", "module.path")
        self.assertIsNone(result)

    def test_query_all_upload_records(self):
        """query_all_upload_records_with_trigger_icm() should query the analysis table."""
        self.connector.query_all_upload_records_with_trigger_icm()
        call_args = self.connector.client_backup.execute.call_args
        query_str = call_args[0][1]
        self.assertIn("NightlyTestFailureAnalysis", query_str)
        self.assertIn("TriggerIcM", query_str)

    def test_query_previous_upload_record(self):
        """query_previsou_upload_record() should search by title."""
        self.connector.query_previsou_upload_record("test_title")
        call_args = self.connector.client_backup.execute.call_args
        query_str = call_args[0][1]
        self.assertIn("test_title", query_str)
        self.assertIn("NightlyTestFailureAnalysis", query_str)


class TestKustoConnectorUploadMethods(unittest.TestCase):
    """Tests for KustoConnector upload/ingest methods."""

    def setUp(self):
        self.connector = _make_connector()

    @patch('kusto_connector.configuration', {**MOCK_CONFIG, 'upload': True})
    def test_upload_analyzed_data(self):
        """upload_analyzed_data() should call _ingest_data with correct table."""
        with patch.object(self.connector, '_ingest_data') as mock_ingest:
            self.connector.upload_analyzed_data({"key": "value"})
            mock_ingest.assert_called_once_with("NightlyTestFailureAnalysis", {"key": "value"})

    @patch('kusto_connector.configuration', {**MOCK_CONFIG, 'upload': True})
    def test_upload_autoblame_data(self):
        """upload_autoblame_data() should call _ingest_data with correct table."""
        with patch.object(self.connector, '_ingest_data') as mock_ingest:
            self.connector.upload_autoblame_data([{"key": "value"}])
            mock_ingest.assert_called_once_with("AutoBlameReport", [{"key": "value"}])

    @patch('kusto_connector.configuration', {**MOCK_CONFIG, 'upload': True})
    def test_ingest_data_with_list(self):
        """_ingest_data with a list should write JSON lines to temp file."""
        data = [{"key1": "val1"}, {"key2": "val2"}]
        self.connector._ingest_data("NightlyTestFailureAnalysis", data)
        self.connector._ingestion_client_backup.ingest_from_file.assert_called_once()

    @patch('kusto_connector.configuration', {**MOCK_CONFIG, 'upload': True})
    def test_ingest_data_with_dict(self):
        """_ingest_data with a dict should write single JSON."""
        data = {"key": "value"}
        self.connector._ingest_data("NightlyTestFailureAnalysis", data)
        self.connector._ingestion_client_backup.ingest_from_file.assert_called_once()

    @patch('kusto_connector.configuration', {**MOCK_CONFIG, 'upload': False})
    def test_ingest_data_upload_disabled(self):
        """_ingest_data with upload=False should skip ingestion."""
        data = [{"key": "value"}]
        self.connector._ingest_data("NightlyTestFailureAnalysis", data)
        self.connector._ingestion_client_backup.ingest_from_file.assert_not_called()

    def test_ingest_data_no_backup_client(self):
        """_ingest_data with no backup client should skip ingestion."""
        self.connector._ingestion_client_backup = None
        data = [{"key": "value"}]
        # Should not raise
        with patch('kusto_connector.configuration', {**MOCK_CONFIG, 'upload': True}):
            self.connector._ingest_data("NightlyTestFailureAnalysis", data)


if __name__ == '__main__':
    unittest.main()
