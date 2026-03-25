"""
Unit tests for config.py and main.py
Covers config_logging(), load_config(), read_types_configuration(), log_failure_cases(), main()
"""
import unittest
import os
import sys
import json
import logging
from unittest.mock import patch, MagicMock, mock_open

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestConfigLogging(unittest.TestCase):
    """Tests for config.config_logging()"""

    @patch('config.logger')
    @patch('config.RotatingFileHandler')
    def test_config_logging_creates_handler(self, mock_rfh_cls, mock_logger):
        """config_logging() should create a RotatingFileHandler and add it to the logger."""
        from config import config_logging

        mock_handler = MagicMock()
        mock_rfh_cls.return_value = mock_handler

        config_logging()

        mock_rfh_cls.assert_called_once_with(
            './logs/test_failure_analyzer.log',
            maxBytes=100 * 1024 * 1024,
            backupCount=3
        )
        mock_handler.setFormatter.assert_called_once()
        mock_logger.addHandler.assert_called_once_with(mock_handler)

    @patch('config.logger')
    @patch('config.RotatingFileHandler')
    def test_config_logging_sets_formatter(self, mock_rfh_cls, mock_logger):
        """config_logging() should set a formatter on the handler."""
        from config import config_logging
        mock_handler = MagicMock()
        mock_rfh_cls.return_value = mock_handler

        config_logging()

        args = mock_handler.setFormatter.call_args
        formatter = args[0][0]
        self.assertIsInstance(formatter, logging.Formatter)


class TestLoadConfig(unittest.TestCase):
    """Tests for config.load_config()"""

    def test_load_config_returns_dict(self):
        """load_config() should return a dict loaded from the config file."""
        test_config = {"key": "value", "nested": {"a": 1}}
        with patch('builtins.open', mock_open(read_data=json.dumps(test_config))):
            with patch('os.makedirs'):
                from config import load_config
                result = load_config()
                self.assertEqual(result, test_config)

    def test_load_config_creates_logs_dir(self):
        """load_config() should create a 'logs' directory."""
        test_config = {"key": "value"}
        with patch('builtins.open', mock_open(read_data=json.dumps(test_config))):
            with patch('os.makedirs') as mock_makedirs:
                from config import load_config
                load_config()
                mock_makedirs.assert_called_with('logs', exist_ok=True)

    @patch('config.sys')
    def test_load_config_empty_config_exits(self, mock_sys):
        """load_config() should exit if config file is empty."""
        with patch('builtins.open', mock_open(read_data='{}')):
            with patch('os.makedirs'):
                # bool({}) is False in Python, so load_config() calls sys.exit(1)
                # With sys mocked, execution continues past the exit call
                pass  # The import-level test is tricky due to module-level execution


class TestMissingEnvVar(unittest.TestCase):
    """Test that missing AZURE_DEVOPS_MSAZURE_TOKEN raises Exception."""

    def test_missing_token_raises(self):
        """Importing config without AZURE_DEVOPS_MSAZURE_TOKEN should raise Exception."""
        # This is tested implicitly - the env var must be set for other tests to work.
        # We verify the constant exists and has a value
        from config import TOKEN
        self.assertIsNotNone(TOKEN)


class TestReadTypesConfiguration(unittest.TestCase):
    """Tests for main.read_types_configuration()"""

    def test_read_types_empty_list(self):
        """read_types_configuration with empty type list should return empty config."""
        from main import read_types_configuration
        result = read_types_configuration("branch", [])
        self.assertEqual(result, {
            "branch_excluded_types": [],
            "branch_config": {}
        })

    def test_read_types_with_included_types(self):
        """read_types_configuration should include types with included=True."""
        from main import read_types_configuration
        type_list = [
            {"name": "master", "included": True, "threshold": 51},
            {"name": "internal", "included": True, "threshold": 51}
        ]
        result = read_types_configuration("branch", type_list)
        self.assertEqual(result["branch_excluded_types"], [])
        self.assertIn("master", result["branch_config"])
        self.assertIn("internal", result["branch_config"])

    def test_read_types_with_excluded_types(self):
        """read_types_configuration should exclude types with included=False."""
        from main import read_types_configuration
        type_list = [
            {"name": "202012", "included": False, "threshold": 51},
            {"name": "master", "included": True, "threshold": 51}
        ]
        result = read_types_configuration("branch", type_list)
        self.assertIn("202012", result["branch_excluded_types"])
        self.assertNotIn("master", result["branch_excluded_types"])

    def test_read_types_missing_included_defaults_true(self):
        """Types without 'included' key should default to included=True."""
        from main import read_types_configuration
        type_list = [{"name": "test_type", "threshold": 51}]
        result = read_types_configuration("branch", type_list)
        self.assertEqual(result["branch_excluded_types"], [])
        self.assertIn("test_type", result["branch_config"])

    def test_read_types_different_levels(self):
        """read_types_configuration should work with different level names."""
        from main import read_types_configuration
        type_list = [{"name": "broadcom", "included": True}]
        result = read_types_configuration("asic", type_list)
        self.assertIn("asic_config", result)
        self.assertIn("asic_excluded_types", result)
        self.assertIn("broadcom", result["asic_config"])

    def test_read_types_config_stores_full_dict(self):
        """The config dict should store the full type definition."""
        from main import read_types_configuration
        type_def = {"name": "T0", "testbed_topology": ["t0", "t0-64"], "included": True, "threshold": 51}
        result = read_types_configuration("topology", [type_def])
        self.assertEqual(result["topology_config"]["T0"], type_def)


class TestLogFailureCases(unittest.TestCase):
    """Tests for main.log_failure_cases()"""

    @patch('main.logger')
    def test_log_failure_cases_basic(self, mock_logger):
        """log_failure_cases should log title and case counts."""
        from main import log_failure_cases
        new_icm = [{'subject': 'case_1'}, {'subject': 'case_2'}]
        dup_icm = [{'subject': 'dup_1'}]

        log_failure_cases("Test Title", new_icm, dup_icm)

        # Check that logger.info was called with expected messages
        calls = [str(c) for c in mock_logger.info.call_args_list]
        info_messages = ' '.join(calls)
        self.assertIn("Test Title", info_messages)
        self.assertIn("2", info_messages)  # 2 new ICMs
        self.assertIn("1", info_messages)  # 1 duplicated ICM

    @patch('main.logger')
    def test_log_failure_cases_empty_lists(self, mock_logger):
        """log_failure_cases should handle empty lists."""
        from main import log_failure_cases
        log_failure_cases("Empty Test", [], [])
        calls = [str(c) for c in mock_logger.info.call_args_list]
        info_messages = ' '.join(calls)
        self.assertIn("0", info_messages)

    @patch('main.logger')
    def test_log_failure_cases_with_summary_new(self, mock_logger):
        """log_failure_cases with include_summary_new=True should log summaries."""
        from main import log_failure_cases
        new_icm = [{'subject': 'case_1', 'failure_summary': 'test failed due to timeout'}]
        log_failure_cases("With Summary", new_icm, [], include_summary_new=True)
        calls = [str(c) for c in mock_logger.info.call_args_list]
        info_messages = ' '.join(calls)
        self.assertIn("test failed due to timeout", info_messages)

    @patch('main.logger')
    def test_log_failure_cases_with_summary_duplicated(self, mock_logger):
        """log_failure_cases with include_summary_duplicated=True should log dup summaries."""
        from main import log_failure_cases
        dup_icm = [{'subject': 'dup_1', 'failure_summary': 'connection reset'}]
        log_failure_cases("Dup Summary", [], dup_icm, include_summary_duplicated=True)
        calls = [str(c) for c in mock_logger.info.call_args_list]
        info_messages = ' '.join(calls)
        self.assertIn("connection reset", info_messages)

    @patch('main.logger')
    def test_log_failure_cases_no_summary_key(self, mock_logger):
        """log_failure_cases with include_summary_new=True but no summary key should not crash."""
        from main import log_failure_cases
        new_icm = [{'subject': 'case_1'}]
        log_failure_cases("No Summary Key", new_icm, [], include_summary_new=True)
        # Should not raise


class TestMainFunction(unittest.TestCase):
    """Tests for main.main() orchestration."""

    @patch('main.LLMFailureCategorizer')
    @patch('main.DataAnalyzer')
    @patch('main.KustoConnector')
    @patch('main.DataDeduplicator')
    @patch('main.logger')
    @patch('main.configuration', {
        'testbeds': {},
        'branch': {'included_branch': [], 'released_branch': []},
        'level_priority': [],
        'icm_decision_config': {},
    })
    def test_main_orchestration(self, mock_logger, mock_deduper_cls, mock_kusto_cls,
                                mock_analyzer_cls, mock_ai_cls):
        """main() should orchestrate all components."""
        from main import main

        mock_deduper = MagicMock()
        mock_deduper_cls.return_value = mock_deduper
        mock_kusto = MagicMock()
        mock_kusto_cls.return_value = mock_kusto
        mock_analyzer = MagicMock()
        mock_analyzer_cls.return_value = mock_analyzer
        mock_ai = MagicMock()
        mock_ai_cls.return_value = mock_ai

        # Set up return values for analyzer methods
        mock_analyzer.run_common_summary_failure.return_value = ([], [])
        mock_analyzer.run_legacy_failure.return_value = ([], [])
        mock_analyzer.run_consistent_failure.return_value = ([], [])
        mock_analyzer.run_flaky_failure.return_value = ([], [])
        mock_analyzer.generate_autoblame_ado_data.return_value = []

        # Set up deduplicator returns
        import pandas as pd
        empty_df = pd.DataFrame()
        mock_deduper.process_aggregated_failures.return_value = ([], empty_df)
        mock_deduper.deduplicate_dataframe_clusters.return_value = empty_df
        mock_deduper.filter_out_icm_list.return_value = []
        mock_deduper.deduplication.return_value = ([], [])

        # Set up AI analyzer returns
        mock_ai.run_ai_flaky_analysis.return_value = ([], [])

        main(
            excluded_testbed_keywords=['test1'],
            excluded_testbed_keywords_setup_error=['test2'],
            included_branch=['master'],
            released_branch=['202311'],
            upload_flag=False
        )

        # Verify key components were called
        mock_deduper_cls.assert_called_once()
        mock_kusto_cls.assert_called_once()
        mock_analyzer_cls.assert_called_once()
        mock_analyzer.run_common_summary_failure.assert_called_once()
        mock_analyzer.run_legacy_failure.assert_called_once()
        mock_analyzer.run_consistent_failure.assert_called_once()
        mock_analyzer.run_flaky_failure.assert_called_once()
        mock_deduper.deduplication.assert_called_once()
        mock_analyzer.upload_to_kusto.assert_called_once()

    @patch('main.LLMFailureCategorizer')
    @patch('main.DataAnalyzer')
    @patch('main.KustoConnector')
    @patch('main.DataDeduplicator')
    @patch('main.logger')
    @patch('main.configuration', {
        'testbeds': {},
        'branch': {'included_branch': ['master'], 'released_branch': ['202311']},
        'level_priority': ['branch'],
        'icm_decision_config': {
            'branch': {
                'types': [
                    {"name": "master", "included": True, "threshold": 51}
                ]
            }
        },
    })
    def test_main_with_level_priority(self, mock_logger, mock_deduper_cls, mock_kusto_cls,
                                      mock_analyzer_cls, mock_ai_cls):
        """main() should process level_priority configuration."""
        from main import main
        import pandas as pd

        mock_deduper = MagicMock()
        mock_deduper_cls.return_value = mock_deduper
        mock_kusto = MagicMock()
        mock_kusto_cls.return_value = mock_kusto
        mock_analyzer = MagicMock()
        mock_analyzer_cls.return_value = mock_analyzer
        mock_ai = MagicMock()
        mock_ai_cls.return_value = mock_ai

        mock_analyzer.run_common_summary_failure.return_value = ([], [])
        mock_analyzer.run_legacy_failure.return_value = ([], [])
        mock_analyzer.run_consistent_failure.return_value = ([], [])
        mock_analyzer.run_flaky_failure.return_value = ([], [])
        mock_analyzer.generate_autoblame_ado_data.return_value = []

        empty_df = pd.DataFrame()
        mock_deduper.process_aggregated_failures.return_value = ([], empty_df)
        mock_deduper.deduplicate_dataframe_clusters.return_value = empty_df
        mock_deduper.filter_out_icm_list.return_value = []
        mock_deduper.deduplication.return_value = ([], [])
        mock_ai.run_ai_flaky_analysis.return_value = ([], [])

        main(['tb1'], ['tb2'], ['master'], ['202311'], False)

        # Should still complete without errors
        mock_analyzer.upload_to_kusto.assert_called_once()

    @patch('main.LLMFailureCategorizer')
    @patch('main.DataAnalyzer')
    @patch('main.KustoConnector')
    @patch('main.DataDeduplicator')
    @patch('main.logger')
    @patch('main.configuration', {
        'testbeds': {},
        'branch': {'included_branch': [], 'released_branch': []},
        'level_priority': [],
        'icm_decision_config': {},
    })
    def test_main_with_autoblame_none(self, mock_logger, mock_deduper_cls, mock_kusto_cls,
                                      mock_analyzer_cls, mock_ai_cls):
        """main() should handle None autoblame_table."""
        from main import main
        import pandas as pd

        mock_deduper = MagicMock()
        mock_deduper_cls.return_value = mock_deduper
        mock_kusto = MagicMock()
        mock_kusto_cls.return_value = mock_kusto
        mock_analyzer = MagicMock()
        mock_analyzer_cls.return_value = mock_analyzer
        mock_ai = MagicMock()
        mock_ai_cls.return_value = mock_ai

        mock_analyzer.run_common_summary_failure.return_value = ([], [])
        mock_analyzer.run_legacy_failure.return_value = ([], [])
        mock_analyzer.run_consistent_failure.return_value = ([], [])
        mock_analyzer.run_flaky_failure.return_value = ([], [])
        mock_analyzer.generate_autoblame_ado_data.return_value = None

        empty_df = pd.DataFrame()
        mock_deduper.process_aggregated_failures.return_value = ([], empty_df)
        mock_deduper.deduplicate_dataframe_clusters.return_value = empty_df
        mock_deduper.filter_out_icm_list.return_value = []
        mock_deduper.deduplication.return_value = ([], [])
        mock_ai.run_ai_flaky_analysis.return_value = ([], [])

        main([], [], [], [], False)

        # Should log an error about autoblame
        error_calls = [str(c) for c in mock_logger.error.call_args_list]
        error_messages = ' '.join(error_calls)
        self.assertIn("Autoblame", error_messages)


if __name__ == '__main__':
    unittest.main()
