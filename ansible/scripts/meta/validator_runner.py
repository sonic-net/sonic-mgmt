"""
MetaValidator Runner - OOP-based validation orchestration for SONiC Mgmt infrastructure

This module provides a clean, object-oriented interface for running meta validations
across SONiC management infrastructure components.
"""

import os
import sys
import json
import logging
import yaml
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

try:
    from ansible.module_utils.graph_utils import LabGraph
except ImportError:
    # Add the ansible directory to the Python path to enable absolute imports
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../..'))
    from ansible.module_utils.graph_utils import LabGraph

from ansible.devutil.testbed_helper import get_testbed_facts
from config_loader import (
    ConfigLoader,
    ValidatorConfigManager,
    ValidationConfig
)
from validators import (
    ValidatorContext,
    ValidationOrchestrator,
    ValidationSummary,
    get_default_registry
)


@dataclass
class ValidationResults:
    """Container for validation results and summary data"""
    all_summaries: List[Tuple[str, ValidationSummary]]
    overall_success: bool
    total_validators: int
    total_passed: int
    total_failed: int
    total_errors: int
    total_warnings: int
    total_infos: int
    groups_processed: int

    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage"""
        if self.total_validators == 0:
            return 0.0
        return (self.total_passed / self.total_validators) * 100


class MetaValidator:
    """
    Main validation orchestrator class for SONiC Mgmt metadata validation

    This class encapsulates the entire validation workflow including:
    - Configuration loading and validation
    - Testbed data loading
    - Validation execution across groups
    - Results aggregation and reporting
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the MetaValidator

        Args:
            logger: Optional logger instance. If not provided, creates a default logger.
        """
        self.logger = logger or logging.getLogger('meta_validator')
        self.config_loader = ConfigLoader()
        self.registry = get_default_registry()
        self.config_manager = ValidatorConfigManager(self.registry, self.config_loader)

        # State variables
        self.config: Optional[ValidationConfig] = None
        self.validators: List = []
        self.groups: List[str] = []
        self.testbeds: List = []
        self.testbed_files: List[str] = []
        self.testbed_facts: Optional[Dict] = None

    def load_configuration(self, config_path: Optional[str] = None) -> ValidationConfig:
        """
        Load and validate the validator configuration

        Args:
            config_path: Optional path to configuration file. If None, uses default config.

        Returns:
            ValidationConfig: The loaded and validated configuration

        Raises:
            SystemExit: If configuration validation fails
        """
        self.logger.info("Loading validator configuration")

        if config_path:
            self.config = self.config_loader.load_from_file(config_path)
            self.logger.info(f"Loaded configuration from: {config_path}")
        else:
            self.config = self.config_loader.get_default_config()
            self.logger.info("Using default configuration")

        # Validate configuration
        config_errors = self.config_manager.validate_config(self.config)
        if config_errors:
            self.logger.error("Configuration validation failed:")
            for error in config_errors:
                self.logger.error(f"  - {error}")
            sys.exit(1)

        # Create validators from configuration
        self.validators = self.config_manager.create_validators_from_config(self.config)
        if not self.validators:
            self.logger.error("No validators could be created")
            sys.exit(1)

        self.logger.info(f"Created {len(self.validators)} validators")
        return self.config

    def load_testbed_data(self,
                          testbed_config_path: str = "ansible/testbed.yaml",
                          testbed_nut_config_path: str = "ansible/testbed.nut.yaml",
                          graph_groups_path: str = "ansible/files/graph_groups.yml",
                          specific_groups: Optional[List[str]] = None
                          ) -> Tuple[List[str], List, List[str], Optional[Dict]]:
        """
        Load testbed configurations and graph groups

        Args:
            testbed_config_path: Path to main testbed configuration file
            testbed_nut_config_path: Path to NUT testbed configuration file
            graph_groups_path: Path to graph groups file
            specific_groups: Optional list of specific groups to validate (overrides graph groups)

        Returns:
            Tuple of (groups, testbeds, testbed_files, testbed_facts)
        """
        self.logger.info("Loading testbed data and graph groups")

        # Load graph groups
        if specific_groups:
            # Load all available groups first to validate specific groups exist
            available_groups = self._load_graph_groups(graph_groups_path)
            invalid_groups = [g for g in specific_groups if g not in available_groups]
            if invalid_groups:
                self.logger.error(f"Invalid groups specified: {', '.join(invalid_groups)}")
                self.logger.error(f"Available groups: {', '.join(available_groups)}")
                sys.exit(1)

            self.groups = specific_groups
            self.logger.info(f"Validating specific groups: {', '.join(specific_groups)}")
        else:
            self.groups = self._load_graph_groups(graph_groups_path)
            self.logger.info(f"Loaded {len(self.groups)} infrastructure groups")

        # Load testbed configurations
        self.testbed_files = []

        # Collect testbed files that exist (convert to absolute paths)
        if os.path.exists(testbed_config_path):
            self.testbed_files.append(os.path.abspath(testbed_config_path))

        if os.path.exists(testbed_nut_config_path):
            self.testbed_files.append(os.path.abspath(testbed_nut_config_path))

        self.testbed_facts = None
        if self.testbed_files:
            # Use testbed_helper to load and validate testbed configurations
            self.testbed_facts = get_testbed_facts(self.testbed_files)
            self.testbeds = self.testbed_facts['testbeds']

            # Report any validation errors
            if self.testbed_facts['validation_errors']:
                self.logger.warning("Testbed validation errors found:")
                for error in self.testbed_facts['validation_errors']:
                    self.logger.warning(f"  - {error}")

            # Log summary
            summary = self.testbed_facts['summary']
            self.logger.info(
                f"Loaded {summary['valid_testbeds']} valid testbeds "
                f"({summary['total_testbeds']} total, {summary['invalid_testbeds']} invalid)"
            )
            self.logger.info(
                f"Found {summary['unique_groups']} unique groups and "
                f"{summary['unique_topologies']} unique topologies"
            )
        else:
            self.testbeds = []
            self.logger.warning("No testbed configuration files found")

        if not self.testbeds:
            self.logger.warning("No valid testbed configurations available")

        return self.groups, self.testbeds, self.testbed_files, self.testbed_facts

    def run_validation(self, fail_fast: bool = False, warnings_as_errors: bool = False) -> ValidationResults:
        """
        Execute validation with global and group-specific validators

        Args:
            fail_fast: If True, stop validation on the first error.
            warnings_as_errors: If True, treat warnings as errors.

        Returns:
            ValidationResults: Comprehensive results of the validation run
        """
        self.logger.info("Starting validation execution")

        if not self.config:
            raise RuntimeError("Configuration must be loaded before running validation")

        if not self.validators:
            raise RuntimeError("No validators available for execution")

        if not self.groups:
            raise RuntimeError("No groups available for validation")

        # Setup orchestrator
        orchestrator = ValidationOrchestrator(
            fail_fast=fail_fast,
            warnings_as_errors=warnings_as_errors
        )

        # Add hooks for logging
        orchestrator.add_hook('before_validator', self._log_validator_start)
        orchestrator.add_hook('after_validator', self._log_validator_end)

        # Load all groups data first
        all_groups_data = self._load_all_groups_data()

        # Separate global and group validators
        global_validators = [v for v in self.validators if v.requires_global_context()]
        group_validators = [v for v in self.validators if not v.requires_global_context()]

        self.logger.info(f"Running {len(global_validators)} global validators and "
                         f"{len(group_validators)} group validators")

        # Track overall results
        all_summaries = []
        overall_success = True

        # Run global validators once with all groups data
        if global_validators:
            self.logger.info("Running global validators")
            global_context = ValidatorContext(
                "global", self.testbeds, all_groups_data
            )

            global_summary = orchestrator.validate(global_validators, global_context)
            all_summaries.append(("global", global_summary))

            if not global_summary.success:
                overall_success = False

            self.logger.info(
                f"Global validation: {global_summary.passed_validators}/{global_summary.executed_validators} "
                f"validators passed"
            )

        # Run group validators for each group
        if group_validators:
            for group in self.groups:
                self.logger.debug(f"Processing group: {group}")

                # Get connection graph for this group from loaded data
                group_data = all_groups_data.get(group, {})
                conn_graph = group_data.get('conn_graph', {})

                if not conn_graph:
                    self.logger.error(f"Failed to load connection graph for group {group}")
                    overall_success = False
                    continue

                self.logger.debug(f"Loaded connection graph for group {group}")

                # Create validation context with single group data in all_groups_data
                single_group_data = {group: group_data}
                context = ValidatorContext(
                    group, self.testbeds, single_group_data
                )

                # Run group validators
                summary = orchestrator.validate(group_validators, context)
                all_summaries.append((group, summary))

                if not summary.success:
                    overall_success = False

                self.logger.debug(
                    f"Group {group}: {summary.passed_validators}/{summary.executed_validators} validators passed"
                )

        # Calculate aggregated metrics
        total_validators = sum(summary.total_validators for _, summary in all_summaries)
        total_passed = sum(summary.passed_validators for _, summary in all_summaries)
        total_failed = sum(summary.failed_validators for _, summary in all_summaries)

        # Count all errors, warnings, and infos
        total_errors = sum(len(result.errors) for _, summary in all_summaries for result in summary.results)
        total_warnings = sum(len(result.warnings) for _, summary in all_summaries for result in summary.results)
        total_infos = sum(len(result.infos) for _, summary in all_summaries for result in summary.results)

        # Create results object
        results = ValidationResults(
            all_summaries=all_summaries,
            overall_success=overall_success,
            total_validators=total_validators,
            total_passed=total_passed,
            total_failed=total_failed,
            total_errors=total_errors,
            total_warnings=total_warnings,
            total_infos=total_infos,
            groups_processed=len([s for s in all_summaries if s[0] != "global"])
        )

        self.logger.info(f"Validation completed: {results.groups_processed} groups processed")
        return results

    def _load_all_groups_data(self) -> Dict[str, Dict[str, Any]]:
        """
        Load connection graph data and inventory data for all groups

        Returns:
            Dict mapping group names to their data (conn_graph, inventory_devices, etc.)
        """
        all_groups_data = {}

        for group in self.groups:
            group_data = {}

            # Load connection graph for this group
            group_data['conn_graph'] = self.load_conn_graph(group)

            # Load inventory data for this group
            group_data['inventory_devices'] = self._load_inventory_file(group)

            all_groups_data[group] = group_data

        self.logger.info(f"Loaded connection graphs and inventory data for {len(all_groups_data)} groups")
        return all_groups_data

    def load_conn_graph(self, group: str) -> Dict[str, Any]:
        try:
            # Load connection graph for this group
            conn_graph_obj = LabGraph(
                    os.path.join(os.path.dirname(__file__), '../../../ansible/files/'),
                    group
                )
            conn_graph = conn_graph_obj.graph_facts

            if conn_graph:
                self.logger.debug(f"Loaded connection graph for group {group}")
                return conn_graph
            else:
                self.logger.warning(f"Failed to load connection graph for group {group}")
                return {}

        except Exception as e:
            self.logger.error(f"Error loading connection graph for group {group}: {str(e)}")
            return {}

    def _load_inventory_file(self, group: str) -> Dict[str, Any]:
        """
        Load ansible inventory YAML file for a group

        Args:
            group: Group name (e.g., 'lab', 'snappi-sonic')

        Returns:
            Dict containing inventory data with device information
        """
        inventory_path = os.path.join(os.path.dirname(__file__), '../../../ansible/', group)

        if not os.path.exists(inventory_path):
            self.logger.warning(f"Inventory file not found for group {group}: {inventory_path}")
            return {}

        try:
            with open(inventory_path, 'r') as f:
                content = f.read()

            try:
                inventory_data = yaml.safe_load(content)
                if inventory_data is not None:
                    self.logger.debug(f"Loaded YAML inventory for group {group}")

                    inventory_devices = self._extract_devices_from_yaml_inventory(inventory_data)
                    self.logger.debug(f"Loaded {len(inventory_devices)} inventory devices for group {group}")

                    return inventory_devices
                else:
                    self.logger.warning(f"Empty or invalid YAML inventory for group {group}")
                    return {}
            except yaml.YAMLError as e:
                self.logger.error(f"Failed to parse inventory file {inventory_path} as YAML: {e}")
                return {}

        except FileNotFoundError:
            self.logger.warning(f"Inventory file not found: {inventory_path}")
            return {}
        except Exception as e:
            self.logger.error(f"Error loading inventory file {inventory_path}: {e}")
            return {}

    def _extract_devices_from_yaml_inventory(self, inventory_data: Dict) -> Dict[str, Any]:
        """Extract device information from YAML format inventory"""
        devices = {}

        def extract_hosts_recursive(data, parent_path=""):
            if isinstance(data, dict):
                if 'hosts' in data:
                    # Found a hosts section
                    for host_name, host_data in data['hosts'].items():
                        if isinstance(host_data, dict):
                            # Copy the entire host_data object
                            device_info = host_data.copy()
                            # Add metadata about inventory source and location
                            device_info['inventory_source'] = 'yaml'
                            device_info['group_path'] = parent_path
                            devices[host_name] = device_info
                        else:
                            # Simple host entry without variables
                            device_info = {
                                'inventory_source': 'yaml',
                                'group_path': parent_path
                            }
                            if host_data:
                                device_info['ansible_host'] = str(host_data)
                            devices[host_name] = device_info

                # Recursively check children
                if 'children' in data:
                    for child_name, child_data in data['children'].items():
                        new_path = f"{parent_path}/{child_name}" if parent_path else child_name
                        extract_hosts_recursive(child_data, new_path)

                # Check direct groups in the structure
                for key, value in data.items():
                    if key not in ['hosts', 'children', 'vars'] and isinstance(value, dict):
                        new_path = f"{parent_path}/{key}" if parent_path else key
                        extract_hosts_recursive(value, new_path)

        extract_hosts_recursive(inventory_data)
        return devices

    def _load_graph_groups(self, graph_groups_file: str) -> List[str]:
        """
        Load infrastructure groups from graph_groups.yml

        Args:
            graph_groups_file: Path to graph_groups.yml file

        Returns:
            List of group names
        """
        try:
            import yaml
            with open(graph_groups_file, 'r') as f:
                groups = yaml.safe_load(f)

            if isinstance(groups, list):
                return groups
            else:
                self.logger.error(f"Invalid format in {graph_groups_file}: expected list, got {type(groups)}")
                return []

        except Exception as e:
            self.logger.error(f"Error loading graph groups from {graph_groups_file}: {str(e)}")
            return []

    def _log_validator_start(self, validator, context):
        """Hook: Log when a validator starts (minimal logging)"""
        self.logger.debug(f"Starting validator: {validator.name}")

    def _log_validator_end(self, validator, result):
        """Hook: Log when a validator completes (minimal logging)"""
        self.logger.debug(f"Completed validator: {validator.name} - {'PASSED' if result.success else 'FAILED'}")

    def print_results(self, results: ValidationResults, report_level: str = "summary",
                      output_format: str = "text") -> None:
        """
        Print comprehensive validation summary and detailed report.

        Args:
            results: ValidationResults object containing the results to print.
            report_level: The level of detail for the report ('summary', 'errors', 'full').
            output_format: The format for output ('text', 'json', or 'yaml').
        """
        if output_format == "json":
            self._print_json_results(results, report_level)
        elif output_format == "yaml":
            self._print_yaml_results(results, report_level)
        else:
            self._print_text_results(results, report_level)

    def _print_text_results(self, results: ValidationResults, report_level: str = "summary") -> None:
        """Print results in text format"""
        print("=" * 60)
        print("VALIDATION REPORT")
        print("=" * 60)

        # Overall statistics
        print(f"Groups processed: {results.groups_processed}")
        print(f"Total validator executions: {results.total_validators}")
        print(f"Passed: {results.total_passed}, Failed: {results.total_failed}")
        print(f"Errors: {results.total_errors}, Warnings: {results.total_warnings}, Infos: {results.total_infos}")
        print(f"Success rate: {results.success_rate:.1f}%")

        # Detailed report by group/scope
        for group, summary in results.all_summaries:
            if group == "global":
                print("--- Global Validators ---")
            else:
                print(f"--- Group: {group} ---")

            for result in summary.results:
                details = f"({len(result.errors)} errors, {len(result.warnings)} warnings, {len(result.infos)} infos)"
                if result.success:
                    print(f"  {result.validator_name}: PASSED {details}")
                else:
                    print(f"  {result.validator_name}: FAILED {details}")

                if report_level == 'full':
                    for error in result.errors:
                        print(f"    - ERROR: {error}")
                    for warning in result.warnings:
                        print(f"    - WARNING: {warning}")
                    for info in result.infos:
                        print(f"    - INFO: {info}")
                elif report_level == 'errors' and result.errors:
                    for error in result.errors:
                        print(f"    - ERROR: {error}")
                elif report_level == 'summary' and result.errors:
                    for error in result.errors[:10]:
                        print(f"    - ERROR: {error}")
                    if len(result.errors) > 10:
                        print(f"    ... and {len(result.errors) - 10} more errors")

        print("=" * 60)
        if results.overall_success:
            print("Overall validation: PASSED")
        else:
            print("Overall validation: FAILED")

    def _issue_to_dict(self, issue) -> Dict[str, Any]:
        """Convert a ValidationIssue to a structured dictionary"""
        return {
            "issue_id": issue.issue_id,
            "keyword": issue.keyword,
            "description": issue.description,
            "message": issue.message,
            "severity": issue.severity.name.lower(),
            "source": issue.source,
            "group": issue.group_name,
            "details": issue.details
        }

    def _create_structured_output(self, results: ValidationResults, report_level: str = "summary") -> Dict[str, Any]:
        """Create structured output object that can be used for both JSON and YAML formats"""
        output = {
            "summary": {
                "groups_processed": results.groups_processed,
                "total_validators": results.total_validators,
                "total_passed": results.total_passed,
                "total_failed": results.total_failed,
                "total_errors": results.total_errors,
                "total_warnings": results.total_warnings,
                "total_infos": results.total_infos,
                "success_rate": round(results.success_rate, 1),
                "overall_success": results.overall_success
            },
            "groups": {}
        }

        # Add detailed results by group
        for group, summary in results.all_summaries:
            group_data = {
                "validators": []
            }

            for result in summary.results:
                validator_data = {
                    "name": result.validator_name,
                    "success": result.success,
                    "group": result.group_name,
                    "execution_time": result.execution_time,
                    "error_count": len(result.errors),
                    "warning_count": len(result.warnings),
                    "info_count": len(result.infos),
                    "metadata": result.metadata
                }

                # Add structured issues based on report level
                if report_level == 'full':
                    validator_data["errors"] = [self._issue_to_dict(error) for error in result.errors]
                    validator_data["warnings"] = [self._issue_to_dict(warning) for warning in result.warnings]
                    validator_data["infos"] = [self._issue_to_dict(info) for info in result.infos]
                elif report_level == 'errors':
                    validator_data["errors"] = [self._issue_to_dict(error) for error in result.errors]
                elif report_level == 'summary':
                    # Only include first 10 errors for summary
                    validator_data["errors"] = [self._issue_to_dict(error) for error in result.errors[:10]]
                    if len(result.errors) > 10:
                        validator_data["truncated_errors"] = len(result.errors) - 10

                group_data["validators"].append(validator_data)

            output["groups"][group] = group_data

        return output

    def _print_json_results(self, results: ValidationResults, report_level: str = "summary") -> None:
        """Print results in JSON format"""
        output = self._create_structured_output(results, report_level)
        print(json.dumps(output, indent=2, ensure_ascii=False))

    def _print_yaml_results(self, results: ValidationResults, report_level: str = "summary") -> None:
        """Print results in YAML format"""
        output = self._create_structured_output(results, report_level)
        print(yaml.dump(output, default_flow_style=False, allow_unicode=True, sort_keys=False))
