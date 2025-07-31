"""
BaseValidator - Base validator classes and interfaces for SONiC Mgmt metadata validators
"""

import logging
import re
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Union, List
import time
from functools import wraps
from .validation_result import ValidationResult


class ValidatorContext:
    """Context object containing validation data and utilities"""

    def __init__(
        self, group_name: str, testbed_info: list[Dict[str, Any]],
        all_groups_data: Optional[Dict[str, Dict[str, Any]]] = None
    ):
        self.group_name = group_name
        self.testbed_info = testbed_info if isinstance(testbed_info, list) else [testbed_info] if testbed_info else []
        self.all_groups_data = all_groups_data or {}

    def get_group_name(self) -> str:
        """Get the name of the validation group"""
        return self.group_name

    def get_testbeds(self) -> list[Dict[str, Any]]:
        """Get all testbed configurations"""
        return self.testbed_info

    def get_connection_graph(self) -> Dict[str, Any]:
        """Get connection graph data - derived from all_groups_data"""
        if self.all_groups_data:
            if len(self.all_groups_data) == 1:
                # Single group - return its connection graph
                group_data = list(self.all_groups_data.values())[0]
                return group_data.get('conn_graph', {})
        # For global context or no data, return empty dict
        return {}

    def get_all_groups_data(self) -> Dict[str, Dict[str, Any]]:
        """Get data from all groups for global validators"""
        return self.all_groups_data

    def get_all_connection_graphs(self) -> Dict[str, Dict[str, Any]]:
        """Get connection graphs from all groups"""
        return {group: data.get('conn_graph', {}) for group, data in self.all_groups_data.items()}

    def get_all_devices_across_groups(self) -> Dict[str, Any]:
        """Get all devices from all groups, with group information"""
        all_devices = {}
        for group_name, group_data in self.all_groups_data.items():
            conn_graph = group_data.get('conn_graph', {})
            devices = conn_graph.get('devices', {})
            for device_name, device_info in devices.items():
                if device_name in all_devices:
                    # Device exists in multiple groups - add group info
                    if 'groups' not in all_devices[device_name]:
                        all_devices[device_name]['groups'] = [all_devices[device_name].get('group', 'unknown')]
                    all_devices[device_name]['groups'].append(group_name)
                else:
                    # Add group information to device
                    device_copy = device_info.copy() if isinstance(device_info, dict) else device_info
                    if isinstance(device_copy, dict):
                        device_copy['group'] = group_name
                    all_devices[device_name] = device_copy
        return all_devices

    def is_global_context(self) -> bool:
        """Check if this context is for global validation"""
        return self.group_name == "global"


def measure_execution_time(func):
    """Decorator to measure validator execution time"""
    @wraps(func)
    def wrapper(self, context: ValidatorContext) -> ValidationResult:
        start_time = time.time()
        result = func(self, context)
        end_time = time.time()
        result.execution_time = end_time - start_time
        return result
    return wrapper


class BaseValidator(ABC):
    """Enhanced base validator class with comprehensive result handling"""

    def __init__(self, name: str, description: str = "", category: str = "general",
                 config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.description = description
        self.category = category
        self.config = config or {}
        self.logger = logging.getLogger(f"meta.{name}")
        self.result = None  # Will be initialized in validate()

    def requires_global_context(self) -> bool:
        """Return False by default - validators are group-scoped unless they inherit from GlobalValidator"""
        return False

    @abstractmethod
    def _validate(self, context: ValidatorContext) -> Union[ValidationResult, None]:
        """
        Core validation logic to be implemented by subclasses.
        Can either return a ValidationResult or use self.result directly and return None.

        Args:
            context: ValidatorContext containing testbed and connection graph data

        Returns:
            ValidationResult or None: Validation result (None if using self.result)
        """
        pass

    @measure_execution_time
    def validate(self, context: ValidatorContext) -> ValidationResult:
        """
        Execute validation with error handling and timing

        Args:
            context: ValidatorContext containing validation data

        Returns:
            ValidationResult: Comprehensive validation result
        """
        # Create ValidationResult and store it as instance variable
        self.result = ValidationResult(validator_name=self.name, group_name=context.get_group_name(), success=True)

        try:
            self.logger.debug(f"Starting validation: {self.name}")

            # Run common pre-validation checks
            if not self._run_pre_validation_checks(context):
                # If pre-validation checks fail, skip the main validation
                self.logger.warning(f"Pre-validation checks failed for {self.name}, skipping main validation")
            else:
                # Run the main validation logic
                result = self._validate(context)

                # If _validate returns a result, use it; otherwise use self.result
                if result is not None:
                    self.result = result

            self.result.validator_name = self.name
            self.result.group_name = context.get_group_name()

            if self.result.success:
                self.logger.info(f"Validation passed: {self.name}")
            else:
                self.logger.warning(f"Validation failed: {self.name} with {self.result.error_count} errors")

        except Exception as e:
            error_msg = f"Unexpected error during {self.name} validation: {str(e)}"
            self.logger.error(error_msg)
            self.result.add_issue('E0001', {"error_message": error_msg, "validator": self.name})

        return self.result

    def get_info(self) -> Dict[str, str]:
        """Get validator information"""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category
        }

    def _check_testbed_data(self, testbed_info: list[Dict[str, Any]], context: ValidatorContext) -> bool:
        """
        Common check for testbed data availability

        Args:
            testbed_info: Testbed information list
            context: ValidatorContext

        Returns:
            bool: True if testbed data is available, False otherwise
        """
        if not testbed_info:
            self.result.add_issue('E0002', {"context": context.get_group_name()})
            return False
        return True

    def _check_connection_graph_data(self, conn_graph: Dict[str, Any], context: ValidatorContext) -> bool:
        """
        Common check for connection graph data availability

        Args:
            conn_graph: Connection graph data
            context: ValidatorContext

        Returns:
            bool: True if connection graph data is available, False otherwise
        """
        if not conn_graph:
            self.result.add_issue('E0003', {"group": context.get_group_name()})
            return False
        return True

    def _run_pre_validation_checks(self, context: ValidatorContext) -> bool:
        """
        Run common pre-validation checks before calling _validate

        Args:
            context: ValidatorContext containing validation data

        Returns:
            bool: True if pre-validation checks pass, False otherwise
        """
        # Check that all_groups_data is present in the context
        all_groups_data = context.get_all_groups_data()
        if not all_groups_data:
            self.result.add_issue('E0004', {"validator": self.name})
            return False

        # Check testbed data
        testbed_info = context.get_testbeds()
        if not self._check_testbed_data(testbed_info, context):
            return False

        return True


class GroupValidator(BaseValidator):
    """Base class for validators that operate on a single group"""

    def __init__(self, name: str, description: str = "", category: str = "general",
                 config: Optional[Dict[str, Any]] = None):
        super().__init__(name, description, category, config)
        self.exclude_groups = self._compile_exclude_patterns(self.config.get('exclude_groups', []))

    def _compile_exclude_patterns(self, patterns: List[str]) -> List[re.Pattern]:
        """
        Compile regex patterns for group exclusion

        Args:
            patterns: List of regex pattern strings

        Returns:
            List of compiled regex patterns
        """
        compiled_patterns = []
        for pattern in patterns:
            try:
                compiled_patterns.append(re.compile(pattern))
            except re.error as e:
                self.logger.warning(f"Invalid regex pattern '{pattern}' in exclude_groups: {e}")
        return compiled_patterns

    def _should_exclude_group(self, group_name: str) -> bool:
        """
        Check if a group should be excluded based on regex patterns

        Args:
            group_name: Name of the group to check

        Returns:
            bool: True if group should be excluded, False otherwise
        """
        for pattern in self.exclude_groups:
            if pattern.match(group_name):
                return True
        return False

    def requires_global_context(self) -> bool:
        """Return False to indicate this validator works with single group context"""
        return False

    def _run_pre_validation_checks(self, context: ValidatorContext) -> bool:
        """
        Run pre-validation checks specific to group validators

        Args:
            context: ValidatorContext containing validation data

        Returns:
            bool: True if pre-validation checks pass, False otherwise
        """
        # Run base pre-validation checks first
        if not super()._run_pre_validation_checks(context):
            return False

        # For group validators, also check connection graph data
        conn_graph = context.get_connection_graph()
        if not self._check_connection_graph_data(conn_graph, context):
            return False

        return True

    @measure_execution_time
    def validate(self, context: ValidatorContext) -> ValidationResult:
        """
        Execute validation with single group context check

        Args:
            context: ValidatorContext containing validation data

        Returns:
            ValidationResult: Comprehensive validation result
        """
        # Check if the group should be excluded
        group_name = context.get_group_name()
        if self._should_exclude_group(group_name):
            # Create a successful ValidationResult for excluded groups
            result = ValidationResult(validator_name=self.name, group_name=group_name, success=True)
            result.metadata['skipped'] = True
            result.metadata['skip_reason'] = 'Group excluded by exclude_groups configuration'
            result.execution_time = 0.0
            self.logger.info(f"Skipping validation for excluded group: {group_name}")
            return result

        # Assert that we have exactly one group in the context
        if context.is_global_context():
            all_groups = context.get_all_groups_data()
            if len(all_groups) != 1:
                raise ValueError(
                    f"Group validator {self.name} requires exactly one group but received "
                    f"{len(all_groups)} groups: {list(all_groups.keys())}"
                )

        return super().validate(context)


class GlobalValidator(BaseValidator):
    """Base class for validators that need access to data from all groups"""

    def requires_global_context(self) -> bool:
        """Return True to indicate this validator needs global context"""
        return True

    @measure_execution_time
    def validate(self, context: ValidatorContext) -> ValidationResult:
        """
        Execute validation with global context check

        Args:
            context: ValidatorContext containing validation data

        Returns:
            ValidationResult: Comprehensive validation result
        """
        # Check that we have all groups data and it contains multiple groups for global validation
        if not context.is_global_context():
            raise ValueError(
                f"Global validator {self.name} requires global context but received single group: "
                f"{context.get_group_name()}"
            )

        return super().validate(context)
