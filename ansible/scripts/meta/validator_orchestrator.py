"""
Validation orchestrator implementing chain of responsibility pattern
"""

import logging
from typing import List, Dict, Callable
from dataclasses import dataclass, field

from validators.base_validator import BaseValidator, ValidationResult, ValidatorContext


@dataclass
class ValidationSummary:
    """Summary of validation results"""
    total_validators: int
    executed_validators: int
    passed_validators: int
    failed_validators: int
    skipped_validators: int
    total_errors: int
    total_warnings: int
    total_execution_time: float
    results: List[ValidationResult] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Overall validation success"""
        return self.failed_validators == 0

    @property
    def success_rate(self) -> float:
        """Success rate as percentage"""
        if self.executed_validators == 0:
            return 0.0
        return (self.passed_validators / self.executed_validators) * 100

    def get_failed_validators(self) -> List[str]:
        """Get names of failed validators"""
        return [result.validator_name for result in self.results if not result.success]

    def get_errors_by_category(self) -> Dict[str, int]:
        """Get error count by category"""
        category_counts = {}
        for result in self.results:
            for issue in result.errors:
                category_counts[issue.category] = category_counts.get(issue.category, 0) + 1
        return category_counts


class ValidationOrchestrator:
    """Orchestrates validation execution with configurable strategies"""

    def __init__(
            self,
            fail_fast: bool = False,
            warnings_as_errors: bool = False
    ):
        self.fail_fast = fail_fast
        self.warnings_as_errors = warnings_as_errors
        self.logger = logging.getLogger("meta.orchestrator")
        self._hooks: Dict[str, List[Callable]] = {
            'before_validation': [],
            'after_validation': [],
            'before_validator': [],
            'after_validator': [],
            'on_error': [],
            'on_warning': []
        }

    def add_hook(self, event: str, callback: Callable):
        """Add a hook callback for validation events"""
        if event in self._hooks:
            self._hooks[event].append(callback)
        else:
            raise ValueError(f"Unknown hook event: {event}")

    def _call_hooks(self, event: str, *args, **kwargs):
        """Call all hooks for an event"""
        for callback in self._hooks.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception as e:
                self.logger.warning(f"Hook callback failed for {event}: {str(e)}")

    def validate(
            self,
            validators: List[BaseValidator],
            context: ValidatorContext
    ) -> ValidationSummary:
        """
        Execute validation using the configured strategy

        Args:
            validators: List of validators to execute
            context: Validation context containing data

        Returns:
            ValidationSummary with comprehensive results
        """
        self.logger.info(f"Starting validating group \"{context.get_group_name()}\" with {len(validators)} validators")
        self._call_hooks('before_validation', validators, context)

        start_time = 0
        results = []
        executed_count = 0
        passed_count = 0
        failed_count = 0
        skipped_count = 0
        total_errors = 0
        total_warnings = 0

        try:
            start_time = self._get_time()

            for validator in validators:
                self.logger.debug(f"Executing validator: {validator.name}")
                self._call_hooks('before_validator', validator, context)

                try:
                    # Execute validator
                    result = validator.validate(context)
                    results.append(result)
                    executed_count += 1

                    # Update counters
                    if result.success:
                        passed_count += 1
                    else:
                        failed_count += 1
                        self._call_hooks('on_error', validator, result)

                    total_errors += result.error_count
                    total_warnings += result.warning_count

                    # Call warning hooks
                    if result.warning_count > 0:
                        self._call_hooks('on_warning', validator, result)

                    self._call_hooks('after_validator', validator, result)

                    # Check strategy for early termination
                    if self._should_stop(result):
                        self.logger.warning("Stopping validation due to fail_fast strategy")
                        skipped_count = len(validators) - executed_count
                        break

                except Exception as e:
                    self.logger.error(f"Validator {validator.name} crashed: {str(e)}")
                    # Create error result for crashed validator
                    error_result = ValidationResult(validator.name, False)
                    error_result.add_error(f"Validator crashed: {str(e)}", "crash", validator.name)
                    results.append(error_result)
                    executed_count += 1
                    failed_count += 1
                    total_errors += 1

                    self._call_hooks('on_error', validator, error_result)

                    if self.fail_fast:
                        skipped_count = len(validators) - executed_count
                        break

            end_time = self._get_time()
            total_execution_time = end_time - start_time

        except Exception as e:
            self.logger.error(f"Orchestrator failed: {str(e)}")
            end_time = self._get_time()
            total_execution_time = end_time - start_time

            # Mark remaining validators as skipped
            skipped_count = len(validators) - executed_count

        # Create summary
        summary = ValidationSummary(
            total_validators=len(validators),
            executed_validators=executed_count,
            passed_validators=passed_count,
            failed_validators=failed_count,
            skipped_validators=skipped_count,
            total_errors=total_errors,
            total_warnings=total_warnings,
            total_execution_time=total_execution_time,
            results=results
        )

        self._call_hooks('after_validation', summary)

        self.logger.info(
            f"Validation completed: {passed_count}/{executed_count} passed, "
            f"{total_errors} errors, {total_warnings} warnings"
        )

        return summary

    def _should_stop(self, result: ValidationResult) -> bool:
        """Determine if validation should stop based on strategy"""
        if self.fail_fast:
            return not result.success
        return False

    def _get_time(self) -> float:
        """Get current time for timing measurements"""
        import time
        return time.time()
