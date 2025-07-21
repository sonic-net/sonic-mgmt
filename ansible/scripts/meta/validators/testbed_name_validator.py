"""
TestbedNameValidator - Validates testbed name uniqueness.
"""

from .base_validator import GlobalValidator, ValidationResult, ValidatorContext, ValidationCategory
from .validator_factory import register_validator


@register_validator("testbed_name")
class TestbedNameValidator(GlobalValidator):
    """Validates that all testbed names are unique across the infrastructure"""

    def __init__(self, config=None):
        super().__init__(
            name="testbed_name",
            description="Validates that all testbed names are unique across the infrastructure",
            category="configuration"
        )
        self.config = config or {}

    def _validate(self, context: ValidatorContext) -> ValidationResult:
        """
        Validate that testbed names are unique

        Args:
            context: ValidatorContext containing testbed and connection graph data

        Returns:
            ValidationResult: Comprehensive validation result
        """
        result = ValidationResult(validator_name=self.name, group_name=context.get_group_name(), success=True)
        testbed_info = context.get_testbeds()

        if not testbed_info:
            result.add_error("No testbed information provided", ValidationCategory.MISSING_DATA)
            return result

        # Collect testbed names
        testbed_names = self._collect_testbed_names(testbed_info, result)

        # Validate uniqueness
        self._validate_name_uniqueness(testbed_names, result)

        # Add metadata
        seen_names = set(testbed_names)
        duplicate_names = set(name for name in testbed_names if testbed_names.count(name) > 1)

        result.metadata.update({
            "total_testbeds": len(testbed_names),
            "unique_names": len(seen_names),
            "duplicate_count": len(duplicate_names),
            "duplicate_names": list(duplicate_names)
        })

        if result.success:
            result.add_info(
                f"Testbed name validation passed for {len(testbed_names)} testbeds",
                ValidationCategory.SUMMARY, result.metadata
            )

        return result

    def _collect_testbed_names(self, testbed_info, result):
        """
        Collect all testbed names from testbed configurations

        Args:
            testbed_info: List of testbed configurations
            result: ValidationResult to add issues to

        Returns:
            list: List of testbed names
        """
        testbed_names = []

        for i, testbed in enumerate(testbed_info):
            if not isinstance(testbed, dict):
                result.add_error(
                    f"Invalid testbed configuration format at index {i}: {type(testbed)}",
                    ValidationCategory.FORMAT, {"index": i, "type": str(type(testbed))}
                )
                continue

            conf_name = testbed.get('conf-name')
            if not conf_name:
                result.add_error(
                    f"Testbed at index {i} missing 'conf-name' field",
                    ValidationCategory.MISSING_DATA, {"index": i, "testbed": testbed}
                )
                continue

            testbed_names.append(conf_name)

        return testbed_names

    def _validate_name_uniqueness(self, testbed_names, result):
        """
        Validate that testbed names are unique

        Args:
            testbed_names: List of testbed names
            result: ValidationResult to add issues to
        """
        seen_names = set()
        duplicate_names = set()

        for name in testbed_names:
            if name in seen_names:
                duplicate_names.add(name)
                result.add_error(
                    f"Duplicate testbed name found: {name}",
                    ValidationCategory.DUPLICATE, {"name": name}
                )
            else:
                seen_names.add(name)
