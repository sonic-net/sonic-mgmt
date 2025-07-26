"""
TestbedNameValidator - Validates testbed name uniqueness.
"""

from .base_validator import GlobalValidator, ValidatorContext, ValidationCategory
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

    def _validate(self, context: ValidatorContext) -> None:
        """
        Validate that testbed names are unique

        Args:
            context: ValidatorContext containing testbed and connection graph data
        """
        testbed_info = context.get_testbeds()

        # Collect and validate testbed names in one pass
        seen_names, duplicate_names, total_testbeds = self._validate_name_uniqueness(testbed_info)

        # Add metadata using the returned values for better performance
        self.result.metadata.update({
            "total_testbeds": total_testbeds,
            "unique_names": len(seen_names),
            "duplicate_count": len(duplicate_names),
            "duplicate_names": list(duplicate_names)
        })

        if self.result.success:
            self.result.add_info(
                f"Testbed name validation passed for {total_testbeds} testbeds",
                ValidationCategory.SUMMARY, self.result.metadata
            )

    def _validate_name_uniqueness(self, testbed_info):
        """
        Collect testbed names and validate uniqueness in a single pass

        Args:
            testbed_info: List of testbed configurations

        Returns:
            tuple: (seen_names, duplicate_names, total_testbeds)
                - seen_names: Set of unique testbed names
                - duplicate_names: Set of duplicate testbed names
                - total_testbeds: Total count of valid testbeds processed
        """
        seen_names = set()
        duplicate_names = set()
        total_testbeds = 0

        for i, testbed in enumerate(testbed_info):
            if not isinstance(testbed, dict):
                self.result.add_error(
                    f"Invalid testbed configuration format at index {i}: {type(testbed)}",
                    ValidationCategory.FORMAT, {"index": i, "type": str(type(testbed))}
                )
                continue

            conf_name = testbed.get('conf-name')
            if not conf_name:
                self.result.add_error(
                    f"Testbed at index {i} missing 'conf-name' field",
                    ValidationCategory.MISSING_DATA, {"index": i, "testbed": testbed}
                )
                continue

            total_testbeds += 1

            # Check for duplicates and track names in one pass
            if conf_name in seen_names:
                duplicate_names.add(conf_name)
                self.result.add_error(
                    f"Duplicate testbed name found: {conf_name}",
                    ValidationCategory.DUPLICATE, {"name": conf_name}
                )
            else:
                seen_names.add(conf_name)

        return seen_names, duplicate_names, total_testbeds
