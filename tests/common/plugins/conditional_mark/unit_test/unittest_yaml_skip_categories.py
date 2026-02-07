"""
Unit tests that load skip_categories from YAML file.
Developers can edit tests_skip_categories.yaml to test different scenarios.
"""

import logging
import os
import sys
import unittest
import yaml
from datetime import datetime, timedelta, timezone

# Add parent directory to import skip_category_validator module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from skip_category_validator import (  # noqa: E402
    validate_skip_category,
    check_expiry_and_format_reason
)

logger = logging.getLogger(__name__)


class TestSkipCategoriesFromYAML(unittest.TestCase):
    """Test category validation by loading configuration from YAML file."""

    @classmethod
    def setUpClass(cls):
        """Load test configuration from YAML file."""
        yaml_file = os.path.join(os.path.dirname(__file__), 'tests_skip_categories.yaml')
        with open(yaml_file, 'r') as f:
            cls.config = yaml.safe_load(f)

        cls.skip_categories = cls.config.get('skip_categories', {})
        logger.info(f"Loaded skip_categories from {yaml_file}")
        logger.info(f"Categories: {list(cls.skip_categories.keys())}")

    def test_yaml_has_skip_categories(self):
        """Verify YAML file has skip_categories section."""
        self.assertIn('skip_categories', self.config)
        self.assertIn('permanent', self.skip_categories)
        self.assertIn('temporary', self.skip_categories)

    def test_permanent_category_config(self):
        """Verify permanent category configuration."""
        permanent = self.skip_categories['permanent']
        self.assertFalse(permanent['requires_expiry_date'])
        self.assertIn('allowed_reasons', permanent)
        self.assertIn('ASIC_NOT_SUPPORTED', permanent['allowed_reasons'])

    def test_temporary_category_config(self):
        """Verify temporary category configuration."""
        temporary = self.skip_categories['temporary']
        self.assertTrue(temporary['requires_expiry_date'])
        self.assertEqual(temporary['max_expiry_days'], 180)
        self.assertIn('allowed_reasons', temporary)
        self.assertIn('BUG_FIX_IN_PROGRESS', temporary['allowed_reasons'])

    def test_valid_permanent_from_yaml(self):
        """Test valid permanent skip from YAML."""
        test_key = 'test_valid_permanent.py::test_asic_not_supported'
        test_config = self.config[test_key]
        mark_details = test_config['skip']

        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            test_key,
            self.skip_categories
        )

        self.assertTrue(apply_mark, f"Errors: {errors}")
        self.assertEqual(len(errors), 0)
        self.assertIn('ASIC does not support', formatted_reason)

    def test_valid_temporary_from_yaml(self):
        """Test valid temporary skip from YAML."""
        test_key = 'test_valid_temporary.py::test_bug_fix'
        test_config = self.config[test_key]
        mark_details = test_config['skip']

        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            test_key,
            self.skip_categories
        )

        self.assertTrue(apply_mark, f"Errors: {errors}")
        self.assertEqual(len(errors), 0)
        self.assertIn('expires', formatted_reason)
        self.assertIn('2026-06-15', formatted_reason)

    def test_expired_skip_from_yaml(self):
        """Test expired skip with default action (fail) from YAML."""
        test_key = 'test_expired.py::test_expired_bug'
        test_config = self.config[test_key]
        mark_details = test_config['skip']

        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            test_key,
            self.skip_categories
        )

        # Default expiry_action is 'fail', so validation error should be returned to fail test run
        self.assertFalse(apply_mark)
        self.assertIsNone(formatted_reason)
        self.assertEqual(len(errors), 1)
        self.assertIn('EXPIRED', errors[0])

    def test_expired_action_fail_from_yaml(self):
        """Test expired skip with expiry_action='fail' from YAML."""
        test_key = 'test_expired_action_fail.py::test_case'
        test_config = self.config[test_key]
        mark_details = test_config['skip']

        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            test_key,
            self.skip_categories
        )

        # With 'fail', validation error should be returned to fail test run
        self.assertFalse(apply_mark)
        self.assertIsNone(formatted_reason)
        self.assertEqual(len(errors), 1)
        self.assertIn('EXPIRED', errors[0])
        self.assertIn('Bug fix was supposed to be done', errors[0])

    def test_expired_action_warn_from_yaml(self):
        """Test expired skip with expiry_action='warn' from YAML."""
        test_key = 'test_expired_action_warn.py::test_case'
        test_config = self.config[test_key]
        mark_details = test_config['skip']

        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            test_key,
            self.skip_categories
        )

        # With 'warn', skip should not be applied (test will run)
        self.assertFalse(apply_mark)
        self.assertNotIn('EXPIRED', formatted_reason)
        self.assertEqual(len(errors), 0)

    def test_expired_action_run_from_yaml(self):
        """Test expired skip with expiry_action='run' from YAML."""
        test_key = 'test_expired_action_run.py::test_case'
        test_config = self.config[test_key]
        mark_details = test_config['skip']

        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            test_key,
            self.skip_categories
        )

        # With 'run', skip should not be applied (test will run silently)
        self.assertFalse(apply_mark)
        self.assertNotIn('EXPIRED', formatted_reason)
        self.assertEqual(len(errors), 0)

    def test_invalid_permanent_with_expiry_from_yaml(self):
        """Test invalid: permanent category with expiry_date."""
        test_key = 'test_invalid_permanent_with_expiry.py::test_case'
        test_config = self.config[test_key]
        mark_details = test_config['skip']

        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            test_key,
            self.skip_categories
        )

        self.assertFalse(apply_mark)
        self.assertEqual(len(errors), 1)
        self.assertIn('Invalid expiry_date', errors[0])

    def test_invalid_temporary_without_expiry_from_yaml(self):
        """Test invalid: temporary category without expiry_date."""
        test_key = 'test_invalid_temporary_without_expiry.py::test_case'
        test_config = self.config[test_key]
        mark_details = test_config['skip']

        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            test_key,
            self.skip_categories
        )

        self.assertFalse(apply_mark)
        self.assertEqual(len(errors), 1)
        self.assertIn('Missing expiry_date', errors[0])

    def test_invalid_category_from_yaml(self):
        """Test invalid: unknown category."""
        test_key = 'test_invalid_category.py::test_case'
        test_config = self.config[test_key]
        mark_details = test_config['skip']

        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            test_key,
            self.skip_categories
        )

        self.assertFalse(apply_mark)
        self.assertEqual(len(errors), 1)
        self.assertIn('Invalid category', errors[0])

    def test_invalid_date_format_from_yaml(self):
        """Test invalid: wrong date format."""
        test_key = 'test_invalid_date_format.py::test_case'
        test_config = self.config[test_key]
        mark_details = test_config['skip']

        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            test_key,
            self.skip_categories
        )

        self.assertFalse(apply_mark)
        self.assertEqual(len(errors), 1)
        self.assertIn('Invalid expiry_date format', errors[0])

    def test_backward_compatibility_from_yaml(self):
        """Test backward compatibility: skip without category."""
        test_key = 'test_backward_compat.py::test_old_format'
        test_config = self.config[test_key]
        mark_details = test_config['skip']

        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            test_key,
            self.skip_categories
        )

        self.assertTrue(apply_mark)
        self.assertEqual(len(errors), 0)
        self.assertIn('Old format', formatted_reason)

    def test_all_permanent_categories_valid(self):
        """Test all permanent categories are valid."""
        permanent_categories = self.skip_categories['permanent']['allowed_reasons']

        for category in permanent_categories:
            is_valid, category_type, error = validate_skip_category(
                category,
                self.skip_categories,
                'skip',
                'test.py::test_case'
            )

            self.assertTrue(is_valid, f"Category {category} should be valid")
            self.assertEqual(category_type, 'permanent')
            self.assertIsNone(error)

    def test_all_temporary_categories_valid(self):
        """Test all temporary categories are valid."""
        temporary_categories = self.skip_categories['temporary']['allowed_reasons']

        for category in temporary_categories:
            is_valid, category_type, error = validate_skip_category(
                category,
                self.skip_categories,
                'skip',
                'test.py::test_case'
            )

            self.assertTrue(is_valid, f"Category {category} should be valid")
            self.assertEqual(category_type, 'temporary')
            self.assertIsNone(error)

    def test_expiry_date_boundary(self):
        """Test expiry date at max_expiry_days boundary."""
        # Calculate exactly 180 days from now
        boundary_date = (datetime.now(timezone.utc) + timedelta(days=180)).date().isoformat()

        mark_details = {
            'reason': 'Test at boundary',
            'category': 'BUG_FIX_IN_PROGRESS',
            'expiry_date': boundary_date
        }

        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            'test.py::test_boundary',
            self.skip_categories
        )

        self.assertTrue(apply_mark, f"Errors: {errors}")
        self.assertEqual(len(errors), 0)

    def test_expiry_date_beyond_boundary(self):
        """Test expiry date beyond max_expiry_days."""
        # 181 days from now
        beyond_date = (datetime.now(timezone.utc) + timedelta(days=181)).date().isoformat()

        mark_details = {
            'reason': 'Test beyond boundary',
            'category': 'BUG_FIX_IN_PROGRESS',
            'expiry_date': beyond_date
        }

        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            'test.py::test_beyond',
            self.skip_categories
        )

        self.assertFalse(apply_mark)
        self.assertEqual(len(errors), 1)
        self.assertIn('exceeds max_expiry_days', errors[0])


class TestModifyYAMLForTesting(unittest.TestCase):
    """Examples showing developers how to modify YAML for testing."""

    def test_example_add_new_permanent_category(self):
        """
        Example: To add a new permanent category, edit tests_skip_categories.yaml:

        permanent:
          allowed_reasons:
            - "ASIC_NOT_SUPPORTED"
            - "YOUR_NEW_CATEGORY"  # Add here

        Then add a test case:

        test_new.py::test_case:
          skip:
            reason: "Test new category"
            category: "YOUR_NEW_CATEGORY"
            conditions:
              - "True"
        """
        self.assertTrue(True)  # Placeholder

    def test_example_change_max_expiry_days(self):
        """
        Example: To change max_expiry_days, edit tests_skip_categories.yaml:

        temporary:
          max_expiry_days: 90  # Change from 180 to 90

        Tests will automatically use the new value.
        """
        self.assertTrue(True)  # Placeholder

    def test_example_test_expired_skip(self):
        """
        Example: To test expired behavior, edit tests_skip_categories.yaml:

        test_your_expired.py::test_case:
          skip:
            category: "BUG_FIX_IN_PROGRESS"
            expiry_date: "2024-01-01"  # Past date
            reason: "This should not be applied"

        Run tests to verify expired skip is not applied.
        """
        self.assertTrue(True)  # Placeholder


if __name__ == '__main__':
    unittest.main()
