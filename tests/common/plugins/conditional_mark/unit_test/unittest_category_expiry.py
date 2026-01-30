import logging
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

# Add parent directory to import skip_category_validator module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from skip_category_validator import (  # noqa: E402
    validate_skip_category,
    validate_expiry_date,
    check_expiry_and_format_reason
)

logger = logging.getLogger(__name__)


class TestCategoryValidation(unittest.TestCase):
    """Test cases for skip category validation."""

    def setUp(self):
        """Set up test fixtures."""
        self.skip_categories = {
            'permanent': {
                'description': 'Permanent skips',
                'requires_expiry_date': False,
                'allowed_reasons': [
                    'ASIC_NOT_SUPPORTED',
                    'TOPO_NOT_SUPPORTED',
                    'FEATURE_NOT_APPLICABLE'
                ]
            },
            'temporary': {
                'description': 'Temporary skips',
                'requires_expiry_date': True,
                'max_expiry_days': 180,
                'allowed_reasons': [
                    'BUG_FIX_IN_PROGRESS',
                    'NEW_FEATURE_UNDER_DEVELOPMENT',
                    'INFRASTRUCTURE_ISSUE'
                ]
            }
        }

    def test_valid_permanent_category(self):
        """Test validation of valid permanent category."""
        is_valid, category_type, error = validate_skip_category(
            'ASIC_NOT_SUPPORTED',
            self.skip_categories,
            'skip',
            'test.py::test_case'
        )
        self.assertTrue(is_valid)
        self.assertEqual(category_type, 'permanent')
        self.assertIsNone(error)

    def test_valid_temporary_category(self):
        """Test validation of valid temporary category."""
        is_valid, category_type, error = validate_skip_category(
            'BUG_FIX_IN_PROGRESS',
            self.skip_categories,
            'skip',
            'test.py::test_case'
        )
        self.assertTrue(is_valid)
        self.assertEqual(category_type, 'temporary')
        self.assertIsNone(error)

    def test_invalid_category(self):
        """Test validation of invalid category."""
        is_valid, category_type, error = validate_skip_category(
            'INVALID_CATEGORY',
            self.skip_categories,
            'skip',
            'test.py::test_case'
        )
        self.assertFalse(is_valid)
        self.assertIsNone(category_type)
        self.assertIn('Invalid category', error)

    def test_missing_category(self):
        """Test validation when category is None (backward compatibility)."""
        is_valid, category_type, error = validate_skip_category(
            None,
            self.skip_categories,
            'skip',
            'test.py::test_case'
        )
        self.assertTrue(is_valid)
        self.assertIsNone(category_type)
        self.assertIsNone(error)


class TestExpiryDateValidation(unittest.TestCase):
    """Test cases for expiry date validation."""

    def setUp(self):
        """Set up test fixtures."""
        self.skip_categories = {
            'permanent': {
                'requires_expiry_date': False,
                'allowed_reasons': ['ASIC_NOT_SUPPORTED']
            },
            'temporary': {
                'requires_expiry_date': True,
                'max_expiry_days': 180,
                'allowed_reasons': ['BUG_FIX_IN_PROGRESS']
            }
        }

    def test_permanent_without_expiry(self):
        """Test permanent category without expiry_date (should pass)."""
        is_valid, error, is_expired = validate_expiry_date(
            None,
            'ASIC_NOT_SUPPORTED',
            'permanent',
            self.skip_categories,
            'skip',
            'test.py::test_case'
        )
        self.assertTrue(is_valid)
        self.assertIsNone(error)
        self.assertFalse(is_expired)

    def test_permanent_with_expiry(self):
        """Test permanent category with expiry_date (should fail)."""
        future_date = (datetime.now(timezone.utc) + timedelta(days=30)).date().isoformat()
        is_valid, error, is_expired = validate_expiry_date(
            future_date,
            'ASIC_NOT_SUPPORTED',
            'permanent',
            self.skip_categories,
            'skip',
            'test.py::test_case'
        )
        self.assertFalse(is_valid)
        self.assertIn('Invalid expiry_date', error)
        self.assertFalse(is_expired)

    def test_temporary_without_expiry(self):
        """Test temporary category without expiry_date (should fail)."""
        is_valid, error, is_expired = validate_expiry_date(
            None,
            'BUG_FIX_IN_PROGRESS',
            'temporary',
            self.skip_categories,
            'skip',
            'test.py::test_case'
        )
        self.assertFalse(is_valid)
        self.assertIn('Missing expiry_date', error)
        self.assertFalse(is_expired)

    def test_temporary_with_valid_future_expiry(self):
        """Test temporary category with valid future expiry_date."""
        future_date = (datetime.now(timezone.utc) + timedelta(days=30)).date().isoformat()
        is_valid, error, is_expired = validate_expiry_date(
            future_date,
            'BUG_FIX_IN_PROGRESS',
            'temporary',
            self.skip_categories,
            'skip',
            'test.py::test_case'
        )
        self.assertTrue(is_valid)
        self.assertIsNone(error)
        self.assertFalse(is_expired)

    def test_temporary_with_expired_date(self):
        """Test temporary category with expired date."""
        past_date = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()
        is_valid, error, is_expired = validate_expiry_date(
            past_date,
            'BUG_FIX_IN_PROGRESS',
            'temporary',
            self.skip_categories,
            'skip',
            'test.py::test_case'
        )
        # Expired dates return is_valid=True but is_expired=True
        self.assertTrue(is_valid)
        self.assertIsNone(error)
        self.assertTrue(is_expired)

    def test_temporary_exceeding_max_days(self):
        """Test temporary category with expiry beyond max_expiry_days."""
        far_future_date = (datetime.now(timezone.utc) + timedelta(days=200)).date().isoformat()
        is_valid, error, is_expired = validate_expiry_date(
            far_future_date,
            'BUG_FIX_IN_PROGRESS',
            'temporary',
            self.skip_categories,
            'skip',
            'test.py::test_case'
        )
        self.assertFalse(is_valid)
        self.assertIn('exceeds max_expiry_days', error)
        self.assertFalse(is_expired)

    def test_invalid_date_format(self):
        """Test invalid date format."""
        is_valid, error, is_expired = validate_expiry_date(
            '12/31/2025',  # Wrong format
            'BUG_FIX_IN_PROGRESS',
            'temporary',
            self.skip_categories,
            'skip',
            'test.py::test_case'
        )
        self.assertFalse(is_valid)
        self.assertIn('Invalid expiry_date format', error)
        self.assertFalse(is_expired)

    def test_expiry_at_max_boundary(self):
        """Test expiry date exactly at max_expiry_days boundary."""
        boundary_date = (datetime.now(timezone.utc) + timedelta(days=180)).date().isoformat()
        is_valid, error, is_expired = validate_expiry_date(
            boundary_date,
            'BUG_FIX_IN_PROGRESS',
            'temporary',
            self.skip_categories,
            'skip',
            'test.py::test_case'
        )
        self.assertTrue(is_valid)
        self.assertIsNone(error)
        self.assertFalse(is_expired)


class TestCheckExpiryAndFormatReason(unittest.TestCase):
    """Test cases for check_expiry_and_format_reason coordinator function."""

    def setUp(self):
        """Set up test fixtures."""
        self.skip_categories = {
            'permanent': {
                'requires_expiry_date': False,
                'allowed_reasons': ['ASIC_NOT_SUPPORTED']
            },
            'temporary': {
                'requires_expiry_date': True,
                'max_expiry_days': 180,
                'allowed_reasons': ['BUG_FIX_IN_PROGRESS']
            }
        }

    def test_valid_permanent_skip(self):
        """Test valid permanent skip mark."""
        mark_details = {
            'reason': 'Not supported on this ASIC',
            'category': 'ASIC_NOT_SUPPORTED'
        }
        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            'test.py::test_case',
            self.skip_categories
        )
        self.assertTrue(apply_mark)
        self.assertEqual(formatted_reason, 'Not supported on this ASIC')
        self.assertEqual(len(errors), 0)

    def test_valid_temporary_skip(self):
        """Test valid temporary skip mark."""
        future_date = (datetime.now(timezone.utc) + timedelta(days=30)).date().isoformat()
        mark_details = {
            'reason': 'Bug being fixed',
            'category': 'BUG_FIX_IN_PROGRESS',
            'expiry_date': future_date
        }
        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            'test.py::test_case',
            self.skip_categories
        )
        self.assertTrue(apply_mark)
        self.assertIn('Bug being fixed', formatted_reason)
        self.assertIn(f'expires {future_date}', formatted_reason)
        self.assertEqual(len(errors), 0)

    def test_expired_skip(self):
        """Test expired skip mark with default expiry_action (fail)."""
        past_date = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()
        mark_details = {
            'reason': 'Bug being fixed',
            'category': 'BUG_FIX_IN_PROGRESS',
            'expiry_date': past_date
        }
        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            'test.py::test_case',
            self.skip_categories
        )
        # Default expiry_action is 'fail', so validation error should be returned to fail test run
        self.assertFalse(apply_mark)
        self.assertIsNone(formatted_reason)
        self.assertEqual(len(errors), 1)
        self.assertIn('EXPIRED', errors[0])
        self.assertIn('Bug being fixed', errors[0])

    def test_expired_skip_action_fail(self):
        """Test expired skip with expiry_action='fail'."""
        past_date = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()
        mark_details = {
            'reason': 'Bug being fixed',
            'category': 'BUG_FIX_IN_PROGRESS',
            'expiry_date': past_date,
            'expiry_action': 'fail'
        }
        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            'test.py::test_case',
            self.skip_categories
        )
        # With 'fail', validation error should be returned to fail test run
        self.assertFalse(apply_mark)
        self.assertIsNone(formatted_reason)
        self.assertEqual(len(errors), 1)
        self.assertIn('EXPIRED', errors[0])
        self.assertIn('Action required', errors[0])

    def test_expired_skip_action_warn(self):
        """Test expired skip with expiry_action='warn'."""
        past_date = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()
        mark_details = {
            'reason': 'Bug being fixed',
            'category': 'BUG_FIX_IN_PROGRESS',
            'expiry_date': past_date,
            'expiry_action': 'warn'
        }
        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            'test.py::test_case',
            self.skip_categories
        )
        # With 'warn', mark should not be applied (test will run)
        self.assertFalse(apply_mark)
        self.assertIn('Bug being fixed', formatted_reason)
        self.assertNotIn('EXPIRED', formatted_reason)
        self.assertEqual(len(errors), 0)

    def test_expired_skip_action_run(self):
        """Test expired skip with expiry_action='run'."""
        past_date = (datetime.now(timezone.utc) - timedelta(days=30)).date().isoformat()
        mark_details = {
            'reason': 'Bug being fixed',
            'category': 'BUG_FIX_IN_PROGRESS',
            'expiry_date': past_date,
            'expiry_action': 'run'
        }
        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            'test.py::test_case',
            self.skip_categories
        )
        # With 'run', mark should not be applied (test will run silently)
        self.assertFalse(apply_mark)
        self.assertIn('Bug being fixed', formatted_reason)
        self.assertNotIn('EXPIRED', formatted_reason)
        self.assertEqual(len(errors), 0)

    def test_invalid_category(self):
        """Test invalid category in skip mark."""
        mark_details = {
            'reason': 'Some reason',
            'category': 'INVALID_CATEGORY'
        }
        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            'test.py::test_case',
            self.skip_categories
        )
        self.assertFalse(apply_mark)
        self.assertIsNone(formatted_reason)
        self.assertEqual(len(errors), 1)
        self.assertIn('Invalid category', errors[0])

    def test_temporary_missing_expiry(self):
        """Test temporary category without expiry_date."""
        mark_details = {
            'reason': 'Bug being fixed',
            'category': 'BUG_FIX_IN_PROGRESS'
        }
        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            'test.py::test_case',
            self.skip_categories
        )
        self.assertFalse(apply_mark)
        self.assertIsNone(formatted_reason)
        self.assertEqual(len(errors), 1)
        self.assertIn('Missing expiry_date', errors[0])

    def test_permanent_with_expiry(self):
        """Test permanent category with expiry_date."""
        future_date = (datetime.now(timezone.utc) + timedelta(days=30)).date().isoformat()
        mark_details = {
            'reason': 'Not supported',
            'category': 'ASIC_NOT_SUPPORTED',
            'expiry_date': future_date
        }
        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            'test.py::test_case',
            self.skip_categories
        )
        self.assertFalse(apply_mark)
        self.assertIsNone(formatted_reason)
        self.assertEqual(len(errors), 1)
        self.assertIn('Invalid expiry_date', errors[0])

    def test_backward_compatibility_no_category(self):
        """Test backward compatibility - skip without category."""
        mark_details = {
            'reason': 'Some old reason'
        }
        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            'test.py::test_case',
            self.skip_categories
        )
        self.assertTrue(apply_mark)
        self.assertEqual(formatted_reason, 'Some old reason')
        self.assertEqual(len(errors), 0)

    def test_multiple_validation_errors(self):
        """Test multiple validation errors are collected."""
        mark_details = {
            'reason': 'Some reason',
            'category': 'INVALID_CATEGORY',
            'expiry_date': '12/31/2025'  # Also invalid format
        }
        apply_mark, formatted_reason, errors = check_expiry_and_format_reason(
            mark_details,
            'skip',
            'test.py::test_case',
            self.skip_categories
        )
        self.assertFalse(apply_mark)
        self.assertIsNone(formatted_reason)
        # Should have error about invalid category
        self.assertGreaterEqual(len(errors), 1)
        self.assertIn('Invalid category', errors[0])


if __name__ == '__main__':
    unittest.main()
