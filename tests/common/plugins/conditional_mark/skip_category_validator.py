"""
Skip category validation functions for conditional_mark plugin.

This module provides validation for skip categories (permanent vs temporary)
and expiry date handling for test skip marks.
"""

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def validate_skip_category(category, skip_categories, mark_name, test_path):
    """Validate that a category exists in the allowed categories.

    Args:
        category (str): The category to validate
        skip_categories (dict): The skip_categories configuration
        mark_name (str): The mark name (skip/xfail)
        test_path (str): The test path for error reporting

    Returns:
        tuple: (is_valid, category_type, error_message)
    """
    logger.debug(f"validate_skip_category called - category: {category}, "
                 f"mark_name: {mark_name}, test_path: {test_path}")

    if not skip_categories:
        # No categories defined, skip validation (backward compatibility)
        logger.debug("No skip_categories defined, skipping validation (backward compatibility)")
        return True, None, None

    if not category:
        # Category not specified - backward compatibility mode
        logger.debug("No category specified, skipping validation (backward compatibility)")
        return True, None, None

    # Check if category exists in any category type
    logger.debug(f"Checking category '{category}' against skip_categories: {list(skip_categories.keys())}")
    for category_type, config in skip_categories.items():
        allowed_reasons = config.get('allowed_reasons', [])
        logger.debug(f"Checking category_type: {category_type}, allowed_reasons: {allowed_reasons}")
        if category in allowed_reasons:
            logger.debug(f"Category '{category}' found in category_type: {category_type}")
            return True, category_type, None

    # Category not found in any allowed_reasons
    logger.debug(f"Category '{category}' not found in any allowed_reasons")
    all_categories = []
    for cat_type, config in skip_categories.items():
        all_categories.extend([f"  {cat_type.capitalize()}: {', '.join(config.get('allowed_reasons', []))}]"])

    error_msg = (
        f"Invalid category '{category}' for {mark_name} mark in '{test_path}'.\n"
        f"Allowed categories:\n" + "\n".join(all_categories)
    )
    return False, None, error_msg


def validate_expiry_date(expiry_date, category, category_type, skip_categories, mark_name, test_path):
    """Validate expiry_date based on category requirements.

    Args:
        expiry_date (str): The expiry date string
        category (str): The category name
        category_type (str): The category type (permanent/temporary)
        skip_categories (dict): The skip_categories configuration
        mark_name (str): The mark name (skip/xfail)
        test_path (str): The test path for error reporting

    Returns:
        tuple: (is_valid, error_message, is_expired)
    """
    logger.debug(f"validate_expiry_date called - expiry_date: {expiry_date}, "
                 f"category: {category}, category_type: {category_type}")

    if not skip_categories or not category_type:
        # No validation if categories not defined or category not specified
        logger.debug("No validation needed - skip_categories or category_type not defined")
        return True, None, False

    category_config = skip_categories.get(category_type, {})
    requires_expiry = category_config.get('requires_expiry_date', False)
    logger.debug(f"category_config: {category_config}, requires_expiry: {requires_expiry}")

    # Check if expiry date is required but missing
    if requires_expiry and not expiry_date:
        logger.debug(f"Expiry date required but missing for category '{category}'")
        error_msg = (
            f"Missing expiry_date for {mark_name} mark in '{test_path}'.\n"
            f"Category '{category}' is '{category_type}' and requires an expiry_date."
        )
        return False, error_msg, False

    # Check if expiry date is provided but not allowed
    if not requires_expiry and expiry_date:
        logger.debug(f"Expiry date provided but not allowed for category '{category}'")
        error_msg = (
            f"Invalid expiry_date for {mark_name} mark in '{test_path}'.\n"
            f"Category '{category}' is '{category_type}' and should not have an expiry_date."
        )
        return False, error_msg, False

    # Validate expiry date format and value
    if expiry_date:
        logger.debug(f"Validating expiry_date format: {expiry_date}")
        try:
            expiry_dt = datetime.strptime(expiry_date, '%Y-%m-%d')
            # Make it timezone aware (UTC)
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            logger.debug(f"expiry_dt: {expiry_dt}, today: {today}")

            # Check if already expired
            if expiry_dt <= today:
                # Expired - test should run
                logger.debug(f"Expiry date {expiry_date} has expired (today: {today.strftime('%Y-%m-%d')})")
                return True, None, True

            # Check max_expiry_days for temporary categories
            if category_type == 'temporary':
                max_expiry_days = category_config.get('max_expiry_days', 180)
                max_allowed_date = today + timedelta(days=max_expiry_days)
                logger.debug(f"Temporary category: max_expiry_days={max_expiry_days}, "
                             f"max_allowed_date={max_allowed_date}")

                if expiry_dt > max_allowed_date:
                    logger.debug(f"expiry_date {expiry_date} exceeds max_expiry_days {max_expiry_days}")
                    error_msg = (
                        f"expiry_date '{expiry_date}' exceeds max_expiry_days ({max_expiry_days}) "
                        f"for {mark_name} mark in '{test_path}'.\n"
                        f"Category '{category}' requires expiry within {max_expiry_days} days "
                        f"from today ({today.strftime('%Y-%m-%d')})."
                    )
                    return False, error_msg, False

        except ValueError as e:
            logger.debug(f"Invalid expiry_date format: {expiry_date}, error: {e}")
            error_msg = (
                f"Invalid expiry_date format '{expiry_date}' for {mark_name} mark in '{test_path}'.\n"
                f"Expected ISO 8601 format: YYYY-MM-DD"
            )
            return False, error_msg, False

    logger.debug("Expiry date validation passed, is_expired=False")
    return True, None, False


def check_expiry_and_format_reason(mark_details, mark_name, test_path, skip_categories):
    """Check if mark has expired and format the reason accordingly.

    Args:
        mark_details (dict): The mark details from YAML
        mark_name (str): The mark name (skip/xfail)
        test_path (str): The test path for error reporting
        skip_categories (dict): The skip_categories configuration

    Returns:
        tuple: (should_apply_mark, formatted_reason, validation_errors)
    """
    logger.debug(f"check_expiry_and_format_reason called - mark_name: {mark_name}, test_path: {test_path}")
    logger.debug(f"mark_details: {mark_details}")

    validation_errors = []

    category = mark_details.get('category')
    expiry_date = mark_details.get('expiry_date')
    reason = mark_details.get('reason', '')
    logger.debug(f"Extracted - category: {category}, expiry_date: {expiry_date}, reason: {reason}")

    # Validate category
    logger.debug("Validating category...")
    is_valid, category_type, error_msg = validate_skip_category(
        category, skip_categories, mark_name, test_path
    )
    if not is_valid:
        logger.debug(f"Category validation failed: {error_msg}")
        validation_errors.append(error_msg)
    else:
        logger.debug(f"Category validation passed, category_type: {category_type}")

    # Validate expiry date
    logger.debug("Validating expiry date...")
    is_valid, error_msg, is_expired = validate_expiry_date(
        expiry_date, category, category_type, skip_categories, mark_name, test_path
    )
    if not is_valid:
        logger.debug(f"Expiry date validation failed: {error_msg}")
        validation_errors.append(error_msg)
    else:
        logger.debug(f"Expiry date validation passed, is_expired: {is_expired}")

    # If there are validation errors, don't apply the mark
    if validation_errors:
        logger.debug(f"Validation errors found: {validation_errors}")
        return False, None, validation_errors

    # If expired, handle based on expiry_action
    if is_expired:
        expiry_action = mark_details.get('expiry_action', 'fail')
        logger.debug(f"Mark has expired, expiry_action: {expiry_action}")
        expired_reason = (
            f"EXPIRED - {mark_name.capitalize()} for test '{test_path}' expired on {expiry_date}.\n"
            f"Original reason: {reason}\n"
        )
        if category:
            expired_reason += f"Category: {category} ({category_type})\n"
        expired_reason += "Action required: Update with new expiry date or fix the underlying issue."

        if expiry_action == 'fail':
            # Fail the test run to force addressing the expired skip
            logger.error(expired_reason)
            logger.debug("Returning validation error to fail test run (expiry_action=fail)")
            return False, None, [expired_reason]
        elif expiry_action == 'warn':
            # Log warning but let test run
            logger.warning(expired_reason)
            logger.debug("Not applying mark, letting test run (expiry_action=warn)")
            return False, reason, []
        else:  # 'run'
            # Don't apply the mark, let test run
            logger.debug("Not applying mark, letting test run (expiry_action=run)")
            return False, reason, []

    # Format reason with expiry date if present
    if expiry_date:
        formatted_reason = f"{reason} (expires {expiry_date})"
        logger.debug(f"Formatted reason with expiry: {formatted_reason}")
    else:
        formatted_reason = reason
        logger.debug(f"Using original reason: {formatted_reason}")

    logger.debug(f"Returning: should_apply_mark=True, formatted_reason={formatted_reason}")
    return True, formatted_reason, []
