"""
Helper module to extract only the category/expiry validation functions
without importing the entire conditional_mark plugin with its dependencies.
"""

from datetime import datetime, timedelta, timezone


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
    if not skip_categories:
        # No categories defined, skip validation (backward compatibility)
        return True, None, None

    if not category:
        # Category not specified - backward compatibility mode
        return True, None, None

    # Check if category exists in any category type
    for category_type, config in skip_categories.items():
        allowed_reasons = config.get('allowed_reasons', [])
        if category in allowed_reasons:
            return True, category_type, None

    # Category not found in any allowed_reasons
    all_categories = []
    for cat_type, config in skip_categories.items():
        all_categories.extend([f"  {cat_type.capitalize()}: {', '.join(config.get('allowed_reasons', []))}"])

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
    if not skip_categories or not category_type:
        # No validation if categories not defined or category not specified
        return True, None, False

    category_config = skip_categories.get(category_type, {})
    requires_expiry = category_config.get('requires_expiry_date', False)

    # Check if expiry date is required but missing
    if requires_expiry and not expiry_date:
        error_msg = (
            f"Missing expiry_date for {mark_name} mark in '{test_path}'.\n"
            f"Category '{category}' is '{category_type}' and requires an expiry_date."
        )
        return False, error_msg, False

    # Check if expiry date is provided but not allowed
    if not requires_expiry and expiry_date:
        error_msg = (
            f"Invalid expiry_date for {mark_name} mark in '{test_path}'.\n"
            f"Category '{category}' is '{category_type}' and should not have an expiry_date."
        )
        return False, error_msg, False

    # Validate expiry date format and value
    if expiry_date:
        try:
            expiry_dt = datetime.strptime(expiry_date, '%Y-%m-%d')
            # Make it timezone aware (UTC)
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

            # Check if already expired
            if expiry_dt <= today:
                # Expired - test should run
                return True, None, True

            # Check max_expiry_days for temporary categories
            if category_type == 'temporary':
                max_expiry_days = category_config.get('max_expiry_days', 180)
                max_allowed_date = today + timedelta(days=max_expiry_days)

                if expiry_dt > max_allowed_date:
                    error_msg = (
                        f"expiry_date '{expiry_date}' exceeds max_expiry_days ({max_expiry_days}) "
                        f"for {mark_name} mark in '{test_path}'.\n"
                        f"Category '{category}' requires expiry within {max_expiry_days} days "
                        f"from today ({today.strftime('%Y-%m-%d')})."
                    )
                    return False, error_msg, False

        except ValueError:
            error_msg = (
                f"Invalid expiry_date format '{expiry_date}' for {mark_name} mark in '{test_path}'.\n"
                f"Expected ISO 8601 format: YYYY-MM-DD"
            )
            return False, error_msg, False

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
    validation_errors = []

    category = mark_details.get('category')
    expiry_date = mark_details.get('expiry_date')
    reason = mark_details.get('reason', '')

    # Validate category
    is_valid, category_type, error = validate_skip_category(
        category, skip_categories, mark_name, test_path
    )
    if not is_valid:
        validation_errors.append(error)

    # Validate expiry date
    is_valid, error, is_expired = validate_expiry_date(
        expiry_date, category, category_type, skip_categories, mark_name, test_path
    )
    if not is_valid:
        validation_errors.append(error)

    # If there are validation errors, don't apply the mark
    if validation_errors:
        return False, None, validation_errors

    # If expired, handle based on expiry_action
    if is_expired:
        expiry_action = mark_details.get('expiry_action', 'fail')
        expired_reason = (
            f"EXPIRED - {mark_name.capitalize()} for test '{test_path}' expired on {expiry_date}.\n"
            f"Original reason: {reason}\n"
        )
        if category:
            expired_reason += f"Category: {category} ({category_type})\n"
        expired_reason += "Action required: Update with new expiry date or fix the underlying issue."

        if expiry_action == 'fail':
            # Keep the skip/xfail but with expired message
            return True, expired_reason, []
        elif expiry_action == 'warn':
            # Log warning but let test run
            return False, reason, []
        else:  # 'run'
            # Don't apply the mark, let test run
            return False, reason, []

    # Format reason with expiry date if present
    if expiry_date:
        formatted_reason = f"{reason} (expires {expiry_date})"
    else:
        formatted_reason = reason

    return True, formatted_reason, []
