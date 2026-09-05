import logging
import pytest

from tests.transceiver.dom.dom_helpers import (
    build_dom_threshold_plan,
    has_dom_threshold_range_attributes,
    read_dom_threshold_data,
    validate_dom_threshold_ranges,
)

logger = logging.getLogger(__name__)


def test_dom_threshold_validation(
    duthost,
    dom_primary_ports,
    port_attributes_dict,
):
    """Verify configured DOM threshold ranges against STATE_DB threshold data."""
    threshold_plan_by_port = build_dom_threshold_plan(port_attributes_dict, dom_primary_ports)
    if not has_dom_threshold_range_attributes(threshold_plan_by_port):
        pytest.skip("No *_threshold_range attributes configured for DOM threshold validation")

    threshold_table_by_port, threshold_read_errors = read_dom_threshold_data(duthost, dom_primary_ports)
    all_failures = ["STATE_DB read:\n  {}".format(read_error) for read_error in threshold_read_errors]
    threshold_failures, checked_attr_count, checked_field_count, checked_port_count, skipped_check_count = (
        validate_dom_threshold_ranges(
            dom_primary_ports,
            threshold_table_by_port,
            threshold_plan_by_port,
        )
    )
    all_failures.extend(threshold_failures)

    if all_failures:
        pytest.fail("DOM threshold validation failures:\n" + "\n".join(all_failures))

    if skipped_check_count:
        logger.warning("DOM threshold validation completed with %d skipped check(s)", skipped_check_count)
    logger.info(
        "DOM threshold validation passed: %d threshold attribute(s), %d field(s) across %d port(s), "
        "%d skipped check(s)",
        checked_attr_count,
        checked_field_count,
        checked_port_count,
        skipped_check_count,
    )
