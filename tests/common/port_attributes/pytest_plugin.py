"""
Pytest plugin providing port_attributes_dict_factory fixture.
This must be registered in tests/conftest.py to be discovered.
"""

import pytest
import logging

from .builder import build_port_attributes_dict

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def port_attributes_dict_factory(ansible_root):
    """
    Factory fixture that returns a function to build port_attributes_dict
    for any DUT. Results are cached per DUT and load-mode combination.

    Usage in tests:
        def test_foo(port_attributes_dict_factory, duthost):
            port_attrs = port_attributes_dict_factory(
                duthost,
                categories={"fec"},
                missing_category_ok=True,
            )
            if not port_attrs:
                # Requested optional category is absent; use legacy policy.
                pass
            else:
                fec_attrs = port_attrs.get("Ethernet0", {}).get("FEC_ATTRIBUTES", {})

    Returns:
        callable: Function that accepts a DUT and load options and returns a
            port_attributes_dict. An absent optional category returns ``{}``.
    """
    cache = {}

    def get_for_dut(
        duthost,
        validate_templates=False,
        categories=None,
        missing_category_ok=False,
    ):
        """
        Get or build port_attributes_dict for the specified DUT.

        Args:
            duthost: DUT host object
            validate_templates: If True, validate against deployment templates
            categories: Optional iterable of category names. ``None`` loads all.
            missing_category_ok: Return ``{}`` when a requested category is absent.

        Returns:
            dict: Nested port_attributes_dict, or ``{}`` for an absent optional
                category.
        """
        if isinstance(categories, str):
            categories = (categories,)
        normalized_categories = None if categories is None else tuple(sorted(set(categories)))
        key = (
            duthost.hostname,
            validate_templates,
            normalized_categories,
            missing_category_ok,
        )
        if key not in cache:
            logger.info(
                "Building port_attributes_dict for %s "
                "(validate_templates=%s, categories=%s, missing_category_ok=%s)",
                duthost.hostname,
                validate_templates,
                normalized_categories,
                missing_category_ok,
            )
            cache[key] = build_port_attributes_dict(
                ansible_root,
                duthost,
                validate_templates=validate_templates,
                categories=normalized_categories,
                missing_category_ok=missing_category_ok,
            )
        else:
            logger.debug(f"Using cached port_attributes_dict for {duthost.hostname}")
        return cache[key]

    return get_for_dut
