"""Compose the shared port-attribute parser and optional FEC validation.

This keeps loading and merging reusable by transceiver and non-transceiver
test categories without duplicating parser logic.
"""

import logging
import os
from pathlib import Path

from tests.common.port_attributes.fec_schema import FEC_CATEGORY_NAME, validate_fec_shard
from tests.common.port_attributes.dut_info_loader import DutInfoLoader
from tests.common.port_attributes.attribute_manager import AttributeManager
from tests.common.port_attributes.template_validator import TemplateValidator
from tests.common.port_attributes.exceptions import DutInfoError, AttributeMergeError
from tests.common.port_attributes.paths import (
    REL_ATTR_DIR,
    REL_DEPLOYMENT_TEMPLATES_FILE,
)

logger = logging.getLogger(__name__)


def build_port_attributes_dict(
    ansible_root,
    duthost,
    validate_templates=False,
    categories=None,
    missing_category_ok=False,
):
    """
    Build port_attributes_dict for the given DUT, reusing the existing
    transceiver attribute parser infrastructure.

    Args:
        ansible_root: Path to the active Ansible directory.
        duthost: DUT host object with .hostname and .facts attributes
        validate_templates: If True, validate against deployment templates.
        categories: Optional iterable of category names. ``None`` preserves the
            existing all-category behavior.
        missing_category_ok: Return an empty mapping without requiring base
            inventory when any explicitly requested category is absent.

    Returns:
        dict: port_attributes_dict with BASE_ATTRIBUTES and selected category
            attributes, or an empty mapping when an optional requested category
            is absent.

    Raises:
        DutInfoError: If present inventory is malformed (should fail, not degrade)
        AttributeMergeError: If attribute merging fails critically
        TemplateValidationError: If template validation fails (when enabled)
    """
    if isinstance(categories, str):
        categories = (categories,)
    selected_categories = None if categories is None else frozenset(categories)
    if selected_categories is not None and not selected_categories:
        raise ValueError("categories must be None or a non-empty iterable")
    if missing_category_ok and (
        selected_categories is None or len(selected_categories) != 1
    ):
        raise ValueError(
            "missing_category_ok=True requires exactly one explicitly requested category"
        )

    logger.info(
        "Building port attributes for DUT %s (categories=%s)",
        duthost.hostname,
        sorted(selected_categories) if selected_categories is not None else "all",
    )

    attr_dir = os.path.join(ansible_root, REL_ATTR_DIR)
    if selected_categories is not None:
        missing_categories = sorted(
            category
            for category in selected_categories
            if not os.path.isdir(os.path.join(attr_dir, category))
        )
        if missing_categories:
            if missing_category_ok:
                logger.info(
                    "Optional attribute categories %s are absent; using legacy policy",
                    missing_categories,
                )
                return {}
            raise AttributeMergeError(
                f"Requested attribute categories are missing: {missing_categories}"
            )

    # Once an explicitly requested optional category is present, its base
    # inventory is intentional configuration and must be complete and valid.
    dut_info_loader = DutInfoLoader(ansible_root)
    try:
        base_attributes = dut_info_loader.build_base_port_attributes(duthost.hostname)
    except DutInfoError as e:
        logger.error("Invalid DUT inventory for %s: %s", duthost.hostname, e)
        raise

    if not base_attributes and selected_categories is None:
        return {}
    if not base_attributes:
        raise DutInfoError(
            f"DUT inventory for {duthost.hostname} is present but contains no ports"
        )

    logger.info(f"Loaded base attributes for {len(base_attributes)} ports")

    if not os.path.isdir(attr_dir):
        logger.info("Attributes directory %s is absent", attr_dir)
        return {}

    # Merge category-specific attributes
    attr_manager = AttributeManager(ansible_root, base_attributes)
    try:
        facts = getattr(duthost, 'facts', {}) or {}
        platform = facts.get('platform', '') if isinstance(facts, dict) else ''
        hwsku = facts.get('hwsku', '') if isinstance(facts, dict) else ''
    except Exception:
        platform, hwsku = '', ''
    # Category-specific FEC validation applies only to explicit FEC consumers;
    # the existing all-category transceiver path keeps generic parser behavior.
    category_validators = None
    if selected_categories is not None and FEC_CATEGORY_NAME in selected_categories:
        category_validators = {FEC_CATEGORY_NAME: validate_fec_shard}
    try:
        port_attributes = attr_manager.build_port_attributes(
            duthost.hostname,
            platform,
            hwsku,
            categories=selected_categories,
            category_validators=category_validators,
        )
    except AttributeMergeError as e:
        logger.error(f"Attribute merging failed: {e}")
        raise

    if selected_categories is not None:
        for category in selected_categories:
            category_key = AttributeManager._category_key(category)
            missing_ports = [
                port_name
                for port_name, port_data in port_attributes.items()
                if category_key not in port_data
            ]
            if missing_ports:
                raise AttributeMergeError(
                    f"Category '{category}' is present but has no usable shards; "
                    f"resolved key '{category_key}' is missing for ports {missing_ports}"
                )

    first_port_data = next(iter(port_attributes.values()), {})
    logger.info(
        f"Merged attributes for categories: "
        f"{list(first_port_data.keys()) if first_port_data else 'none'}"
    )

    # Optional template validation
    if validate_templates:
        templates_path = Path(ansible_root) / REL_DEPLOYMENT_TEMPLATES_FILE
        if templates_path.exists():
            logger.info("Validating port attributes against deployment templates")
            validator = TemplateValidator(ansible_root)
            validator.validate(port_attributes)
        else:
            logger.warning(
                f"Template validation requested but {REL_DEPLOYMENT_TEMPLATES_FILE} not found"
            )

    return port_attributes
