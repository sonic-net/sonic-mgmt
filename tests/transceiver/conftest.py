import os
import pytest
import logging
import warnings

from .inventory.parser import TransceiverInventory

from tests.common.platform.interface_utils import get_physical_port_indices

# Import attribute infra components
from tests.transceiver.infra.dut_info_loader import DutInfoLoader
from tests.transceiver.infra.attribute_manager import AttributeManager
from tests.transceiver.infra.template_validator import STATUS_FULLY, STATUS_PARTIAL, TemplateValidator
from tests.transceiver.infra.exceptions import DutInfoError, AttributeMergeError, TemplateValidationError
from tests.transceiver.infra.utils import format_kv_block
from tests.transceiver.infra.paths import (
    REL_ATTR_DIR,
    REL_DEPLOYMENT_TEMPLATES_FILE,
    get_repo_root,
)

logger = logging.getLogger(__name__)

REPO_ROOT = get_repo_root()


def pytest_addoption(parser):
    """Add transceiver infra specific CLI options."""
    parser.addoption(
        "--skip_transceiver_template_validation", action="store_true", default=False,
        help="Skip template validation even if deployment templates file exists"
    )


def _load_platform_hwsku(duthost):
    """Derive (platform, hwsku) from a single duthost fixture.

    Returns (platform, hwsku) or (None, None) if unavailable.
    """
    try:
        if duthost:
            platform = duthost.facts.get('platform')
            hwsku = duthost.facts.get('hwsku')
            if platform and hwsku:
                return platform, hwsku
    except Exception as e:
        logger.error("Failed to derive platform/hwsku from duthost: %s", e)
    return None, None


@pytest.fixture(scope='session')
def port_attributes_dict(request, duthost):
    """Session-scoped merged port attributes (BASE + category).

    Loads dut_info.json via DutInfoLoader and merges category attribute files via AttributeManager.
    Optionally validates templates. Failure scenarios abort early to avoid invalid test runs.
    Logs compliance summary (if performed) before returning the merged attributes dict.
    """
    dut_name = duthost.hostname
    if not dut_name:
        pytest.skip("No DUT name available for transceiver attribute initialization")

    platform, hwsku = _load_platform_hwsku(duthost)
    logger.info(
        "Transceiver infra context resolved: dut_name=%s platform=%s hwsku=%s", dut_name, platform, hwsku
    )
    if not platform or not hwsku:
        logger.warning("Platform/HWSKU not determined; platform/hwsku specific overrides may not apply")

    logger.info("Building transceiver base port attributes for DUT '%s'", dut_name)
    loader = DutInfoLoader(REPO_ROOT)
    try:
        base_dict = loader.build_base_port_attributes(dut_name)
    except DutInfoError as e:
        pytest.fail(f"Failed loading base port attributes: {e}")

    if not base_dict:
        pytest.skip(f"No ports found for DUT '{dut_name}' in dut_info.json")

    attr_dir = os.path.join(REPO_ROOT, REL_ATTR_DIR)
    if not os.path.isdir(attr_dir):
        pytest.skip(f"Attributes directory {attr_dir} absent; returning base attributes only")

    logger.info("Merging category attributes from %s", attr_dir)
    mgr = AttributeManager(REPO_ROOT, base_dict)
    try:
        merged = mgr.build_port_attributes(dut_name, platform or '', hwsku or '')
    except AttributeMergeError as e:
        pytest.fail(f"Category attribute merging failed: {e}")
    if not merged:
        pytest.skip(f"No merged attributes found for DUT '{dut_name}'")

    # Run compliance validation (validator handles detailed logging and raises on required misses)
    templates_path = os.path.join(REPO_ROOT, REL_DEPLOYMENT_TEMPLATES_FILE)
    if not request.config.getoption('--skip_transceiver_template_validation') and os.path.isfile(templates_path):
        logger.info("Validating transceiver attributes against templates in %s", templates_path)
        validator = TemplateValidator(REPO_ROOT)
        try:
            # Validate merged attributes; raises on missing required attributes (partials only warn)
            compliance_dict = validator.validate(merged)
            results = compliance_dict.get('results', [])
            fail_messages = []
            full_count = 0
            partial_count = 0
            fail_count = 0
            for r in results:
                status = r.get('status')
                port = r.get('port')
                deployment = r.get('deployment')
                if status == STATUS_FULLY:
                    full_count += 1
                    logger.info("PASS: %s (%s) - %s", port, deployment, status)
                elif status == STATUS_PARTIAL:
                    partial_count += 1
                    missing_opt = ', '.join(r.get('missing_optional', []))
                    warnings.warn(f"PARTIAL: {port} missing optional: {missing_opt}")
                else:
                    fail_count += 1
                    missing_req = ', '.join(r.get('missing_required', []))
                    fail_messages.append(f"{port} missing required: {missing_req}")
            total_ports = compliance_dict.get('total_ports', len(results))
            logger.info(
                "Template validation summary: total=%d full=%d partial=%d fail=%d",
                total_ports,
                full_count,
                partial_count,
                fail_count,
            )
            if fail_messages:
                pytest.fail("Template validation failures:\n" + "\n".join(fail_messages))
        except TemplateValidationError as e:
            pytest.fail(f"Template validation failed: {e}")

    return merged


# Ensure infra initialized before any test in this package
@pytest.fixture(autouse=True, scope='session')
def _ensure_transceiver_infra_initialized(port_attributes_dict):
    logger.info("Transceiver infrastructure initialized: %d ports", len(port_attributes_dict))
    for port, categories in port_attributes_dict.items():
        for category, attrs in categories.items():
            logger.info(format_kv_block(f"{port} {category}", attrs))
    return


@pytest.fixture(scope="session")
def transceiver_inventory_obj():
    """
    Fixture to provide a single TransceiverInventory object for the session.
    """
    base_path = os.path.dirname(os.path.realpath(__file__))
    return TransceiverInventory(base_path)


@pytest.fixture(scope="session")
def get_transceiver_inventory(transceiver_inventory_obj):
    """
    Fixture to provide transceiver inventory information.
    """
    return transceiver_inventory_obj.get_transceiver_info()


@pytest.fixture(scope="session")
def get_transceiver_common_attributes(transceiver_inventory_obj):
    """
    Fixture to provide common attributes from TransceiverInventory.
    """
    return transceiver_inventory_obj.common_attributes


@pytest.fixture(scope="session")
def get_dev_transceiver_details(duthost, get_transceiver_inventory):
    """
    Get transceiver details from transceiver_inventory for the given DUT.

    @param duthost: DUT host
    @param get_transceiver_inventory: Transceiver inventory
    @return: Returns transceiver details in a dictionary for the given DUT with port as key
    """
    hostname = duthost.hostname
    details = get_transceiver_inventory.get(hostname, {})
    if not details:
        logging.error(f"No transceiver details found for host: {hostname}")
    return details


@pytest.fixture(scope="module")
def get_lport_to_pport_mapping(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Fixture to get the mapping of logical ports to physical ports.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    lport_to_pport_mapping = get_physical_port_indices(duthost)

    logging.info("Logical to Physical Port Mapping: {}".format(lport_to_pport_mapping))
    return lport_to_pport_mapping
