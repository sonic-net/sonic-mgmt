"""Integration test for gnmic capabilities via gnmi_tls fixture."""
import pytest
import logging

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]


def test_gnmic_capabilities(gnmi_tls):  # noqa: F811
    """Test gnmic capabilities() returns expected encodings and models."""
    result = gnmi_tls.gnmic.capabilities()
    logger.info("Capabilities response: %s", result)

    assert "version" in result, \
        f"Missing version in response: {list(result.keys())}"
    assert "supported-models" in result, \
        f"Missing supported-models in response: {list(result.keys())}"
    assert len(result["supported-models"]) > 0, \
        "supported-models should not be empty"

    encodings = result.get("encodings", [])
    assert "JSON_IETF" in encodings, \
        f"JSON_IETF not in encodings: {encodings}"

    logger.info("version: %s", result["version"])
    logger.info("encodings: %s", encodings)
    logger.info("supported-models count: %d", len(result["supported-models"]))
