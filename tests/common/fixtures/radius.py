import logging
import pytest

from tests.radius.utils import load_radius_creds

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def radius_creds(creds_all_duts):
    """load radius creds into test fixure"""
    test_creds = load_radius_creds()
    creds_all_duts.update(test_creds)
    return creds_all_duts

