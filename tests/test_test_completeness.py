import pytest
import logging
from tests.common.plugins.test_completeness import CompletenessLevel

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.supported_completeness_level(CompletenessLevel.Debug, CompletenessLevel.Basic, \
        CompletenessLevel.Confident, CompletenessLevel.Thorough)
]

logger = logging.getLogger(__name__)


def test_test_completeness_default(request):
    defined_levels = [mark.args for mark in request.node.iter_markers(name="completeness_level")]
    logger.info("Completeness level set: {}".format(str(defined_levels)))

@pytest.mark.supported_completeness_level(CompletenessLevel.Debug)
def test_test_completeness_defined(request):
    defined_levels = [mark.args for mark in request.node.iter_markers(name="completeness_level")]
    logger.info("Completeness level set: {}".format(str(defined_levels)))

@pytest.mark.supported_completeness_level(CompletenessLevel.Confident, CompletenessLevel.Thorough)
def test_test_completeness_lower_level(request):
    defined_levels = [mark.args for mark in request.node.iter_markers(name="completeness_level")]
    logger.info("Completeness level set: {}".format(str(defined_levels)))

@pytest.mark.supported_completeness_level(CompletenessLevel.Debug, CompletenessLevel.Basic, CompletenessLevel.Confident, CompletenessLevel.Thorough)
def test_test_completeness_highest_level(request):
    defined_levels = [mark.args for mark in request.node.iter_markers(name="completeness_level")]
    logger.info("Completeness level set: {}".format(str(defined_levels)))