import pytest
import logging
import random
import hashlib
from tests.common.helpers.constants import RANDOM_SEED


logger = logging.getLogger()


def pytest_addoption(parser):
    parser.addoption("--random_seed", action="store", default=None,
                     help="seed which is for random to generate the specified random data, by default is None"
                          "when random_seed is None, it will doesn't set seed for random."
                          "When random seed is integer, it will set seed with the value")


@pytest.fixture(scope='session', autouse=True)
def random_seed(request):
    random_seed = request.config.getoption("random_seed")
    if random_seed:
        logger.info("Save customized seed {} to cache".format(random_seed))
        request.config.cache.set(RANDOM_SEED, int(random_seed))
    else:
        if request.config.cache.get(RANDOM_SEED, None):
            logger.info("Random seed is set to none. Not setting any value as a test seed.")
            request.config.cache.set(RANDOM_SEED, None)


@pytest.fixture(scope='function', autouse=True)
def set_random_seed(request, random_seed):
    """
    This fixture will set the seed for random
    """
    random_seed = request.config.cache.get(RANDOM_SEED, None)
    if random_seed:
        test_name = request.node.name
        random_seed = str(random_seed) + get_test_name_hash_hex_value(test_name)
        logger.info("\n Random seed is {} for {}\n".format(random_seed, test_name))
        random.seed(random_seed)


def get_test_name_hash_hex_value(test_name):
    return hashlib.md5(test_name.encode()).hexdigest()
