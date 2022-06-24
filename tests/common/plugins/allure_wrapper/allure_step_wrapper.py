import logging
from allure_commons._allure import step as raw_allure_step
logger = logging.getLogger(__name__)


def step(title):
    logger.info("Allure step: {}".format(title))
    return raw_allure_step(title)
