
import json
import sys
import logging
from logging.handlers import RotatingFileHandler


CONFI_FILE = 'config.json'
configuration = {}

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s :%(name)s:%(lineno)d %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)


def config_logging():
    """Configure log to rotating file

    * Remove the default handler from app.logger.
    * Add RotatingFileHandler to the app.logger.
        File size: 10MB
        File number: 3
    * The Werkzeug handler is untouched.
    """
    rfh = RotatingFileHandler(
        '/tmp/test_failure_analyzer.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=3)
    fmt = logging.Formatter(
        '%(asctime)s %(levelname)s:%(funcName)s %(lineno)d:%(message)s')
    rfh.setFormatter(fmt)
    logger.addHandler(rfh)


def load_config():
    with open(CONFI_FILE) as f:
        configuration = json.load(f)

    if not configuration:
        logger.error("Config config doesn't exist, please check.")
        sys.exit(1)
    return configuration

configuration = load_config()