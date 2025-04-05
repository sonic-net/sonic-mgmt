
import json
import sys
import logging
from logging.handlers import RotatingFileHandler
import os

current_file_path = os.path.abspath(__file__)
current_folder = os.path.dirname(current_file_path)
CONFI_FILE = current_folder+'/config.json'
configuration = {}

# Configure the root logger
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s %(filename)s:%(lineno)d [%(threadName)s] %(levelname)s - %(message)s')

# Use the root logger instead of a named logger
logger = logging.getLogger()

TOKEN = os.environ.get('AZURE_DEVOPS_MSAZURE_TOKEN')

if not TOKEN:
    raise Exception(
        'Must export environment variable AZURE_DEVOPS_MSAZURE_TOKEN')
AUTH = ('', TOKEN)

ICM_PREFIX = '[SONiC_Nightly][Failed_Case]'
BRANCH_PREFIX_LEN = 6


DATABASE = 'SonicTestData'
ICM_DATABASE = 'IcMDataWarehouse'
ADO_DATABASE = 'AzureDevOps'
PARENT_ID1 = "13410203"
PARENT_ID2 = "16726166"

ALL_FAILURES_CSV = 'logs/failures_df.csv'
ALL_RESUTLS_CSV = 'logs/week_results_df.csv'
FAILURES_AFTER_ANALYSIS_CSV = 'logs/failures_df_post.csv'
MIDDLE_FAILURES_CSV = 'logs/middle_failures_df.csv'
FAILURES_AFTER_AGGREGATION_CSV = 'logs/aggregated_df_post.csv'

def config_logging():
    """Configure log to rotating file

    * Remove the default handler from app.logger.
    * Add RotatingFileHandler to the app.logger.
        File size: 10MB
        File number: 3
    * The Werkzeug handler is untouched.
    """
    rfh = RotatingFileHandler(
        './logs/test_failure_analyzer.log',
        maxBytes=100*1024*1024,  # 100MB
        backupCount=3)
    fmt = logging.Formatter(
        '%(asctime)s %(levelname)s:%(funcName)s %(lineno)d:%(message)s')
    rfh.setFormatter(fmt)
    logger.addHandler(rfh)


def load_config():
    os.makedirs('logs', exist_ok=True)
    with open(CONFI_FILE) as f:
        logging.info("Loading config file: {}".format(CONFI_FILE))
        configuration = json.load(f)

    if not configuration:
        logger.error("Config config doesn't exist, please check.")
        sys.exit(1)
    return configuration

configuration = load_config()
