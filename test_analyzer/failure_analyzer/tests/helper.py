import sys, os
sys.path.append("..")
from main import read_types_configuration
import json
from pandas.testing import assert_frame_equal
import logging

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s :%(name)s:%(lineno)d %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)

EXCLUDED_TESTBED_KEYWORDS = ['3132', 'e1031', 's6000', '7280', 'slx', '3164', 'azd', 'dx010', 'vms7-t0-4600c-2', 'vms12-t0-8-lag-2700', 'testbed-bjw-can-4600c-1', 'vms21-t1-8101-02', 'vms61-t1-8101-01', 'testbed-bjw-can-8102-1', 'vms20-rdma-t1-8102', 'vms21-t1-8102-01', 'vms28-dual-t0-8102', 'vms61-dual-t0-8102', 'vms61-t0-8102-01', 'vms63-t0-dual-4600-1', 'vms7-t0-s6100', 'testbed-bjw-can-7050qx-2', 'testbed-bjw-can-7050qx-3', 'vms11-t0-7050qx-acs-4', 'tbtk5-t0-2700-3', 'vms24-t1-7050qx-acs-01', 'testbed-bjw-can-7050qx-1', 's6100', 'testbed-bjw2-can-t0-8102-5', 'testbed-bjw2-can-t0-8102-6', 'vms20-rdma-t0-8111', 'vms12-t0-7060x6-2', 'vms67-t0-7060x6-th5p-1']
EXCLUDED_TESTBED_KEYWORDS_SETUP_ERROR = ['3132', 'e1031', 's6000', '7280', 'slx', '3164', 'azd', 'dx010', 'vms7-t0-4600c-2', 'vms12-t0-8-lag-2700', 'testbed-bjw-can-4600c-1', 'vms21-t1-8101-02', 'vms61-t1-8101-01', 'testbed-bjw-can-8102-1', 'vms20-rdma-t1-8102', 'vms21-t1-8102-01', 'vms28-dual-t0-8102', 'vms61-dual-t0-8102', 'vms61-t0-8102-01', 'vms63-t0-dual-4600-1', 'vms7-t0-s6100', 'testbed-bjw-can-7050qx-2', 'testbed-bjw-can-7050qx-3', 'vms11-t0-7050qx-acs-4', 'tbtk5-t0-2700-3', 'vms24-t1-7050qx-acs-01', 'testbed-bjw-can-7050qx-1', 's6100', 'testbed-bjw2-can-t0-8102-5', 'testbed-bjw2-can-t0-8102-6', 'vms20-rdma-t0-8111', 'vms12-t0-7060x6-2', 'vms67-t0-7060x6-th5p-1']
INCLUDED_BRANCH = ['master', 'internal', '202012', '202205', '202305', '202311', '202405']
RELEASED_BRANCH = ['202012', '202205', '202305', '202311', '202405']

def load_config(config_file):
    with open(config_file) as f:
        config = json.load(f)
    config["testbeds"] = {}
    config["testbeds"]["excluded_testbed_keywords"] = EXCLUDED_TESTBED_KEYWORDS
    config["testbeds"]["excluded_testbed_keywords_setup_error"] = EXCLUDED_TESTBED_KEYWORDS_SETUP_ERROR

    config['branch'] = config.get('branch', {})
    config["branch"]["included_branch"] = INCLUDED_BRANCH
    config["branch"]["released_branch"] = RELEASED_BRANCH

    for level in config['level_priority']:
        config.update(read_types_configuration(level, config["icm_decision_config"].get(level, {}).get("types", [])))
    return config

def check_next_level_data(data1, data2):
    for level in data1:
        print(level)
        assert_frame_equal(data1.get(level), data2.get(level))

    for level in data2:
        print(level)
        assert_frame_equal(data1.get(level), data2.get(level))