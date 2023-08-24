# -*- coding:UTF-8 -*-

import re
from tests.common.ixia.ixia_helpers import logger_msg
from tests.common.helpers.assertions import pytest_assert

"""
Smoke test, 2.1. View version information
"""


def test_smoking_2_1(duthost):
    ###############################################################
    #                   STEP1: Set result value to True
    ###############################################################
    # 1.1 result default is True, if at the end it False than test if Fail
    result = True

    ###############################################################
    #                   STEP2: Send DUT configuration
    ###############################################################
    logger_msg('DUT show version.')
    ret = str(duthost.shell('show version'))
    logger_msg(ret)
    if re.search('SONiC Software Version', ret):
        logger_msg('CHECK1:show version Success.')

    else:
        logger_msg('CHECK1:show version Fail.', 'ERROR')
        result = False

    ##############################################################
    #       STEP3: Determine whether the test case passes
    ##############################################################
    pytest_assert(result is True, 'Test case test_smoking_2_1 failed')
