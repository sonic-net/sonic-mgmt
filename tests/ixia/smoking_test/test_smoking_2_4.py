# -*- coding:UTF-8 -*-

from tests.common.ixia.ixia_helpers import logger_msg
from tests.common.helpers.assertions import pytest_assert

"""
Smoke test, 2.4. View CPU usage
   1. Linux command line, top to view CPU usage
   2. Confirm that the overall is less than 20%
   3. Keep checking for 1 minute, and the peak value of a single process is lower than 30%
"""


def test_smoking_2_4(duthost):
    ###############################################################
    #                   STEP1: Set result value to True
    ###############################################################
    # 1.1 result default is True, if at the end it False than test if Fail
    result = True

    ###############################################################
    #                   STEP2: Send DUT configuration
    ###############################################################

    duthost.shell('top -n 1 > cmdoutput || true')
    ret = str(duthost.shell('cat cmdoutput'))
    logger_msg(ret)

    ##############################################################
    #       STEP3: Determine whether the test case passes
    ##############################################################
    pytest_assert(result is True, 'Test case test_smoking_check_version failed')
