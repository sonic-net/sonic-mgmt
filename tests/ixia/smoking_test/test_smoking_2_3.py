# -*- coding:UTF-8 -*-

import re
from tests.common.ixia.ixia_helpers import logger_msg
from tests.common.helpers.assertions import pytest_assert

"""
Smoke test, 2.3. View memory usage
Under SONiC CLI, show system-memory
"""


def test_smoking_2_3(duthost):
    ###############################################################
    #                   STEP1: Set result value to True
    ###############################################################
    # 1.1 result default is True, if at the end it False than test if Fail
    result = True

    ###############################################################
    #                   STEP2: Send DUT configuration
    ###############################################################
    logger_msg('DUT view memory usage')
    ret = str(duthost.shell('show system-memory'))
    logger_msg(ret)
    if re.search('Mem', ret):
        logger_msg('CHECK1: Check the memory usage successfully.')
    else:
        logger_msg('CHECK1: Failed to check memory usage.', 'ERROR')
        result = False

    ##############################################################
    #       STEP3: Determine whether the test case passes
    ##############################################################
    pytest_assert(result is True, 'Test case test_smoking_2_3 failed')
