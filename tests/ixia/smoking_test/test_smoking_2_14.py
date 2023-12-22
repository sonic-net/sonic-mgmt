# -*- coding:UTF-8 -*-

from tests.common.ixia.ixia_helpers import logger_msg
from tests.common.helpers.assertions import pytest_assert

"""
Smoke test, 2.14.MGMT-LLDP test
"""


def test_smoking_2_14(duthost):
    ###############################################################
    #                   STEP1: Set result value to True
    ###############################################################
    # 1.1 result default is True, if at the end it False than test if Fail
    result = True

    ###############################################################
    #                   STEP2: Send DUT configuration
    ###############################################################
    ret = str(duthost.shell('show lldp neighbor'))
    logger_msg(ret)

    ##############################################################
    #       STEP3: Determine whether the test case passes
    ##############################################################
    pytest_assert(result is True, 'Test case test_smoking_2_14 failed')
