""" A SONIC test case using the injected tgen_api fixture
"""
import pytest
from tgenapi import TgenApi
from tgenmodels import *
from tgenfixtures import *


def test_pfc_pause_lossless(tgen_api):
    # configure dut

    # create a configuration
    tgen_api.config.flows = [
        Flow('Test Traffic', tgen_api.config.ports[0], packet=[Ethernet(), Ipv4()]),
        Flow('Background Traffic', tgen_api.config.ports[0], packet=[Ethernet()]),
        Flow('Pause Traffic', tgen_api.config.ports[1], packet=[PfcPause()])
    ]

    # configure and control the test tool
    tgen_api.configure()
    tgen_api.start()
    tgen_api.stop()
    
    # asserts for pass/fail

    # teardown the test tool
    tgen_api.deconfigure()

