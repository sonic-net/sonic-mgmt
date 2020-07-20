""" 
A SONIC pytest fixture returning a TgenApi implementation
"""

import pytest
from tgenmodels import Config, Port
from tgenapi import TgenApi
from keystgenapi import KeysTgenApi

from common.fixtures.conn_graph_facts import conn_graph_facts, \
     fanout_graph_facts

from common.reboot import logger
from common.ixia.ixia_helpers import  IxiaFanoutManager

import common.tgen_api


@pytest.fixture
def TgenApi(ixia_api_server_session):
    """
    Fixture: TgenApi -> Creates a IxNetwork session. 

    Note: ixia_api_server_session is a function level fixture and 
        automatically removes session when test case execution is
        complete. So we need not take care of session tear down
        here.

    Args: 
        ixia_api_server_session (pytest fisture): ixia_api_server_session
            fixture

    Returns:
        Ixia KeysTgenApi object instance, which is a derived class from 
        abstract class "TgenApi".
    """

    tgen = KeysTgenApi(session=ixia_api_server_session)
    return tgen

