import logging
import time
import pytest
from common.utilities import wait_until

from common.reboot import logger


from common.fixtures.conn_graph_facts import conn_graph_facts, \
     fanout_graph_facts

from common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_user,\
     ixia_api_serv_passwd, ixia_api_serv_port, ixia_api_serv_session_id, \
     ixia_api_server_session

from common.tgen_api.tgenfixtures import TgenApi


def test_testbed(TgenApi):
    
    TgenApi.configure()
    TgenApi.start()
    
    logger.info("wait for two seconds")
    time.sleep(2)

    TgenApi.stop()
 
