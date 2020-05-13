import pytest
import time
import json
import os

from common.fixtures.conn_graph_facts import fanout_graph_facts
from common.fixtures.pfc_asym import *


@pytest.fixture(autouse=True)
def flush_neighbors(duthost):
    """ Clear ARP table to make sure that neighbors learning will be triggered """
    duthost.command("sonic-clear arp")
