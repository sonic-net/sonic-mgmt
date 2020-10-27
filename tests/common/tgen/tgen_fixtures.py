## tgn fixtures file where multiple vendors can define as per Open TGEN approach
import pytest

@pytest.fixture(scope='module')
def api(fanout_graph_facts,
        tbinfo,
        duthost):
    """
    Common api fixture for tgen of any platform. 
    
    Support is available for IXIA currently, please update for other traffic generators
    """
    # This is a dynamic approach for getting the tgen platform

    if 'ixia-sonic' in fanout_graph_facts.keys():
        from ixnetwork_open_traffic_generator.ixnetworkapi import IxNetworkApi
        from ixia import IXIA
        ixia = IXIA(tbinfo,duthost)
        ixnetwork_api = IxNetworkApi(address=ixia.api_serv_ip,
                                     port=ixia.api_serv_port,
                                     username=ixia.api_serv_user,
                                     password=ixia.api_serv_passwd)
        yield ixnetwork_api
        if ixnetwork_api.assistant is not None:
            ixnetwork_api.assistant.Session.remove()
    else:
        pytest.fail("The test supports only for IXIA TGEN, please add for other vendors")