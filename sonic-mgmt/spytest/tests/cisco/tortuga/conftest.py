import pytest
from spytest import st

@pytest.fixture(scope="session", autouse=True)
def global_config():
    
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    '''
    Save config to avoid seeing following logs:
    sudo: unable to resolve host sonic: Name or service not known
    '''
    config = "sudo hostname sonic;sudo config save -y"
    for node in nodes:
    	#Apply config
    	st.config(node, config, skip_error_check=False, conf=True)
  
