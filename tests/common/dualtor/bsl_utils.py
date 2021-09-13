import logging
import pytest

logger = logging.getLogger(__name__)
 

@pytest.fixture
def mock_transceiver_info_table(duthosts):
    """
    Replace the 'manufacturer' and 'model' fields for each port in the
    TRANSCEIVER_INFO table with Y cable values to enable `config mux hwmode`
    commands

    This can be reversed by restarting the `pmon` service on the device
    For now, auto-cleanup in this fixture is omitted to enable manual testing
    """
    mock_values = {
        'manufacturer': 'Credo',
        'model': 'CACXXX321P2PXXMS'
    }
    sonic_db_cmd = 'sonic-db-cli STATE_DB hset "TRANSCEIVER_INFO|{}" "{}" "{}"'

    for dut in duthosts:
        cmds = []
        mux_intfs = dut.get_running_config_facts()['MUX_CABLE'].keys()
        
        for intf in mux_intfs:
            for field, value in mock_values.items():
                cmds.append(sonic_db_cmd.format(intf, field, value))
        
        dut.shell_cmds(cmds=cmds)
