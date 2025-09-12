import pytest
import logging


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any"),
    pytest.mark.device_type("vs"),
]

pytestmark = [
    pytest.mark.disable_loganalyzer
]

def clear_all_cross_configuration(duthost):
    existed_cross = duthost.show_and_parse('show ocs cross-connect')
    cross_connect_pair = []
    if len(existed_cross) != 0:
       for each_cross in existed_cross:
           cross_connect_pair.append(each_cross['id'])
    if cross_connect_pair != []:
        for delete_cross in cross_connect_pair:
            duthost.shell(f'sudo config ocs cross-connect delete {delete_cross}')


def test_cross_connect_cli_traverse(duthost):
    clear_all_cross_configuration(duthost)
    for input_port in range(1,65):
        for output_port in range(1,65):
            port_pair = f"{input_port}A-{output_port}B"
            duthost.shell(f'sudo config ocs cross-connect add {port_pair}')
            configured_cross=duthost.show_and_parse('show ocs cross-connect config')
            assert configured_cross[0]['id'] == port_pair, f'Failed to configure cross-connect {port_pair}'
            logging.info(f'Success to configure cross-connect {port_pair}')
            duthost.shell(f'sudo config ocs cross-connect delete {port_pair}')

    
