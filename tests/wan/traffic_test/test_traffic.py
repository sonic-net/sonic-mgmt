import logging
import pytest
import subprocess

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('wan-3link-tg'),
    pytest.mark.device_type('vs')
]


def start_traffic():

    result = dict()
    process = subprocess.Popen(['docker', 'exec',
                                'trex', 'sh', '-c',
                                'python /var/trex/v2.41/trex_client/stl/examples/stl_imix.py'],
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    while True:
        output = process.stdout.readline()
        if not output:
            break
        out = output.strip().split(':')
        result[out[0]] = out[1]

        return_code = process.poll()
        if return_code is not None:
            break

    return result


def test_traffic():

    output = start_traffic()

    assert int(output['lost']) <= 0, "Packets lost happen!"
