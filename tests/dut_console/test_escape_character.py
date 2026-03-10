import logging
import pytest


TOTAL_PACKETS = 100
packet_number = 10
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def test_console_escape(duthost_console):
    duthost_console.send_command("ping 127.0.0.1 -c {} -i 1".format(TOTAL_PACKETS),
                                 expect_string=r"icmp_seq={}".format(packet_number))
    # Send interrupt character directly
    duthost_console.write_channel("\x03")
    # Matching the expected output content
    duthost_console.read_until_pattern(pattern=r"{} packets transmitted".format(packet_number))
