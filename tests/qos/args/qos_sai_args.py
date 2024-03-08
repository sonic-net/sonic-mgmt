# QoS-SAI Args file
from tests.common.utilities import str2bool


def add_qos_sai_args(parser):
    """
        Adding arguments required for QoS SAI test cases

       Args:
            parser: pytest parser object

        Returns:
            None
    """
    qos_group = parser.getgroup("QoS test suite options")

    qos_group.addoption(
        "--disable_test",
        action="store",
        type=str2bool,
        default=True,
        help="Control execution of buffer watermark experimental tests",
    )

    qos_group.addoption(
        "--qos_dst_ports",
        action="store",
        type=lambda opt_value: [int(v) for v in opt_value.translate(None, "[]").split(',')],
        default=None,
        help="QoS SAI comma separated list of destination ports. Test currently expects exactly 3 destination ports",
    )

    qos_group.addoption(
        "--qos_src_ports",
        action="store",
        type=lambda opt_value: [int(v) for v in opt_value.translate(None, "[]").split(',')],
        default=None,
        help="QoS SAI comma separated list of source ports. Test currently expects exactly 1 source port",
    )

    qos_group.addoption(
        "--qos_dual_tor",
        action="store",
        type=str2bool,
        default=False,
        help="Test QoS on dual ToR ports"
    )

    qos_group.addoption(
        "--port_target_speed",
        action="store",
        type=str,
        default=None,
        help="port_target_speed is only for testQosSaiDwrr."
             "When it is None, test will do nothing,"
             "When it is set a value of port speed, the tested dst port and the corresponding fanout port"
             "will be changed to the set value. It can be set to like 50000, 10000"
    )
