# QoS-SAI Args file

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
        type=bool,
        default=True,
        help="Control execution of buffer watermark experimental tests",
    )

    qos_group.addoption(
        "--qos_swap_syncd",
        action="store",
        type=bool,
        default=True,
        help="Swap syncd container with syncd-rpc container",
    )

    qos_group.addoption(
        "--qos_dst_ports",
        action="store",
        type=lambda opt_value: [int(v) for v in opt_value.translate(None, "[]").split(',')],
        default=[0, 1, 3],
        help="QoS SAI comma separated list of destination ports. Test currently expects exactly 3 destination ports",
    )

    qos_group.addoption(
        "--qos_src_ports",
        action="store",
        type=lambda opt_value: [int(v) for v in opt_value.translate(None, "[]").split(',')],
        default=[2],
        help="QoS SAI comma separated list of source ports. Test currently expects exactly 1 source port",
    )

