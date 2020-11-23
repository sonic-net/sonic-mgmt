# This file contains the list of API's which performs watermark feature operations.
# Author : Shiva Kumar Boddula (shivakumarboddula.boddula@broadcom.com)

from spytest import st

def clear_watermark_counters(dut, **kwargs):
    """
    Clear priority-group or queue watermark counters.
    Author: Shiva Kumar Boddula (shivakumarboddula.boddula@broadcom.com)

    :param :dut:
    :param :threshold_type:  priority-group|queue
    :param :buffer_type: if threshold_type:priority-group {shared|headroom} |
                                                            else threshold_type:queue {unicast|multicast}
    :return:
    """
    if 'threshold_type' not in kwargs and 'buffer_type' not in kwargs and 'cli_type' not in kwargs:
        st.error("Mandatory parameter threshold_type/buffer_type/cli_type not found")
        return False
    cli_type = st.get_ui_type(dut, **kwargs)
    if "priority-group" in kwargs['threshold_type'] or "queue" in kwargs['threshold_type']:
        if cli_type == "click":
            command = "sonic-clear {} watermark {}".format(kwargs['threshold_type'], kwargs['buffer_type'])
        elif cli_type == "klish":
            command = "clear {} watermark {}".format(kwargs['threshold_type'], kwargs['buffer_type'])
    else:
        st.error("Invalid threshold_type provided '{}'".format(kwargs['threshold_type']))
        return False
    st.config(dut, command, type=cli_type)
    return True

def show_watermark_counters(dut, **kwargs):
    """
    Show priority-group or queue watermark counters.
    Author: Shiva Kumar Boddula (shivakumarboddula.boddula@broadcom.com)

    :param dut:
    :param :threshold_type:  priority-group|queue
    :param :buffer_type: if threshold_type:priority-group {shared|headroom} |
                                                            else threshold_type:queue {unicast|multicast}
    :param :cli_type:  click|klish
    :return:
    """
    if 'threshold_type' not in kwargs and 'buffer_type' not in kwargs and 'cli_type' not in kwargs:
        st.error("Mandatory parameter threshold_type/buffer_type/cli_type not found")
        return False
    cli_type = st.get_ui_type(dut, **kwargs)
    if "priority-group" in kwargs['threshold_type'] or "queue" in kwargs['threshold_type']:
        command = "show {} watermark {}".format(kwargs['threshold_type'], kwargs['buffer_type'])
    else:
        st.error("Invalid threshold_type provided '{}'".format(kwargs['threshold_type']))
        return False
    st.show(dut, command, skip_tmpl=True, type=cli_type)
    return True
