from spytest import st
from utilities.common import filter_and_select, make_list
from utilities.utils import get_supported_ui_type_list


def show_knet_stats(dut, type, **kwargs):
    """
    API to show KNET Packet stats on DUT
    Author : Nagarjuna Suravarapu (nagarjuna.survarapu@broadcom.com)
    :param dut:
    :param type: -a|pkt-type|rx-queue
    :return:
    """
    intf = kwargs.get("intf", "")
    verbose = " -v" if kwargs.get("verbose", False) else ""
    if type == "pkt-type":
        cmd = "show knet stats pkt-type{} {}".format(verbose, intf)
    else:
        cmd = "show knet stats rx-queue{} {}".format(verbose, intf)
    output = st.show(dut, cmd, type="click")
    return output


def clear_knet_stats(dut, type, **kwargs):
    """
    API to clear KNET Packet stats on DUT
    Author : Nagarjuna Suravarapu (nagarjuna.survarapu@broadcom.com)
    :param dut:
    :param type: all|pkt-type|rx-queue
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type)
    if cli_type in ["klish", "rest-patch", "rest-put", "click"]:
        intf = kwargs.get("intf", "")
        if type == "all":
            command = "sonic-clear knet stats"
        elif type == "pkt-type":
            command = "show knet stats pkt-type -c {}".format(intf)
        else:
            command = "show knet stats rx-queue -c {}".format(intf)
        st.config(dut, command, type="click")
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def validate_knet_counters(dut, pkt_type, queue, **kwargs):
    """
    This proc is to validate KNET counters
    Author: Jagadish Chatrasi<jagadish.chatrasi@broadcom.com>
    :param dut:
    :param type: pkt_type
    :param type: queue
    :return:
    """
    if 'exp_rate' in kwargs and 'tolerance' in kwargs:
        nooftimes = 3
        for itercountvar in range(nooftimes):
            if itercountvar != 0:
                st.wait(1)
            cli_out = show_knet_stats(dut, type='rx-queue')
            out1 = filter_and_select(cli_out, ["rx_pkts"], {"queue": queue})
            st.wait(10)
            cli_out = show_knet_stats(dut, type='rx-queue')
            out2 = filter_and_select(cli_out, ["rx_pkts"], {"queue": queue})
            if len(out1) == 0 or len(out2) == 0:
                st.log("ERROR: cpu_queue is not lised in the show output")
                return False
            st.log("CPU Queue {} 1st Rx_pkts value is {} & 2nd Rx_Pkts value after 10 sec is {}".format(queue,
                                                                                                        out1[0]['rx_pkts'], out2[0]['rx_pkts']))
            ob_value = (int(out2[0]['rx_pkts']) - int(out1[0]['rx_pkts'])) // 10
            start_value = int(kwargs['exp_rate']) - int(kwargs['tolerance'])
            end_value = int(kwargs['exp_rate']) + int(kwargs['tolerance'])
            if ob_value >= start_value and ob_value <= end_value:
                st.log('obtained rate {} for CPU queue {} is in the range b/w '
                       '{} and {}'.format(ob_value, queue, start_value, end_value))
                return True
            else:
                st.error('obtained rate {} for CPU queue {} is NOT in the range b/w '
                         '{} and {}'.format(ob_value, queue, start_value, end_value))
                if itercountvar < (nooftimes - 1):
                    st.log("Re-verifying again..")
                    continue
                return False
    else:
        queue_type = kwargs.get('queue_type', 'rx-queue')
        verify_counters = make_list(kwargs['verify_counters']) if kwargs.get('verify_counters') else None
        output1 = show_knet_stats(dut, type='pkt-type')
        output2 = show_knet_stats(dut, type=queue_type)
        if kwargs.get('intf'):
            kwargs['intf'] = st.get_other_names(dut, [kwargs['intf']])[0] if '/' in kwargs['intf'] else kwargs['intf']
            output1 = show_knet_stats(dut, type='pkt-type', intf=kwargs['intf'])
            output2 = show_knet_stats(dut, type=queue_type, intf=kwargs['intf'])
            output1 = filter_and_select(output1, match={'pkt_type': pkt_type})
            output2 = filter_and_select(output2, match={'queue': queue})
            if not (output1 and output2 and isinstance(output1, list) and isinstance(output2, list) and isinstance(output1[0], dict) and isinstance(output2[0], dict) and int(output1[0]['rx_pkts']) > 0 and int(output2[0]['rx_pkts']) > 0):
                st.log("KNET counters are not observed for pkt_type: {}, RX-Queue: {}, interface: {}".format(pkt_type, queue, kwargs['intf']))
                return False
        output1 = filter_and_select(output1, match={'pkt_type': pkt_type})
        output2 = filter_and_select(output2, match={'queue': queue})
        if not (output1 and output2 and isinstance(output1, list) and isinstance(output2, list) and isinstance(output1[0], dict) and isinstance(output2[0], dict) and int(output1[0]['rx_pkts']) > 0 and int(output2[0]['rx_pkts']) > 0):
            st.log("KNET counters are not observed for pkt_type: {}, RX-Queue: {}".format(pkt_type, queue))
            return False
        if kwargs.get('tx_queue'):
            if not (output1 and isinstance(output1, list) and isinstance(output1[0], dict) and int(output1[0]['tx_pkts']) > 0):
                st.log("KNET counters are not observed for pkt_type: {}, TX-Packets".format(pkt_type))
                return False
        if verify_counters:
            for verify_counter in verify_counters:
                if not (output1 and isinstance(output1, list) and isinstance(output1[0], dict) and int(output1[0][verify_counter]) > 0):
                    st.log("KNET counters for counter '{}' are not observed for pkt_type: {}".format(verify_counter, pkt_type))
                    return False
        return True


def validate_clear_knet_counters(dut, pkt_type, queue, **kwargs):
    """
    This proc is to validate clear KNET counters
    Author: Jagadish Chatrasi<jagadish.chatrasi@broadcom.com>
    :param dut:
    :param type: pkt_type
    :param type: queue
    :return:
    """
    stats_clear_type = kwargs.get('stats_clear_type', 'all')
    queue_type = kwargs.get('queue_type', 'rx-queue')
    pkt_stats_before = show_knet_stats(dut, type='pkt-type')
    queue_stats_before = show_knet_stats(dut, type=queue_type)
    clear_knet_stats(dut, type=stats_clear_type)
    st.wait(1, 'Waiting for KNET statistics to clear')
    pkt_stats_after = show_knet_stats(dut, type='pkt-type')
    queue_stats_after = show_knet_stats(dut, type=queue_type)
    pkt_stats_before = filter_and_select(pkt_stats_before, ['rx_pkts', 'tx_pkts'], match={'pkt_type': pkt_type})
    queue_stats_before = filter_and_select(queue_stats_before, ['rx_pkts'], match={'queue': queue})
    pkt_stats_after = filter_and_select(pkt_stats_after, ['rx_pkts', 'tx_pkts'], match={'pkt_type': pkt_type})
    queue_stats_after = filter_and_select(queue_stats_after, ['rx_pkts'], match={'queue': queue})
    if not (pkt_stats_after or queue_stats_after):
        return True
    elif pkt_stats_after and queue_stats_after and pkt_stats_before and queue_stats_before:
        if ((int(pkt_stats_after[0]['rx_pkts']) < int(pkt_stats_before[0]['rx_pkts'])) or (int(pkt_stats_after[0]['rx_pkts']) == 0)) and ((int(pkt_stats_after[0]['tx_pkts']) < int(pkt_stats_before[0]['tx_pkts'])) or (int(pkt_stats_after[0]['tx_pkts']) == 0)) and ((int(queue_stats_after[0]['rx_pkts']) < int(queue_stats_before[0]['rx_pkts'])) or (int(queue_stats_after[0]['rx_pkts']) == 0)):
            return True
    elif pkt_stats_after and pkt_stats_before:
        if ((int(pkt_stats_after[0]['rx_pkts']) < int(pkt_stats_before[0]['rx_pkts'])) or (int(pkt_stats_after[0]['rx_pkts']) == 0)) and ((int(pkt_stats_after[0]['tx_pkts']) < int(pkt_stats_before[0]['tx_pkts'])) or (int(pkt_stats_after[0]['tx_pkts']) == 0)):
            return True
    elif queue_stats_after and queue_stats_before:
        if ((int(queue_stats_after[0]['rx_pkts']) < int(queue_stats_before[0]['rx_pkts'])) or (int(queue_stats_after[0]['rx_pkts']) == 0)):
            return True
    else:
        st.log("KNET entry for pkt_type: {} / queue: {} is found even the KNET statistics are cleared".format(pkt_type, queue))
        return False


def get_knet_counter(dut, type, counter, match, **kwargs):
    """
    API to get KNET counter on DUT
    Author : Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param type: -a|pkt-type|rx-queue
    :param counter:
    :param match:
    :return:
    """
    output = show_knet_stats(dut, type, **kwargs)
    out = filter_and_select(output, make_list(counter), match=match)
    st.debug("out: {}".format(out))
    if out and isinstance(out, list) and out[0].get(counter):
        return out[0][counter]
    return False


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type
