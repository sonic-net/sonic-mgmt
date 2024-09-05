import re
from spytest import st

def verify_interface_ping(src_obj, dev_handle, dst_ip, ping_count=5, exp_count=5):
    ping_count, exp_count = int(ping_count), int(exp_count)
    if src_obj.tg_type == 'stc':
        result = src_obj.tg_emulation_ping(handle=dev_handle, host=dst_ip, count=ping_count)
        st.log("ping output: {}".format(result))
        return True if int(result['tx']) == ping_count and int(result['rx']) == exp_count else False
    elif src_obj.tg_type in ['ixia', 'scapy']:
        count = 0
        for _ in range(ping_count):
            result = src_obj.tg_interface_config(protocol_handle=dev_handle, send_ping='1', ping_dst=dst_ip)
            st.log("ping output: {}".format(result))
            if "ping_details" not in result.values()[1]:
                st.warn("ping_details details not found in o/p")
            elif 'No sessions were started' in result.values()[1]:
                src_obj.get_session_errors()
                st.report_tgen_fail('tgen_failed_api', result.values()[1]['ping_details'])
            else:
                try:
                    result = result.values()[1]['ping_details']
                    if src_obj.tg_type == 'scapy':
                        ping_out = re.search(r'([0-9]+)\s+packets transmitted,\s+([0-9]+)\s+received', result)
                    else:
                        ping_out = re.search(r'([0-9]+)\s+requests sent,\s+([0-9]+)\s+replies received', result)
                    tx_pkt, rx_pkt = ping_out.group(1), ping_out.group(2)
                    if int(tx_pkt) == int(rx_pkt):
                        count += 1
                except AttributeError:
                    st.warn("ping command o/p not matching regular expression")
        return True if count == exp_count else False
    else:
        st.error("Need to add code for this tg type: {}".format(src_obj.tg_type))
        return False
