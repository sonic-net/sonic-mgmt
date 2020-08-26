from spytest import st
mask_tbd = 10
def get_args(identifier, value, attribs, pps, tg_type):
    tmp = {}
    if identifier == "SRC_IP":
       parts = value.split('/')
       tmp['ip_src_addr'] = parts[0]
       tmp['l3_protocol'] = "ipv4"
       if len(parts) > 1 :
         if parts[1] != "32":
           tmp['ip_src_mode'] = "increment"
           tmp['ip_src_step'] = "0.0.0.1"
           tmp['ip_src_count'] = pps
    if identifier == "DST_IP":
       parts = value.split('/')
       tmp['ip_dst_addr'] = parts[0]
       tmp['l3_protocol'] = "ipv4"
       if len(parts) > 1 :
         if parts[1] != "32":
           tmp['ip_dst_mode'] = "increment"
           tmp['ip_dst_step'] = "0.0.0.1"
           tmp['ip_dst_count'] = pps
    if identifier == "SRC_IPV6":
       parts = value.split('/')
       tmp['ipv6_src_addr'] = parts[0]
       tmp['l3_protocol'] = "ipv6"
       if len(parts) > mask_tbd:
          if parts[1] != "128":
             tmp['ipv6_src_mode'] = "increment"
             tmp['ipv6_src_step'] = "TBD"
             tmp['ipv6_src_count'] = pps
    if identifier == "DST_IPV6":
       parts = value.split('/')
       tmp['ipv6_dst_addr'] = parts[0]
       tmp['l3_protocol'] = "ipv6"
       if len(parts) > mask_tbd:
          if parts[1] != "128":
             tmp['ipv6_dst_mode'] = "increment"
             tmp['ipv6_dst_step'] = "TBD"
             tmp['ipv6_dst_count'] = pps
    if identifier == "L4_SRC_PORT":
       if attribs['IP_PROTOCOL'] == 6:
          tmp['tcp_src_port'] = value
       elif attribs['IP_PROTOCOL'] == 17:
          tmp['udp_src_port'] = value
    if identifier == "L4_DST_PORT":
       if attribs['IP_PROTOCOL'] == 6:
          tmp['tcp_dst_port'] = value
       elif attribs['IP_PROTOCOL'] == 17:
          tmp['udp_dst_port'] = value
    if identifier == "L4_SRC_PORT_RANGE":
       parts = value.split('-')
       if attribs['IP_PROTOCOL'] == 6:
          tmp['tcp_src_port'] = int(parts[0])
          tmp['tcp_src_port_mode'] = (tg_type == 'stc' and 'increment' or 'incr') #STC
          tmp['tcp_src_port_count'] = 10
          tmp['tcp_src_port_step'] = 1
       elif attribs['IP_PROTOCOL'] == 17:
          tmp['udp_src_port'] = int(parts[0])
          tmp['udp_src_port_mode'] = (tg_type == 'stc' and 'increment' or 'incr') #STC
          tmp['udp_src_port_count'] = 10
          tmp['udp_src_port_step'] = 1
    if identifier == "L4_DST_PORT_RANGE":
       parts = value.split('-')
       if attribs['IP_PROTOCOL'] == 6:
          tmp['tcp_dst_port'] = int(parts[0])
          tmp['tcp_dst_port_mode'] = (tg_type == 'stc' and 'increment' or 'incr') #STC
          tmp['tcp_dst_port_count'] = 10
          tmp['tcp_dst_port_step'] = 1
       elif attribs['IP_PROTOCOL'] == 17:
          tmp['udp_dst_port'] = int(parts[0])
          tmp['udp_dst_port_mode'] = (tg_type == 'stc' and 'increment' or 'incr') #STC
          tmp['udp_dst_port_count'] = 10
          tmp['udp_dst_port_step'] = 1
    if identifier == "IP_PROTOCOL":
       #tmp['ip_protocol'] = value
       if attribs['IP_PROTOCOL'] == 6:
          tmp['l4_protocol'] = "tcp"
       elif attribs['IP_PROTOCOL'] == 17:
          tmp['l4_protocol'] = "udp"
    if identifier == "TCP_FLAGS":
       if value == "4/4":
          tmp['l4_protocol'] = "tcp"
          tmp['tcp_rst_flag'] = 1
    return tmp

def get_args_l3(identifier, value, attribs, pps, tg_type):
    tmp = {}
    if identifier == "SRC_IP":
       parts = value.split('/')
       tmp['ip_src_addr'] = parts[0]
       tmp['l3_protocol'] = "ipv4"
       if len(parts) > 1 :
         if parts[1] != "32":
           tmp['ip_src_mode'] = "fixed"
    if identifier == "DST_IP":
       parts = value.split('/')
       tmp['ip_dst_addr'] = parts[0]
       tmp['l3_protocol'] = "ipv4"
       if len(parts) > 1 :
         if parts[1] != "32":
           tmp['ip_dst_mode'] = "fixed"
    if identifier == "SRC_IPV6":
       parts = value.split('/')
       tmp['ipv6_src_addr'] = parts[0]
       tmp['l3_protocol'] = "ipv6"
       if len(parts) > mask_tbd:
          if parts[1] != "128":
             tmp['ipv6_src_mode'] = "fixed"
    if identifier == "DST_IPV6":
       parts = value.split('/')
       tmp['ipv6_dst_addr'] = parts[0]
       tmp['l3_protocol'] = "ipv6"
       if len(parts) > mask_tbd:
          if parts[1] != "128":
             tmp['ipv6_dst_mode'] = "fixed"
    if identifier == "L4_SRC_PORT":
       if attribs['IP_PROTOCOL'] == 6:
          tmp['tcp_src_port'] = value
       elif attribs['IP_PROTOCOL'] == 17:
          tmp['udp_src_port'] = value
    if identifier == "L4_DST_PORT":
       if attribs['IP_PROTOCOL'] == 6:
          tmp['tcp_dst_port'] = value
       elif attribs['IP_PROTOCOL'] == 17:
          tmp['udp_dst_port'] = value
    if identifier == "L4_SRC_PORT_RANGE":
       parts = value.split('-')
       if attribs['IP_PROTOCOL'] == 6:
          tmp['tcp_src_port'] = int(parts[0])
          tmp['tcp_src_port_mode'] = (tg_type == 'stc' and 'increment' or 'incr') #STC
          tmp['tcp_src_port_count'] = 10
          tmp['tcp_src_port_step'] = 1
       elif attribs['IP_PROTOCOL'] == 17:
          tmp['udp_src_port'] = int(parts[0])
          tmp['udp_src_port_mode'] = (tg_type == 'stc' and 'increment' or 'incr') #STC
          tmp['udp_src_port_count'] = 10
          tmp['udp_src_port_step'] = 1
    if identifier == "L4_DST_PORT_RANGE":
       parts = value.split('-')
       if attribs['IP_PROTOCOL'] == 6:
          tmp['tcp_dst_port'] = int(parts[0])
          tmp['tcp_dst_port_mode'] = (tg_type == 'stc' and 'increment' or 'incr') #STC
          tmp['tcp_dst_port_count'] = 10
          tmp['tcp_dst_port_step'] = 1
       elif attribs['IP_PROTOCOL'] == 17:
          tmp['udp_dst_port'] = int(parts[0])
          tmp['udp_dst_port_mode'] = (tg_type == 'stc' and 'increment' or 'incr') #STC
          tmp['udp_dst_port_count'] = 10
          tmp['udp_dst_port_step'] = 1
    if identifier == "IP_PROTOCOL":
       #tmp['ip_protocol'] = value
       if attribs['IP_PROTOCOL'] == 6:
          tmp['l4_protocol'] = "tcp"
       elif attribs['IP_PROTOCOL'] == 17:
          tmp['l4_protocol'] = "udp"
    if identifier == "TCP_FLAGS":
       if value == "4/4":
          tmp['l4_protocol'] = "tcp"
          tmp['tcp_rst_flag'] = 1
    return tmp

def report_result(status):
    if status:
       st.report_pass('test_case_passed')
    else:
       st.report_fail('test_case_failed')
