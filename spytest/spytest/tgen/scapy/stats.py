from dicts import SpyTestDict


def port_stats_init(stats=None):
    stats = stats or SpyTestDict()
    stats.clear()
    stats.framesSent = 0
    stats.bytesSent = 0
    stats.framesReceived = 0
    stats.bytesReceived = 0
    stats.oversizeFramesReceived = 0
    stats.userDefinedStat1 = 0
    stats.userDefinedStat2 = 0
    stats.captureFilter = 0
    return stats


def dhcpc_stats_aggregate_init(port_name):
    res = SpyTestDict()
    res.port_name = port_name
    res.offer_rx_count = 0
    res.success_percentage = 0
    res.release_tx_count = 0
    res.setup_success = 0
    res.ack_rx_count = 0
    res.rx = SpyTestDict()
    res.rx.force_renew = 0
    res.enabled_interfaces = 0
    res.currently_idle = 0
    res.addr_discovered = 0
    res.teardown_initiated = 0
    res.teardown_success = 0
    res.total_failed = 0
    res.request_tx_count = 0
    res.discover_tx_count = 0
    res.currently_attempting = 0
    res.nak_rx_count = 0
    res.sessions_total = 0
    res.sessions_not_started = 0
    res.setup_fail = 0
    res.total_attempted = 0
    res.avgerage_teardown_rate = 0
    res.setup_initiated = 0
    res.currently_bound = 0
    res.teardown_failed = 0
    res.declines_tx_count = 0
    res.average_setup_time = 0
    return res


def dhcpc_stats_session_init(handle):
    res = SpyTestDict()
    res.lease_time = 3600
    res.address = ""
    res.device_group = ""
    res.port_name = handle
    res.protocol = ""
    res.offer_rx_count = 1
    res.information = "none"
    res.release_tx_count = 0
    res["discover/rapid_commit_tx"] = 0
    res.ack_rx_count = 1
    res.rx = SpyTestDict()
    res.rx.force_renew = 0
    res.gateway = ""
    res.ip_addr = "0.0.0.0"
    res.Address = ""
    res.device_id = 0
    res.status = ""
    res.request_tx_count = 1
    res.discover_tx_count = 1
    res.lease_establishment_time = 12
    res["ack/rapid_commit_rx"] = 0
    res.nak_rx_count = 0
    res.topology = ""
    res["lease/rapid_commit"] = ""
    res.Gateway = ""
    res.Prefix = 24
    res.declines_tx_count = 0
    return res


def dhcps_stats_aggregate_init(port_name):
    res = SpyTestDict()
    res.port_name = port_name
    res.rx = SpyTestDict()
    res.rx.solicit = 0
    res.rx.confirm = 0
    res.rx.renew = 0
    res.rx.rebind = 0
    res.rx.request = 0
    res.rx.decline = 0
    res.rx.release = 0
    res.rx.inform = 0
    res.rx.relay_forward = 0
    res.rx.relay_reply = 0
    res.tx = SpyTestDict()
    res.tx.advertisement = 0
    res.tx.reply = 0
    res.total_addresses_allocated = 0
    res.total_addresses_renewed = 0
    res.current_addresses_allocated = 0
    res.total_prefixes_allocated = 0
    res.total_prefixes_renewed = 0
    res.current_prefixes_allocated = 0
    res.reconfigure_tx = 0
    res.sessions_up = 0
    res.sessions_down = 0
    res.sessions_not_started = 0
    res.session_total = 0
    res.nak_sent = 0
    res.solicits_ignored = 0
    return res
