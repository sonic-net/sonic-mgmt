
feature_groups = ["broadcom", "upstream", "201911", "202012", "202111", "master"]

feature_names = [
    "confirm-reboot",
    "port-group",
    "bcmcmd",
    "system-status",
    "system-status-core",
    "intf-range",
    "vlan-range",
    "warm-reboot",
    "arp-clear-nowait",
    "strom-control",
    "dpb",
    "intf-alias",
    "klish",
    "radius",
    "ztp",
    "span-mirror-session",
    "crm-all-families",
    "interface-mtu",
    "threshold",
    "rest",
    "gnmi",
    "bgp-neighbotship-performance",
    "prevent-delete-vlans-with-members",
    "routing-mode-separated-by-default",
    "config-acl-table-delete-command",
    "config-acl-rule-delete-command",
    "crm-config-clear-command",
    "config-profiles-get-factory-command",
    "certgen-command",
    "host-account-manager",
    "show-lldp-statistics-command",
    "show-interfaces-counters-clear-command",
    "show-interfaces-counters-interface-command",
    "show-interfaces-counters-detailed-command",
    "sonic-clear-logging-command",
    "show-mac-count-command",
    "sonic-clear-fdb-type-command",
    "config-mac-add-command",
    "config-mac-aging_time-command",
    "show-mac-aging_time-command",
    "config-ipv6-command",
    "config-loopback-add-command",
    "show-bgp-summary-click-command",
    "show-vrf-verbose-command",
    "vrf-needed-for-unbind",
    "show-kdump-status-command",
    "show-mac-aging-time-command",
    "config_mirror_session_add_erspan",
    "config_mirror_session_add_span",
    "config_mirror_session_add_type",
    "config_static_portchannel",
    "config_max_route_scale",
    "sai-removes-vlan-1",
    "nat-default-enabled",
    "sflow-default-enabled",
    "ip_vrf_exec_mgmt_ntpstat",
    "remove_qos_profile",
    "swss-copp-config",
    "scapy-lldp-default-enable",
    "tech-support-port-status-fail",
    "tech-support-function",
    "tech-support-testcase",
    "show-tech-support-since",
    "flex-dpb",
    "base-config-roce",
    "ifname-type",
    "std-ext"
]

default_supported = [
    "show-interfaces-counters-interface-command",
    "intf-range", "interface-mtu",
    "show-kdump-status-command",
    "span-mirror-session"
]

default_unsupported = [
    "remove-default-bgp",
    "sudo-show-interfaces-status",
    "config-session",
    "config-replace"
]


class Feature(object):
    def __init__(self, fgroup=None, fsupp=None, funsupp=None):
        fgroup = fgroup or feature_groups[0]
        if fgroup not in feature_groups:
            raise ValueError("unknown feature group {}".format(fgroup))
        self.supported = dict()
        self.init_default()
        if fgroup == "master":
            self.init_master()
        elif fgroup == "201911":
            self.init_201911()
        elif fgroup == "202012":
            self.init_202012()
        elif fgroup == "202111":
            self.init_202111()
        elif fgroup == "upstream":
            self.init_upstream()
        else:
            self.init_broadcom()
        self.init_common()
        self.set_supported(fsupp)
        self.set_unsupported(funsupp)

    def set_supported_value(self, value, *args):
        for name in args:
            if name is None:
                continue
            if isinstance(name, list):
                for n in name:
                    self.supported[n] = value
            else:
                self.supported[name] = value

    def set_supported(self, *args):
        self.set_supported_value(True, *args)

    def set_unsupported(self, *args):
        self.set_supported_value(False, *args)

    def init_broadcom(self):
        self.set_supported(feature_names)

    def init_default(self):
        self.set_supported(default_supported)
        self.set_unsupported(default_unsupported)

    def init_common(self):
        self.set_unsupported("tech-support-function")
        self.set_unsupported("tech-support-testcase")
        self.set_supported("tech-support-port-status-fail")
        self.set_unsupported("confirm-reboot")
        self.set_unsupported("base-config-roce")

    def init_201911(self):
        self.set_unsupported(feature_names)

    def init_202012(self):
        self.init_201911()
        self.set_supported("bcmcmd")
        self.set_supported("crm-all-families")
        self.set_supported("show-mac-count-command")
        self.set_supported("show-interfaces-counters-detailed-command")

    def init_202111(self):
        self.init_202012()
        self.set_supported("prevent-delete-vlans-with-members")
        self.set_supported("remove-default-bgp")
        self.set_supported("sudo-show-interfaces-status")
        self.set_supported("scapy-lldp-default-enable")

    def init_master(self):
        self.init_202111()

    def init_upstream(self):
        self.init_202012()
        self.set_supported("bcmcmd", "system-status", "dpb")
        self.set_supported("config-mac-aging_time-command")
        self.set_supported("show-mac-aging-time-command")
        self.set_supported("config-mac-add-command")
        self.set_supported("vlan-range")
        self.set_supported("crm-all-families")
        self.set_supported("crm-config-clear-command")
        self.set_supported("config-ipv6-command")
        self.set_supported("show-mac-count-command")
        self.set_supported("show-interfaces-counters-detailed-command")
        self.set_supported("swss-copp-config")

    def is_supported(self, name, dut=None):
        if name not in self.supported:
            raise ValueError("unknown feature name {}".format(name))
        return self.supported[name]

    def get_all(self):
        return sorted(self.supported.items())
