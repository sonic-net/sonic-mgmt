
feature_groups = ["broadcom", "master", "upstream", "201911"]

feature_names = [
    "port-group",
    "bcmcmd",
    "system-status",
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
    "bgp-neighbotship-performance",
    "prevent-delete-vlans-with-members",
    "routing-mode-seperated-by-default",
    "config-acl-table-delete-command",
    "config-acl-rule-delete-command",
    "crm-config-clear-command",
    "config-profiles-get-factory-command",
    "certgen-command",
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
    "config_mirror_session_add_type",
    "config_static_portchannel",
    "config_max_route_scale",
    "sai-removes-vlan-1",
    "nat-default-enabled",
    "sflow-default-enabled",
]

class Feature(object):
    def __init__(self, feature_group):
        if feature_group not in feature_groups:
            raise ValueError("unknown build type {}".format(feature_group))
        self.supported = dict()
        if feature_group == "master":
            self.init_master()
        elif feature_group == "201911":
            self.init_201911()
        elif feature_group == "upstream":
            self.init_upstream()
        else:
            self.init_broadcom()

    def set_supported_value(self, value, *args):
        for name in args:
            if isinstance(name, list):
                for n in name:
                    self.supported[n] = value
            else:
                self.supported[name] = value

    def set_supported(self, *args):
        self.set_supported_value(True, *args)

    def set_unsupported(self, *args):
        self.set_supported_value(False, *args)

    def init_master(self):
        self.set_unsupported(feature_names)
        self.set_supported("show-interfaces-counters-interface-command")
        self.set_supported("intf-range", "interface-mtu")
        self.set_supported("show-kdump-status-command")
        self.set_supported("span-mirror-session")

    def init_201911(self):
        self.set_unsupported(feature_names)

    def init_upstream(self):
        self.init_master()
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

    def init_broadcom(self):
        self.set_supported(feature_names)

    def is_supported(self, name):
        if name not in self.supported:
            raise ValueError("unknown feature name {}".format(name))
        return self.supported[name]

    def get_all(self):
        return sorted(self.supported.items())

if __name__ == "__main__":
    for feature_group in feature_groups:
        f = Feature(feature_group)
        for fname in feature_names:
            print(feature_group, fname, f.is_supported(fname))
        print(feature_group, f.get_all())

