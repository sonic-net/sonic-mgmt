import p4runtime_sh.shell as p4sh
import logging
from p4_utils import init_p4runtime_shell


class TableDef:
    def __init__(self, name: str, id: str):
        self.name = name
        self.id = id

    def print(self):
        logging.debug(f"Reading table {self.id}")
        entries = p4sh.TableEntry(self.id).read()

        logging.debug(f"Dumping table entries {self.id}")
        print(f"======= Table: {self.name} =======")
        for entry in entries:
            print(entry)

        print("")


pipeline_table_defs = [
    TableDef("VIP check", "dash_ingress.vip"),
    TableDef("Appliance", "dash_ingress.appliance"),
    TableDef("Direction Lookup", "dash_ingress.direction_lookup_stage.direction_lookup"),
    TableDef("MAC to ENI ID", "dash_ingress.eni_lookup_stage.eni_ether_address_map"),
    TableDef("ENI lookup", "dash_ingress.eni"),
    TableDef("Routing Group", "dash_ingress.outbound.outbound_routing_stage.outbound_routing_group"),
    TableDef("Route Lookup", "dash_ingress.outbound.outbound_routing_stage.routing"),
    TableDef("VNET Mapping Lookup", "dash_ingress.outbound.outbound_mapping_stage.ca_to_pa"),
    TableDef("Destination VNET Lookup", "dash_ingress.outbound.outbound_mapping_stage.vnet"),
    TableDef("Tunnel Lookup", "dash_ingress.tunnel_stage.tunnel"),
    TableDef("Meter Bucket Lookup", "dash_ingress.metering_update_stage.meter_bucket"),
    TableDef("Meter Policy Lookup", "dash_ingress.metering_update_stage.meter_policy"),
    TableDef("Meter Rule Lookup", "dash_ingress.metering_update_stage.meter_rule"),
    TableDef("Underlay Routing", "dash_ingress.underlay.underlay_routing"),
    # TableDef("ACL", "dash_ingress.acl_group"),
    # TableDef("", "dash_ingress.outbound.acl.stage1"),
    # TableDef("", "dash_ingress.outbound.acl.stage2"),
    # TableDef("", "dash_ingress.outbound.acl.stage3"),
    # TableDef("", "dash_ingress.pa_validation"),
    # TableDef("Flow Table", "dash_ingress.conntrack_lookup_stage.flow_table"),
    # TableDef("Flow", "dash_ingress.conntrack_lookup_stage.flow_entry"),
    # TableDef("", "dash_ingress.conntrack_lookup_stage.flow_entry_bulk_get_session"),
    # TableDef("", "dash_ingress.conntrack_lookup_stage.flow_entry_bulk_get_session_filter"),
    # TableDef("", "dash_ingress.ha_stage.ha_scope"),
    # TableDef("", "dash_ingress.ha_stage.ha_set"),
    # TableDef("", "dash_ingress.inbound.acl.stage1"),
    # TableDef("", "dash_ingress.inbound.acl.stage2"),
    # TableDef("", "dash_ingress.inbound.acl.stage3"),
    # TableDef("", "dash_ingress.inbound_routing"),
]


def dump_tables():
    for table_def in pipeline_table_defs:
        table_def.print()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    # p4sh.global_options["verbose"] = False

    init_p4runtime_shell()
    dump_tables()
