#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function


__metaclass__ = type
"""
The facts class for nxos
this file validates each subset of facts and selectively
calls the appropriate facts gathering function
"""
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.facts.facts import (
    FactsBase,
)

from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.acl_interfaces.acl_interfaces import (
    Acl_interfacesFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.acls.acls import (
    AclsFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.bfd_interfaces.bfd_interfaces import (
    Bfd_interfacesFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.bgp_address_family.bgp_address_family import (
    Bgp_address_familyFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.bgp_global.bgp_global import (
    Bgp_globalFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.bgp_neighbor_address_family.bgp_neighbor_address_family import (
    Bgp_neighbor_address_familyFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.bgp_templates.bgp_templates import (
    Bgp_templatesFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.fc_interfaces.fc_interfaces import (
    Fc_interfacesFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.hostname.hostname import (
    HostnameFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.hsrp_interfaces.hsrp_interfaces import (
    Hsrp_interfacesFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.interfaces.interfaces import (
    InterfacesFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.l2_interfaces.l2_interfaces import (
    L2_interfacesFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.l3_interfaces.l3_interfaces import (
    L3_interfacesFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.lacp.lacp import (
    LacpFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.lacp_interfaces.lacp_interfaces import (
    Lacp_interfacesFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.lag_interfaces.lag_interfaces import (
    Lag_interfacesFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.legacy.base import (
    Config,
    Default,
    Features,
    Hardware,
    Interfaces,
    Legacy,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.lldp_global.lldp_global import (
    Lldp_globalFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.lldp_interfaces.lldp_interfaces import (
    Lldp_interfacesFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.logging_global.logging_global import (
    Logging_globalFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.ntp_global.ntp_global import (
    Ntp_globalFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.ospf_interfaces.ospf_interfaces import (
    Ospf_interfacesFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.ospfv2.ospfv2 import (
    Ospfv2Facts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.ospfv3.ospfv3 import (
    Ospfv3Facts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.prefix_lists.prefix_lists import (
    Prefix_listsFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.route_maps.route_maps import (
    Route_mapsFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.snmp_server.snmp_server import (
    Snmp_serverFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.static_routes.static_routes import (
    Static_routesFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.telemetry.telemetry import (
    TelemetryFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.vlans.vlans import (
    VlansFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.vrf_address_family.vrf_address_family import (
    Vrf_address_familyFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.vrf_global.vrf_global import (
    Vrf_globalFacts,
)
from ansible_collections.cisco.nxos.plugins.module_utils.network.nxos.facts.vrf_interfaces.vrf_interfaces import (
    Vrf_interfacesFacts,
)


FACT_LEGACY_SUBSETS = dict(
    default=Default,
    legacy=Legacy,
    hardware=Hardware,
    interfaces=Interfaces,
    config=Config,
    features=Features,
)
NX_FACT_RESOURCE_SUBSETS = dict(
    bfd_interfaces=Bfd_interfacesFacts,
    hsrp_interfaces=Hsrp_interfacesFacts,
    lag_interfaces=Lag_interfacesFacts,
    lldp_global=Lldp_globalFacts,
    telemetry=TelemetryFacts,
    vlans=VlansFacts,
    lacp=LacpFacts,
    lacp_interfaces=Lacp_interfacesFacts,
    interfaces=InterfacesFacts,
    l3_interfaces=L3_interfacesFacts,
    l2_interfaces=L2_interfacesFacts,
    lldp_interfaces=Lldp_interfacesFacts,
    acl_interfaces=Acl_interfacesFacts,
    acls=AclsFacts,
    static_routes=Static_routesFacts,
    ospfv2=Ospfv2Facts,
    ospfv3=Ospfv3Facts,
    ospf_interfaces=Ospf_interfacesFacts,
    bgp_global=Bgp_globalFacts,
    bgp_address_family=Bgp_address_familyFacts,
    bgp_neighbor_address_family=Bgp_neighbor_address_familyFacts,
    route_maps=Route_mapsFacts,
    prefix_lists=Prefix_listsFacts,
    logging_global=Logging_globalFacts,
    ntp_global=Ntp_globalFacts,
    snmp_server=Snmp_serverFacts,
    hostname=HostnameFacts,
    bgp_templates=Bgp_templatesFacts,
    vrf_global=Vrf_globalFacts,
    vrf_address_family=Vrf_address_familyFacts,
    vrf_interfaces=Vrf_interfacesFacts,
)
MDS_FACT_RESOURCE_SUBSETS = dict(
    fc_interfaces=Fc_interfacesFacts,
    logging_global=Logging_globalFacts,
    ntp_global=Ntp_globalFacts,
    snmp_server=Snmp_serverFacts,
)


class Facts(FactsBase):
    """The fact class for nxos"""

    VALID_LEGACY_GATHER_SUBSETS = frozenset(FACT_LEGACY_SUBSETS.keys())

    def __init__(self, module, chassis_type="nexus"):
        super(Facts, self).__init__(module)
        self.chassis_type = chassis_type

    def get_resource_subsets(self):
        """Return facts resource subsets based on
        target device model.
        """
        facts_resource_subsets = NX_FACT_RESOURCE_SUBSETS
        if self.chassis_type == "mds":
            facts_resource_subsets = MDS_FACT_RESOURCE_SUBSETS
        return facts_resource_subsets

    def get_facts(self, legacy_facts_type=None, resource_facts_type=None, data=None):
        """Collect the facts for nxos
        :param legacy_facts_type: List of legacy facts types
        :param resource_facts_type: List of resource fact types
        :param data: previously collected conf
        :rtype: dict
        :return: the facts gathered
        """
        VALID_RESOURCE_SUBSETS = self.get_resource_subsets()

        if frozenset(VALID_RESOURCE_SUBSETS.keys()):
            self.get_network_resources_facts(VALID_RESOURCE_SUBSETS, resource_facts_type, data)

        if self.VALID_LEGACY_GATHER_SUBSETS:
            self.get_network_legacy_facts(FACT_LEGACY_SUBSETS, legacy_facts_type)

        return self.ansible_facts, self._warnings
