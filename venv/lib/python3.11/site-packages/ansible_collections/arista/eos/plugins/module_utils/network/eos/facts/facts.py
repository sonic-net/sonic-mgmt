# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The facts class for eos
this file validates each subset of facts and selectively
calls the appropriate facts gathering function
"""

from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.facts.facts import (
    FactsBase,
)

from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.acl_interfaces.acl_interfaces import (
    Acl_interfacesFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.acls.acls import (
    AclsFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.bgp_address_family.bgp_address_family import (
    Bgp_afFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.bgp_global.bgp_global import (
    Bgp_globalFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.hostname.hostname import (
    HostnameFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.interfaces.interfaces import (
    InterfacesFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.l2_interfaces.l2_interfaces import (
    L2_interfacesFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.l3_interfaces.l3_interfaces import (
    L3_interfacesFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.lacp.lacp import (
    LacpFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.lacp_interfaces.lacp_interfaces import (
    Lacp_interfacesFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.lag_interfaces.lag_interfaces import (
    Lag_interfacesFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.legacy.base import (
    Config,
    Default,
    Hardware,
    Interfaces,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.lldp_global.lldp_global import (
    Lldp_globalFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.lldp_interfaces.lldp_interfaces import (
    Lldp_interfacesFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.logging_global.logging_global import (
    Logging_globalFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.ntp_global.ntp_global import (
    Ntp_globalFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.ospf_interfaces.ospf_interfaces import (
    Ospf_interfacesFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.ospfv2.ospfv2 import (
    Ospfv2Facts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.ospfv3.ospfv3 import (
    Ospfv3Facts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.prefix_lists.prefix_lists import (
    Prefix_listsFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.route_maps.route_maps import (
    Route_mapsFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.snmp_server.snmp_server import (
    Snmp_serverFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.static_routes.static_routes import (
    Static_routesFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.vlans.vlans import (
    VlansFacts,
)
from ansible_collections.arista.eos.plugins.module_utils.network.eos.facts.vrf_global.vrf_global import (
    Vrf_globalFacts,
)


FACT_LEGACY_SUBSETS = dict(
    default=Default,
    hardware=Hardware,
    interfaces=Interfaces,
    config=Config,
)
FACT_RESOURCE_SUBSETS = dict(
    interfaces=InterfacesFacts,
    l2_interfaces=L2_interfacesFacts,
    l3_interfaces=L3_interfacesFacts,
    lacp=LacpFacts,
    lacp_interfaces=Lacp_interfacesFacts,
    lag_interfaces=Lag_interfacesFacts,
    lldp_global=Lldp_globalFacts,
    lldp_interfaces=Lldp_interfacesFacts,
    vlans=VlansFacts,
    acl_interfaces=Acl_interfacesFacts,
    acls=AclsFacts,
    static_routes=Static_routesFacts,
    ospfv2=Ospfv2Facts,
    ospfv3=Ospfv3Facts,
    ospf_interfaces=Ospf_interfacesFacts,
    bgp_address_family=Bgp_afFacts,
    bgp_global=Bgp_globalFacts,
    route_maps=Route_mapsFacts,
    prefix_lists=Prefix_listsFacts,
    logging_global=Logging_globalFacts,
    ntp_global=Ntp_globalFacts,
    snmp_server=Snmp_serverFacts,
    hostname=HostnameFacts,
    vrf_global=Vrf_globalFacts,
)


class Facts(FactsBase):
    """The fact class for eos"""

    VALID_LEGACY_GATHER_SUBSETS = frozenset(FACT_LEGACY_SUBSETS.keys())
    VALID_RESOURCE_SUBSETS = frozenset(FACT_RESOURCE_SUBSETS.keys())

    def get_facts(
        self,
        legacy_facts_type=None,
        resource_facts_type=None,
        data=None,
    ):
        """Collect the facts for eos
        :param legacy_facts_type: List of legacy facts types
        :param resource_facts_type: List of resource fact types
        :param data: previously collected conf
        :rtype: dict
        :return: the facts gathered
        """
        if self.VALID_RESOURCE_SUBSETS:
            self.get_network_resources_facts(
                FACT_RESOURCE_SUBSETS,
                resource_facts_type,
                data,
            )

        if self.VALID_LEGACY_GATHER_SUBSETS:
            self.get_network_legacy_facts(
                FACT_LEGACY_SUBSETS,
                legacy_facts_type,
            )
        return self.ansible_facts, self._warnings
