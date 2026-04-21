#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
from ansible.plugins.action import ActionBase

try:
    from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
        AnsibleArgSpecValidator,
    )
except ImportError:
    ANSIBLE_UTILS_IS_INSTALLED = False
else:
    ANSIBLE_UTILS_IS_INSTALLED = True
from ansible.errors import AnsibleActionFail
from ansible_collections.cisco.meraki.plugins.plugin_utils.meraki import (
    MERAKI,
    meraki_argument_spec,
    meraki_compare_equality2,
    get_dict_result,
)
from ansible_collections.cisco.meraki.plugins.plugin_utils.exceptions import (
    InconsistentParameters,
)

# Get common arguments specification
argument_spec = meraki_argument_spec()
# Add arguments specific for this module
argument_spec.update(
    dict(
        state=dict(type="str", default="present", choices=["present"]),
        activeDirectory=dict(type="dict"),
        adultContentFilteringEnabled=dict(type="bool"),
        apTagsAndVlanIds=dict(type="list"),
        authMode=dict(type="str"),
        availabilityTags=dict(type="list"),
        availableOnAllAps=dict(type="bool"),
        bandSelection=dict(type="str"),
        concentratorNetworkId=dict(type="str"),
        defaultVlanId=dict(type="int"),
        disassociateClientsOnVpnFailover=dict(type="bool"),
        dnsRewrite=dict(type="dict"),
        dot11r=dict(type="dict"),
        dot11w=dict(type="dict"),
        enabled=dict(type="bool"),
        encryptionMode=dict(type="str"),
        enterpriseAdminAccess=dict(type="str"),
        gre=dict(type="dict"),
        ipAssignmentMode=dict(type="str"),
        lanIsolationEnabled=dict(type="bool"),
        ldap=dict(type="dict"),
        localRadius=dict(type="dict"),
        mandatoryDhcpEnabled=dict(type="bool"),
        minBitrate=dict(type="float"),
        name=dict(type="str"),
        namedVlans=dict(type="dict"),
        oauth=dict(type="dict"),
        perClientBandwidthLimitDown=dict(type="int"),
        perClientBandwidthLimitUp=dict(type="int"),
        perSsidBandwidthLimitDown=dict(type="int"),
        perSsidBandwidthLimitUp=dict(type="int"),
        psk=dict(type="str"),
        radiusAccountingEnabled=dict(type="bool"),
        radiusAccountingInterimInterval=dict(type="int"),
        radiusAccountingServers=dict(type="list"),
        radiusAttributeForGroupPolicies=dict(type="str"),
        radiusAuthenticationNasId=dict(type="str"),
        radiusCalledStationId=dict(type="str"),
        radiusCoaEnabled=dict(type="bool"),
        radiusFailoverPolicy=dict(type="str"),
        radiusFallbackEnabled=dict(type="bool"),
        radiusGuestVlanEnabled=dict(type="bool"),
        radiusGuestVlanId=dict(type="int"),
        radiusLoadBalancingPolicy=dict(type="str"),
        radiusOverride=dict(type="bool"),
        radiusProxyEnabled=dict(type="bool"),
        radiusServerAttemptsLimit=dict(type="int", choices=[1, 2, 3, 4, 5]),
        radiusServerTimeout=dict(type="int", choices=list(range(1, 11))),
        radiusServers=dict(type="list"),
        radiusTestingEnabled=dict(type="bool"),
        secondaryConcentratorNetworkId=dict(type="str"),
        speedBurst=dict(type="dict"),
        splashGuestSponsorDomains=dict(type="list"),
        splashPage=dict(type="str"),
        useVlanTagging=dict(type="bool"),
        visible=dict(type="bool"),
        vlanId=dict(type="int"),
        walledGardenEnabled=dict(type="bool"),
        walledGardenRanges=dict(type="list"),
        wpaEncryptionMode=dict(type="str"),
        networkId=dict(type="str"),
        number=dict(type="str"),
    )
)

required_if = [
    ("state", "present", ["name", "networkId", "number"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class NetworksWirelessSsids(object):
    def __init__(self, params, meraki):
        self.meraki = meraki
        self.new_object = dict(
            activeDirectory=params.get("activeDirectory"),
            adultContentFilteringEnabled=params.get("adultContentFilteringEnabled"),
            apTagsAndVlanIds=params.get("apTagsAndVlanIds"),
            authMode=params.get("authMode"),
            availabilityTags=params.get("availabilityTags"),
            availableOnAllAps=params.get("availableOnAllAps"),
            bandSelection=params.get("bandSelection"),
            concentratorNetworkId=params.get("concentratorNetworkId"),
            defaultVlanId=params.get("defaultVlanId"),
            disassociateClientsOnVpnFailover=params.get(
                "disassociateClientsOnVpnFailover"
            ),
            dnsRewrite=params.get("dnsRewrite"),
            dot11r=params.get("dot11r"),
            dot11w=params.get("dot11w"),
            enabled=params.get("enabled"),
            encryptionMode=params.get("encryptionMode"),
            enterpriseAdminAccess=params.get("enterpriseAdminAccess"),
            gre=params.get("gre"),
            ipAssignmentMode=params.get("ipAssignmentMode"),
            lanIsolationEnabled=params.get("lanIsolationEnabled"),
            ldap=params.get("ldap"),
            localRadius=params.get("localRadius"),
            mandatoryDhcpEnabled=params.get("mandatoryDhcpEnabled"),
            minBitrate=params.get("minBitrate"),
            name=params.get("name"),
            namedVlans=params.get("namedVlans"),
            oauth=params.get("oauth"),
            perClientBandwidthLimitDown=params.get("perClientBandwidthLimitDown"),
            perClientBandwidthLimitUp=params.get("perClientBandwidthLimitUp"),
            perSsidBandwidthLimitDown=params.get("perSsidBandwidthLimitDown"),
            perSsidBandwidthLimitUp=params.get("perSsidBandwidthLimitUp"),
            psk=params.get("psk"),
            radiusAccountingEnabled=params.get("radiusAccountingEnabled"),
            radiusAccountingInterimInterval=params.get(
                "radiusAccountingInterimInterval"
            ),
            radiusAccountingServers=params.get("radiusAccountingServers"),
            radiusAttributeForGroupPolicies=params.get(
                "radiusAttributeForGroupPolicies"
            ),
            radiusAuthenticationNasId=params.get("radiusAuthenticationNasId"),
            radiusCalledStationId=params.get("radiusCalledStationId"),
            radiusCoaEnabled=params.get("radiusCoaEnabled"),
            radiusFailoverPolicy=params.get("radiusFailoverPolicy"),
            radiusFallbackEnabled=params.get("radiusFallbackEnabled"),
            radiusGuestVlanEnabled=params.get("radiusGuestVlanEnabled"),
            radiusGuestVlanId=params.get("radiusGuestVlanId"),
            radiusLoadBalancingPolicy=params.get("radiusLoadBalancingPolicy"),
            radiusOverride=params.get("radiusOverride"),
            radiusProxyEnabled=params.get("radiusProxyEnabled"),
            radiusRadsec=params.get("radiusRadsec"),
            radiusServerAttemptsLimit=params.get("radiusServerAttemptsLimit"),
            radiusServerTimeout=params.get("radiusServerTimeout"),
            radiusServers=params.get("radiusServers"),
            radiusTestingEnabled=params.get("radiusTestingEnabled"),
            secondaryConcentratorNetworkId=params.get("secondaryConcentratorNetworkId"),
            speedBurst=params.get("speedBurst"),
            splashGuestSponsorDomains=params.get("splashGuestSponsorDomains"),
            splashPage=params.get("splashPage"),
            useVlanTagging=params.get("useVlanTagging"),
            visible=params.get("visible"),
            vlanId=params.get("vlanId"),
            walledGardenEnabled=params.get("walledGardenEnabled"),
            walledGardenRanges=params.get("walledGardenRanges"),
            wpaEncryptionMode=params.get("wpaEncryptionMode"),
            network_id=params.get("networkId"),
            number=params.get("number"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        if (
            self.new_object.get("networkId") is not None
            or self.new_object.get("network_id") is not None
        ):
            new_object_params["networkId"] = self.new_object.get(
                "networkId"
            ) or self.new_object.get("network_id")
        return new_object_params

    def get_params_by_id(self, name=None, id=None):
        new_object_params = {}
        if (
            self.new_object.get("networkId") is not None
            or self.new_object.get("network_id") is not None
        ):
            new_object_params["networkId"] = self.new_object.get(
                "networkId"
            ) or self.new_object.get("network_id")
        if (
            self.new_object.get("number") is not None
            or self.new_object.get("number") is not None
        ):
            new_object_params["number"] = self.new_object.get("number")
        return new_object_params

    def update_by_id_params(self):
        new_object_params = {}
        if (
            self.new_object.get("activeDirectory") is not None
            or self.new_object.get("active_directory") is not None
        ):
            new_object_params["activeDirectory"] = self.new_object.get(
                "activeDirectory"
            ) or self.new_object.get("active_directory")
        if (
            self.new_object.get("adultContentFilteringEnabled") is not None
            or self.new_object.get("adult_content_filtering_enabled") is not None
        ):
            new_object_params["adultContentFilteringEnabled"] = self.new_object.get(
                "adultContentFilteringEnabled"
            )
        if (
            self.new_object.get("apTagsAndVlanIds") is not None
            or self.new_object.get("ap_tags_and_vlan_ids") is not None
        ):
            new_object_params["apTagsAndVlanIds"] = self.new_object.get(
                "apTagsAndVlanIds"
            ) or self.new_object.get("ap_tags_and_vlan_ids")
        if (
            self.new_object.get("authMode") is not None
            or self.new_object.get("auth_mode") is not None
        ):
            new_object_params["authMode"] = self.new_object.get(
                "authMode"
            ) or self.new_object.get("auth_mode")
        if (
            self.new_object.get("availabilityTags") is not None
            or self.new_object.get("availability_tags") is not None
        ):
            new_object_params["availabilityTags"] = self.new_object.get(
                "availabilityTags"
            ) or self.new_object.get("availability_tags")
        if (
            self.new_object.get("availableOnAllAps") is not None
            or self.new_object.get("available_on_all_aps") is not None
        ):
            new_object_params["availableOnAllAps"] = self.new_object.get(
                "availableOnAllAps"
            )
        if (
            self.new_object.get("bandSelection") is not None
            or self.new_object.get("band_selection") is not None
        ):
            new_object_params["bandSelection"] = self.new_object.get(
                "bandSelection"
            ) or self.new_object.get("band_selection")
        if (
            self.new_object.get("concentratorNetworkId") is not None
            or self.new_object.get("concentrator_network_id") is not None
        ):
            new_object_params["concentratorNetworkId"] = self.new_object.get(
                "concentratorNetworkId"
            ) or self.new_object.get("concentrator_network_id")
        if (
            "defaultVlanId" in self.new_object
            or "default_vlan_id" in self.new_object
        ):
            default_vlan_id = (
                self.new_object.get("defaultVlanId")
                if "defaultVlanId" in self.new_object
                else self.new_object.get("default_vlan_id")
            )
            if default_vlan_id is not None:
                new_object_params["defaultVlanId"] = default_vlan_id
        if (
            self.new_object.get("disassociateClientsOnVpnFailover") is not None
            or self.new_object.get("disassociate_clients_on_vpn_failover") is not None
        ):
            new_object_params["disassociateClientsOnVpnFailover"] = self.new_object.get(
                "disassociateClientsOnVpnFailover"
            )
        if (
            self.new_object.get("dnsRewrite") is not None
            or self.new_object.get("dns_rewrite") is not None
        ):
            new_object_params["dnsRewrite"] = self.new_object.get(
                "dnsRewrite"
            ) or self.new_object.get("dns_rewrite")
        if (
            self.new_object.get("dot11r") is not None
            or self.new_object.get("dot11r") is not None
        ):
            new_object_params["dot11r"] = self.new_object.get(
                "dot11r"
            ) or self.new_object.get("dot11r")
        if (
            self.new_object.get("dot11w") is not None
            or self.new_object.get("dot11w") is not None
        ):
            new_object_params["dot11w"] = self.new_object.get(
                "dot11w"
            ) or self.new_object.get("dot11w")
        if (
            self.new_object.get("enabled") is not None
            or self.new_object.get("enabled") is not None
        ):
            new_object_params["enabled"] = self.new_object.get("enabled")
        if (
            self.new_object.get("encryptionMode") is not None
            or self.new_object.get("encryption_mode") is not None
        ):
            new_object_params["encryptionMode"] = self.new_object.get(
                "encryptionMode"
            ) or self.new_object.get("encryption_mode")
        if (
            self.new_object.get("enterpriseAdminAccess") is not None
            or self.new_object.get("enterprise_admin_access") is not None
        ):
            new_object_params["enterpriseAdminAccess"] = self.new_object.get(
                "enterpriseAdminAccess"
            ) or self.new_object.get("enterprise_admin_access")
        if (
            self.new_object.get("gre") is not None
            or self.new_object.get("gre") is not None
        ):
            new_object_params["gre"] = self.new_object.get(
                "gre"
            ) or self.new_object.get("gre")
        if (
            self.new_object.get("ipAssignmentMode") is not None
            or self.new_object.get("ip_assignment_mode") is not None
        ):
            new_object_params["ipAssignmentMode"] = self.new_object.get(
                "ipAssignmentMode"
            ) or self.new_object.get("ip_assignment_mode")
        if (
            self.new_object.get("lanIsolationEnabled") is not None
            or self.new_object.get("lan_isolation_enabled") is not None
        ):
            new_object_params["lanIsolationEnabled"] = self.new_object.get(
                "lanIsolationEnabled"
            )
        if (
            self.new_object.get("ldap") is not None
            or self.new_object.get("ldap") is not None
        ):
            new_object_params["ldap"] = self.new_object.get(
                "ldap"
            ) or self.new_object.get("ldap")
        if (
            self.new_object.get("localRadius") is not None
            or self.new_object.get("local_radius") is not None
        ):
            new_object_params["localRadius"] = self.new_object.get(
                "localRadius"
            ) or self.new_object.get("local_radius")
        if (
            self.new_object.get("mandatoryDhcpEnabled") is not None
            or self.new_object.get("mandatory_dhcp_enabled") is not None
        ):
            new_object_params["mandatoryDhcpEnabled"] = self.new_object.get(
                "mandatoryDhcpEnabled"
            )
        if (
            self.new_object.get("minBitrate") is not None
            or self.new_object.get("min_bitrate") is not None
        ):
            new_object_params["minBitrate"] = self.new_object.get(
                "minBitrate"
            ) or self.new_object.get("min_bitrate")
        if (
            self.new_object.get("name") is not None
            or self.new_object.get("name") is not None
        ):
            new_object_params["name"] = self.new_object.get(
                "name"
            ) or self.new_object.get("name")
        if (
            self.new_object.get("namedVlans") is not None
            or self.new_object.get("named_vlans") is not None
        ):
            new_object_params["namedVlans"] = self.new_object.get(
                "namedVlans"
            ) or self.new_object.get("named_vlans")
        if (
            self.new_object.get("oauth") is not None
            or self.new_object.get("oauth") is not None
        ):
            new_object_params["oauth"] = self.new_object.get(
                "oauth"
            ) or self.new_object.get("oauth")
        if (
            "perClientBandwidthLimitDown" in self.new_object
            or "per_client_bandwidth_limit_down" in self.new_object
        ):
            per_client_bandwidth_limit_down = (
                self.new_object.get("perClientBandwidthLimitDown")
                if "perClientBandwidthLimitDown" in self.new_object
                else self.new_object.get("per_client_bandwidth_limit_down")
            )
            if per_client_bandwidth_limit_down is not None:
                new_object_params["perClientBandwidthLimitDown"] = per_client_bandwidth_limit_down
        if (
            "perClientBandwidthLimitUp" in self.new_object
            or "per_client_bandwidth_limit_up" in self.new_object
        ):
            per_client_bandwidth_limit_up = (
                self.new_object.get("perClientBandwidthLimitUp")
                if "perClientBandwidthLimitUp" in self.new_object
                else self.new_object.get("per_client_bandwidth_limit_up")
            )
            if per_client_bandwidth_limit_up is not None:
                new_object_params["perClientBandwidthLimitUp"] = per_client_bandwidth_limit_up
        if (
            "perSsidBandwidthLimitDown" in self.new_object
            or "per_ssid_bandwidth_limit_down" in self.new_object
        ):
            per_ssid_bandwidth_limit_down = (
                self.new_object.get("perSsidBandwidthLimitDown")
                if "perSsidBandwidthLimitDown" in self.new_object
                else self.new_object.get("per_ssid_bandwidth_limit_down")
            )
            if per_ssid_bandwidth_limit_down is not None:
                new_object_params["perSsidBandwidthLimitDown"] = per_ssid_bandwidth_limit_down
        if (
            "perSsidBandwidthLimitUp" in self.new_object
            or "per_ssid_bandwidth_limit_up" in self.new_object
        ):
            per_ssid_bandwidth_limit_up = (
                self.new_object.get("perSsidBandwidthLimitUp")
                if "perSsidBandwidthLimitUp" in self.new_object
                else self.new_object.get("per_ssid_bandwidth_limit_up")
            )
            if per_ssid_bandwidth_limit_up is not None:
                new_object_params["perSsidBandwidthLimitUp"] = per_ssid_bandwidth_limit_up
        if (
            self.new_object.get("psk") is not None
            or self.new_object.get("psk") is not None
        ):
            new_object_params["psk"] = self.new_object.get(
                "psk"
            ) or self.new_object.get("psk")
        if (
            self.new_object.get("radiusAccountingEnabled") is not None
            or self.new_object.get("radius_accounting_enabled") is not None
        ):
            new_object_params["radiusAccountingEnabled"] = self.new_object.get(
                "radiusAccountingEnabled"
            )
        if (
            "radiusAccountingInterimInterval" in self.new_object
            or "radius_accounting_interim_interval" in self.new_object
        ):
            radius_accounting_interim_interval = (
                self.new_object.get("radiusAccountingInterimInterval")
                if "radiusAccountingInterimInterval" in self.new_object
                else self.new_object.get("radius_accounting_interim_interval")
            )
            if radius_accounting_interim_interval is not None:
                new_object_params["radiusAccountingInterimInterval"] = radius_accounting_interim_interval
        if (
            self.new_object.get("radiusAccountingServers") is not None
            or self.new_object.get("radius_accounting_servers") is not None
        ):
            new_object_params["radiusAccountingServers"] = self.new_object.get(
                "radiusAccountingServers"
            ) or self.new_object.get("radius_accounting_servers")
        if (
            self.new_object.get("radiusAttributeForGroupPolicies") is not None
            or self.new_object.get("radius_attribute_for_group_policies") is not None
        ):
            new_object_params["radiusAttributeForGroupPolicies"] = self.new_object.get(
                "radiusAttributeForGroupPolicies"
            ) or self.new_object.get("radius_attribute_for_group_policies")
        if (
            self.new_object.get("radiusAuthenticationNasId") is not None
            or self.new_object.get("radius_authentication_nas_id") is not None
        ):
            new_object_params["radiusAuthenticationNasId"] = self.new_object.get(
                "radiusAuthenticationNasId"
            ) or self.new_object.get("radius_authentication_nas_id")
        if (
            self.new_object.get("radiusCalledStationId") is not None
            or self.new_object.get("radius_called_station_id") is not None
        ):
            new_object_params["radiusCalledStationId"] = self.new_object.get(
                "radiusCalledStationId"
            ) or self.new_object.get("radius_called_station_id")
        if (
            self.new_object.get("radiusCoaEnabled") is not None
            or self.new_object.get("radius_coa_enabled") is not None
        ):
            new_object_params["radiusCoaEnabled"] = self.new_object.get(
                "radiusCoaEnabled"
            )
        if (
            self.new_object.get("radiusFailoverPolicy") is not None
            or self.new_object.get("radius_failover_policy") is not None
        ):
            new_object_params["radiusFailoverPolicy"] = self.new_object.get(
                "radiusFailoverPolicy"
            ) or self.new_object.get("radius_failover_policy")
        if (
            self.new_object.get("radiusFallbackEnabled") is not None
            or self.new_object.get("radius_fallback_enabled") is not None
        ):
            new_object_params["radiusFallbackEnabled"] = self.new_object.get(
                "radiusFallbackEnabled"
            )
        if (
            self.new_object.get("radiusGuestVlanEnabled") is not None
            or self.new_object.get("radius_guest_vlan_enabled") is not None
        ):
            new_object_params["radiusGuestVlanEnabled"] = self.new_object.get(
                "radiusGuestVlanEnabled"
            )
        if (
            "radiusGuestVlanId" in self.new_object
            or "radius_guest_vlan_id" in self.new_object
        ):
            radius_guest_vlan_id = (
                self.new_object.get("radiusGuestVlanId")
                if "radiusGuestVlanId" in self.new_object
                else self.new_object.get("radius_guest_vlan_id")
            )
            if radius_guest_vlan_id is not None:
                new_object_params["radiusGuestVlanId"] = radius_guest_vlan_id
        if (
            self.new_object.get("radiusLoadBalancingPolicy") is not None
            or self.new_object.get("radius_load_balancing_policy") is not None
        ):
            new_object_params["radiusLoadBalancingPolicy"] = self.new_object.get(
                "radiusLoadBalancingPolicy"
            ) or self.new_object.get("radius_load_balancing_policy")
        if (
            self.new_object.get("radiusOverride") is not None
            or self.new_object.get("radius_override") is not None
        ):
            new_object_params["radiusOverride"] = self.new_object.get("radiusOverride")
        if (
            self.new_object.get("radiusProxyEnabled") is not None
            or self.new_object.get("radius_proxy_enabled") is not None
        ):
            new_object_params["radiusProxyEnabled"] = self.new_object.get(
                "radiusProxyEnabled"
            )
        if (
            "radiusServerAttemptsLimit" in self.new_object
            or "radius_server_attempts_limit" in self.new_object
        ):
            radius_server_attempts_limit = (
                self.new_object.get("radiusServerAttemptsLimit")
                if "radiusServerAttemptsLimit" in self.new_object
                else self.new_object.get("radius_server_attempts_limit")
            )
            if radius_server_attempts_limit is not None:
                new_object_params["radiusServerAttemptsLimit"] = radius_server_attempts_limit
        if (
            "radiusServerTimeout" in self.new_object
            or "radius_server_timeout" in self.new_object
        ):
            radius_server_timeout = (
                self.new_object["radiusServerTimeout"]
                if "radiusServerTimeout" in self.new_object
                else self.new_object.get("radius_server_timeout")
            )
            if radius_server_timeout is not None:
                new_object_params["radiusServerTimeout"] = radius_server_timeout
        if (
            self.new_object.get("radiusServers") is not None
            or self.new_object.get("radius_servers") is not None
        ):
            new_object_params["radiusServers"] = self.new_object.get(
                "radiusServers"
            ) or self.new_object.get("radius_servers")
        if (
            self.new_object.get("radiusTestingEnabled") is not None
            or self.new_object.get("radius_testing_enabled") is not None
        ):
            new_object_params["radiusTestingEnabled"] = self.new_object.get(
                "radiusTestingEnabled"
            )
        if (
            self.new_object.get("secondaryConcentratorNetworkId") is not None
            or self.new_object.get("secondary_concentrator_network_id") is not None
        ):
            new_object_params["secondaryConcentratorNetworkId"] = self.new_object.get(
                "secondaryConcentratorNetworkId"
            ) or self.new_object.get("secondary_concentrator_network_id")
        if (
            self.new_object.get("speedBurst") is not None
            or self.new_object.get("speed_burst") is not None
        ):
            new_object_params["speedBurst"] = self.new_object.get(
                "speedBurst"
            ) or self.new_object.get("speed_burst")
        if (
            self.new_object.get("splashGuestSponsorDomains") is not None
            or self.new_object.get("splash_guest_sponsor_domains") is not None
        ):
            new_object_params["splashGuestSponsorDomains"] = self.new_object.get(
                "splashGuestSponsorDomains"
            ) or self.new_object.get("splash_guest_sponsor_domains")
        if (
            self.new_object.get("splashPage") is not None
            or self.new_object.get("splash_page") is not None
        ):
            new_object_params["splashPage"] = self.new_object.get(
                "splashPage"
            ) or self.new_object.get("splash_page")
        if (
            self.new_object.get("useVlanTagging") is not None
            or self.new_object.get("use_vlan_tagging") is not None
        ):
            new_object_params["useVlanTagging"] = self.new_object.get("useVlanTagging")
        if (
            self.new_object.get("visible") is not None
            or self.new_object.get("visible") is not None
        ):
            new_object_params["visible"] = self.new_object.get("visible")
        if "vlanId" in self.new_object or "vlan_id" in self.new_object:
            vlan_id = (
                self.new_object.get("vlanId")
                if "vlanId" in self.new_object
                else self.new_object.get("vlan_id")
            )
            if vlan_id is not None:
                new_object_params["vlanId"] = vlan_id
        if (
            self.new_object.get("walledGardenEnabled") is not None
            or self.new_object.get("walled_garden_enabled") is not None
        ):
            new_object_params["walledGardenEnabled"] = self.new_object.get(
                "walledGardenEnabled"
            )
        if (
            self.new_object.get("walledGardenRanges") is not None
            or self.new_object.get("walled_garden_ranges") is not None
        ):
            new_object_params["walledGardenRanges"] = self.new_object.get(
                "walledGardenRanges"
            ) or self.new_object.get("walled_garden_ranges")
        if (
            self.new_object.get("wpaEncryptionMode") is not None
            or self.new_object.get("wpa_encryption_mode") is not None
        ):
            new_object_params["wpaEncryptionMode"] = self.new_object.get(
                "wpaEncryptionMode"
            ) or self.new_object.get("wpa_encryption_mode")
        if (
            self.new_object.get("networkId") is not None
            or self.new_object.get("network_id") is not None
        ):
            new_object_params["networkId"] = self.new_object.get(
                "networkId"
            ) or self.new_object.get("network_id")
        if (
            self.new_object.get("number") is not None
            or self.new_object.get("number") is not None
        ):
            new_object_params["number"] = self.new_object.get(
                "number"
            ) or self.new_object.get("number")
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method, using get all
        try:
            items = self.meraki.exec_meraki(
                family="wireless",
                function="getNetworkWirelessSsids",
                params=self.get_all_params(name=name),
            )
            if isinstance(items, dict):
                if "response" in items:
                    items = items.get("response")
            result = get_dict_result(items, "name", name)
            if result is None:
                result = items
        except Exception as e:
            print("Error: ", e)
            result = None
        return result

    def get_object_by_id(self, id):
        result = None
        try:
            items = self.meraki.exec_meraki(
                family="wireless",
                function="getNetworkWirelessSsid",
                params=self.get_params_by_id(),
            )
            if isinstance(items, dict):
                if "response" in items:
                    items = items.get("response")
            result = items
        except Exception as e:
            print("Error: ", e)
            result = None
        return result

    def exists(self):
        prev_obj = None
        id_exists = False
        name_exists = False
        o_id = self.new_object.get("networkId") or self.new_object.get("network_id")
        o_id = o_id or self.new_object.get("number") or self.new_object.get("number")
        name = o_id or self.new_object.get("name")
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            _id = _id or prev_obj.get("number")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters(
                    "The 'id' and 'name' params don't refer to the same object"
                )
            if _id:
                self.new_object.update(dict(id=_id))
                self.new_object.update(dict(number=_id))
            if _id:
                prev_obj = self.get_object_by_id(_id)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("activeDirectory", "activeDirectory"),
            ("adultContentFilteringEnabled", "adultContentFilteringEnabled"),
            ("apTagsAndVlanIds", "apTagsAndVlanIds"),
            ("authMode", "authMode"),
            ("availabilityTags", "availabilityTags"),
            ("availableOnAllAps", "availableOnAllAps"),
            ("bandSelection", "bandSelection"),
            ("concentratorNetworkId", "concentratorNetworkId"),
            ("defaultVlanId", "defaultVlanId"),
            ("disassociateClientsOnVpnFailover", "disassociateClientsOnVpnFailover"),
            ("dnsRewrite", "dnsRewrite"),
            ("dot11r", "dot11r"),
            ("dot11w", "dot11w"),
            ("enabled", "enabled"),
            ("encryptionMode", "encryptionMode"),
            ("enterpriseAdminAccess", "enterpriseAdminAccess"),
            ("gre", "gre"),
            ("ipAssignmentMode", "ipAssignmentMode"),
            ("lanIsolationEnabled", "lanIsolationEnabled"),
            ("ldap", "ldap"),
            ("localRadius", "localRadius"),
            ("mandatoryDhcpEnabled", "mandatoryDhcpEnabled"),
            ("minBitrate", "minBitrate"),
            ("name", "name"),
            ("namedVlans", "namedVlans"),
            ("oauth", "oauth"),
            ("perClientBandwidthLimitDown", "perClientBandwidthLimitDown"),
            ("perClientBandwidthLimitUp", "perClientBandwidthLimitUp"),
            ("perSsidBandwidthLimitDown", "perSsidBandwidthLimitDown"),
            ("perSsidBandwidthLimitUp", "perSsidBandwidthLimitUp"),
            ("psk", "psk"),
            ("radiusAccountingEnabled", "radiusAccountingEnabled"),
            ("radiusAccountingInterimInterval", "radiusAccountingInterimInterval"),
            ("radiusAccountingServers", "radiusAccountingServers"),
            ("radiusAttributeForGroupPolicies", "radiusAttributeForGroupPolicies"),
            ("radiusAuthenticationNasId", "radiusAuthenticationNasId"),
            ("radiusCalledStationId", "radiusCalledStationId"),
            ("radiusCoaEnabled", "radiusCoaEnabled"),
            ("radiusFailoverPolicy", "radiusFailoverPolicy"),
            ("radiusFallbackEnabled", "radiusFallbackEnabled"),
            ("radiusGuestVlanEnabled", "radiusGuestVlanEnabled"),
            ("radiusGuestVlanId", "radiusGuestVlanId"),
            ("radiusLoadBalancingPolicy", "radiusLoadBalancingPolicy"),
            ("radiusOverride", "radiusOverride"),
            ("radiusProxyEnabled", "radiusProxyEnabled"),
            ("radiusRadsec", "radiusRadsec"),
            ("radiusServerAttemptsLimit", "radiusServerAttemptsLimit"),
            ("radiusServerTimeout", "radiusServerTimeout"),
            ("radiusServers", "radiusServers"),
            ("radiusTestingEnabled", "radiusTestingEnabled"),
            ("secondaryConcentratorNetworkId", "secondaryConcentratorNetworkId"),
            ("speedBurst", "speedBurst"),
            ("splashGuestSponsorDomains", "splashGuestSponsorDomains"),
            ("splashPage", "splashPage"),
            ("useVlanTagging", "useVlanTagging"),
            ("visible", "visible"),
            ("vlanId", "vlanId"),
            ("walledGardenEnabled", "walledGardenEnabled"),
            ("walledGardenRanges", "walledGardenRanges"),
            ("wpaEncryptionMode", "wpaEncryptionMode"),
            ("networkId", "networkId"),
            ("number", "number"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        current_obj["number"] = str(current_obj.get("number"))
        return any(
            not meraki_compare_equality2(
                current_obj.get(meraki_param), requested_obj.get(ansible_param)
            )
            for (meraki_param, ansible_param) in obj_params
        )

    def update(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("number")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("number")
            if id_:
                self.new_object.update(dict(number=id_))
        result = self.meraki.exec_meraki(
            family="wireless",
            function="updateNetworkWirelessSsid",
            params=self.update_by_id_params(),
            op_modifies=True,
        )
        return result


class ActionModule(ActionBase):
    def __init__(self, *args, **kwargs):
        if not ANSIBLE_UTILS_IS_INSTALLED:
            raise AnsibleActionFail(
                "ansible.utils is not installed. Execute 'ansible-galaxy collection install ansible.utils'"
            )
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_async = False
        self._supports_check_mode = False
        self._result = None

    # Checks the supplied parameters against the argument spec for this module
    def _check_argspec(self):
        aav = AnsibleArgSpecValidator(
            data=self._task.args,
            schema=dict(argument_spec=argument_spec),
            schema_format="argspec",
            schema_conditionals=dict(
                required_if=required_if,
                required_one_of=required_one_of,
                mutually_exclusive=mutually_exclusive,
                required_together=required_together,
            ),
            name=self._task.action,
        )
        valid, errors, self._task.args = aav.validate()
        if not valid:
            raise AnsibleActionFail(errors)

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        meraki = MERAKI(self._task.args)
        obj = NetworksWirelessSsids(self._task.args, meraki)

        state = self._task.args.get("state")

        response = None
        if state == "present":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                if obj.requires_update(prev_obj):
                    response = obj.update()
                    meraki.object_updated()
                else:
                    response = prev_obj
                    meraki.object_already_present()
            else:
                meraki.fail_json("Object does not exists, plugin only has update")

        self._result.update(dict(meraki_response=response))
        self._result.update(meraki.exit_json())
        return self._result
