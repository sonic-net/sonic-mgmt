# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.mso.plugins.module_utils.constants import TEMPLATE_TYPES, DOMAIN_TYPE_MAP, VM_DOMAIN_PROVIDER_MAP
from ansible_collections.cisco.mso.plugins.module_utils.utils import generate_api_endpoint
from collections import namedtuple

KVPair = namedtuple("KVPair", "key value")
Item = namedtuple("Item", "index details")
SearchQuery = namedtuple("SearchQuery", "key kv_pairs")


class MSOTemplate:
    def __init__(self, mso_module, template_type=None, template_name=None, template_id=None, schema_name=None, schema_id=None, fail_module=False):
        self.mso = mso_module
        self.templates_path = "templates"
        self.summaries_path = "{0}/summaries".format(self.templates_path)
        self.template = {}
        self.template_path = ""
        self.template_name = template_name
        self.template_id = template_id
        self.template_type = template_type
        self.template_summary = {}
        self.template_objects_cache = {}
        self.schema_path = None
        self.schema_name = schema_name
        self.schema_id = schema_id

        if template_id:
            # Checking if the template with id exists to avoid error: MSO Error 400: Template ID 665da24b95400f375928f195 invalid
            self.template_summary = self.mso.get_obj(self.summaries_path, templateId=self.template_id)
            if self.template_summary:
                self.template_path = "{0}/{1}".format(self.templates_path, self.template_id)
                self.template = self.mso.query_obj(self.template_path)
                self.template_name = self.template.get("displayName")
                self.template_type = self.template.get("templateType")
                if template_type == "application":
                    self._set_schema_properties()
            else:
                self.mso.fail_json(
                    msg="Provided template id '{0}' does not exist. Existing templates: {1}".format(
                        self.template_id,
                        [
                            "Template '{0}' with id '{1}'".format(template.get("templateName"), template.get("templateId"))
                            for template in self.mso.query_objs(self.summaries_path)
                        ],
                    )
                )
        elif template_name:
            if not template_type:
                self.mso.fail_json(msg="Template type must be provided when using template name.")
            self.template_summary = self.mso.get_obj(
                self.summaries_path,
                templateName=self.template_name,
                templateType=TEMPLATE_TYPES[template_type]["template_type"],
                schemaName=self.schema_name,
                schemaId=self.schema_id,
            )
            if self.template_summary:
                self.template_path = "{0}/{1}".format(self.templates_path, self.template_summary.get("templateId"))
                self.template = self.mso.query_obj(self.template_path)
                self.template_id = self.template.get("templateId")
                self.template_type = self.template.get("templateType")
                if template_type == "application":
                    self._set_schema_properties()

            if fail_module and not self.template:
                self.mso.fail_json(
                    msg="Provided template name '{0}' does not exist. Existing templates: {1}".format(
                        self.template_name,
                        [
                            "Template '{0}' with id '{1}'".format(template.get("templateName"), template.get("templateId"))
                            for template in self.mso.query_objs(self.summaries_path, templateType=TEMPLATE_TYPES[template_type]["template_type"])
                        ],
                    )
                )

        elif template_type:
            self.template = self.mso.query_objs(self.summaries_path, templateType=TEMPLATE_TYPES[template_type]["template_type"])
        else:
            self.template = self.mso.query_objs(self.summaries_path)

        # Remove unwanted keys from existing object for better output and diff compares
        if isinstance(self.template, dict):
            for key in ["_updateVersion", "version"]:
                self.template.pop(key, None)

    def _set_schema_properties(self):
        self.schema_name = self.template_summary.get("schemaName")
        self.schema_id = self.template_summary.get("schemaId")
        self.schema_path = "schemas/{0}".format(self.schema_id)

    @staticmethod
    def get_object_from_list(search_list, kv_list):
        """
        Get the first matched object from a list of mso object dictionaries.
        :param search_list: Objects to search through -> List.
        :param kv_list: Key/value pairs that should match in the object. -> List[KVPair(Str, Str)]
        :return: The index and details of the object. -> Item (Named Tuple)
                 Values of provided keys of all existing objects. -> List
        """

        # Sometimes the attribute returned by api might be None
        # If search_list is None, iterating over it will throw an error
        # Thus we need to return the match of None and without existing values
        if search_list is None:
            return None, []

        def kv_match(kvs, item):
            return all((item.get(kv.key) == kv.value for kv in kvs))

        match = next((Item(index, item) for index, item in enumerate(search_list) if kv_match(kv_list, item)), None)
        existing = [item.get(kv.key) for item in search_list for kv in kv_list if item.get(kv.key) is not None]
        return match, existing

    def validate_template(self, template_type):
        """
        Validate that attributes are set to a value that is not equal None.
        :return: None
        """
        if not self.template or not isinstance(self.template, dict):
            self.mso.fail_json(msg="Template '{0}' not found.".format(self.template_name))
        if self.template.get("templateType") != template_type:
            self.mso.fail_json(msg="Template type must be '{0}'.".format(template_type))

    def get_object_by_key_value_pairs(self, object_description, search_list, kv_list, fail_module=False):
        """
        Get the object from a list of mso object dictionaries by name.
        :param object_description: Description of the object to search for -> Str
        :param search_list: Objects to search through -> List.
        :param kv_list: Key/value pairs that should match in the object. -> List[KVPair(Str, Str)]
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: The object. -> Dict | None
        """
        match, existing = self.get_object_from_list(search_list, kv_list)
        if not match and fail_module:
            msg = "Provided {0} with '{1}' not matching existing object(s): {2}".format(object_description, kv_list, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        return match

    def get_object_by_uuid(self, object_description, search_list, uuid, fail_module=False):
        """
        Get the object from a list of mso object dictionaries by uuid.
        :param object_description: Description of the object to search for -> Str
        :param search_list: Objects to search through -> List.
        :param uuid: UUID of the object to search for -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: The object. -> Dict | None
        """
        kv_list = [KVPair("uuid", uuid)]
        return self.get_object_by_key_value_pairs(object_description, search_list, kv_list, fail_module)

    def get_vlan_pool_uuid(self, vlan_pool_name):
        """
        Get the UUID of a VLAN pool by name.
        :param vlan_pool_name: Name of the VLAN pool to search for -> Str
        :return: UUID of the VLAN pool. -> Str
        """
        existing_vlan_pools = self.template.get("fabricPolicyTemplate", {}).get("template", {}).get("vlanPools", [])
        kv_list = [KVPair("name", vlan_pool_name)]
        match = self.get_object_by_key_value_pairs("VLAN Pool", existing_vlan_pools, kv_list, fail_module=True)
        return match.details.get("uuid")

    def get_vlan_pool_name(self, vlan_pool_uuid):
        """
        Get the UUID of a VLAN pool by name.
        :param vlan_pool_name: Name of the VLAN pool to search for -> Str
        :return: UUID of the VLAN pool. -> Str
        """
        existing_vlan_pools = self.template.get("fabricPolicyTemplate", {}).get("template", {}).get("vlanPools", [])
        kv_list = [KVPair("uuid", vlan_pool_uuid)]
        match = self.get_object_by_key_value_pairs("VLAN Pool", existing_vlan_pools, kv_list, fail_module=True)
        return match.details.get("name")

    def get_route_map(self, attr_name, tenant_id, tenant_name, route_map, route_map_objects):
        """
        Retrieves the details of a specific route map object based on the provided attributes.
        :param attr_name: The attribute name for error messaging. -> Str
        :param tenant_id: The ID of the tenant. -> Str
        :param tenant_name: The name of the tenant. -> Str
        :param route_map: The name of the route map. -> Str
        :param route_map_objects: The list of route map objects to search from. -> List
        :return: The details of the route map object if found, otherwise an empty dictionary. -> Dict
        """
        if route_map and tenant_id and route_map_objects:
            route_map_object = self.get_object_from_list(
                route_map_objects,
                [KVPair("name", route_map), KVPair("tenantId", tenant_id)],
            )
            if route_map_object[0]:
                return route_map_object[0].details
            else:
                self.mso.fail_json(msg="Provided Route Map {0}: {1} with the tenant: {2} not found.".format(attr_name, route_map, tenant_name))
        else:
            return {}

    def get_vrf_object(self, vrf_dict, tenant_id, templates_objects_path):
        """
        Get VRF object based on provided parameters.
        :param vrf_dict: Dictionary containing VRF details. -> Dict
        :param tenant_id: Id of the tenant. -> Str
        :param templates_objects_path: Path to the templates objects. -> Str
        :return: VRF object if found, otherwise fail with an error message. -> Dict
        """

        vrf_path = generate_api_endpoint(templates_objects_path, **{"type": "vrf", "tenant-id": tenant_id, "include-common": "true"})
        vrf_objects = self.mso.query_objs(vrf_path)
        vrf_kv_list = [
            KVPair("name", vrf_dict.get("name")),
            KVPair("templateName", vrf_dict.get("template")),
            KVPair("schemaName", vrf_dict.get("schema")),
            KVPair("tenantId", tenant_id),
        ]

        vrf_object = self.get_object_from_list(vrf_objects, vrf_kv_list)

        if vrf_object[0]:
            return vrf_object[0]
        else:
            self.mso.fail_json(msg="Provided VRF {0} not found.".format(vrf_dict.get("name")))

    def get_l3out_node_routing_policy_object(self, uuid=None, name=None, fail_module=False):
        """
        Get the L3Out Node Routing Policy by UUID or Name.
        :param uuid: UUID of the L3Out Node Routing Policy to search for -> Str
        :param name: Name of the L3Out Node Routing Policy to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_l3out_node_routing_policy = self.template.get("tenantPolicyTemplate", {}).get("template", {}).get("l3OutNodePolGroups", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "L3Out Node Routing Policy", existing_l3out_node_routing_policy, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module
            )
        return existing_l3out_node_routing_policy  # Query all objects

    def get_interface_policy_group_uuid(self, interface_policy_group):
        """
        Get the UUID of an Interface Policy Group by name.
        :param interface_policy_group: Name of the Interface Policy Group to search for -> Str
        :return: UUID of the Interface Policy Group. -> Str
        """
        existing_policy_groups = self.template.get("fabricPolicyTemplate", {}).get("template", {}).get("interfacePolicyGroups", [])
        kv_list = [KVPair("name", interface_policy_group)]
        match = self.get_object_by_key_value_pairs("Interface Policy Groups", existing_policy_groups, kv_list, fail_module=True)
        return match.details.get("uuid")

    def get_ipsla_monitoring_policy(self, uuid=None, name=None, fail_module=False):
        """
        Get the IPSLA Monitoring Policy by UUID or Name.
        :param uuid: UUID of the IPSLA Monitoring Policy to search for -> Str
        :param name: Name of the IPSLA Monitoring Policy to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_ipsla_policies = self.template.get("tenantPolicyTemplate", {}).get("template", {}).get("ipslaMonitoringPolicies", [])
        if name or uuid:
            return self.get_object_by_key_value_pairs(
                "IPSLA Monitoring Policy",
                existing_ipsla_policies,
                [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
                fail_module=fail_module,
            )
        return existing_ipsla_policies

    def get_l3out_object(self, uuid=None, name=None, fail_module=False, search_object=None):
        """
        Get the L3Out by uuid or name.
        :param uuid: UUID of the L3Out to search for -> Str
        :param name: Name of the L3Out to search for -> Str
        :param search_object: The object to search in -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        if not search_object:
            search_object = self.template
        existing_l3outs = search_object.get("l3outTemplate", {}).get("l3outs", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs("L3Out", existing_l3outs, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
        return existing_l3outs  # Query all objects

    def get_l3out_node_group(self, name, l3out_object, fail_module=False):
        """
        Get the L3Out Node Group Policy by name.
        :param name: Name of the L3Out Node Group Policy to search for -> Str
        :param l3out_object: L3Out object to search Node Group Policy -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the Name is existing in the search list -> Dict
                 When the Name is not existing in the search list -> None
                 When the Name is None, and the search list is not empty -> List[Dict]
                 When the Name is None, and the search list is empty -> List[]
        """
        existing_l3out_node_groups = l3out_object.get("nodeGroups", [])
        if name:  # Query a specific object
            return self.get_object_by_key_value_pairs("L3Out Node Group Policy", existing_l3out_node_groups, [KVPair("name", name)], fail_module)
        return existing_l3out_node_groups  # Query all objects

    def get_port_channel_match(self, port_channel, mso_templates):
        """
        Get the port channel from the provided port channel reference or uuid.
        :param port_channel: The port channel object containing reference or uuid to search for -> ndo_l3out_port_channel_spec
        :param mso_templates: MSO Templates object to search for referenced templates -> MSOTemplates
        :return: The matched port channel object or None if not found -> Dict | None
        """
        port_channel_match = None
        if port_channel:
            port_channel_uuid = port_channel.get("uuid")
            if port_channel_uuid:
                port_channel_match = self.get_template_object_by_uuid("portChannel", port_channel_uuid, True)
            else:
                fabric_resource_mso_template = mso_templates.get_template(
                    "fabric_resource",
                    port_channel.get("reference").get("template"),
                    port_channel.get("reference").get("template_id"),
                    fail_module=True,
                )
                port_channel_match = fabric_resource_mso_template.get_port_channel(
                    None,
                    port_channel.get("reference").get("name"),
                    fail_module=True,
                ).details
        return port_channel_match

    def get_port_channel(self, uuid=None, name=None, fail_module=False):
        """
        Get the port channel by uuid or name.
        :param uuid: UUID of the Port Channel to search for -> Str
        :param name: Name of the Port Channel to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_port_channels = self.template.get("fabricResourceTemplate", {}).get("template", {}).get("portChannels", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "Port Channel", existing_port_channels, [KVPair("uuid", uuid)] if uuid else [KVPair("name", name)], fail_module=fail_module
            )
        return existing_port_channels

    def get_virtual_port_channel_match(self, virtual_port_channel, mso_templates):
        """
        Get the virtual port channel from the provided virtual port channel reference or uuid.
        :param virtual_port_channel: The virtual port channel object containing reference or uuid to search for -> ndo_l3out_virtual_port_channel_spec
        :param mso_templates: MSO Templates object to search for referenced templates -> MSOTemplates
        :return: The matched virtual port channel object or None if not found -> Dict | None
        """
        virtual_port_channel_match = None
        if virtual_port_channel:
            virtual_port_channel_uuid = virtual_port_channel.get("uuid")
            if virtual_port_channel_uuid:
                virtual_port_channel_match = self.get_template_object_by_uuid("virtualPortChannel", virtual_port_channel_uuid, True)
            else:
                fabric_resource_mso_template = mso_templates.get_template(
                    "fabric_resource",
                    virtual_port_channel.get("reference").get("template"),
                    virtual_port_channel.get("reference").get("template_id"),
                    fail_module=True,
                )
                virtual_port_channel_match = fabric_resource_mso_template.get_virtual_port_channel(
                    virtual_port_channel_uuid,
                    virtual_port_channel.get("reference").get("name"),
                    fail_module=True,
                ).details
        return virtual_port_channel_match

    def get_virtual_port_channel(self, uuid=None, name=None, fail_module=False):
        """
        Get the virtual port channel by uuid or name.
        :param uuid: UUID of the Virtual Port Channel to search for -> Str
        :param name: Name of the Virtual Port Channel to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_virtual_port_channels = self.template.get("fabricResourceTemplate", {}).get("template", {}).get("virtualPortChannels", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "Virtual Port Channel", existing_virtual_port_channels, [KVPair("uuid", uuid)] if uuid else [KVPair("name", name)], fail_module=fail_module
            )
        return existing_virtual_port_channels

    def get_l3out_node(self, l3out_object, pod_id, node_id, fail_module=False):
        """
        Get the L3Out Node by pod_id and node_id.
        :param l3out_object: L3Out object to search for the Node -> Dict
        :param pod_id: Pod ID of the Node to search for -> Str
        :param node_id: Node ID of the Node to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the pod_id | node_id is existing in the search list -> Dict
                 When the pod_id | node_id is not existing in the search list -> None
                 When both pod_id and node_id are None, and the search list is not empty -> List[Dict]
                 When both pod_id and node_id are None, and the search list is empty -> List[]
        """
        existing_l3out_nodes = l3out_object.get("nodes", [])
        if pod_id and node_id:  # Query a specific object
            return self.get_object_by_key_value_pairs("L3Out Node", existing_l3out_nodes, [KVPair("podID", pod_id), KVPair("nodeID", node_id)], fail_module)
        return existing_l3out_nodes  # Query all objects

    def get_l3out_node_static_route(self, node_object, prefix, fail_module=False):
        """
        Get the L3Out Node Static Route by prefix.
        :param node_object: L3Out Node object to search for the Static Route -> Dict
        :param prefix: Prefix of the Static Route to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the prefix is existing in the search list -> Dict
                 When the prefix is not existing in the search list -> None
                 When the prefix is None, and the search list is not empty -> List[Dict]
                 When the prefix is None, and the search list is empty -> List[]
        """
        existing_l3out_static_routes = node_object.get("staticRoutes", [])
        if prefix:  # Query a specific object
            return self.get_object_by_key_value_pairs("L3Out Node Static Route", existing_l3out_static_routes, [KVPair("prefix", prefix)], fail_module)
        return existing_l3out_static_routes  # Query all objects

    def get_l3out_node_static_route_next_hop(self, static_route_object, ip, fail_module=False):
        """
        Get the L3Out Node Static Route Next Hop by IP.
        :param static_route_object: L3Out Node Static Route object to search for the Next Hop -> Dict
        :param ip: IP of the Static Route Next Hop to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the IP is existing in the search list -> Dict
                 When the IP is not existing in the search list -> None
                 When the IP is None, and the search list is not empty -> List[Dict]
                 When the IP is None, and the search list is empty -> List[]
        """
        existing_l3out_static_route_next_hops = static_route_object.get("nextHops", [])
        if ip:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "L3Out Node Static Route Next Hop", existing_l3out_static_route_next_hops, [KVPair("nextHopIP", ip)], fail_module
            )
        return existing_l3out_static_route_next_hops  # Query all objects

    def get_ipsla_track_list(self, uuid=None, name=None, fail_module=False):
        """
        Get the IPSLA Track List by uuid or name.
        :param uuid: UUID of the IPSLA Track List to search for -> Str
        :param name: Name of the IPSLA Track List to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_ipsla_track_lists = self.template.get("tenantPolicyTemplate", {}).get("template", {}).get("ipslaTrackLists", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "IPSLA Track List",
                existing_ipsla_track_lists,
                [KVPair("uuid", uuid)] if uuid else [KVPair("name", name)],
                fail_module=fail_module,
            )
        return existing_ipsla_track_lists  # Query all objects

    def get_l3out_secondary_address(self, parent_object, parent_type, secondary_address, side_b, fail_module=False):
        """
        Get the L3Out Secondary Address by address.
        :param parent_object: The parent object to search for the secondary IP address -> Dict
        :param secondary_address: The secondary address to search for -> Str
        :param side_b: The side indicator for the SVI VPC parent object.
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the address is existing in the search list -> Dict
                 When the address is not existing in the search list -> None
                 When the address is None, and the search list is not empty -> List[Dict]
                 When the address is None, and the search list is empty -> List[]
        """
        if parent_type == "floating_svi_path_attributes":
            existing_secondary_address = parent_object.get("secondaryAddresses", [])
        else:
            existing_secondary_address = parent_object.get("sideBAddresses" if side_b else "addresses", {}).get("secondary", [])

        if secondary_address:  # Query a specific object
            kv_list = [KVPair("address", secondary_address)]
            return self.get_object_by_key_value_pairs("L3Out Secondary IP Address", existing_secondary_address, kv_list, fail_module)
        return existing_secondary_address  # Query all objects

    def get_l3out_routed_interface(self, l3out_object, pod_id, node_id, path, path_ref, fail_module=False):
        """
        Get the L3Out Routed Interface by pod_id, node_id, path, and path_ref.
        :param l3out_object: L3Out object to search for the Routed Interface -> Dict
        :param pod_id: Pod ID of the Routed Interface to search for -> Str
        :param node_id: Node ID of the Routed Interface to search for -> Str
        :param path: Path of the Routed Interface to search for -> Str
        :param path_ref: Path reference of the Routed Interface to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the pod_id, node_id, path | path_ref is existing in the search list -> Dict
                 When the pod_id, node_id, path | path_ref is not existing in the search list -> None
                 When both pod_id, node_id, path and path_ref are None, and the search list is not empty -> List[Dict]
                 When both pod_id, node_id, path and path_ref are None, and the search list is empty -> List[]
        """
        existing_l3out_interfaces = l3out_object.get("interfaces", [])
        if (pod_id and node_id and path) or path_ref:  # Query a specific object
            if path_ref:
                kv_list = [KVPair("pathRef", path_ref)]
            else:
                kv_list = [KVPair("podID", pod_id), KVPair("nodeID", node_id), KVPair("path", path)]

            return self.get_object_by_key_value_pairs("L3Out Interface", existing_l3out_interfaces, kv_list, fail_module)
        return existing_l3out_interfaces  # Query all objects

    def get_l3out_routed_sub_interface(self, l3out_object, pod_id, node_id, path, path_ref, encap, fail_module=False):
        """
        Get the L3Out Routed Sub-Interface by pod_id, node_id, path, and path_ref.
        :param l3out_object: L3Out object to search for the Routed Sub-Interface -> Dict
        :param pod_id: Pod ID of the Routed Sub-Interface to search for -> Str
        :param node_id: Node ID of the Routed Sub-Interface to search for -> Str
        :param path: Path of the Routed Sub-Interface to search for -> Str
        :param path_ref: Path reference of the Routed Sub-Interface to search for -> Str
        :param encap: Encapsulation details of the Routed Sub-Interface to search for -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the pod_id, node_id, path | path_ref with encap is existing in the search list -> Dict
                 When the pod_id, node_id, path | path_ref with encap is not existing in the search list -> None
                 When both pod_id, node_id, path, path_ref, and encap are None, and the search list is not empty -> List[Dict]
                 When both pod_id, node_id, path, path_ref, and encap are None, and the search list is empty -> List[]
        """
        existing_l3out_interfaces = l3out_object.get("subInterfaces", [])
        if ((pod_id and node_id and path) or path_ref) and encap:  # Query a specific object
            if path_ref:
                kv_list = [KVPair("pathRef", path_ref), KVPair("encap", encap)]
            else:
                kv_list = [KVPair("podID", pod_id), KVPair("nodeID", node_id), KVPair("path", path), KVPair("encap", encap)]

            return self.get_object_by_key_value_pairs("L3Out Sub-Interface", existing_l3out_interfaces, kv_list, fail_module)
        return existing_l3out_interfaces  # Query all objects

    def get_l3out_svi_interface(self, l3out_object, pod_id, node_id, path, encap, path_ref, fail_module=False):
        """
        Get the L3Out SVI Interface by pod_id, node_id, path, and path_ref.
        :param l3out_object: L3Out object to search for the SVI Interface -> Dict
        :param pod_id: Pod ID of the SVI Interface to search for -> Str
        :param node_id: Node ID of the SVI Interface to search for -> Str
        :param path: Path of the SVI Interface to search for -> Str
        :param encap: Encapsulation details of the Floating SVI Interface to search for -> Dict
        :param path_ref: Path reference of the SVI Interface to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the pod_id, node_id, path | path_ref is existing in the search list -> Dict
                 When the pod_id, node_id, path | path_ref is not existing in the search list -> None
                 When both pod_id, node_id, path and path_ref are None, and the search list is not empty -> List[Dict]
                 When both pod_id, node_id, path and path_ref are None, and the search list is empty -> List[]
        """
        existing_l3out_svi_interfaces = l3out_object.get("sviInterfaces", [])
        if encap and ((pod_id and node_id and path) or path_ref):  # Query a specific object
            if path_ref:
                kv_list = [KVPair("pathRef", path_ref), KVPair("encap", encap)]
            else:
                kv_list = [KVPair("podID", pod_id), KVPair("nodeID", node_id), KVPair("path", path), KVPair("encap", encap)]

            return self.get_object_by_key_value_pairs("L3Out SVI Interface", existing_l3out_svi_interfaces, kv_list, fail_module)
        return existing_l3out_svi_interfaces  # Query all objects

    def get_l3out_floating_svi_interface(self, l3out_object, pod_id, node_id, encap, fail_module=False):
        """
        Get the L3Out Floating SVI Interface by pod_id and node_id.
        :param l3out_object: L3Out object to search for the Floating SVI Interface -> Dict
        :param pod_id: Pod ID of the Floating SVI Interface to search for -> Str
        :param node_id: Node ID of the Floating SVI Interface to search for -> Str
        :param encap: Encapsulation details of the Floating SVI Interface to search for -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the pod_id, node_id and encap are existing in the search list -> Dict
                 When the pod_id, node_id and encap are not existing in the search list -> None
                 When both pod_id, node_id, and encap are None, and the search list is not empty -> List[Dict]
                 When both pod_id, node_id, and encap are None, and the search list is empty -> List[]
        """
        existing_l3out_floating_svi_interfaces = l3out_object.get("floatingSviInterfaces", [])
        if pod_id and node_id and encap:  # Query a specific object
            kv_list = [KVPair("podID", pod_id), KVPair("nodeID", node_id), KVPair("encap", encap)]

            return self.get_object_by_key_value_pairs("L3Out Floating SVI Interface", existing_l3out_floating_svi_interfaces, kv_list, fail_module)
        return existing_l3out_floating_svi_interfaces  # Query all objects

    def get_l3out_floating_svi_interface_path_attributes(self, l3out_floating_svi_interface_object, domain_type, domain, fail_module=False):
        """
        Get the L3Out Floating SVI Interface Path Attributes by domain_type and domain.
        :param l3out_floating_svi_interface_object: L3Out Floating SVI Interface object to search for the Path Attributes -> Dict
        :param domain_type: Domain type of the Path Attributes to search for -> Str
        :param domain: Domain of the Path Attributes to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the domain_type and domain are existing in the search list -> Dict
                 When the domain_type and domain are not existing in the search list -> None
                 When both domain_type and domain are None, and the search list is not empty -> List[Dict]
                 When both domain_type and domain are None, and the search list is empty -> List[]
        """
        existing_path_attributes = l3out_floating_svi_interface_object.get("svi", {}).get("floatingPathAttributes", [])
        if domain_type and domain:  # Query a specific object
            kv_list = [KVPair("domainType", domain_type), KVPair("domain", domain)]
            return self.get_object_by_key_value_pairs("L3Out Floating SVI Interface Path Attributes", existing_path_attributes, kv_list, fail_module)
        return existing_path_attributes  # Query all objects

    def get_node_settings_object(self, uuid=None, name=None, fail_module=False):
        """
        Get the Fabric Node Settings by uuid or name.
        :param uuid: UUID of the Node Setting to search for -> Str
        :param name: Name of the Node Setting to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_objects = self.template.get("fabricPolicyTemplate", {}).get("template", {}).get("nodePolicyGroups", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs("Node Settings", existing_objects, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
        return existing_objects  # Query all objects

    def get_pod_profile_object(self, uuid=None, name=None, search_object=None, fail_module=False):
        """
        Get the Pod Profile by uuid or name.
        :param uuid: UUID of the Pod Profile to search for -> Str
        :param name: Name of the Pod Profile to search for -> Str
        :param search_object: The object to search in -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        if not search_object:
            search_object = self.template
        existing_objects = search_object.get("fabricResourceTemplate", {}).get("template", {}).get("podProfiles", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs("Pod Profile", existing_objects, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
        return existing_objects  # Query all objects

    def get_pod_settings_object(self, uuid=None, name=None, search_object=None, fail_module=False):
        """
        Get the Pod Settings by uuid or name.
        :param uuid: UUID of the Pod Settings to search for -> Str
        :param name: Name of the Pod Settings to search for -> Str
        :param search_object: The object to search in -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        if not search_object:
            search_object = self.template
        existing_objects = search_object.get("fabricPolicyTemplate", {}).get("template", {}).get("podPolicyGroups", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs("Pod Settings", existing_objects, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
        return existing_objects  # Query all objects

    def get_ntp_policy_object(self, uuid=None, name=None, search_object=None, fail_module=False):
        """
        Get the NTP Policy by uuid or name.
        :param uuid: UUID of the NTP Policy to search for -> Str
        :param name: Name of the NTP Policy to search for -> Str
        :param search_object: The object to search in -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        if not search_object:
            search_object = self.template
        existing_objects = search_object.get("fabricPolicyTemplate", {}).get("template", {}).get("ntpPolicies", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs("NTP Policy", existing_objects, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
        return existing_objects  # Query all objects

    def get_ptp_policy_profile_object(self, uuid=None, name=None, fail_module=False):
        # This object is an exception where the template can only contain a single PTP Policy, thus an additional layer of nested query is done
        """
        Get the PTP Policy Profile by UUID or Name.
        :param uuid: UUID of the PTP Profile to search for -> Str
        :param name: Name of the PTP Profile to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_ptp_profile = self.template.get("fabricPolicyTemplate", {}).get("template", {}).get("ptpPolicy", {}).get("profiles", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "PTP Policy Profile", existing_ptp_profile, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module
            )
        return existing_ptp_profile  # Query all objects

    def get_macsec_policy_object(self, uuid=None, name=None, search_object=None, fail_module=False):
        """
        Get the MACsec Policy by uuid or name.
        :param uuid: UUID of the MACsec Policy to search for -> Str
        :param name: Name of the MACsec Policy to search for -> Str
        :param search_object: The object to search in -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        if not search_object:
            search_object = self.template
        existing_objects = search_object.get("fabricPolicyTemplate", {}).get("template", {}).get("macsecPolicies", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs("MACsec Policy", existing_objects, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
        return existing_objects  # Query all objects

    def get_l3out_interface_routing_policy_object(self, uuid=None, name=None, fail_module=False):
        """
        Get the L3Out Interface Routing Policy by UUID or Name.
        :param uuid: UUID of the L3Out Interface Routing Policy to search for -> Str
        :param name: Name of the L3Out Interface Routing Policy to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_l3out_interface_routing_policy = self.template.get("tenantPolicyTemplate", {}).get("template", {}).get("l3OutIntfPolGroups", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "L3Out Interface Routing Policy",
                existing_l3out_interface_routing_policy,
                [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
                fail_module,
            )
        return existing_l3out_interface_routing_policy  # Query all objects

    def get_match_rule_policy_object(self, uuid=None, name=None, search_object=None, fail_module=False):
        """
        Get the Match Rule Policy by uuid or name.
        :param uuid: UUID of the Match Rule Policy to search for -> Str
        :param name: Name of the Match Rule Policy to search for -> Str
        :param search_object: The object to search in -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        if not search_object:
            search_object = self.template
        existing_objects = search_object.get("tenantPolicyTemplate", {}).get("template", {}).get("matchRulePolicies", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "Match Rule Policy",
                existing_objects,
                [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
                fail_module,
            )
        return existing_objects  # Query all objects

    def get_direct_child_object(self, parent_object, description, endpoint, identifiers=None, fail_module=False):
        """
        Get the direct child object using its identifiers and its parent object.
        :param parent_object: Parent object data where to search the direct child object -> Dict
        :param description: Description of the child object to search for -> Str
        :param endpoint: NDO API child object's endpoint -> Str
        :param identifiers: child object's identifiers with coresponding identifier's name and value -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When one of the child object identifiers is existing in the search list -> Dict
                 When the child object identifiers are not existing in the search list -> None
                 When the child object identifiers are None, and the search list is not empty -> List[Dict]
                 When the child object identifiers ae None, and the search list is empty -> List[]
        """
        if isinstance(identifiers, dict) and identifiers.values():  # Query a specific object
            for key, value in identifiers.items():
                if value:
                    child_object_kvpair = KVPair(key, value)
            return self.get_object_by_key_value_pairs(
                description,
                parent_object.details.get(endpoint, []),
                [child_object_kvpair],
                fail_module,
            )
        return parent_object.details.get(endpoint, [])  # Query all objects

    def get_template_policy_uuid(self, template_type, policy_name, policy_type):
        """
        Get the UUID of a Tenant Policy by name.
        :param template_type: The type of template -> Str
        :param policy_name: Name of the policy -> Str
        :param policy_type: The type of the policy specified in the API response -> Str
        :return: UUID of the tenant policy -> Str
        """
        existing_policies = self.template.get(TEMPLATE_TYPES[template_type]["template_type_container"], {}).get("template", {}).get(policy_type, [])
        match = self.get_object_by_key_value_pairs(policy_type, existing_policies, [KVPair("name", policy_name)], fail_module=True)
        return match.details.get("uuid")

    def clear_template_objects_cache(self):
        self.template_objects_cache = {}

    def get_template_object_name_by_uuid(self, object_type, uuid, fail_module=True):
        """
        Retrieve the name of a specific object type in the MSO template using its UUID.
        :param mso: An instance of the MSO class, which provides methods for making API requests -> MSO Class instance
        :param object_type: The type of the object to retrieve the name for -> Str
        :param uuid: The UUID of the object to retrieve the name for -> Str
        :return: Str | None: The processed result which could be:
              When the UUID is existing, returns object name -> Str
              When the UUID is not existing -> None
        """
        response_object = self.get_template_object_by_uuid(object_type, uuid, fail_module)
        if response_object:
            return response_object.get("name")

    def get_template_object_by_uuid(self, object_type, uuid, fail_module=True, use_cache=False):
        """
        Retrieve a specific object type in the MSO template using its UUID.
        :param object_type: The type of the object to retrieve -> Str
        :param uuid: The UUID of the object to retrieve -> Str
        :param use_cache: Use the cached result of the templates/objects API for the UUID -> Bool
        :return: Dict | None: The processed result which could be:
            When the UUID is existing, returns object -> Dict
            When the UUID is not existing -> None
        """
        response_object = None
        if use_cache and uuid in self.template_objects_cache.keys():
            response_object = self.template_objects_cache[uuid]
        else:
            response_object = self.mso.request("templates/objects?type={0}&uuid={1}".format(object_type, uuid), "GET")
            self.template_objects_cache[uuid] = response_object
        if not response_object and fail_module:
            msg = "Provided {0} with UUID of '{1}' not found.".format(object_type, uuid)
            self.mso.fail_json(msg=msg)
        return response_object

    def update_config_with_template_and_references(self, config_data, reference_collections=None, set_template=True, use_cache=False):
        """
        Return the updated config_data with the template values and reference_collections if provided
        :param config_data: The original config_data that requires to be updated -> Dict
        :param reference_collections: A dict containing the object type, references and the corresponding names -> Dict
        :param set_template: Adds the templateId and templateName to the config_data -> Bool
        :param use_cache: Use the cached result of the templates/objects API for the ref UUID -> Bool
        :return: Updated config_data with names for references -> Dict
        Example 1:
        reference_collections = {
            "qos": {
                "name": "qosName",
                "reference": "qosRef",
                "type": "qos",
                "template": "qosTemplateName",
                "templateId": "qosTemplateId",
            },
            "interfaceRoutingPolicy": {
                "name": "interfaceRoutingPolicyName",
                "reference": "interfaceRoutingPolicyRef",
                "type": "l3OutIntfPolGroup",
                "template": "interfaceRoutingPolicyTemplateName",
                "templateId": "interfaceRoutingPolicyTemplateId",
            },
        }
        config_data = {
            "qosRef": "unique-qos-id",
            "interfaceRoutingPolicyRef": "unique-interface-id"
        }
        updated_config_data = mso_template_object.update_config_with_template_and_references(mso_instance, config_data, reference_collections)
        Expected Output:
        {    "templateName": "template_name",
             "templateId": "unique-template-id",
             "qosRef": "unique-qos-id",
             "interfaceRoutingPolicyRef": "unique-interface-id",
             "qosName": "Resolved QoS Name",
             "qosTemplateName": "Resolved QoS Template Name",
             "qosTemplateId": "Resolved QoS Template ID",
             "interfaceRoutingPolicyName": "Resolved Interface Routing Policy Name",
             "interfaceRoutingPolicyTemplateName": "Resolved Interface Routing Policy Template Name",
             "interfaceRoutingPolicyTemplateId": "Resolved Interface Routing Policy Template ID"
         }
        Example 2:
        reference_collections = {
            "stateLimitRouteMap": {
                "name": "stateLimitRouteMapName",
                "reference": "stateLimitRouteMapRef",
                "type": "mcastRouteMap"
            },
            "reportPolicyRouteMap": {
                "name": "reportPolicyRouteMapName",
                "reference": "reportPolicyRouteMapRef",
                "type": "mcastRouteMap"
            },
            "staticReportRouteMap": {
                "name": "staticReportRouteMapName",
                "reference": "staticReportRouteMapRef",
                "type": "mcastRouteMap"
            },
        }
        config_data = {
            "stateLimitRouteMapRef": "unique-state-limit-id",
            "reportPolicyRouteMapRef": "unique-report-policy-id"
        }
        updated_config_data = mso_template_object.update_config_with_template_and_references(mso_instance, config_data, reference_collections)
         Expected Output:
         {   "templateName": "template_name",
             "templateId": "unique-template-id",
             "stateLimitRouteMapRef": "unique-state-limit-id",
             "reportPolicyRouteMapRef": "unique-report-policy-id",
             "stateLimitRouteMapName": "Resolved State Limit Route Map Name",
             "reportPolicyRouteMapName": "Resolved Report Policy Route Map Name"
         }
        """

        # Set template ID and template name if available
        if set_template:
            if self.template_id:
                config_data["templateId"] = self.template_id
            if self.template_name:
                config_data["templateName"] = self.template_name
            if self.schema_id:
                config_data["schemaId"] = self.schema_id
            if self.schema_name:
                config_data["schemaName"] = self.schema_name

        # Update config data with reference names if reference_collections is provided
        if reference_collections:
            for reference_details in reference_collections.values():
                if config_data.get(reference_details.get("reference")):
                    template_object = self.get_template_object_by_uuid(
                        reference_details.get("type"), config_data.get(reference_details.get("reference")), True, use_cache
                    )
                    config_data[reference_details.get("name")] = template_object.get("name")
                    if reference_details.get("template"):
                        config_data[reference_details.get("template")] = template_object.get("templateName")
                    if reference_details.get("templateId"):
                        config_data[reference_details.get("templateId")] = template_object.get("templateId")
                    if reference_details.get("schemaId"):
                        config_data[reference_details.get("schemaId")] = template_object.get("schemaId")
                    if reference_details.get("schema"):
                        config_data[reference_details.get("schema")] = template_object.get("schemaName")
            for config_value in config_data.values():
                if isinstance(config_value, dict):
                    self.update_config_with_template_and_references(config_value, reference_collections, False, use_cache)
                elif isinstance(config_value, list):
                    for item in config_value:
                        if isinstance(item, dict):
                            self.update_config_with_template_and_references(item, reference_collections, False, use_cache)
        return config_data

    def update_config_with_port_channel_references(self, update_object):
        if update_object:
            reference_details = None
            if update_object.get("pathRef"):
                if update_object.get("pathType") == "vpc":
                    reference_details = {
                        "virtual_port_channel_reference": {
                            "name": "virtualPortChannelName",
                            "reference": "pathRef",
                            "type": "virtualPortChannel",
                            "template": "virtualPortChannelTemplateName",
                            "templateId": "virtualPortChannelTemplateId",
                        }
                    }
                elif update_object.get("pathType") == "pc":
                    reference_details = {
                        "port_channel_reference": {
                            "name": "portChannelName",
                            "reference": "pathRef",
                            "type": "portChannel",
                            "template": "portChannelTemplateName",
                            "templateId": "portChannelTemplateId",
                        }
                    }
            self.update_config_with_template_and_references(
                update_object,
                reference_details,
                True,
            )

    def update_config_with_node_references(self, interface, l3out_object):

        pod_id = interface.get("podID")
        node_id = interface.get("nodeID")
        node_id_2 = None

        if interface.get("pathType") == "pc":
            interface_details = self.mso.get_site_interface_details(
                self.template.get("l3outTemplate", {}).get("siteId"),
                port_channel_uuid=interface.get("pathRef"),
            )
            pod_id = interface_details.get("pod")
            node_id = interface_details.get("node")
        elif interface.get("pathType") == "vpc":
            interface_details = self.mso.get_site_interface_details(
                self.template.get("l3outTemplate", {}).get("siteId"),
                virtual_port_channel_uuid=interface.get("pathRef"),
            )
            pod_id = interface_details.get("pod")
            node_id = interface_details.get("node1")
            node_id_2 = interface_details.get("node2")

        node = self.get_l3out_node(l3out_object.details, pod_id, node_id)
        if node and not isinstance(node, list):
            interface["node"] = node.details

        if node_id_2:
            node_2 = self.get_l3out_node(l3out_object.details, pod_id, node_id_2)
            if node_2 and not isinstance(node_2, list):
                interface["sideBNode"] = node_2.details

    def update_config_with_ptp_references(self, routed_interface, mso_templates):
        ptp = routed_interface.get("ptpConfig")
        if ptp:
            reference_details = {
                "ptp_profile_reference": {
                    "name": "ptpProfileName",
                    "reference": "ptpProfileRef",
                    "type": "ptpProfile",
                    "template": "ptpProfileTemplateName",
                    "templateId": "ptpProfileTemplateId",
                }
            }
            self.update_config_with_template_and_references(
                ptp,
                reference_details,
                False,
            )
            # The PTP policy details cannot be updated via update_config_with_template_and_references because the object type is not supported.
            # The PTP policy details cannot be updated because the uuid is unknown and can only be retrieved from the template.
            # Adding additional logic to populate the parent details in output.
            ptpPolicy = (
                mso_templates.get_template(
                    "fabric_policy",
                    ptp.get("ptpProfileTemplateName"),
                    ptp.get("ptpProfileTemplateId"),
                    fail_module=True,
                )
                .template.get("fabricPolicyTemplate", {})
                .get("template", {})
                .get("ptpPolicy", {})
            )
            routed_interface["ptpConfig"]["ptpPolicyName"] = ptpPolicy.get("name")
            routed_interface["ptpConfig"]["ptpPolicyRef"] = ptpPolicy.get("uuid")

    def update_match_rule_policy_child_object_with_template_and_parent(self, match_rule_policy, config_data):
        """
        Return the updated Match Rule Policy child object config_data with the template and policy values
        :param config_data: The Match Rule Policy data -> Dict
        :param config_data: The original config_data that requires to be updated -> Dict
        :return: Updated config_data with names and ids for template and Match Rule Policy -> Dict
        """
        self.update_config_with_template_and_references(config_data)
        if match_rule_policy.get("uuid"):
            config_data["matchRulePolicyUuid"] = match_rule_policy["uuid"]
        if match_rule_policy.get("name"):
            config_data["matchRulePolicyName"] = match_rule_policy["name"]
        return config_data

    def get_route_map_policy_for_multicast_uuid(self, route_map_policy_for_multicast_name):
        """
        Get the UUID of an Route Map Policy for Multicast by name.
        :param route_map_policy_for_multicast_name: Name of the Route Map Policy for Multicast to search for -> Str
        :return: UUID of the Route Map Policy for Multicast. -> Str
        """
        existing_route_map_policies = self.template.get("tenantPolicyTemplate", {}).get("template", {}).get("mcastRouteMapPolicies", [])
        kv_list = [KVPair("name", route_map_policy_for_multicast_name)]
        match = self.get_object_by_key_value_pairs("Route Map Policy for Multicast", existing_route_map_policies, kv_list, fail_module=True)
        return match.details.get("uuid")

    def get_fabric_template_object_by_key_value(self, object_type, object_description, kv_list, fail_module=False):
        """
        Get the Fabric Policy by policy type and search criteria.
        The search criteria could be name and UUID of the object.
        :param object_type: The type of the object to retrieve the name for -> Str
        :param object_description: Description of the object to search for -> Str
        :param kv_list: Key/value pairs that should match in the object. -> List[KVPair(Str, Str)]
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Dict | None: The processed result which could be:
              When the object is existing in the search list -> Dict
              When the object is not existing -> None
        """
        response_object = self.mso.request("getfabricpolicies?type={0}".format(object_type), "GET")
        search_list = response_object.get("items", [{"spec": {"policies": []}}])[0].get("spec", {}).get("policies", [])
        match = self.get_object_by_key_value_pairs(object_description, search_list, kv_list, fail_module)
        if match:
            return match.details

    def get_fabric_span_session(self, uuid=None, name=None, fail_module=False):
        """
        Get the Fabric SPAN Session by uuid or name.
        :param uuid: UUID of the Fabric SPAN Session to search for -> Str
        :param name: Name of the Fabric SPAN Session to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_objects = self.template.get("monitoringTemplate", {}).get("template", {}).get("spanSessions", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs("SPAN Session", existing_objects, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module)
        return existing_objects  # Query all objects

    def get_fabric_span_session_source(self, name, search_list, fail_module=False):
        """
        Get the Fabric SPAN Session Source by name.
        :param name: Name of the Fabric SPAN Session Source to search for -> Str
        :param search_list: Objects to search through -> List.
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | List[Dict] | List[]: The processed result which could be:
                 When the Name is existing in the search list -> Dict
                 When both Name is None, and the search list is not empty -> List[Dict]
                 When both Name is None, and the search list is empty -> List[]
        """
        if name and search_list:  # Query a specific object
            return self.get_object_by_key_value_pairs("SPAN Session Source", search_list, [KVPair("name", name)], fail_module)
        return search_list  # Query all objects

    def get_application_template_contract(self, uuid=None, name=None, fail_module=False):
        """
        Get the Application Template Contract by uuid or name.
        :param uuid: UUID of the Contract to search for -> Str
        :param name: Name of the Contract to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        existing_objects = self.template.get("appTemplate", {}).get("template", {}).get("contracts", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "Template Contract", existing_objects, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module
            )
        return existing_objects  # Query all objects

    def get_parent_details_for_nested_object_in_l3out(self, mso_templates, l3out_object):
        """
        Get the parent details for a nested object in the L3Out object.
        :param mso_templates: The MSO templates to search through -> List[Dict]
        :param l3out_object: The L3Out object to find the parent for -> Dict
        :return: The parent details for the nested object -> Dict, Str | None, None
        """
        port_channel_uuid = virtual_port_channel_uuid = pod_id = encap = parent_match = parent_path = None
        parent_type = self.mso.params.get("parent_type")
        node_group = self.mso.params.get("node_group")
        node_id = self.mso.params.get("node_id")
        path = self.mso.params.get("path")
        port_channel = self.get_port_channel_match(self.mso.params.get("port_channel"), mso_templates)
        if port_channel:
            port_channel_uuid = port_channel.get("uuid")
        virtual_port_channel = self.get_virtual_port_channel_match(self.mso.params.get("virtual_port_channel"), mso_templates)
        if virtual_port_channel:
            virtual_port_channel_uuid = virtual_port_channel.get("uuid")
        encapsulation_type = self.mso.params.get("encapsulation_type")
        encapsulation_value = self.mso.params.get("encapsulation_value")
        domain_type = DOMAIN_TYPE_MAP.get(self.mso.params.get("domain_type"))
        domain_provider = self.mso.params.get("domain_provider")
        if domain_type == "physicalDomain":
            domain = "uni/phys-{0}".format(self.mso.params.get("domain"))
        elif domain_type == "vmmDomain":
            domain = "uni/vmmp-{0}/dom-{1}".format(VM_DOMAIN_PROVIDER_MAP.get(self.mso.params.get("domain_provider")), self.mso.params.get("domain"))

        if node_id or path or port_channel or virtual_port_channel:
            pod_id = self.mso.get_site_interface_details(
                site_id=self.template.get("l3outTemplate", {}).get("siteId"),
                node=node_id,
                port=path,
                port_channel_uuid=port_channel_uuid,
                virtual_port_channel_uuid=virtual_port_channel_uuid,
            )
            if path or port_channel or virtual_port_channel:
                pod_id = pod_id.get("pod")

        if encapsulation_type and encapsulation_value:
            encap = {"encapType": encapsulation_type, "value": encapsulation_value}

        if parent_type == "node_group":
            parent_match = self.get_l3out_node_group(node_group, l3out_object.details, fail_module=True)
            parent_path = "/l3outTemplate/l3outs/{0}/nodeGroups/{1}".format(l3out_object.index, parent_match.index if parent_match else "-")
        elif parent_type == "floating_svi":
            parent_match = self.get_l3out_floating_svi_interface(l3out_object.details, pod_id, node_id, encap, fail_module=True)
            parent_path = "/l3outTemplate/l3outs/{0}/floatingSviInterfaces/{1}".format(l3out_object.index, parent_match.index if parent_match else "-")
        elif parent_type == "routed":
            parent_match = self.get_l3out_routed_interface(l3out_object.details, pod_id, node_id, path, port_channel_uuid, fail_module=True)
            parent_path = "/l3outTemplate/l3outs/{0}/interfaces/{1}".format(l3out_object.index, parent_match.index if parent_match else "-")
        elif parent_type == "routed_sub":
            parent_match = self.get_l3out_routed_sub_interface(l3out_object.details, pod_id, node_id, path, port_channel_uuid, encap, fail_module=True)
            parent_path = "/l3outTemplate/l3outs/{0}/subInterfaces/{1}".format(l3out_object.index, parent_match.index if parent_match else "-")
        elif parent_type == "svi":
            parent_match = self.get_l3out_svi_interface(
                l3out_object.details, pod_id, node_id, path, encap, port_channel_uuid or virtual_port_channel_uuid, fail_module=True
            )
            parent_path = "/l3outTemplate/l3outs/{0}/sviInterfaces/{1}".format(l3out_object.index, parent_match.index if parent_match else "-")
        elif parent_type == "floating_svi_path_attributes":
            floating_svi_object = self.get_l3out_floating_svi_interface(l3out_object.details, pod_id, node_id, encap, True)
            parent_match = self.get_l3out_floating_svi_interface_path_attributes(floating_svi_object.details, domain_type, domain, fail_module=True)
            parent_path = "/l3outTemplate/l3outs/{0}/floatingSviInterfaces/{1}/svi/floatingPathAttributes/{2}".format(
                l3out_object.index, floating_svi_object.index, parent_match.index if parent_match else "-"
            )

        return parent_match, parent_path

    def set_parent_details_for_nested_object_in_l3out(self, parent_type, parent_object, update_object):
        """
        Set the parent details for a nested object in the L3Out object.
        :param parent_type: The type of the parent object -> Str
        :param parent_object: The parent object details -> Dict
        :param update_object: The object to update with parent details -> Dict
        """
        parent_output_prepend = ""
        if parent_type == "node_group":
            parent_output_prepend = "nodeGroup"
        elif parent_type == "floating_svi":
            parent_output_prepend = "floatingSviInterface"
        elif parent_type == "routed":
            parent_output_prepend = "routedInterface"
        elif parent_type == "routed_sub":
            parent_output_prepend = "routedSubInterface"
        elif parent_type == "svi":
            parent_output_prepend = "sviInterface"
        elif parent_type == "floating_svi_path_attributes":
            parent_output_prepend = "floatingPathAttributes"

        pod_id = parent_object.get("podID")
        if pod_id:
            update_object["{0}PodID".format(parent_output_prepend)] = pod_id

        node_id = parent_object.get("nodeID")
        if node_id:
            update_object["{0}NodeID".format(parent_output_prepend)] = node_id

        path_type = parent_object.get("pathType")
        if path_type:
            update_object["{0}PathType".format(parent_output_prepend)] = path_type

        encap = parent_object.get("encap")
        if encap:
            update_object["{0}Encap".format(parent_output_prepend)] = encap

        path_ref = parent_object.get("pathRef")
        if path_ref:
            # Add pathType and pathRef to the update_object in order to resolve the port_channel or virtual_port_channel
            update_object["pathType"] = path_type
            update_object["pathRef"] = path_ref
            self.update_config_with_port_channel_references(update_object)
            update_object.pop("pathType", None)
            update_object.pop("pathRef", None)
            update_object["{0}PathRef".format(parent_output_prepend)] = path_ref

        path = parent_object.get("path")
        if path:
            update_object["{0}Path".format(parent_output_prepend)] = path

        name = parent_object.get("name")
        if name:
            update_object["{0}Name".format(parent_output_prepend)] = name

        domain = parent_object.get("domain")
        if domain:
            update_object["{0}Domain".format(parent_output_prepend)] = domain

    def get_route_map_policy(self, uuid=None, name=None, template_object=None, fail_module=False):
        """
        Get the Route Map Policy for Route Control by UUID or Name.
        :param uuid: UUID of the Route Map Policy for Route Control to search for -> Str
        :param name: Name of the Route Map Policy for Route Control to search for -> Str
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                When the UUID | Name is existing in the search list -> Dict
                When the UUID | Name is not existing in the search list -> None
                When both UUID and Name are None, and the search list is not empty -> List[Dict]
                When both UUID and Name are None, and the search list is empty -> List[]
        """
        template_object = template_object if template_object else self.template
        match = template_object.get("tenantPolicyTemplate", {}).get("template", {}).get("routeMapPolicies", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "Route Map Policy for Route Control", match, [KVPair("uuid", uuid) if uuid else KVPair("name", name)], fail_module
            )
        return match  # Query all objects

    def get_set_rule_policy_object(self, uuid=None, name=None, search_object=None, fail_module=False):
        """
        Get the Set Rule Policy by uuid or name.
        :param uuid: UUID of the Set Rule Policy to search for -> Str
        :param name: Name of the Set Rule Policy to search for -> Str
        :param search_object: The object to search in -> Dict
        :param fail_module: When match is not found fail the ansible module -> Bool
        :return: Dict | None | List[Dict] | List[]: The processed result which could be:
                 When the UUID | Name is existing in the search list -> Dict
                 When the UUID | Name is not existing in the search list -> None
                 When both UUID and Name are None, and the search list is not empty -> List[Dict]
                 When both UUID and Name are None, and the search list is empty -> List[]
        """
        if not search_object:
            search_object = self.template

        existing_objects = search_object.get("tenantPolicyTemplate", {}).get("template", {}).get("setRulePolicies", [])
        if uuid or name:  # Query a specific object
            return self.get_object_by_key_value_pairs(
                "Set Rule Policy",
                existing_objects,
                [KVPair("uuid", uuid) if uuid else KVPair("name", name)],
                fail_module,
            )

        return existing_objects  # Query all objects
