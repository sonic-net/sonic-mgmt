# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# Copyright: (c) 2025, Samita Bhattacharjee (@samiib) <samitab@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from collections import namedtuple

KVPair = namedtuple("KVPair", "key value")
Item = namedtuple("Item", "index details")


class MSOSchema:
    def __init__(self, mso_module, schema_name, template_name=None, site_name=None, schema_id=None, template_id=None):
        self.mso = mso_module
        self.schema_name = schema_name
        if schema_id:
            self.id, self.path, self.schema = mso_module.query_schema_by_id(schema_id)
            self.schema_name = self.schema.get("displayName")
        else:
            self.id, self.path, self.schema = mso_module.query_schema(schema_name)
        self.schema_objects = {}
        self.template_id = template_id
        self.template_name = template_name
        if self.template_id:
            self.set_template_from_id(self.template_id)
        elif self.template_name:
            self.set_template(self.template_name)
        if site_name and self.template_name:
            self.set_site(self.template_name, site_name)

    @staticmethod
    def get_object_from_list(search_list, kv_list):
        """
        Get the first matched object from a list of mso object dictionaries.
        :param search_list: Objects to search through -> List.
        :param kv_list: Key/value pairs that should match in the object. -> List[KVPair(Str, Str)]
        :return: The index and details of the object. -> Item (Named Tuple)
                 Values of provided keys of all existing objects. -> List
        """

        def kv_match(kvs, item):
            return all((item.get(kv.key) == kv.value for kv in kvs))

        match = next((Item(index, item) for index, item in enumerate(search_list) if kv_match(kv_list, item)), None)
        existing = [item.get(kv.key) for item in search_list for kv in kv_list]
        return match, existing

    def validate_schema_objects_present(self, required_schema_objects):
        """
        Validate that attributes are set to a value that is not equal None.
        :param required_schema_objects: List of schema objects to verify. -> List
        :return: None
        """
        for schema_object in required_schema_objects:
            if schema_object not in self.schema_objects.keys():
                msg = "Required attribute '{0}' is not specified on schema instance with name {1}".format(schema_object, self.schema_name)
                self.mso.fail_json(msg=msg)

    def set_template(self, template_name, fail_module=True):
        """
        Get template item that matches the name of a template.
        :param template_name: Name of the template to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Template item. -> Item(Int, Dict) | None
        """

        kv_list = [KVPair("name", template_name)]
        match, existing = self.get_object_from_list(self.schema.get("templates"), kv_list)
        if not match and fail_module:
            msg = "Provided template '{0}' not matching existing template(s): {1}".format(template_name, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.template_id = match.details.get("templateID")
        self.schema_objects["template"] = match

    def set_template_from_id(self, template_id, fail_module=True):
        """
        Get template item that matches the id of a template.
        :param template_id: ID of the template to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Template item. -> Item(Int, Dict) | None
        """
        kv_list = [KVPair("templateID", template_id)]
        match, existing = self.get_object_from_list(self.schema.get("templates"), kv_list)
        if not match and fail_module:
            msg = "Provided template ID '{0}' not matching existing template(s): {1}".format(template_id, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.template_name = match.details.get("name")
        self.schema_objects["template"] = match

    def set_template_vrf(self, vrf, fail_module=True):
        """
        Get template VRF item that matches the name of a VRF.
        :param vrf: Name of the VRF to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Template VRF item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["template"])
        kv_list = [KVPair("name", vrf)]
        match, existing = self.get_object_from_list(self.schema_objects["template"].details.get("vrfs"), kv_list)
        if not match and fail_module:
            msg = "Provided VRF '{0}' not matching existing VRF(s): {1}".format(vrf, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["template_vrf"] = match

    def set_template_vrf_rp(self, ip, fail_module=True):
        """
        Get template VRF RP item that matches the ip of a VRF RP.
        :param ip: IP of the RP to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Template VRF RP item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["template_vrf"])
        kv_list = [KVPair("ipAddress", ip)]
        match, existing = self.get_object_from_list(self.schema_objects["template_vrf"].details.get("rpConfigs"), kv_list)
        if not match and fail_module:
            msg = "Provided IP '{0}' not matching existing IP(s): {1}".format(ip, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["template_vrf_rp"] = match

    def set_template_bd(self, bd, fail_module=True):
        """
        Get template bridge domain item that matches the name of a bd.
        :param bd: Name of the bd to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Template bd item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["template"])
        kv_list = [KVPair("name", bd)]
        match, existing = self.get_object_from_list(self.schema_objects["template"].details.get("bds"), kv_list)
        if not match and fail_module:
            msg = "Provided BD '{0}' not matching existing bd(s): {1}".format(bd, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["template_bd"] = match

    def set_template_bd_dhcp_relay_policy(self, relay_policy_ref, fail_module=True):
        """
        Get template bridge domain dhcp relay policy item that matches the name of a bd.
        :param relay_policy_ref: Reference of the relay policy to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Template bd relay policy item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["template"])
        kv_list = [KVPair("ref", relay_policy_ref)]
        match, existing = self.get_object_from_list(self.schema_objects["template_bd"].details.get("dhcpLabels"), kv_list)
        if not match and fail_module:
            msg = "Provided Relay Policy Reference '{0}' not matching existing relay policy reference(s): {1}".format(relay_policy_ref, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["template_bd_dhcp_relay_policy"] = match

    def set_template_anp(self, anp, anp_uuid=None, fail_module=True):
        """
        Get template application profile item that matches the name of an anp.
        :param anp: Name of the anp to match. -> Str
        :param anp: UUID of the anp to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Template anp item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["template"])
        kv_list = [KVPair("uuid", anp_uuid) if anp_uuid else KVPair("name", anp)]
        match, existing = self.get_object_from_list(self.schema_objects["template"].details.get("anps"), kv_list)
        if not match and fail_module:
            msg = "Provided ANP '{0}' not matching existing anp(s): {1}".format(anp_uuid if anp_uuid else anp, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["template_anp"] = match

    def set_template_anp_epg(self, epg, fail_module=True):
        """
        Get template endpoint group item that matches the name of an epg.
        :param epg: Name of the epg to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Template epg item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["template_anp"])
        kv_list = [KVPair("name", epg)]
        match, existing = self.get_object_from_list(self.schema_objects["template_anp"].details.get("epgs"), kv_list)
        if not match and fail_module:
            msg = "Provided EPG '{0}' not matching existing epg(s): {1}".format(epg, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["template_anp_epg"] = match

    def set_template_anp_epg_contract(self, contract_ref, relation_type, fail_module=True):
        """
        Get template endpoint group contract item that matches the reference and type of an contract.
        :param contract_ref: Reference of the contract to match. -> Str
        :param relation_type: Relation_type of the contract to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Template epg item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["template_anp_epg"])
        kv_list = [KVPair("contractRef", contract_ref), KVPair("relationshipType", relation_type)]
        match, existing = self.get_object_from_list(self.schema_objects["template_anp_epg"].details.get("contractRelationships"), kv_list)
        if not match and fail_module:
            msg = "Provided Contract Reference '{0}' with type '{1}' not matching existing contacts(s): {2}".format(
                contract_ref, relation_type, ", ".join(existing)
            )
            self.mso.fail_json(msg=msg)
        self.schema_objects["template_anp_epg_contract"] = match

    def set_template_anp_epg_useg_attr(self, useg_attr, fail_module=True):
        """
        Get template endpoint group item that matches the name of an EPG uSeg Attribute.
        :param useg_attr: Name of the EPG uSeg Attribute to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Template EPG uSeg Attribute item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["template_anp_epg"])
        kv_list = [KVPair("name", useg_attr)]
        match, existing = self.get_object_from_list(self.schema_objects["template_anp_epg"].details.get("uSegAttrs"), kv_list)
        if not match and fail_module:
            msg = "Provided uSeg Attribute '{0}' does not match the existing uSeg Attribute(s): {1}".format(useg_attr, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["template_anp_epg_useg_attribute"] = match

    def set_template_anp_epg_annotation(self, annotation_key, fail_module=True):
        """
        Get template endpoint group annotation that matches the key of an EPG annotation.
        :param useg_attr: Key of the EPG Annotation to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Template EPG Annotation item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["template_anp_epg"])
        kv_list = [KVPair("tagKey", annotation_key)]
        match, existing = self.get_object_from_list(self.schema_objects["template_anp_epg"].details.get("tagAnnotations"), kv_list)
        if not match and fail_module:
            msg = "Provided Annotation Key '{0}' does not match the existing Annotation(s): {1}".format(annotation_key, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["template_anp_epg_annotation"] = match

    def set_template_external_epg(self, external_epg, fail_module=True):
        """
        Get template external epg item that matches the name of an anp.
        :param anp: Name of the anp to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Template anp item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["template"])
        kv_list = [KVPair("name", external_epg)]
        match, existing = self.get_object_from_list(self.schema_objects["template"].details.get("externalEpgs"), kv_list)
        if not match and fail_module:
            msg = "Provided External EPG '{0}' not matching existing external_epg(s): {1}".format(external_epg, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["template_external_epg"] = match

    def set_site(self, template_name, site_name, fail_module=True):
        """
        Get site item that matches the name of a site.
        :param template_name: Name of the template to match. -> Str
        :param site_name: Name of the site to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Site item. -> Item(Int, Dict) | None
        """
        if not self.schema.get("sites"):
            msg = "No sites associated with schema '{0}'. Associate the site with the schema using (M) mso_schema_site.".format(self.schema_name)
            self.mso.fail_json(msg=msg)

        kv_list = [KVPair("siteId", self.mso.lookup_site(site_name)), KVPair("templateName", template_name)]
        match, existing = self.get_object_from_list(self.schema.get("sites"), kv_list)
        if not match and fail_module:
            msg = "Provided site '{0}' not associated with template '{1}'. Site is currently associated with template(s): {2}".format(
                site_name, template_name, ", ".join(existing[1::2])
            )
            self.mso.fail_json(msg=msg)
        self.schema_objects["site"] = match

    def set_site_bd(self, bd_name, fail_module=True):
        """
        Get site bridge domain item that matches the name of a bd.
        :param bd_name: Name of the bd to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Site bd item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["template", "site"])
        kv_list = [KVPair("bdRef", self.mso.bd_ref(schema_id=self.id, template=self.schema_objects["template"].details.get("name"), bd=bd_name))]
        match, existing = self.get_object_from_list(self.schema_objects["site"].details.get("bds"), kv_list)
        if not match and fail_module:
            msg = "Provided BD '{0}' not matching existing site bd(s): {1}".format(bd_name, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["site_bd"] = match

    def set_site_bd_subnet(self, subnet, fail_module=True):
        """
        Get site bridge domain subnet item that matches the ip of a subnet.
        :param subnet: Subnet (ip) to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Site bd subnet item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["site_bd"])
        kv_list = [KVPair("ip", subnet)]
        match, existing = self.get_object_from_list(self.schema_objects["site_bd"].details.get("subnets"), kv_list)
        if not match and fail_module:
            msg = "Provided subnet '{0}' not matching existing site bd subnet(s): {1}".format(subnet, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["site_bd_subnet"] = match

    def set_site_anp(self, anp_name, fail_module=True):
        """
        Get site application profile item that matches the name of a anp.
        :param anp_name: Name of the anp to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Site anp item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["template_anp", "site"])
        kv_list = [KVPair("anpRef", self.schema_objects["template_anp"].details.get("anpRef"))]
        match, existing = self.get_object_from_list(self.schema_objects["site"].details.get("anps"), kv_list)
        if not match and fail_module:
            msg = "Provided ANP '{0}' not matching existing site anp(s): {1}".format(anp_name, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["site_anp"] = match

    def set_site_anp_epg(self, epg_name, fail_module=True):
        """
        Get site anp epg item that matches the epgs.
        :param epg: epg to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Site anp epg item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["site_anp", "template_anp_epg"])
        kv_list = [KVPair("epgRef", self.schema_objects["template_anp_epg"].details.get("epgRef"))]
        match, existing = self.get_object_from_list(self.schema_objects["site_anp"].details.get("epgs"), kv_list)
        if not match and fail_module:
            msg = "Provided EPG '{0}' not matching existing site anp epg(s): {1}".format(epg_name, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["site_anp_epg"] = match

    def set_site_anp_epg_useg_attr(self, useg_attr, fail_module=True):
        """
        Get site endpoint group item that matches the name of an EPG uSeg Attribute.
        :param useg_attr: Name of the EPG uSeg Attribute to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Site EPG uSeg Attribute item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["site_anp_epg"])
        kv_list = [KVPair("name", useg_attr)]
        match, existing = self.get_object_from_list(self.schema_objects["site_anp_epg"].details.get("uSegAttrs"), kv_list)
        if not match and fail_module:
            msg = "Provided Site uSeg Attribute '{0}' does not match the existing Site uSeg Attribute(s): {1}".format(useg_attr, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["site_anp_epg_useg_attribute"] = match

    def set_site_contract(self, contract_name, fail_module=True):
        """
        Get site contract item that matches the name of a contract.
        :param contract_name: Name of the contract to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Site contract item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["template", "site"])
        kv_list = [
            KVPair(
                "contractRef", self.mso.contract_ref(schema_id=self.id, template=self.schema_objects["template"].details.get("name"), contract=contract_name)
            )
        ]
        match, existing = self.get_object_from_list(self.schema_objects["site"].details.get("contracts"), kv_list)
        if not match and fail_module:
            msg = "Provided Contract '{0}' not matching existing site contract(s): {1}".format(contract_name, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["site_contract"] = match

    def set_site_service_graph(self, site_service_graph, fail_module=True):
        """
        Get site item that matches the name of a service graph.
        :param service_graph: Name of the service graph to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Site service graph item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["template", "site"])

        kv_list = [
            KVPair(
                "serviceGraphRef",
                self.mso.service_graph_ref(schema_id=self.id, template=self.schema_objects["template"].details.get("name"), service_graph=site_service_graph),
            )
        ]

        site_service_graph = self.schema_objects["site"].details.get("serviceGraphs")
        match, existing = self.get_object_from_list(site_service_graph, kv_list)
        if not match and fail_module:
            msg = "Provided Site Service Graph '{0}' not matching existing site service graph(s): {1}".format(site_service_graph, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["site_service_graph"] = match

    def set_site_anp_epg_static_port(self, path, fail_module=True):
        """
        Get site anp epg static port path item that matches the path of Static Port.
        :param path: Path of the Static Port to match. -> Str
        :param fail_module: When match is not found fail the ansible module. -> Bool
        :return: Site anp epg item. -> Item(Int, Dict) | None
        """
        self.validate_schema_objects_present(["site_anp_epg"])
        kv_list = [KVPair("path", path)]
        match, existing = self.get_object_from_list(self.schema_objects["site_anp_epg"].details.get("staticPorts"), kv_list)
        if not match and fail_module:
            msg = "Provided Static Port Path '{0}' not matching existing static port path(s): {1}".format(path, ", ".join(existing))
            self.mso.fail_json(msg=msg)
        self.schema_objects["site_anp_epg_static_port"] = match
