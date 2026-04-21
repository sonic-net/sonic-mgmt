from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.mso.plugins.module_utils.schema import MSOSchema


class MSOSchemas:
    def __init__(self, mso_module):
        self.mso = mso_module
        self.schemas_by_id = {}
        self.schemas_by_name = {}

    def get_template_from_schema(self, schema_name, schema_id, template_name, template_id, refresh=False):
        if not refresh:
            existing_schema = None

            if schema_id in self.schemas_by_id:
                existing_schema = self.schemas_by_id[schema_id]
            elif schema_name in self.schemas_by_name:
                existing_schema = self.schemas_by_name[schema_name]

            if existing_schema:
                if template_id:
                    existing_schema.set_template_from_id(template_id)
                elif template_name:
                    existing_schema.set_template(template_name)
                return existing_schema

        new_schema = MSOSchema(self.mso, schema_name, template_name, None, schema_id, template_id)
        self.schemas_by_id[new_schema.id] = new_schema
        self.schemas_by_name[new_schema.schema_name] = new_schema
        return new_schema

    def get_epg_uuid(self, epg_obj, epg_uuid):
        """
        Returns the EPG UUID in a given schema, template and ANP.

        :param epg_obj: A dictionary containing the epg reference object. -> Dict
        :param epg_uuid: The EPG UUID to return if specified. -> Str
        :return: The EPG UUID if found, otherwise it fails the module. -> Str
        """
        if epg_uuid:
            return epg_uuid
        schema = self.get_template_from_schema(
            epg_obj.get("schema"),
            epg_obj.get("schema_id"),
            epg_obj.get("template"),
            epg_obj.get("template_id"),
        )
        schema.set_template_anp(epg_obj.get("anp"), epg_obj.get("anp_uuid"), fail_module=True)
        schema.set_template_anp_epg(epg_obj.get("name"), fail_module=True)
        return schema.schema_objects.get("template_anp_epg").details.get("uuid")
