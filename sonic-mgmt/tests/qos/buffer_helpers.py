import ast


class DutDbInfo:
    def __init__(self, duthost):
        self.duthost = duthost
        self.update_db_info()

    def get_asic_db(self):
        return ast.literal_eval(self.duthost.shell('sonic-db-dump -n ASIC_DB -y')['stdout'])

    def get_appl_db(self):
        return ast.literal_eval(self.duthost.shell('sonic-db-dump -n APPL_DB -y')['stdout'])

    def get_config_db(self):
        return ast.literal_eval(self.duthost.shell('sonic-db-dump -n CONFIG_DB -y ')['stdout'])

    def get_port_info_from_config_db(self, port):
        return self.config_db.get("PORT|{}".format(port)).get("value")

    def get_profile_name_from_appl_db(self, table, port, ids):
        return self.appl_db.get("{}:{}:{}".format(table, port, ids)).get("value").get("profile")

    def get_buffer_profile_oid_in_pg_from_asic_db(self, buffer_item_asic_key, asic_key_name):
        return self.asic_db.get(buffer_item_asic_key).get("value").get(asic_key_name)

    def get_profile_info_from_appl_db(self, expected_profile_key):
        return self.appl_db.get(expected_profile_key).get("value")

    def get_buffer_profile_key_from_asic_db(self, buffer_profile_oid):
        for key in self.asic_db.keys():
            if buffer_profile_oid in key:
                return key
        raise Exception("Not find the profile key for {}".format(buffer_profile_oid))

    def get_buffer_profile_info_from_asic_db(self, buffer_profile_key):
        return self.asic_db.get(buffer_profile_key).get("value")

    def update_db_info(self):
        self.config_db = self.get_config_db()
        self.appl_db = self.get_appl_db()
        self.asic_db = self.get_asic_db()
