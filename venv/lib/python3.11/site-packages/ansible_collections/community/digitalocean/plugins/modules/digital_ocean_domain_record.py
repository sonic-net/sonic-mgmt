#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: digital_ocean_domain_record
author: "Adam Papai (@woohgit)"
version_added: 1.1.0
short_description: Manage DigitalOcean domain records
description:
    - Create/delete a domain record in DigitalOcean.
options:
  state:
    description:
     - Indicate desired state of the target.
    default: present
    choices: [ present, absent ]
    type: str
  record_id:
    description:
      - Used with C(force_update=yes) and C(state='absent') to update or delete a specific record.
    type: int
  force_update:
    description:
        - If there is already a record with the same C(name) and C(type) force update it.
    default: false
    type: bool
  domain:
    description:
     - Name of the domain.
    required: true
    type: str
  type:
    description:
     - The type of record you would like to create.
    choices: [ A, AAAA, CNAME, MX, TXT, SRV, NS, CAA ]
    type: str
  data:
    description:
     - This is the value of the record, depending on the record type.
    type: str
  name:
    description:
     - Required for C(A, AAAA, CNAME, TXT, SRV) records. The host name, alias, or service being defined by the record.
    default: "@"
    type: str
  priority:
    description:
     - The priority of the host for C(SRV, MX) records).
    type: int
  port:
    description:
     - The port that the service is accessible on for SRV records only.
    type: int
  weight:
    description:
     - The weight of records with the same priority for SRV records only.
    type: int
  ttl:
    description:
     - Time to live for the record, in seconds.
    default: 1800
    type: int
  flags:
    description:
     - An unsignedinteger between 0-255 used for CAA records.
    type: int
  tag:
    description:
     - The parameter tag for CAA records.
    choices: [ issue, wildissue, iodef ]
    type: str
  oauth_token:
    description:
     - DigitalOcean OAuth token. Can be specified in C(DO_API_KEY), C(DO_API_TOKEN), or C(DO_OAUTH_TOKEN) environment variables
    aliases: ['API_TOKEN']
    type: str

notes:
  - Version 2 of DigitalOcean API is used.
  - The number of requests that can be made through the API is currently limited to 5,000 per hour per OAuth token.
"""

EXAMPLES = """
- name: Create default A record for example.com
  community.digitalocean.digital_ocean_domain_record:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    domain: example.com
    type: A
    name: "@"
    data: 127.0.0.1

- name: Create A record for www
  community.digitalocean.digital_ocean_domain_record:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    domain: example.com
    type: A
    name: www
    data: 127.0.0.1

- name: Update A record for www based on name/type/data
  community.digitalocean.digital_ocean_domain_record:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    domain: example.com
    type: A
    name: www
    data: 127.0.0.2
    force_update: true

- name: Update A record for www based on record_id
  community.digitalocean.digital_ocean_domain_record:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    domain: example.com
    record_id: 123456
    type: A
    name: www
    data: 127.0.0.2
    force_update: true

- name: Remove www record based on name/type/data
  community.digitalocean.digital_ocean_domain_record:
    state: absent
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    domain: example.com
    type: A
    name: www
    data: 127.0.0.1

- name: Remove www record based on record_id
  community.digitalocean.digital_ocean_domain_record:
    state: absent
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    domain: example.com
    record_id: 1234567

- name: Create CNAME records for www, git and status subdomains
  community.digitalocean.digital_ocean_domain_record:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    domain: example.com
    type: CNAME
    name: "{{ item }}"
    data: example.com
  with_items:
    - www
    - git
    - status

- name: Create MX record with priority 10 for example.com
  community.digitalocean.digital_ocean_domain_record:
    state: present
    oauth_token: "{{ lookup('ansible.builtin.env', 'DO_API_TOKEN') }}"
    domain: example.com
    type: MX
    data: mail1.example.com
    priority: 10
"""

RETURN = r"""
data:
    description: a DigitalOcean Domain Record
    returned: success
    type: dict
    sample: {
        "id": 3352896,
        "type": "CNAME",
        "name": "www",
        "data": "192.168.0.1",
        "priority": 10,
        "port": 5556,
        "ttl": 3600,
        "weight": 10,
        "flags": 16,
        "tag": "issue"
    }
"""


from ansible.module_utils.basic import env_fallback
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.digitalocean.plugins.module_utils.digital_ocean import (
    DigitalOceanHelper,
)


class DigitalOceanDomainRecordManager(DigitalOceanHelper, object):
    def __init__(self, module):
        super(DigitalOceanDomainRecordManager, self).__init__(module)
        self.module = module
        self.domain = module.params.get("domain").lower()
        self.records = self.__get_all_records()
        self.payload = self.__build_payload()
        self.force_update = module.params.get("force_update", False)
        self.record_id = module.params.get("record_id", None)

    def check_credentials(self):
        # Check if oauth_token is valid or not
        response = self.get("account")
        if response.status_code == 401:
            self.module.fail_json(
                msg="Failed to login using oauth_token, please verify validity of oauth_token"
            )

    def verify_domain(self):
        # URL https://api.digitalocean.com/v2/domains/[NAME]
        response = self.get("domains/%s" % self.domain)
        status_code = response.status_code
        json = response.json

        if status_code not in (200, 404):
            self.module.fail_json(
                msg="Error getting domain [%(status_code)s: %(json)s]"
                % {"status_code": status_code, "json": json}
            )
        elif status_code == 404:
            self.module.fail_json(
                msg="No domain named '%s' found. Please create a domain first"
                % self.domain
            )

    def __get_all_records(self):
        records = []
        page = 1
        while True:
            # GET /v2/domains/$DOMAIN_NAME/records
            response = self.get(
                "domains/%(domain)s/records?page=%(page)s"
                % {"domain": self.domain, "page": page}
            )
            status_code = response.status_code
            json = response.json

            if status_code != 200:
                self.module.fail_json(
                    msg="Error getting domain records [%(status_code)s: %(json)s]"
                    % {"status_code": status_code, "json": json}
                )

            for record in json["domain_records"]:
                records.append(dict([(str(k), v) for k, v in record.items()]))

            if "pages" in json["links"] and "next" in json["links"]["pages"]:
                page += 1
            else:
                break

        return records

    def __normalize_data(self):
        # for the MX, CNAME, SRV, CAA records make sure the data ends with a dot
        if (
            self.payload["type"] in ["CNAME", "MX", "SRV", "CAA"]
            and self.payload["data"] != "@"
            and not self.payload["data"].endswith(".")
        ):
            data = "%s." % self.payload["data"]
        else:
            data = self.payload["data"]

        return data

    def __find_record_by_id(self, record_id):
        for record in self.records:
            if record["id"] == record_id:
                return record
        return None

    def __get_matching_records(self):
        """Collect exact and similar records

        It returns an exact record if there is any match along with the record_id.
        It also returns multiple records if there is no exact match
        """

        # look for exactly the same record used by (create, delete)
        for record in self.records:
            r = dict(record)
            del r["id"]
            # python3 does not have cmp so let's use the official workaround
            if r == self.payload:
                return r, record["id"], None

        # look for similar records used by (update)
        similar_records = []
        for record in self.records:
            if (
                record["type"] == self.payload["type"]
                and record["name"] == self.payload["name"]
            ):
                similar_records.append(record)

        if similar_records:
            return None, None, similar_records

        # if no exact neither similar records
        return None, None, None

    def __create_record(self):
        # before data comparison, we need to make sure that
        # the payload['data'] is not normalized, but
        # during create/update digitalocean expects normalized data
        self.payload["data"] = self.__normalize_data()

        # POST /v2/domains/$DOMAIN_NAME/records
        response = self.post("domains/%s/records" % self.domain, data=self.payload)
        status_code = response.status_code
        json = response.json
        if status_code == 201:
            changed = True
            return changed, json["domain_record"]
        else:
            self.module.fail_json(
                msg="Error creating domain record [%(status_code)s: %(json)s]"
                % {"status_code": status_code, "json": json}
            )

    def create_or_update_record(self):
        # if record_id is given we need to update the record no matter what
        if self.record_id:
            changed, result = self.__update_record(self.record_id)
            return changed, result

        record, record_id, similar_records = self.__get_matching_records()

        # create the record if no similar or exact record were found
        if not record and not similar_records:
            changed, result = self.__create_record()
            return changed, result

        # no exact match, but we have similar records
        # so if force_update == True we should update it
        if not record and similar_records:
            # if we have 1 similar record
            if len(similar_records) == 1:
                # update if we were told to do it so
                if self.force_update:
                    record_id = similar_records[0]["id"]
                    changed, result = self.__update_record(record_id)
                # if no update was given, create it
                else:
                    changed, result = self.__create_record()
                return changed, result
            # we have multiple similar records, bun not exact match
            else:
                # we have multiple similar records, can't decide what to do
                if self.force_update:
                    self.module.fail_json(
                        msg="Can't update record, too many similar records: %s"
                        % similar_records
                    )
                # create it
                else:
                    changed, result = self.__create_record()
                return changed, result
        # record matches
        else:
            changed = False
            result = "Record has been already created"
            return changed, result

    def __update_record(self, record_id):
        # before data comparison, we need to make sure that
        # the payload['data'] is not normalized, but
        # during create/update digitalocean expects normalized data
        self.payload["data"] = self.__normalize_data()

        # double check if the record exist
        record = self.__find_record_by_id(record_id)

        # record found
        if record:
            # PUT /v2/domains/$DOMAIN_NAME/records/$RECORD_ID
            response = self.put(
                "domains/%(domain)s/records/%(record_id)s"
                % {"domain": self.domain, "record_id": record_id},
                data=self.payload,
            )
            status_code = response.status_code
            json = response.json
            if status_code == 200:
                changed = True
                return changed, json["domain_record"]
            else:
                self.module.fail_json(
                    msg="Error updating domain record [%(status_code)s: %(json)s]"
                    % {"status_code": status_code, "json": json}
                )
        # recond not found
        else:
            self.module.fail_json(
                msg="Error updating domain record. Record does not exist. [%s]"
                % record_id
            )

    def __build_payload(self):
        payload = dict(
            data=self.module.params.get("data"),
            flags=self.module.params.get("flags"),
            name=self.module.params.get("name"),
            port=self.module.params.get("port"),
            priority=self.module.params.get("priority"),
            type=self.module.params.get("type"),
            tag=self.module.params.get("tag"),
            ttl=self.module.params.get("ttl"),
            weight=self.module.params.get("weight"),
        )

        # DigitalOcean stores every data in lowercase except TXT
        if payload["type"] != "TXT" and payload["data"]:
            payload["data"] = payload["data"].lower()

        # digitalocean stores data: '@' if the data=domain
        if payload["data"] == self.domain:
            payload["data"] = "@"

        return payload

    def delete_record(self):
        # if record_id is given, try to find the record based on the id
        if self.record_id:
            record = self.__find_record_by_id(self.record_id)
            record_id = self.record_id
        # if no record_id is given, try to a single matching record
        else:
            record, record_id, similar_records = self.__get_matching_records()
            if not record and similar_records:
                if len(similar_records) == 1:
                    record, record_id = similar_records[0], similar_records[0]["id"]
                else:
                    self.module.fail_json(
                        msg="Can't delete record, too many similar records: %s"
                        % similar_records
                    )
        # record was not found, we're done
        if not record:
            changed = False
            return changed, record
        # record found, lets delete it
        else:
            # DELETE /v2/domains/$DOMAIN_NAME/records/$RECORD_ID.
            response = self.delete(
                "domains/%(domain)s/records/%(id)s"
                % {"domain": self.domain, "id": record_id}
            )
            status_code = response.status_code
            json = response.json
            if status_code == 204:
                changed = True
                msg = "Successfully deleted %s" % record["name"]
                return changed, msg
            else:
                self.module.fail_json(
                    msg="Error deleting domain record. [%(status_code)s: %(json)s]"
                    % {"status_code": status_code, "json": json}
                )


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(choices=["present", "absent"], default="present"),
            oauth_token=dict(
                aliases=["API_TOKEN"],
                no_log=True,
                fallback=(
                    env_fallback,
                    ["DO_API_TOKEN", "DO_API_KEY", "DO_OAUTH_TOKEN"],
                ),
            ),
            force_update=dict(type="bool", default=False),
            record_id=dict(type="int"),
            domain=dict(type="str", required=True),
            type=dict(choices=["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "NS", "CAA"]),
            name=dict(type="str", default="@"),
            data=dict(type="str"),
            priority=dict(type="int"),
            port=dict(type="int"),
            weight=dict(type="int"),
            ttl=dict(type="int", default=1800),
            tag=dict(choices=["issue", "wildissue", "iodef"]),
            flags=dict(type="int"),
        ),
        # TODO
        # somehow define the absent requirements: record_id OR ('name', 'type', 'data')
        required_if=[("state", "present", ("type", "name", "data"))],
    )

    manager = DigitalOceanDomainRecordManager(module)

    # verify credentials and domain
    manager.check_credentials()
    manager.verify_domain()

    state = module.params.get("state")

    if state == "present":
        changed, result = manager.create_or_update_record()
    elif state == "absent":
        changed, result = manager.delete_record()

    module.exit_json(changed=changed, result=result)


if __name__ == "__main__":
    main()
