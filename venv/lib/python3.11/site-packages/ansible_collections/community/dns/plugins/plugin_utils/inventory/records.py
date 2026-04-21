# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# Copyright (c) 2020 Markus Bergholz <markuman+spambelongstogoogle@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import abc
import typing as t
from collections.abc import Sequence

from ansible.errors import AnsibleError
from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.template import Templar
from ansible.utils.display import Display
from ansible_collections.community.dns.plugins.module_utils.conversion.base import (
    DNSConversionError,
)
from ansible_collections.community.dns.plugins.module_utils.conversion.converter import (
    RecordConverter,
)
from ansible_collections.community.dns.plugins.module_utils.provider import (
    ProviderInformation,
    ensure_type,
)
from ansible_collections.community.dns.plugins.module_utils.zone_record_api import (
    DNSAPIAuthenticationError,
    DNSAPIError,
    ZoneRecordAPI,
)
from ansible_collections.community.dns.plugins.plugin_utils.unsafe import make_unsafe
from ansible_collections.community.library_inventory_filtering_v1.plugins.plugin_utils.inventory_filter import (
    filter_host,
    parse_filters,
)


display = Display()


class RecordsInventoryModule(BaseInventoryPlugin, metaclass=abc.ABCMeta):
    VALID_ENDINGS = ("dns.yaml", "dns.yml")
    NAME: str

    def __init__(self) -> None:
        super().__init__()
        self.provider_information: ProviderInformation | None = None
        self.api: ZoneRecordAPI | None = None

    @abc.abstractmethod
    def setup_api(self) -> None:
        """
        This function needs to set up self.provider_information and self.api.
        It can indicate errors by raising DNSAPIError.
        """

    def verify_file(self, path: str) -> bool:
        if super().verify_file(path):
            if path.endswith(self.VALID_ENDINGS):
                return True
            endings = " or ".join(
                ["'{0}'".format(ending) for ending in self.VALID_ENDINGS]
            )
            display.debug(f"{self.NAME} inventory filename must end with {endings}")
        return False

    def parse(
        self, inventory: t.Any, loader: t.Any, path: str, cache: bool = False
    ) -> None:
        super().parse(inventory, loader, path, cache)

        self._read_config_data(path)

        self.templar = Templar(loader=loader)

        try:
            self.setup_api()
            assert self.provider_information is not None
            assert self.api is not None

            record_converter = RecordConverter(self.provider_information, self)
            record_converter.emit_deprecations(display.deprecated)

            zone_name = self.get_option("zone_name")
            if self.templar.is_template(zone_name):
                zone_name = self.templar.template(variable=zone_name)
            zone_id = self.get_option("zone_id")
            if zone_id is not None:
                if self.templar.is_template(zone_id):
                    zone_id = self.templar.template(variable=zone_id)
                # For templating, we need to make the zone_id type 'string' or 'raw'.
                # This converts the value to its proper type expected by the API.
                zone_id_type = self.provider_information.get_record_id_type()
                try:
                    zone_id = ensure_type(zone_id, zone_id_type)
                except TypeError as exc:
                    raise AnsibleError(
                        f"Error while ensuring that zone_id is of type {zone_id_type}: {exc}"
                    )

            if zone_name is not None:
                zone_with_records = self.api.get_zone_with_records_by_name(zone_name)
            elif zone_id is not None:
                zone_with_records = self.api.get_zone_with_records_by_id(zone_id)
            else:
                raise AnsibleError("One of zone_name and zone_id must be specified!")

            if zone_with_records is None:
                raise AnsibleError("Zone does not exist")

            record_converter.process_multiple_from_api(zone_with_records.records)
            record_converter.process_multiple_to_user(zone_with_records.records)

        except DNSConversionError as e:
            raise AnsibleError(f"Error while converting DNS values: {e.error_message}")
        except DNSAPIAuthenticationError as e:
            raise AnsibleError(f"Cannot authenticate: {e}")
        except DNSAPIError as e:
            raise AnsibleError(f"Error: {e}")

        simple_filters = self.get_option("simple_filters")
        filters = parse_filters(self.get_option("filters"))

        filter_types = simple_filters.get("type") or ["A", "AAAA", "CNAME"]
        if not isinstance(filter_types, Sequence) or isinstance(
            filter_types, (str, bytes)
        ):
            filter_types = [filter_types]

        if self.inventory is None:
            raise AssertionError("Inventory must not be None in parse()")
        for record in zone_with_records.records:
            if record.type in filter_types:
                name = zone_with_records.zone.name
                if record.prefix:
                    name = f"{record.prefix}.{name}"
                facts = {
                    "ansible_host": make_unsafe(record.target),
                }
                if not filter_host(self, name, facts, filters):
                    continue

                self.inventory.add_host(name)
                for key, value in facts.items():
                    self.inventory.set_variable(name, key, value)
