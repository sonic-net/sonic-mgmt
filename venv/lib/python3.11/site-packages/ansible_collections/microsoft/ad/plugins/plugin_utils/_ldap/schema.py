# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

import base64
import typing as t

try:
    import sansldap
except Exception:
    pass  # Check is in __init__.py

from ...filter.ldap_converters import as_guid, as_sid
from .client import SyncLDAPClient


class LDAPSchema:
    def __init__(
        self,
        attribute_types: t.Dict[str, "sansldap.schema.AttributeTypeDescription"],
    ) -> None:
        self.attribute_types = attribute_types

    @classmethod
    def load_schema(cls, client: SyncLDAPClient) -> "LDAPSchema":
        root_dse = client.root_dse
        attribute_types = list(
            client.search(
                filter=sansldap.FilterPresent("objectClass"),
                attributes=["attributeTypes"],
                search_base=root_dse.subschema_subentry,
                search_scope=sansldap.SearchScope.BASE,
            ).values()
        )[0]["attributeTypes"]

        attribute_info: t.Dict[str, sansldap.schema.AttributeTypeDescription] = {}
        for info in attribute_types:
            type_description = sansldap.schema.AttributeTypeDescription.from_string(info.decode("utf-8"))
            if type_description.names:
                attribute_info[type_description.names[0].lower()] = type_description

        return LDAPSchema(attribute_info)

    def cast_object(
        self,
        attribute: str,
        values: t.List[bytes],
    ) -> t.Any:
        info = self.attribute_types.get(attribute.lower(), None)

        caster: t.Callable[[bytes], t.Any]
        if attribute == "objectSid":
            caster = as_sid

        elif attribute == "objectGuid":
            caster = as_guid

        elif not info or not info.syntax:
            caster = _as_str

        elif info.syntax == "1.3.6.1.4.1.1466.115.121.1.7":
            caster = _as_bool

        elif info.syntax in ["1.3.6.1.4.1.1466.115.121.1.27", "1.2.840.113556.1.4.906"]:
            caster = _as_int

        elif info.syntax in ["1.3.6.1.4.1.1466.115.121.1.40", "1.2.840.113556.1.4.907", "OctetString"]:
            caster = _as_bytes

        else:
            caster = _as_str

        casted_values: t.List = []
        for v in values:
            casted_values.append(caster(v))

        if info and info.single_value:
            return casted_values[0] if casted_values else None
        else:
            return casted_values


def _as_bool(value: bytes) -> bool:
    return value == b"TRUE"


def _as_int(value: bytes) -> int:
    return int(value)


def _as_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode()


def _as_str(value: bytes) -> str:
    return value.decode("utf-8", errors="surrogateescape")
