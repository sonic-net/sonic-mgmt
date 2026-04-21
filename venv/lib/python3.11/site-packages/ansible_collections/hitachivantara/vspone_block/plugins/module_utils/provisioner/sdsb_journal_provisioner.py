import re

try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.ansible_common import log_entry_exit
    from ..common.sdsb_utils import is_valid_uuid
    from ..message.sdsb_journal_msgs import SDSBJournalValidationMsg
    from ..provisioner.sdsb_vps_provisioner import SDSBVpsProvisioner
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.ansible_common import log_entry_exit
    from common.sdsb_utils import is_valid_uuid
    from message.sdsb_journal_msgs import SDSBJournalValidationMsg
    from provisioner.sdsb_vps_provisioner import SDSBVpsProvisioner


class SDSBJournalProvisioner:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_JOURNAL
        )
        vps_provisioner = SDSBVpsProvisioner(connection_info)

    @log_entry_exit
    def get_journals(self, spec=None):
        if spec:
            if spec.vps_id is not None:
                pattern = (
                    r"^system$|^[A-Fa-f0-9]{8}(-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}$"
                )
                if not re.match(pattern, str(spec.vps_id)):
                    raise ValueError(SDSBJournalValidationMsg.VPS_ID_INVALID.value)
            if spec.number is not None:
                if not isinstance(spec.number, int) or not (0 <= spec.number <= 255):
                    raise ValueError(
                        SDSBJournalValidationMsg.NUMBER_OUT_OF_RANGE.value.format(
                            spec.number
                        )
                    )
            if spec.storage_controller_id is not None:
                if not isinstance(spec.storage_controller_id, str):
                    raise ValueError(
                        SDSBJournalValidationMsg.NUMBER_OUT_OF_RANGE.value.format(
                            spec.storage_controller_id
                        )
                    )
                if spec.storage_controller_id is not None and not is_valid_uuid(
                    spec.storage_controller_id
                ):
                    raise ValueError(SDSBJournalValidationMsg.ID_INVALID.value)

            if spec.vps_name is not None:
                pattern = r"^(?!system$)[\-A-Za-z0-9,\.:@_]{1,32}$"
                if not re.match(pattern, str(spec.vps_name)):
                    raise ValueError(SDSBJournalValidationMsg.VPS_ID_INVALID.value)
        journals = self.gateway.get_journals(spec)
        return journals.data_to_snake_case_list()

    @log_entry_exit
    def delete_journal(self, spec=None):
        journal_id = None
        # id is provided
        if spec and spec.id:
            if not is_valid_uuid(spec.id):
                raise ValueError(SDSBJournalValidationMsg.ID_INVALID.value)
            journal_id = spec.id

        # Number provided
        elif spec and spec.number is not None:
            journal_obj = self.get_journal_by_number(spec.number)

            if not journal_obj or not getattr(journal_obj, "data", None):
                raise ValueError(SDSBJournalValidationMsg.JOURNAL_NUMBER_ABSENT.value)

            existing_data = journal_obj.data[0]
            journal_id = existing_data.id

        else:
            raise ValueError(SDSBJournalValidationMsg.NO_SPEC.value)
        # Delete the journal via API using id
        self.gateway.delete_journal(journal_id)
        self.connection_info.changed = True
        return f"Journal, {journal_id}, is deleted successfully."

    @log_entry_exit
    def get_journal_by_number(self, number):
        return self.gateway.get_journal_by_number(number)

    @log_entry_exit
    def get_journal_by_id(self, id):
        return self.gateway.get_journal_by_id(id)

    @log_entry_exit
    def delete_journal_volume(self, spec=None):

        if not spec.id and not spec.number:
            raise ValueError(SDSBJournalValidationMsg.ID_AND_NUMBER_NOT_PROVIDE.value)
        if not spec.volume_ids:
            raise ValueError(SDSBJournalValidationMsg.VOLUME_IDS_ABSENT.value)
        if spec.id and not is_valid_uuid(spec.id):
            raise ValueError(
                SDSBJournalValidationMsg.JOURNAL_ID_INVALID.value.format(spec.id)
            )
        # Validate all volume IDs
        if spec.volume_ids:
            for vol_id in spec.volume_ids:
                if vol_id is not None and not is_valid_uuid(vol_id):
                    raise ValueError(SDSBJournalValidationMsg.VOLUME_ID_INVALID.value)

        # VPS Resolution
        vps_id = spec.vps_id
        vps_name = spec.vps_name

        if spec.vps_name and not spec.vps_id:
            if not hasattr(self, "vps_provisioner") or self.vps_provisioner is None:
                self.vps_provisioner = SDSBVpsProvisioner(self.connection_info)

            vps_obj = self.vps_provisioner.get_vps_by_name(spec.vps_name)
            if not vps_obj:
                raise ValueError(
                    SDSBJournalValidationMsg.VPS_NAME.value.format(spec.vps_name)
                )
            spec.vps_id = vps_obj.id

        # Resolve journal ID if only number is given
        journal_id = spec.id
        if not journal_id:
            journal_info = self.gateway.get_journal_by_number(spec.number)
            if not journal_info or not getattr(journal_info, "data", None):
                raise ValueError(SDSBJournalValidationMsg.JOURNAL_NUMBER_ABSENT.value)

            existing_data = journal_info.data[0]
            journal_id = existing_data.id

        # Perform shrink operation through gateway
        self.gateway.shrink_journal_by_id(journal_id, spec)
        self.connection_info.changed = True

        # Return updated journal info
        updated_info = self.gateway.get_journal_by_id(journal_id)
        return updated_info.camel_to_snake_dict()

    @log_entry_exit
    def expand_journal_volume(self, spec=None):
        if not spec.id and not spec.number:
            raise ValueError(SDSBJournalValidationMsg.ID_AND_NUMBER_NOT_PROVIDE.value)
        if not spec.volume_ids:
            raise ValueError(SDSBJournalValidationMsg.VOLUME_IDS_ABSENT.value)
        if spec.id and not is_valid_uuid(spec.id):
            raise ValueError(
                SDSBJournalValidationMsg.JOURNAL_ID_INVALID.value.format(spec.id)
            )
        # Validate all volume IDs
        if spec.volume_ids:
            for vol_id in spec.volume_ids:
                if vol_id is not None and not is_valid_uuid(vol_id):
                    raise ValueError(SDSBJournalValidationMsg.VOLUME_ID_INVALID.value)

        # VPS Resolution
        vps_id = getattr(spec, "vps_id", None)
        vps_name = getattr(spec, "vps_name", None)

        if spec.vps_name and not spec.vps_id:
            if not hasattr(self, "vps_provisioner") or self.vps_provisioner is None:
                self.vps_provisioner = SDSBVpsProvisioner(self.connection_info)

            vps_obj = self.vps_provisioner.get_vps_by_name(spec.vps_name)
            if not vps_obj:
                raise ValueError(
                    SDSBJournalValidationMsg.VPS_NAME.value.format(spec.vps_name)
                )
            spec.vps_id = vps_obj.id

        # Resolve journal ID if only number is given
        journal_id = spec.id

        if not journal_id:
            journal_info = self.gateway.get_journal_by_number(spec.number)
            if not journal_info or not getattr(journal_info, "data", None):
                raise ValueError(SDSBJournalValidationMsg.JOURNAL_NUMBER_ABSENT.value)

            existing_data = journal_info.data[0]
            journal_id = existing_data.id

        self.gateway.expand_journal_by_id(journal_id, spec)
        self.connection_info.changed = True

        # Return updated journal info
        updated_info = self.gateway.get_journal_by_id(journal_id)
        return updated_info.camel_to_snake_dict()

    @log_entry_exit
    def is_equal(self, a, b):
        """Recursively compare dicts/lists/values for equality,
        including special handling for mirror_unit structures."""

        # Handle None cases directly
        if a is None and b is None:
            return True
        if a is None or b is None:
            return False

        # comparing mirror_unit (dict) vs mirror_units (list)
        if isinstance(a, list) and isinstance(b, dict) and "number" in b:
            # Find matching mu_number
            mu_number = b.get("number")
            # match = next((mu for mu in a if mu.get("mu_number") == mu_number), None)
            match = next(
                (
                    mu
                    for mu in a
                    if (
                        mu.get("mu_number")
                        if isinstance(mu, dict)
                        else getattr(mu, "muNumber", None)
                    )
                    == mu_number
                ),
                None,
            )

            if not match:
                return False

            # Normalize both sides before comparing
            mapped_existing = {
                "number": match.get("mu_number"),
                "copy_pace": match.get("copy_pace"),
                "data_transfer_speed_bps": match.get("copy_speed"),
            }
            return self.is_equal(mapped_existing, b)

        # Normal dictionary comparison
        if isinstance(a, dict) and isinstance(b, dict):
            if set(a.keys()) != set(b.keys()):
                return False
            return all(self.is_equal(a[k], b[k]) for k in a)

        # List comparison (ignore order)
        if isinstance(a, list) and isinstance(b, list):
            return sorted(a) == sorted(b)

        # comparison
        return a == b

    @log_entry_exit
    def create_update_journal(self, spec):
        """
        Creates, updates, or retrieves a journal depending on spec.
        """
        # Validate journal identifiers
        if not spec.id and not spec.number:
            raise ValueError(SDSBJournalValidationMsg.ID_AND_NUMBER_NOT_PROVIDE.value)
        elif spec.id and not isinstance(spec.id, (str, int)):
            raise ValueError(SDSBJournalValidationMsg.ID_INVALID.value.format(spec.id))
        elif spec.number and not isinstance(spec.number, int):
            raise ValueError(
                SDSBJournalValidationMsg.JOURNAL_ID_INVALID.value.format(spec.number)
            )
        if spec.number:
            if not isinstance(spec.number, int) or not (0 <= spec.number <= 255):
                raise ValueError(
                    SDSBJournalValidationMsg.NUMBER_OUT_OF_RANGE.value.format(
                        spec.number
                    )
                )

        # VPS handling
        if spec.vps_id and spec.vps_name:
            spec.vps_name = None  # vps_id takes precedence
        elif not spec.vps_id and spec.vps_name:
            self.vps_provisioner = SDSBVpsProvisioner(self.connection_info)
            vps_obj = self.vps_provisioner.get_vps_by_name(spec.vps_name)
            if not vps_obj:
                raise ValueError(
                    SDSBJournalValidationMsg.VPS_NAME.value.format(spec.vps_name)
                )
            spec.vps_id = vps_obj.id

        # Main routing logic
        if spec.id:
            return self._handle_by_id(spec)
        elif spec.number is not None:
            return self._handle_by_number(spec)
        else:
            raise ValueError(SDSBJournalValidationMsg.JOURNAL_NUMBER_ABSENT.value)

    # Helper method
    @log_entry_exit
    def _get_meaningful_fields_and_changes(self, spec, existing_data):
        """Extract meaningful fields from spec and detect changes."""

        DEFAULT_FIELDS = {
            "enable_cache_mode": False,
            "enable_inflow_control": False,
            "data_overflow_watch_in_sec": 60,
            "vps_id": None,
            "vps_name": None,
            "mirror_unit": None,
            "volume_ids": None,
        }

        # Extract only user-specified (non-empty) fields
        spec_dict = {
            k: v
            for k, v in spec.__dict__.items()
            if v not in [None, "", []] and k not in ["id", "number"]
        }

        # Remove fields with default values
        meaningful_fields = {
            k: v
            for k, v in spec_dict.items()
            if k not in DEFAULT_FIELDS or v != DEFAULT_FIELDS[k]
        }

        # Mapping from Python field names → API response keys
        API_KEY_MAP = {
            "data_overflow_watch_in_sec": "data_overflow_watch_in_seconds",
            "enable_inflow_control": "is_inflow_control_enabled",
            "enable_cache_mode": "is_cache_mode_enabled",
            "mirror_unit": "mirror_units",
        }

        changed = False
        for k, v in meaningful_fields.items():
            api_key = API_KEY_MAP.get(k, k)
            data = existing_data.camel_to_snake_dict()
            existing_value = data.get(api_key)
            if not self.is_equal(existing_value, v):
                changed = True

        return meaningful_fields, changed

    # Handle by id
    @log_entry_exit
    def _handle_by_id(self, spec):
        """Handles journal update or retrieval by ID."""

        journal_info = self.gateway.get_journal_by_id(spec.id)
        if not journal_info or not getattr(journal_info, "data", None):
            raise ValueError(SDSBJournalValidationMsg.VOLUME_ID_INVALID.value)

        existing_data = journal_info
        journal_id = existing_data.id

        # Use shared helper for field comparison
        meaningful_fields, changed = self._get_meaningful_fields_and_changes(
            spec, existing_data
        )

        if not meaningful_fields:
            self.connection_info.changed = False
            # return camel_dict_to_snake_case(existing_data)
            return existing_data.camel_to_snake_dict()

        if not changed:
            self.connection_info.changed = False
            return existing_data.camel_to_snake_dict()

        # Perform update
        self.gateway.update_journal(journal_id, spec)
        self.connection_info.changed = True
        updated_data = self.get_journal_by_id(journal_id)
        # return camel_dict_to_snake_case(updated_data)
        return updated_data.camel_to_snake_dict()

    # Handle by number
    @log_entry_exit
    def _handle_by_number(self, spec):
        """Handles create, update, or get journal by number."""

        journal_info = self.gateway.get_journal_by_number(spec.number)

        # CASE 1: Journal does not exist → CREATE
        if not journal_info or not getattr(journal_info, "data", None):
            if not spec.volume_ids:
                raise ValueError(SDSBJournalValidationMsg.JOURNAL_NUMBER_ABSENT.value)

            for vol_id in spec.volume_ids:
                if vol_id and not is_valid_uuid(vol_id):
                    raise ValueError(SDSBJournalValidationMsg.VOLUME_ID_INVALID.value)

            created_id = self.gateway.create_journal(spec)
            self.connection_info.changed = True
            data = self.get_journal_by_id(created_id)
            return data.camel_to_snake_dict()

        # CASE 2: Journal exists → UPDATE or GET
        existing_data = journal_info.data[0]
        journal_id = existing_data.id

        # If only fetching by volume_ids
        if spec.volume_ids:
            return existing_data.camel_to_snake_dict()

        # Use shared helper for field comparison
        meaningful_fields, changed = self._get_meaningful_fields_and_changes(
            spec, existing_data
        )

        if not meaningful_fields:
            self.connection_info.changed = False
            return existing_data.camel_to_snake_dict()

        if not changed:
            self.connection_info.changed = False
            return existing_data.camel_to_snake_dict()

        # Perform update
        self.gateway.update_journal(journal_id, spec)
        self.connection_info.changed = True
        updated_data = self.get_journal_by_id(journal_id)
        return updated_data.camel_to_snake_dict()
