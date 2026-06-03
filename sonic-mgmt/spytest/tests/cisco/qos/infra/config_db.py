"""
ConfigDb - A dict-like interface to SONiC CONFIG_DB.

Provides simple read/write access to CONFIG_DB with nested dict semantics.

Usage:
    from config_db import ConfigDb

    config = ConfigDb(dut)

    # Read access
    for profile_name in config["BUFFER_PROFILE"]:
        print(profile_name)

    dscp_map = config["DSCP_TO_TC_MAP"]["OCI_DSCP_TO_TC_DOWNLINK_MAP"]
    print(dscp_map["10"])  # prints TC value

    # Write access (immediately writes to CONFIG_DB)
    config["DSCP_TO_TC_MAP"]["OCI_DSCP_TO_TC_DOWNLINK_MAP"]["10"] = "5"

    # Delete
    del config["BUFFER_PROFILE"]["my_profile"]
"""
import json
from spytest import st


class ConfigDbError(Exception):
    """Raised when a CONFIG_DB operation fails."""
    pass


class ConfigDbView:
    """
    A dict-like view into CONFIG_DB that tracks its path for write operations.

    This class wraps nested dictionaries and records the path taken to reach
    the current level, enabling write-back to the correct Redis key.
    """

    def __init__(self, config_db, path, data):
        """
        Args:
            config_db: Root ConfigDb instance (for write operations)
            path: List of keys traversed to reach this level
            data: The actual dict data at this level
        """
        self._config_db = config_db
        self._path = path
        self._data = data

    def __getitem__(self, key):
        if key not in self._data:
            raise KeyError(f"Key '{key}' not found at path {self._path}")

        value = self._data[key]
        if isinstance(value, dict):
            return ConfigDbView(self._config_db, self._path + [key], value)
        return value

    def __setitem__(self, key, value):
        """Write a value to CONFIG_DB.

        If value is a dict, it initializes the key in the local cache.
        For empty dicts at TABLE|KEY level, no Redis write occurs until
        fields are added (Redis doesn't support empty hashes).
        For non-empty dicts, all fields are written to Redis.
        For scalar values, writes directly to Redis.
        """
        full_path = self._path + [key]

        if isinstance(value, dict):
            # Setting a dict value - initialize in local cache
            if len(full_path) < 2:
                raise ConfigDbError("Cannot set dict at table level")

            # Create the entry in local cache
            self._data[key] = {}

            # If dict is non-empty, write all fields to Redis
            if value:
                redis_key = "|".join(full_path)
                for field, field_value in value.items():
                    self._config_db._hset(redis_key, str(field), str(field_value))
                    self._data[key][field] = field_value
            # If empty dict, just initialize local cache - Redis hash created on first field set
            return

        if len(full_path) < 2:
            raise ConfigDbError("Cannot set value at table level - need at least TABLE|KEY")

        # Redis key format: TABLE|KEY or TABLE|KEY|SUBKEY
        # The field is the last element if we're setting a leaf value
        # For CONFIG_DB: first N-1 elements form the key, last is the field
        redis_key = "|".join(full_path[:-1])
        field = full_path[-1]

        self._config_db._hset(redis_key, field, str(value))
        self._data[key] = value

    def __delitem__(self, key):
        """Delete a key from CONFIG_DB."""
        full_path = self._path + [key]

        if len(full_path) < 2:
            raise ConfigDbError("Cannot delete at table level")

        # If deleting a table entry (path has 2 elements), use DEL
        # If deleting a field (path has 3+ elements), use HDEL
        if len(full_path) == 2:
            redis_key = "|".join(full_path)
            self._config_db._del(redis_key)
        else:
            redis_key = "|".join(full_path[:-1])
            field = full_path[-1]
            self._config_db._hdel(redis_key, field)

        del self._data[key]

    def __contains__(self, key):
        return key in self._data

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def keys(self):
        return self._data.keys()

    def values(self):
        return self._data.values()

    def items(self):
        return self._data.items()

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __repr__(self):
        return f"ConfigDbView(path={self._path}, data={self._data})"


class ConfigDb:
    """
    Dict-like interface to SONiC CONFIG_DB.

    Loads the full CONFIG_DB on init and provides nested dict access.
    Write operations are immediately sent to the DUT.
    """

    def __init__(self, dut):
        """
        Args:
            dut: DUT name/handle for spytest commands
        """
        self._dut = dut
        self._data = self._load()

    def _load(self):
        """Load full CONFIG_DB as nested dict."""
        cmd = "sonic-cfggen -d --print-data"
        # Use trace_log=1 to only log the command, not the full CONFIG_DB output
        # (trace_log=0 doesn't work due to framework bug with `or` logic)
        result = st.show(self._dut, cmd, skip_tmpl=True, skip_error_check=True, trace_log=1)

        if not result:
            raise ConfigDbError("Failed to load CONFIG_DB")

        # The output may contain extra text after the JSON (e.g., shell prompt)
        # Find the JSON object by locating the first '{' and last '}'
        start = result.find('{')
        end = result.rfind('}')

        if start == -1 or end == -1 or end <= start:
            raise ConfigDbError("No valid JSON object found in CONFIG_DB output")

        json_str = result[start:end + 1]

        try:
            data = json.loads(json_str)
            st.log(f"ConfigDb: Loaded {len(data)} tables from CONFIG_DB")
            return data
        except json.JSONDecodeError as e:
            raise ConfigDbError(f"Failed to parse CONFIG_DB JSON: {e}")

    def _hset(self, key, field, value):
        """Set a hash field in CONFIG_DB."""
        cmd = f'sudo redis-cli -n 4 HSET "{key}" "{field}" "{value}"'
        result = st.config(self._dut, cmd)
        # redis-cli HSET returns integer (0 if field existed, 1 if new)
        # Any error would typically show in the output
        if result is None:
            raise ConfigDbError(f"HSET failed for {key}.{field}")
        st.log(f"ConfigDb: HSET {key} {field}={value}")

    def _hdel(self, key, field):
        """Delete a hash field from CONFIG_DB."""
        cmd = f'sudo redis-cli -n 4 HDEL "{key}" "{field}"'
        result = st.config(self._dut, cmd)
        if result is None:
            raise ConfigDbError(f"HDEL failed for {key}.{field}")
        st.log(f"ConfigDb: HDEL {key} {field}")

    def _del(self, key):
        """Delete an entire key from CONFIG_DB."""
        cmd = f'sudo redis-cli -n 4 DEL "{key}"'
        result = st.config(self._dut, cmd)
        if result is None:
            raise ConfigDbError(f"DEL failed for {key}")
        st.log(f"ConfigDb: DEL {key}")

    def refresh(self):
        """Refresh local cache from CONFIG_DB on DUT."""
        self._data = self._load()

    def __getitem__(self, key):
        if key not in self._data:
            raise KeyError(f"Table '{key}' not found in CONFIG_DB")

        value = self._data[key]
        if isinstance(value, dict):
            return ConfigDbView(self, [key], value)
        return value

    def __contains__(self, key):
        return key in self._data

    def __iter__(self):
        return iter(self._data)

    def keys(self):
        return self._data.keys()

    def get(self, key, default=None):
        """Get a table, returning default if not found."""
        try:
            return self[key]
        except KeyError:
            return default

    def __repr__(self):
        tables = list(self._data.keys())[:5]
        return f"ConfigDb(dut={self._dut}, tables={tables}...)"
