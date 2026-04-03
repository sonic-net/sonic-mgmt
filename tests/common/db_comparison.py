"""
Database comparison utilities for SONiC testing.

This module provides functionality to take snapshots of Redis databases in SONiC
and compare them to identify differences. It supports various SONiC database types
including APPL_DB, CONFIG_DB, and STATE_DB.

Main features:
- Take snapshots of Redis databases
- Compare snapshots and generate detailed diffs
- Filter out volatile/transient data that changes frequently
- Provide metrics on database differences
"""

from enum import Enum
import json
import logging
import os
import re
import copy
from typing import Dict, List, Tuple
from collections import Counter
from dataclasses import dataclass

from tests.common.helpers.custom_msg_utils import add_custom_msg

logger = logging.getLogger(__name__)


def match_key(key, kset):
    """
    Check if a key matches any pattern in the given set.

    Args:
        key (str): The key to match against patterns
        kset (iterable): Set of patterns to match against. Patterns can be:
                        - String prefixes (checked with startswith)
                        - Regular expressions (checked with re.match)

    Returns:
        bool: True if the key matches any pattern in kset, False otherwise
    """
    for k in kset:
        if key.startswith(k):
            return True
        elif re.match(k, key):
            return True
    return False


def dut_dump(redis_cmd, duthost, data_dir, fname):
    """
    Execute a Redis dump command on a DUT and fetch the resulting JSON file.

    Args:
        redis_cmd (str): The Redis dump command to execute on the DUT
        duthost: The DUT host object with shell and fetch capabilities
        data_dir (str): Local directory path where the dump file will be stored
        fname (str): Base filename for the dump file (without extension)

    Returns:
        dict: The parsed JSON content from the Redis dump file

    Raises:
        AssertionError: If the Redis command fails or file operations fail
    """
    db_read = {}

    dump_file = "/tmp/{}.json".format(fname)
    ret = duthost.shell("{} -o {}".format(redis_cmd, dump_file))
    assert ret["rc"] == 0, "Failed to run cmd:{}".format(redis_cmd)

    ret = duthost.fetch(src=dump_file, dest=data_dir)
    dest_file = ret.get("dest", None)

    assert dest_file is not None, "Failed to fetch src={} dest:{}".format(dump_file, data_dir)
    assert os.path.exists(dest_file), "Fetched file not exist: {}".format(dest_file)

    with open(dest_file, "r") as s:
        db_read = json.load(s)
    return db_read


class DBType(Enum):
    """Supported Redis database types in SONiC. Value is their numeric DB index."""
    APPL = 0
    ASIC = 1
    CONFIG = 4
    STATE = 6


# These are the keys/fields that are always ignored during comparison due to their volatile nature
VOLATILE_VALUES = {
    DBType.APPL: {
        "expireat",
        "ttl",
        "last_up_time",
        # These are below the 'LLDP_ENTRY_TABLE:*' top-level keys
        "lldp_rem_time_mark",
    },
    DBType.CONFIG: {
        "expireat",
        "ttl"
    },
    DBType.STATE: {
        "expireat",
        "ttl",
        "timestamp",
        "update_time",
        "last_update_time",
        "lastupdate",
        "successful_sync_time",
        # These are below 'STORAGE_INFO|*'
        "latest_fsio_writes",
        "last_sync_time",
        "total_fsio_reads",
        "latest_fsio_reads",
        "total_fsio_writes",
        "disk_io_writes",
        "disk_io_reads",
        # These are below the 'PROCESS_STATS|*' top-level keys
        "CPU",
        "MEM",
        "PPID",
        "STIME",
        "TIME",
        "TT",
        "UID",
        # These are below 'LAG_TABLE|*' top-level keys
        "setup.pid",
        # These are below 'DOCKER_STATS|*' top-level keys
        "PIDS",
        "MEM_BYTES",
        "MEM%",
        "CPU%",
        # These are below 'TEMPERATURE_INFO|*' top-level keys
        "temperature",
        "maximum_temperature",
        "minimum_temperature",
        # These are below 'PSU_INFO|*' top-level keys
        "power",
        "temp",
        "input_voltage",
        "input_current",
        "voltage",
        "current",
        # These are below 'FAN_INFO|*' top-level keys
        "speed",
        "speed_target",
    }
}


@dataclass
class DbComparisonMetrics:
    """Metrics summarizing the comparison between two DB snapshots"""
    # Count of all keys in a dump unfiltered
    total_a_keys: int = 0
    # Total number of a values including volatile. These are the entries below "values"
    total_a_values_incl_volatile: int = 0
    # Total number of a values excluding volatile. These are the entries below "values"
    total_a_values_excl_volatile: int = 0
    # From a dump how many of these keys were not found in b dump
    num_differing_keys_a: int = 0
    # From a dump how many of these values were not found in b dump or were different to those in b dump
    num_differing_values_a: int = 0
    # Count of all keys in b dump unfiltered
    total_b_keys: int = 0
    # Total number of b values including volatile. These are the entries below "values"
    total_b_values_incl_volatile: int = 0
    # Total number of b values excluding volatile. These are the entries below "values"
    total_b_values_excl_volatile: int = 0
    # From b dump how many of these keys were not found in a dump
    num_differing_keys_b: int = 0
    # From b dump how many of these values were not found in a dump or were different to those in a dump
    num_differing_values_b: int = 0
    # Sum of keys that were only found in a or only found in b - not both
    num_overall_differing_keys: int = 0
    # Total number of differing values including ones only a has, only b has and where both have but they are different
    num_overall_differing_values: int = 0

    def to_dict_with_labels(self, a_label: str, b_label: str) -> dict:
        """
        Convert metrics to a dictionary with custom labels for the two snapshots being compared.

        This method transforms the generic 'a' and 'b' field names in the metrics to use
        custom labels that are more meaningful in the context of the comparison (e.g.,
        'before_reboot' and 'after_reboot').

        Args:
            a_label (str): Label to use for snapshot 'a' metrics (replaces 'a' in field names)
            b_label (str): Label to use for snapshot 'b' metrics (replaces 'b' in field names)

        Returns:
            dict: Dictionary containing all metrics with labeled field names, where:
                - Keys follow pattern: {metric_name}_{label}
                - Includes totals, counts, and difference metrics for both snapshots
                - Contains overall summary metrics for the comparison
        """
        return {
            f"total_{a_label}_keys": self.total_a_keys,
            f"total_{a_label}_values_incl_volatile": self.total_a_values_incl_volatile,
            f"total_{a_label}_values_excl_volatile": self.total_a_values_excl_volatile,
            f"num_differing_keys_{a_label}": self.num_differing_keys_a,
            f"num_differing_values_{a_label}": self.num_differing_values_a,
            f"total_{b_label}_keys": self.total_b_keys,
            f"total_{b_label}_values_incl_volatile": self.total_b_values_incl_volatile,
            f"total_{b_label}_values_excl_volatile": self.total_b_values_excl_volatile,
            f"num_differing_keys_{b_label}": self.num_differing_keys_b,
            f"num_differing_values_{b_label}": self.num_differing_values_b,
            "num_overall_differing_keys": self.num_overall_differing_keys,
            "num_overall_differing_values": self.num_overall_differing_values,
        }

    def populate_diff_metrics_from_diff(self, diff, label_a: str = "a", label_b: str = "b"):
        """
        Calculate and populate metrics based on the provided diff dictionary.

        This method analyzes the diff structure to count differing keys and values,
        updating the metrics fields accordingly. It handles two types of differences:
        1. Top-level keys that exist only in one snapshot
        2. Shared keys with differing values

        Args:
            diff (dict): The diff dictionary containing differences between snapshots
            label_a (str): Label for the first snapshot (default: "a")
            label_b (str): Label for the second snapshot (default: "b")
        """
        num_differing_keys_a = 0
        num_differing_values_a = 0
        num_differing_keys_b = 0
        num_differing_values_b = 0
        num_overall_differing_keys = 0
        num_overall_differing_values = 0
        for tl_key, contents in diff.items():
            if label_a in contents and label_b in contents:
                # There was a diff at the tl_key meaning that this top-level key was only present in one of the dumps
                label_a_content = contents[label_a]
                label_b_content = contents[label_b]
                assert (label_a_content is not None and label_b_content is None) or \
                       (label_b_content is not None and label_a_content is None), \
                       f"Unexpected diff state for {tl_key}: {contents}"
                num_overall_differing_keys += 1

                def _count_values(content):
                    if isinstance(content, dict) and "value" in content:
                        return len(content["value"])
                    assert False, (f"Unexpected label_a_content type for {tl_key}: {label_a_content}. "
                                   f"Type: {type(label_a_content)}")
                if label_a_content is not None:
                    num_differing_keys_a += 1
                    a_content_key_count = _count_values(label_a_content)
                    num_differing_values_a += a_content_key_count
                    num_overall_differing_values += a_content_key_count
                if label_b_content is not None:
                    num_differing_keys_b += 1
                    b_content_key_count = _count_values(label_b_content)
                    num_differing_values_b += b_content_key_count
                    num_overall_differing_values += b_content_key_count

                continue

            if "value" in contents:
                # The top-level keys are the same across both dumps but the values differed
                # e.g. "value": {"txfault1": {"a": null,"b": "N/A"}}
                values = contents["value"]
                num_overall_differing_values += len(values)
                for _, value_content in values.items():
                    label_a_content = value_content.get(label_a, None)
                    if label_a_content is not None:
                        # a has value for this label and it differs
                        num_differing_values_a += 1
                    label_b_content = value_content.get(label_b, None)
                    if label_b_content is not None:
                        # b has value for this label and it differs
                        num_differing_values_b += 1

                continue

            # Should never get here because there is only ever a diff at the top-level key
            # or one of the values within the key
            assert False, f"Unexpected diff state for {tl_key}: {contents}"

        self.num_differing_keys_a = num_differing_keys_a
        self.num_differing_values_a = num_differing_values_a
        self.num_differing_keys_b = num_differing_keys_b
        self.num_differing_values_b = num_differing_values_b
        self.num_overall_differing_keys = num_overall_differing_keys
        self.num_overall_differing_values = num_overall_differing_values


class SnapshotDiff:
    """Container for differing values and metrics of a snapshot comparison for a singleDB supporting metric tracking
    """
    def __init__(self, db_type: DBType, snapshot_a: dict, snapshot_b: dict, label_a: str = "a", label_b: str = "b"):
        self._db_type = db_type
        self._snapshot_a = snapshot_a
        self._snapshot_b = snapshot_b
        self._label_a = label_a
        self._label_b = label_b

        # Start building metrics on snapshot
        self._metrics = DbComparisonMetrics()
        self._metrics.total_a_keys = len(self._snapshot_a)
        self._metrics.total_a_values_incl_volatile, self._metrics.total_a_values_excl_volatile = \
            _sum_total_values(db_type, self._snapshot_a)
        self._metrics.total_b_keys = len(self._snapshot_b)
        self._metrics.total_b_values_incl_volatile, self._metrics.total_b_values_excl_volatile = \
            _sum_total_values(db_type, self._snapshot_b)

        # Build the diff
        if db_type == DBType.STATE:
            state_db_diff = self._diff_state_db_process_stats(self._snapshot_a, self._snapshot_b)
            # Remove all 'PROCESS_STATS|*' keys from the dbs since they've already been diffed
            self._snapshot_a = {k: v for k, v in self._snapshot_a.items() if not k.startswith("PROCESS_STATS|")}
            self._snapshot_b = {k: v for k, v in self._snapshot_b.items() if not k.startswith("PROCESS_STATS|")}
            remaining_diff = self._diff_dict(db_type, self._snapshot_a, self._snapshot_b)
            self._diff = {**state_db_diff, **remaining_diff}
        else:
            self._diff = self._diff_dict(db_type, self._snapshot_a, self._snapshot_b)

        # Now that diff has been built, get metrics on the diff components
        self._metrics.populate_diff_metrics_from_diff(self._diff, label_a=self._label_a, label_b=self._label_b)

    @property
    def diff(self) -> dict:
        return self._diff

    @property
    def metrics(self) -> DbComparisonMetrics:
        return self._metrics

    def _diff_state_db_process_stats(self, state_db_a: dict, state_db_b: dict) -> dict:
        """Between reboots or process restarts the PID can change but there is an
        equivalent process running. This pairs up the PROCESS_STATS entries and diffs
        based on the process running vs not.

        NOTE: That some PROCESS_STATS entries have a CMD: "" i.e. empty but there is still
              a non-zero PPID. In reality these entries form a tree and should be assembled
              into a tree structure and the trees of each compared. For now, this is simply
              a count of process matches. So far this has been adequate.
        """

        # Extract all the CMD entries out of the DB's
        db_a_processes = []
        db_b_processes = []
        for extracted_cmd_store, state_db in [(db_a_processes, state_db_a), (db_b_processes, state_db_b)]:
            for key, content in state_db.items():
                if re.match(r"^PROCESS_STATS\|\d+", key):
                    assert "value" in content and "CMD" in content["value"], \
                        f"Unexpected PROCESS_STATS entry: {key} : {content}"
                    extracted_cmd_store.append(content["value"]["CMD"])

        db_a_processes_counter = Counter(db_a_processes)
        db_b_processes_counter = Counter(db_b_processes)
        db_a_only_processes = list((db_a_processes_counter - db_b_processes_counter).elements())
        db_b_only_processes = list((db_b_processes_counter - db_a_processes_counter).elements())

        if len(db_a_only_processes) == 0 and len(db_b_only_processes) == 0:
            return {}

        value_dict = {}
        # Insert the a only processes first ...
        for i, cmd in enumerate(db_a_only_processes):
            value_dict[f"CMD{i}"] = {self._label_a: cmd, self._label_b: None}
        # ... followed by db_b only processes
        for i, cmd in enumerate(db_b_only_processes, start=len(value_dict)):
            value_dict[f"CMD{i}"] = {self._label_a: None, self._label_b: cmd}

        return {
            "PROCESS_STATS|*": {
                "value": value_dict
            }
        }

    def _diff_dict(self, db_type: DBType, dict_a: dict, dict_b: dict) -> dict:

        result = {}
        always_ignore_keys = set(VOLATILE_VALUES.get(db_type, []))

        a_keys = set(dict_a.keys()) - always_ignore_keys
        b_keys = set(dict_b.keys()) - always_ignore_keys
        a_only_keys = a_keys - b_keys
        b_only_keys = b_keys - a_keys
        keys_in_both = a_keys & b_keys

        # Process a-only keys
        for key in a_only_keys:
            if isinstance(dict_a[key], dict):
                # Remove always ignore keys
                val = copy.deepcopy(dict_a[key])
                _recursively_remove_keys_matching_pattern(val, always_ignore_keys)
            else:
                val = dict_a[key]
            result[key] = {
                self._label_a: val,
                self._label_b: None
            }

        # Process b-only keys
        for key in b_only_keys:
            if isinstance(dict_b[key], dict):
                # Remove always ignore keys
                val = copy.deepcopy(dict_b[key])
                _recursively_remove_keys_matching_pattern(val, always_ignore_keys)
            else:
                val = dict_b[key]
            result[key] = {
                self._label_a: None,
                self._label_b: val
            }

        # Process keys that are in both
        for key in keys_in_both:
            value_a = dict_a[key]
            value_b = dict_b[key]
            if isinstance(value_a, dict) and isinstance(value_b, dict):
                nested_diff = self._diff_dict(db_type, value_a, value_b)
                if nested_diff:
                    result[key] = nested_diff
            elif value_a != value_b:
                result[key] = {
                    self._label_a: value_a,
                    self._label_b: value_b
                }
            # otherwise they are the same and therefore not included in the diff

        return result

    def to_dict(self):
        return {
            "diff": self._diff,
            "metrics": self._metrics.to_dict_with_labels(self._label_a, self._label_b)
        }

    def write_metrics_to_custom_msg(self, pytest_request, msg_suffix: str = ""):
        """Writes the metrics to the pytest custom msg for the test case"""
        path = f"db_comparison.{self._db_type.name.lower()}"
        path += f".{msg_suffix}" if msg_suffix else ""
        add_custom_msg(pytest_request, path, self._metrics.to_dict_with_labels(self._label_a, self._label_b))

    def write_snapshot_to_disk(self, base_dir: str, file_suffix: str = ""):
        content = self.to_dict()
        filename = f"{self._db_type.name.lower()}_diff"
        filename += f"_{file_suffix}" if file_suffix else ""
        filename += ".json"
        filepath = f"{base_dir}/{filename}"
        with open(filepath, "w") as f:
            f.write(json.dumps(content, indent=4, default=str))
        logger.info(f"Wrote snapshot diff to {filepath}")

    def remove_top_level_key(self, top_level_key: str):
        """Removes top-level key from the diff and updates metrics accordingly

        This is useful if you want to ignore an expected difference. For example, if a cold
        reboot snapshot has a key that is expected to be missing from a warm reboot snapshot like
        WARM_RESTART_TABLE in STATE_DB.
        """

        if top_level_key not in self._diff:
            raise ValueError(f"Top-level key {top_level_key} not found in diff")

        contents = self._diff[top_level_key]

        # Recalculate metrics prior to removal
        if self._label_a in contents and self._label_b in contents:
            # This top level key only exists in one of the snapshots
            label_a_content = contents[self._label_a]
            label_b_content = contents[self._label_b]
            if label_a_content is not None:
                self._metrics.num_differing_keys_a -= 1
                a_content_key_count = len(label_a_content["value"])
                self._metrics.num_differing_values_a -= a_content_key_count
                self._metrics.num_overall_differing_values -= a_content_key_count
            if label_b_content is not None:
                self._metrics.num_differing_keys_b -= 1
                b_content_key_count = len(label_b_content["value"])
                self._metrics.num_differing_values_b -= b_content_key_count
                self._metrics.num_overall_differing_values -= b_content_key_count

        elif "value" in contents:
            # The top-level keys are the same across both dumps but the values differed
            # e.g. "value": {"txfault1": {"a": null,"b": "N/A"}}
            values = contents["value"]
            self._metrics.num_overall_differing_values -= len(values)
            for _, value_content in values.items():
                label_a_content = value_content.get(self._label_a, None)
                if label_a_content is not None:
                    # a has value for this label and it differs
                    self._metrics.num_differing_values_a -= 1
                label_b_content = value_content.get(self._label_b, None)
                if label_b_content is not None:
                    # b has value for this label and it differs
                    self._metrics.num_differing_values_b -= 1

        else:
            raise NotImplementedError("Unexpected contents structure")

        # Remove the key
        del self._diff[top_level_key]


def _recursively_remove_keys_matching_pattern(d_for_removal, patterns):
    """
    Recursively remove keys from a dictionary that match any pattern in the given set.

    This function traverses a dictionary structure and removes any keys that match
    patterns in the provided set. It modifies the dictionary in-place and recursively
    processes nested dictionaries.

    Args:
        d_for_removal (dict): Dictionary to remove keys from (modified in-place)
        patterns (iterable): Set of patterns to match against keys using match_key()
    """
    if isinstance(d_for_removal, dict):
        keys_to_remove = [k for k in d_for_removal if match_key(k, patterns)]
        for k in keys_to_remove:
            del d_for_removal[k]
        for v in d_for_removal.values():
            _recursively_remove_keys_matching_pattern(v, patterns)


def _sum_total_values(db_type: DBType, db_dump: dict) -> Tuple[int, int]:
    """Summarize the number of total values in the DB dump."""
    total_incl_volatile = 0
    total_excl_volatile = 0
    always_ignore_keys = VOLATILE_VALUES.get(db_type, [])
    for tl_key, content in db_dump.items():
        assert "value" in content, f"Unexpected entry in {db_type.name} DB: {tl_key} : {content}"
        value_dict = content["value"]
        for key in value_dict:
            total_incl_volatile += 1
            if key not in always_ignore_keys:
                total_excl_volatile += 1
    return total_incl_volatile, total_excl_volatile


class SonicRedisDBSnapshotter:
    """
    Class for taking and comparing Redis database snapshots on SONiC devices.

    This class provides functionality to capture snapshots of Redis databases
    on SONiC devices and compare them to identify differences. It manages
    snapshot storage and provides methods for diff analysis.

    Attributes:
        _duthost: The device under test host object
        _snapshot_base_dir (str): Base directory for storing snapshots
        _snapshots (List[str]): List of snapshot names taken
    """

    def __init__(self, duthost, snapshot_base_dir):
        """
        Initialize the snapshotter with a DUT host and storage directory.

        Args:
            duthost: The device under test host object
            snapshot_base_dir (str): Base directory path where snapshots will be stored
        """
        self._duthost = duthost
        self._snapshot_base_dir = snapshot_base_dir
        os.makedirs(self._snapshot_base_dir, exist_ok=True)
        self._snapshots: List[str] = []

    def take_snapshot(self, snapshot_name: str, snapshot_dbs: List[DBType]):
        """
        Take a snapshot of specified Redis databases on the DUT.

        This method captures the current state of the specified Redis databases
        and stores them as JSON files in a snapshot directory.

        Args:
            snapshot_name (str): Name identifier for this snapshot
            snapshot_dbs (List[DBType]): List of database types to snapshot
        """
        logger.info(f"Taking snapshot: {snapshot_name} for {self._duthost.hostname}")
        # NOTE: Need trailing slash below to avoid additional dir nesting
        snapshot_dir = f"{self._snapshot_base_dir}/{snapshot_name}/"
        os.makedirs(snapshot_dir, exist_ok=True)
        for db in snapshot_dbs:
            cmd = f"redis-dump -d {db.value} --pretty"
            dump = dut_dump(cmd, self._duthost, snapshot_dir, db.name)
            with open(f"{snapshot_dir}/{db.name}.json", "w") as f:
                f.write(json.dumps(dump, indent=4, default=str))

        logger.info(f"Snapshot {snapshot_name} taken for {self._duthost.hostname} at {snapshot_dir}")

    def diff_snapshots(self, snapshot_a: str, snapshot_b: str) -> Dict[DBType, SnapshotDiff]:
        """
        Compare two snapshots and return detailed differences for each database.

        This method loads two previously taken snapshots and compares them,
        generating SnapshotDiff objects for each database type that contains
        the differences and metrics.

        Args:
            snapshot_a (str): Name of the first snapshot to compare
            snapshot_b (str): Name of the second snapshot to compare

        Returns:
            Dict[DBType, SnapshotDiff]: Dictionary mapping database types to their
                                      corresponding SnapshotDiff objects

        Raises:
            AssertionError: If the snapshots don't contain the same database types
        """
        snapshot_a_dir = f"{self._snapshot_base_dir}/{snapshot_a}"
        snapshot_a_dbs = [f for f in os.listdir(snapshot_a_dir) if f.endswith(".json")]

        snapshot_b_dir = f"{self._snapshot_base_dir}/{snapshot_b}"
        snapshot_b_dbs = [f for f in os.listdir(snapshot_b_dir) if f.endswith(".json")]

        assert set(snapshot_a_dbs) == set(snapshot_b_dbs), "Snapshotted dbs do not match. Cannot compare"

        result = {}

        for db_file in snapshot_a_dbs:
            db_name = db_file.replace(".json", "")
            db_type = DBType[db_name]
            if db_type == DBType.ASIC:
                # NOTE: ASIC DB diffing not currently supported
                continue
            db_dump_a = json.load(open(os.path.join(snapshot_a_dir, db_file), 'r'))
            db_dump_b = json.load(open(os.path.join(snapshot_b_dir, db_file), 'r'))
            snapshot_diff = SnapshotDiff(db_type, db_dump_a, db_dump_b, label_a=snapshot_a, label_b=snapshot_b)

            result[db_type] = snapshot_diff

        return result
