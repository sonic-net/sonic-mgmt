"""AttributeManager: sharded category loader, validator, and priority resolver.

Each test category owns a directory under
``ansible/files/transceiver/inventory/attributes/<category>/`` whose contents
are sharded by ownership scope. The shard contract enforced here mirrors the
File Organization and Loader Validation sections of
``docs/testplan/transceiver/test_plan.md``.

Shard contract (path => merged-tree slot the body is grafted into):

  Category-level: ``<cat>/<cat>.json``
        Body keys are a subset of
        ``mandatory``, ``defaults``, ``dut``,
        ``transceivers`` (only ``transceivers.deployment_configurations``).
  Platform-level: ``<cat>/platforms/<PLATFORM>/<cat>.json``
        Body is grafted at ``tree['platforms'][<PLATFORM>]``.
  HWSKU-level:    ``<cat>/platforms/<PLATFORM>/hwskus/<HWSKU>.json``
        Body is grafted at ``tree['hwskus'][<PLATFORM>][<HWSKU>]`` so that
        the same ``<HWSKU>`` name appearing under two different platform
        directories never collides (each (platform, hwsku) pair is its own
        disjoint leaf and only the current DUT's (platform, hwsku) is
        consulted at resolution time).
  Vendor-level:   ``<cat>/transceivers/vendors/<V>/<cat>.json``
        Body is grafted at ``tree['transceivers']['vendors'][<V>]['defaults']``.
  Per-PN:         ``<cat>/transceivers/vendors/<V>/part_numbers/<PN>/<cat>.json``
        Body is grafted at
        ``tree['transceivers']['vendors'][<V>]['part_numbers'][<PN>]``.

Each non-category shard carries only its scope's body; the scope itself is
encoded in the directory path. Two shards therefore always own disjoint
subtrees of the merged in-memory tree, which removes whole classes of
errors by construction (path/payload mismatch, duplicate leaves, wrapper
typos) -- the directory IS the schema.

The loader fails fast on the remaining violations:

1. Category top-key whitelist: the category-level shard may only define
   ``mandatory`` / ``defaults`` / ``dut`` and
   ``transceivers.deployment_configurations``.
2. Body-shape sanity: every shard body must be a JSON object;
   per-PN reserved sub-slots (``firmware_overrides`` /
   ``platform_hwsku_overrides``) when present must be dict-of-dict.
3. Normalization check: any vendor / PN directory that owns a shard
   must appear in ``normalization_mappings.json``.
4. Mandatory-field resolution: every ``mandatory`` field must resolve via
   the priority hierarchy for every port.

Priority hierarchy (highest to lowest), applied per port:

1. ``dut.<DUT_NAME>``
2. ``transceivers.vendors.<V>.part_numbers.<PN>.platform_hwsku_overrides.<PLATFORM>+<HWSKU>``
3. ``transceivers.vendors.<V>.part_numbers.<PN>.firmware_overrides.<FW_VERSION>``  (reserved)
4. ``transceivers.vendors.<V>.part_numbers.<PN>`` (excluding override slots)
5. ``transceivers.vendors.<V>.defaults``
6. ``transceivers.deployment_configurations.<DEPLOYMENT>``
7. ``hwskus.<PLATFORM>.<HWSKU>`` (scoped by the DUT's platform)
8. ``platforms.<PLATFORM>``
9. ``defaults``
"""

import json
import logging
import os

from .attribute_keys import BASE_ATTRIBUTES_KEY
from .exceptions import AttributeMergeError
from .paths import REL_ATTR_DIR, REL_NORMALIZATION_MAPPINGS_FILE

logger = logging.getLogger(__name__)

ATTRIBUTES_REL_DIR = REL_ATTR_DIR
CATEGORY_SUFFIX = '_ATTRIBUTES'

# Slot names that are reserved within a per-PN block: they hold conditional
# override sub-trees rather than direct attribute leaves.
PN_RESERVED_SUBSLOTS = ('firmware_overrides', 'platform_hwsku_overrides')

# Allowed top-level keys in a category-level shard body.
_CATEGORY_TOP_KEYS = frozenset({'mandatory', 'defaults', 'dut', 'transceivers'})


class AttributeManager:
    """Discover, validate, and merge sharded category attribute files."""

    def __init__(self, repo_root, base_port_dict):
        self.repo_root = repo_root
        self.base_port_dict = base_port_dict
        self._normalized_vendors = None
        self._normalized_pns = None

    # ------------------------------------------------------------------ utils
    @staticmethod
    def _category_key(category_name):
        return f"{category_name.upper()}{CATEGORY_SUFFIX}"

    @staticmethod
    def _load_json(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise AttributeMergeError(f"Failed to load attribute file {file_path}: {e}") from e

    def _load_normalization_sets(self):
        """Load normalized vendor / PN sets used by the shard-directory check.

        Returns two sets of *normalized* names (values of the mapping dicts).
        If the file is missing, returns empty sets so a category-only test
        environment without any vendor / PN shards still works.
        """
        if self._normalized_vendors is not None:
            return self._normalized_vendors, self._normalized_pns
        path = os.path.join(self.repo_root, REL_NORMALIZATION_MAPPINGS_FILE)
        if not os.path.isfile(path):
            self._normalized_vendors = set()
            self._normalized_pns = set()
            return self._normalized_vendors, self._normalized_pns
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            raise AttributeMergeError(
                f"Failed to load normalization_mappings.json: {e}"
            ) from e
        self._normalized_vendors = set(data.get('vendor_names', {}).values())
        self._normalized_pns = set(data.get('part_numbers', {}).values())
        return self._normalized_vendors, self._normalized_pns

    # -------------------------------------------------------- shard discovery
    def _discover_categories(self):
        """Return ``(category_name, category_dir)`` tuples for each subdirectory."""
        attributes_dir = os.path.join(self.repo_root, ATTRIBUTES_REL_DIR)
        if not os.path.isdir(attributes_dir):
            logger.info("Attributes directory %s not present; nothing to load", attributes_dir)
            return []
        categories = []
        for entry in sorted(os.listdir(attributes_dir)):
            full = os.path.join(attributes_dir, entry)
            if os.path.isdir(full):
                categories.append((entry, full))
        return categories

    def _discover_shards(self, category_name, category_dir):
        """Walk a category directory and classify every JSON shard.

        Directory entries are sorted so that shard processing order is
        deterministic across filesystems and Python versions.
        """
        expected_filename = f"{category_name}.json"
        shards = []
        for root, dirs, files in os.walk(category_dir):
            dirs.sort()
            rel = os.path.relpath(root, category_dir)
            parts = [] if rel == '.' else rel.split(os.sep)
            for fname in sorted(files):
                if not fname.endswith('.json'):
                    continue
                full = os.path.join(root, fname)
                shards.append(self._classify_shard(category_name, expected_filename, parts, fname, full))
        return shards

    @staticmethod
    def _classify_shard(category_name, expected_filename, parts, fname, full_path):
        """Classify a shard by its directory path. Raises on unknown locations."""
        if not parts:
            if fname != expected_filename:
                raise AttributeMergeError(
                    f"Unexpected file at category root: {full_path}. "
                    f"Only {expected_filename} is allowed here."
                )
            return ('category', full_path, {})
        if parts[0] == 'platforms':
            if len(parts) == 2:
                if fname != expected_filename:
                    raise AttributeMergeError(
                        f"Unexpected filename {fname} at {full_path}; "
                        f"expected {expected_filename}."
                    )
                return ('platform', full_path, {'platform': parts[1]})
            if len(parts) == 3 and parts[2] == 'hwskus':
                hwsku = fname[:-len('.json')]
                return ('hwsku', full_path, {'platform': parts[1], 'hwsku': hwsku})
            raise AttributeMergeError(
                f"Unrecognized path under platforms/: {full_path}. "
                "Allowed: platforms/<P>/<cat>.json or platforms/<P>/hwskus/<H>.json."
            )
        if parts[:2] == ['transceivers', 'vendors']:
            if len(parts) == 3:
                if fname != expected_filename:
                    raise AttributeMergeError(
                        f"Unexpected filename {fname} at {full_path}; "
                        f"expected {expected_filename}."
                    )
                return ('vendor', full_path, {'vendor': parts[2]})
            if len(parts) == 5 and parts[3] == 'part_numbers':
                if fname != expected_filename:
                    raise AttributeMergeError(
                        f"Unexpected filename {fname} at {full_path}; "
                        f"expected {expected_filename}."
                    )
                return ('pn', full_path, {'vendor': parts[2], 'pn': parts[4]})
            raise AttributeMergeError(
                f"Unrecognized path under transceivers/vendors/: {full_path}."
            )
        raise AttributeMergeError(
            f"Shard {full_path} is not in a recognized location for category "
            f"'{category_name}'."
        )

    # -------------------------------------------------- body-shape validation
    def _validate_shard_body(self, kind, path, meta, body):
        if not isinstance(body, dict):
            raise AttributeMergeError(f"Shard {path}: top-level value must be a JSON object.")
        if kind == 'category':
            extras = set(body.keys()) - _CATEGORY_TOP_KEYS
            if extras:
                raise AttributeMergeError(
                    f"Shard {path}: keys {sorted(extras)} are not allowed at the "
                    f"category level (allowed: {sorted(_CATEGORY_TOP_KEYS)})."
                )
            transceivers = body.get('transceivers', {})
            if not isinstance(transceivers, dict):
                raise AttributeMergeError(f"Shard {path}: 'transceivers' must be an object.")
            bad = set(transceivers.keys()) - {'deployment_configurations'}
            if bad:
                raise AttributeMergeError(
                    f"Shard {path}: only 'transceivers.deployment_configurations' is "
                    f"allowed in a category-level shard (got {sorted(bad)})."
                )
            return
        if kind == 'vendor':
            self._check_vendor_normalized(path, meta['vendor'])
            return
        if kind == 'pn':
            self._check_vendor_normalized(path, meta['vendor'])
            self._check_pn_normalized(path, meta['pn'])
            for slot in PN_RESERVED_SUBSLOTS:
                if slot not in body:
                    continue
                slot_val = body[slot]
                if not isinstance(slot_val, dict):
                    raise AttributeMergeError(
                        f"Shard {path}: '{slot}' must be an object keyed by variant."
                    )
                for variant_key, variant_body in slot_val.items():
                    if not isinstance(variant_body, dict):
                        raise AttributeMergeError(
                            f"Shard {path}: '{slot}.{variant_key}' must be an object."
                        )
            return
        # platform / hwsku: any dict of attributes is acceptable.

    def _check_vendor_normalized(self, path, vendor):
        normalized_vendors, _ = self._load_normalization_sets()
        if vendor not in normalized_vendors:
            raise AttributeMergeError(
                f"Shard {path}: vendor directory '{vendor}' is not registered in "
                "normalization_mappings.json (vendor_names values)."
            )

    def _check_pn_normalized(self, path, pn):
        _, normalized_pns = self._load_normalization_sets()
        if pn not in normalized_pns:
            raise AttributeMergeError(
                f"Shard {path}: PN directory '{pn}' is not registered in "
                "normalization_mappings.json (part_numbers values)."
            )

    # -------------------------------------------- merge + priority resolution
    def _merge_category(self, category_name, shards):
        """Graft each shard body into its merged-tree slot.

        Because each non-category shard owns a disjoint subtree
        (``platforms.<P>``, ``hwskus.<P>.<H>``, ``transceivers.vendors.<V>``...),
        no two shards can collide and a direct assignment per scope suffices.
        Only the category-level body needs key-by-key merging into the root.
        """
        _ = category_name  # reserved for future per-category diagnostics
        tree = {}
        for kind, path, meta, body in shards:
            self._validate_shard_body(kind, path, meta, body)
            if kind == 'category':
                self._graft_category(tree, body)
            elif kind == 'platform':
                tree.setdefault('platforms', {})[meta['platform']] = body
            elif kind == 'hwsku':
                # Scope the HWSKU body by its parent platform so two
                # ``platforms/<P>/hwskus/<H>.json`` shards under different
                # platform directories with the same ``<H>`` filename do not
                # silently overwrite each other based on walk order.
                (tree.setdefault('hwskus', {})
                     .setdefault(meta['platform'], {}))[meta['hwsku']] = body
            elif kind == 'vendor':
                self._vendor_node(tree, meta['vendor'])['defaults'] = body
            elif kind == 'pn':
                pns = self._vendor_node(tree, meta['vendor']).setdefault('part_numbers', {})
                pns[meta['pn']] = body
        return tree

    @staticmethod
    def _vendor_node(tree, vendor):
        return (
            tree
            .setdefault('transceivers', {})
            .setdefault('vendors', {})
            .setdefault(vendor, {})
        )

    @staticmethod
    def _graft_category(tree, body):
        for key in ('mandatory', 'defaults', 'dut'):
            if key in body:
                tree[key] = body[key]
        deployment = body.get('transceivers', {}).get('deployment_configurations')
        if deployment is not None:
            tree.setdefault('transceivers', {})['deployment_configurations'] = deployment

    @staticmethod
    def _resolve_priority(tree, base_attrs, dut_name, platform, hwsku):
        merged = {}
        deployment = base_attrs.get('deployment')
        vendor_name = base_attrs.get('normalized_vendor_name')
        part_number = base_attrs.get('normalized_vendor_pn')
        # ``active_firmware_version`` is a reserved BASE_ATTRIBUTES key:
        # ``DutInfoLoader`` does not currently populate it, so
        # ``firmware_overrides`` shards are silently inert until the producer
        # (planned to live with the CDB firmware upgrade test infrastructure)
        # populates this key per port. The slot is reserved in the schema so
        # contributors do not invent ad-hoc keys for firmware-conditional
        # overrides; the resolver fail-safes to the empty layer when the key
        # is absent.
        firmware_version = base_attrs.get('active_firmware_version')

        defaults_layer = tree.get('defaults', {})
        platform_layer = tree.get('platforms', {}).get(platform, {})
        hwsku_layer = tree.get('hwskus', {}).get(platform, {}).get(hwsku, {})
        dut_layer = tree.get('dut', {}).get(dut_name, {})

        transceivers = tree.get('transceivers', {})
        deployment_layer = {}
        if deployment:
            deployment_layer = transceivers.get('deployment_configurations', {}).get(deployment, {})
        vendor_section = transceivers.get('vendors', {}).get(vendor_name, {}) if vendor_name else {}
        vendor_defaults_layer = vendor_section.get('defaults', {})
        pn_block = vendor_section.get('part_numbers', {}).get(part_number, {}) if part_number else {}

        firmware_layer = {}
        if firmware_version:
            firmware_layer = pn_block.get('firmware_overrides', {}).get(firmware_version, {})
        platform_hwsku_layer = pn_block.get('platform_hwsku_overrides', {}).get(
            f"{platform}+{hwsku}", {}
        )
        pn_attr_layer = {
            k: v for k, v in pn_block.items() if k not in PN_RESERVED_SUBSLOTS
        }

        for layer in (
            defaults_layer,
            platform_layer,
            hwsku_layer,
            deployment_layer,
            vendor_defaults_layer,
            pn_attr_layer,
            firmware_layer,
            platform_hwsku_layer,
            dut_layer,
        ):
            merged.update(layer)
        return merged

    # ------------------------------------------------ schema + mandatory check
    @staticmethod
    def _validate_category_schema(tree, category_name):
        """Schema-level checks that don't depend on any port."""
        mandatory = tree.get('mandatory', [])
        defaults_keys = tree.get('defaults', {}).keys()
        overlap = set(mandatory).intersection(defaults_keys)
        if overlap:
            raise AttributeMergeError(
                f"Category '{category_name}' invalid: fields {sorted(overlap)} "
                "appear in both 'mandatory' and 'defaults'."
            )

    @staticmethod
    def _validate_mandatory(tree, merged, category_name, port_name):
        mandatory = tree.get('mandatory', [])
        missing = [m for m in mandatory if m not in merged]
        if missing:
            raise AttributeMergeError(
                f"Port {port_name}: category '{category_name}' missing mandatory "
                f"fields {missing}."
            )

    # ----------------------------------------------------------- entry point
    def build_port_attributes(self, dut_name, platform, hwsku):
        categories = self._discover_categories()
        if not categories:
            return self.base_port_dict

        for category_name, category_dir in categories:
            shards_raw = self._discover_shards(category_name, category_dir)
            if not shards_raw:
                continue
            shards = [(kind, path, meta, self._load_json(path)) for kind, path, meta in shards_raw]
            tree = self._merge_category(category_name, shards)
            self._validate_category_schema(tree, category_name)
            category_key = self._category_key(category_name)
            logger.info(
                "Loaded category '%s' from %d shard(s) -> key '%s'",
                category_name, len(shards), category_key,
            )
            for port_name, port_data in self.base_port_dict.items():
                base_attrs = port_data.get(BASE_ATTRIBUTES_KEY, {})
                merged = self._resolve_priority(tree, base_attrs, dut_name, platform, hwsku)
                self._validate_mandatory(tree, merged, category_name, port_name)
                port_data[category_key] = merged
        return self.base_port_dict
