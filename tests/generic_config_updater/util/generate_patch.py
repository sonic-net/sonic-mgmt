import json
import jsonpatch
import os

ASICID = "asic0"


def generate_config_patch(full_config_path, no_leaf_config_path):
    """
    Generate a JSON patch file by comparing two configuration files.
    Args:
        full_config_path (str): Path to the full configuration JSON file
        no_leaf_config_path (str): Path to the configuration JSON file without leaf
    Returns:
        str: Path to the generated patch file
    """
    # Load full configuration
    with open(full_config_path, 'r') as file:
        full_config = json.load(file)

    # Load configuration without leaf
    with open(no_leaf_config_path, 'r') as file:
        no_leaf_config = json.load(file)

    # Generate patches
    patches = jsonpatch.make_patch(no_leaf_config, full_config)

    # Add Cluster supported Tables
    filtered_tables = [
        "ACL_TABLE", "BGP_NEIGHBOR", "BUFFER_PG", "CABLE_LENGTH", "DEVICE_NEIGHBOR",
        "DEVICE_NEIGHBOR_METADATA", "PFC_WD", "PORT", "PORTCHANNEL",
        "PORTCHANNEL_INTERFACE", "PORTCHANNEL_MEMBER", "PORT_QOS_MAP"
    ]
    admin_status_tables = ["BGP_NEIGHBOR", "PORT", "PORTCHANNEL"]

    filtered_patch_list = []
    for patch in patches.patch:
        # Get table name from path: /asic0/TABLE_NAME/...
        table_name = patch['path'].split('/')[2] if len(patch['path'].split('/')) > 2 else None

        # Skip if table not supported
        if table_name not in filtered_tables:
            continue

        # Add admin_status for specific tables
        if patch['op'] == 'add' and table_name in admin_status_tables:
            if 'admin_status' not in patch.get('value', {}):
                patch['value']['admin_status'] = 'up'

        filtered_patch_list.append(patch)
    filtered_patch = jsonpatch.JsonPatch(filtered_patch_list)

    # Generate output path in same directory as full config
    output_dir = os.path.dirname(full_config_path)
    output_file = os.path.join(output_dir, 'generated_patch.json')

    # Write patch to file
    with open(output_file, 'w') as file:
        json.dump(filtered_patch.patch, file, indent=4)

    return output_file
