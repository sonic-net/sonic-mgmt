#!/usr/bin/env python3

"""
This script assembles the image URLs for a multi-hop upgrade path.
"""

import logging
import os
import argparse
import sys
import re
import requests

# Note the production upgrade paths are defined in Networking-Metadata repo at:
# src/data/Network/ServiceConfigurations/FUSE/FUSCo/UpgradePathDefinitions/UpgradePathDefinition_SONiC.yaml
BASE_UPGRADE_PATH = {
    "SONiC-Arista-7060-ToRRouter": [
        ("IMAGE_BRCM_ABOOT_201811", 105),
        ("IMAGE_BRCM_ABOOT_202012_SLIM", 97),
        ("IMAGE_BRCM_ABOOT_202305_SLIM", 22),
        ("IMAGE_BRCM_ABOOT_202311_SLIM", 30),
    ],
    "SONiC-Arista-7260CX364-ToRRouter": [
        ("IMAGE_BRCM_ABOOT_201811", 105),
        ("IMAGE_BRCM_ABOOT_202012", 97),
        ("IMAGE_BRCM_ABOOT_202305", 22),
        ("IMAGE_BRCM_ABOOT_202311", 30),
    ],
    "SONiC-Mellanox-2700-ToRRouter": [
        ("IMAGE_MLNX_201911", 88),
        ("IMAGE_MLNX_202205", 40),
        ("IMAGE_MLNX_202305", 31),
        ("IMAGE_MLNX_202311", 30),
    ],
    "SONiC-Arista-7050CX3-ToRRouter": [
        ("IMAGE_BRCM_ABOOT_202012", 97),
        ("IMAGE_BRCM_ABOOT_202305", 22),
    ]
}


def build_image_url(img_env_var: str, version: str, use_bjw_image: bool = False) -> str:

    # Look up the URL in the environment
    bjw_prefix = "BJW_" if use_bjw_image and not img_env_var.startswith("BJW_") else ""
    env_var_key = f"{bjw_prefix}{img_env_var}"
    base_image_url = os.environ.get(env_var_key)
    if not base_image_url:
        raise EnvironmentError(f"Environment variable '{env_var_key}' not set.")

    if version == "latest":
        return base_image_url

    # The env var url only contains the YYYYMM of the build but not the DD, therefore search for the
    # full date in the image directory with the info we have to build the full URL
    base_image_url_parts = base_image_url.rsplit("/", 1)
    directory_url = base_image_url_parts[0] + "/"
    base_image_name = base_image_url_parts[1]  # e.g. sonic-aboot-broadcom.swi
    try:
        response = requests.get(directory_url, timeout=60)
        response.raise_for_status()
    except Exception as e:
        raise RuntimeError(f"Failed to fetch directory listing from '{directory_url}': {e}")

    base_image_name_parts = base_image_name.split(".")
    complete_image_name_pattern = \
        (rf'<a href="({base_image_name_parts[0]}-\d{{8}}\.{version}\.{base_image_name_parts[1]})">'
         rf'{base_image_name_parts[0]}-\d{{8}}\.{version}\.{base_image_name_parts[1]}</a>')
    match = re.search(complete_image_name_pattern, response.text)
    if not match:
        raise RuntimeError((f"Failed to find image name matching '{complete_image_name_pattern}' "
                            f"in directory listing {directory_url}."))
    complete_image_name = match.group(1)

    full_image_url = directory_url + complete_image_name
    return full_image_url


def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(message)s")

    parser = argparse.ArgumentParser(
        description="Assemble the image URLs for a multi-hop upgrade path"
    )
    parser.add_argument(
        "--base-upgrade-path",
        type=str,
        required=False,
        dest="base_upgrade_path",
        choices=BASE_UPGRADE_PATH.keys(),
        help="The base upgrade path for the device to follow",
    )
    parser.add_argument(
        "--bjw-lab",
        action="store_true",
        dest="use_bjw_image",
        help="Use BJW lab image URLs",
    )
    parser.add_argument(
        "--additional-upgrade-hop-locations",
        type=str,
        required=False,
        default="",
        dest="additional_upgrade_hop_locations",
        help=("A comma-separated list of additional upgrade hop locations to add to the end of the upgrade path."
              " This gets zipped together with --additional-upgrade-hop-numbers to resolve the image urls."),
    )
    parser.add_argument(
        "--additional-upgrade-hop-numbers",
        type=str,
        required=False,
        default="",
        dest="additional_upgrade_hop_numbers",
        help=("A comma-separated list of additional upgrade hop numbers to add to the end of the upgrade path."
              " This gets zipped together with --additional-upgrade-hop-locations to resolve the image urls."),
    )
    args = parser.parse_args()
    base_upgrade_path = args.base_upgrade_path
    use_bjw_image = args.use_bjw_image
    additional_upgrade_hop_locations = args.additional_upgrade_hop_locations.split(",") \
        if args.additional_upgrade_hop_locations else []
    additional_upgrade_hop_numbers = args.additional_upgrade_hop_numbers.split(",") \
        if args.additional_upgrade_hop_numbers else []

    image_url_hops = []

    # Add the base image paths
    if base_upgrade_path:
        base_image_url_hops = []
        upgrade_path = BASE_UPGRADE_PATH[base_upgrade_path]
        for version_env_var, build_num in upgrade_path:
            image_url = build_image_url(version_env_var, str(build_num), use_bjw_image)
            base_image_url_hops.append(image_url)
        logging.info(f"Base image URL hops: {base_image_url_hops}")
        image_url_hops += base_image_url_hops
    else:
        logging.info("No base upgrade path specified, skipping")

    # Add the additional image paths
    if len(additional_upgrade_hop_locations) != len(additional_upgrade_hop_numbers):
        sys.exit((f"Error: The number of additional upgrade hop locations ({len(additional_upgrade_hop_locations)}) "
                  f"does not match the number of additional upgrade hop numbers "
                  f"({len(additional_upgrade_hop_numbers)})"))
    additional_image_locations_and_numbers = list(zip(additional_upgrade_hop_locations, additional_upgrade_hop_numbers))
    if additional_image_locations_and_numbers:
        additional_image_url_hops = []
        for version_env_var, build_num in additional_image_locations_and_numbers:
            if build_num == "custom":
                # A custom image url has been passed in - no images to build
                image_url = version_env_var
            else:
                image_url = build_image_url(version_env_var, build_num, use_bjw_image)
            additional_image_url_hops.append(image_url)
        logging.info(f"Additional image URL hops: {additional_image_url_hops}")
        image_url_hops += additional_image_url_hops
    else:
        logging.info("No additional upgrade hops specified, skipping")

    if not image_url_hops:
        sys.exit("No image URL hops to process, exiting")

    logging.info("\nUpgrade path image URLs:")
    for image_url in image_url_hops:
        logging.info(f"  {image_url}")

    upgrade_path_image_urls_path = "/tmp/upgrade-path-image-urls.csv"
    with open(upgrade_path_image_urls_path, "w") as upgrade_path_image_urls_file:
        upgrade_path_image_urls_file.write(",".join(image_url_hops))
    logging.info(f"\nWrote upgrade path image URLs to '{upgrade_path_image_urls_path}'")

    return 0  # Success


if __name__ == "__main__":
    main()
