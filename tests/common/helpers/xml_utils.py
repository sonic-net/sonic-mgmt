import xml.etree.ElementTree as ET
import os
import logging
import ipaddress
import re
logger = logging.getLogger(__name__)


def _parse_ip_address(text):
    """Return the IP address in text (an optional /prefix is ignored), or None."""
    if not isinstance(text, str):
        return None
    try:
        return ipaddress.ip_address(text.strip().split('/')[0])
    except ValueError:
        return None


def _text_matches(search_text, elem_text, exact_match=False, allowed_suffix=None):
    """Check whether element text matches the text we were asked to remove.

    exact_match=False (default): original behaviour, plain substring match.

    exact_match=True: the whole text, or a whole ';'/','-separated item of it (e.g.
    <AttachTo>PortChannel101;PortChannel102</AttachTo>), must equal the search text,
    so PortChannel1 does not match PortChannel10 and 10.0.0.1 does not match
    10.0.0.10. Surrounding whitespace is ignored. IP addresses are compared as
    addresses (case-insensitive for IPv6, an optional /prefix on either side is
    ignored), so 10.0.0.1 matches both '10.0.0.1' and '10.0.0.1/31'.

    allowed_suffix (exact mode only): regex for a suffix that may follow the search text,
    e.g. '-ASIC' followed by digits lets T1 match T1-ASIC0 but still not T10.
    """
    if not elem_text:
        return False
    if not exact_match:
        return search_text in elem_text
    if not isinstance(search_text, str) or not isinstance(elem_text, str):
        return False
    search = search_text.strip()
    if not search:
        return False
    search_ip = _parse_ip_address(search)
    for item in re.split(r'[;,]', elem_text):
        item = item.strip()
        if not item:
            continue
        if item == search:
            return True
        if allowed_suffix and re.fullmatch(re.escape(search) + allowed_suffix, item):
            return True
        if search_ip is not None and search_ip == _parse_ip_address(item):
            return True
    return False


def remove_xml_entries(file_path, text_to_remove, element_tag_to_check=None, remove_parent_if_matched=True,
                       exact_match=False, allowed_suffix=None):
    """
    Reads an XML file, removes entries related to a specific text, and rewrites the file.

    Args:
        file_path (str): The path to the XML file.
        text_to_remove (str): The text string to search for within elements.
        element_tag_to_check (str, optional): If provided, only checks the text
                                              content of elements with this specific tag.
                                              If None, checks the text of any element.
                                              Defaults to None.
        remove_parent_if_matched (bool, optional): If True, removes the parent element
                                                   of the matched entry. If False, removes
                                                   the matched element itself. Defaults to True.
        exact_match (bool, optional): If False (default), an element matches when
                                      text_to_remove is a substring of its text. If True,
                                      the whole element text must match (IP addresses are
                                      compared as addresses). See _text_matches().
        allowed_suffix (str, optional): With exact_match, regex of a suffix allowed after
                                        text_to_remove (e.g. '-ASIC' followed by digits).
    """
    if not os.path.exists(file_path):
        raise RuntimeError(f"Error: File not found at {file_path}")

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as e:
        raise RuntimeError(f"Error parsing XML file {file_path}: {e}")
    except Exception as e:
        raise RuntimeError(f"An unexpected error occurred while reading {file_path}: {e}")

    # Build a parent map to easily find parents for removal
    # This maps each child element to its direct parent.
    parent_map = {c: p for p in tree.iter() for c in p}

    elements_to_mark_for_removal = set()  # Use a set to avoid marking the same element multiple times

    for elem in root.iter():
        # Determine if this element should be considered for removal based on its tag
        tag_matches_criteria = (element_tag_to_check is None) or (elem.tag == element_tag_to_check)

        # Check if the element's text matches the string to remove
        if tag_matches_criteria and _text_matches(text_to_remove, elem.text, exact_match, allowed_suffix):
            if elem == root:
                # Special handling for root: we can't remove the root itself from a parent.
                # If root matches and we're not removing its parent, we'll clear its content.
                if not remove_parent_if_matched:
                    elements_to_mark_for_removal.add(root)
                else:
                    logger.info(
                        f"Warning: Root element '{root.tag}' matches '{text_to_remove}'"
                        f" and 'remove_parent_if_matched' is True. Cannot remove root's "
                        f"parent. Skipping removal of root.")
            elif remove_parent_if_matched:
                # If we need to remove the parent of the matched element
                if elem in parent_map:
                    elements_to_mark_for_removal.add(parent_map[elem])
            else:
                # If we need to remove the matched element itself
                elements_to_mark_for_removal.add(elem)

    # Perform the removals
    removed_count = 0
    for elem_to_remove in elements_to_mark_for_removal:
        if elem_to_remove == root:
            # If root was marked for removal (and remove_parent_if_matched was False), clear its content
            elem_to_remove.clear()
            logger.info(
                f"Cleared content of root element '{root.tag}' as it matched"
                f" '{text_to_remove}' and was marked for self-removal.")
            removed_count += 1
        elif elem_to_remove in parent_map:
            parent_map[elem_to_remove].remove(elem_to_remove)
            removed_count += 1
        else:
            # This case should ideally not happen if parent_map is correctly built and elem_to_remove is not root
            raise RuntimeError(
                f"Warning: Could not remove element '{elem_to_remove.tag}' "
                f"as its parent was not found in the map.")

    if removed_count == 0:
        logger.info(f"No entries related to '{text_to_remove}' were found or removed.")
        return 0

    try:
        # Write the modified tree back to the file
        # xml_declaration=True ensures <?xml version="1.0" encoding="utf-8"?> is added
        tree.write(file_path, encoding="utf-8", xml_declaration=True)
        logger.info(f"Successfully removed {removed_count} entries of: {text_to_remove} and rewrote {file_path}")
    except Exception as e:
        raise RuntimeError(f"Error writing XML file {file_path}: {e}")
    return removed_count


def modify_minigraph(minigraph_file, minigraph_data, rsb_mode, platform_asic=None):
    if "minigraph_interfaces" not in minigraph_data:
        raise RuntimeError("Couldnot find any interface data in minigraph_data")

    all_active_ports = minigraph_data['minigraph_ports'].keys()
    all_active_fp_ports = [x for x in all_active_ports if "-BP" not in x]

    # By default it is nochange.
    interfaces_to_remove = []
    interfaces_not_to_remove = all_active_fp_ports

    if rsb_mode == "no_front_panel_ports":
        interfaces_to_remove = all_active_fp_ports
        interfaces_not_to_remove = []
    elif rsb_mode == "one_front_panel_port":
        if len(all_active_fp_ports) > 1:
            interfaces_to_remove = all_active_fp_ports[1:]
            interfaces_not_to_remove = [all_active_fp_ports[0]]

    remove_count = 0
    is_broadcom_dnx = platform_asic == "broadcom-dnx"
    if not is_broadcom_dnx:
        for entry in interfaces_to_remove:
            remove_count += remove_xml_entries(
                minigraph_file,
                text_to_remove=entry,
                element_tag_to_check=None,
                remove_parent_if_matched=True)
            remove_count += remove_xml_entries(
                minigraph_file,
                text_to_remove=minigraph_data['minigraph_port_name_to_alias_map'][entry],
                element_tag_to_check=None,
                remove_parent_if_matched=True)

            # TODO: take care of vlan members

            for pc, data in minigraph_data['minigraph_portchannels'].items():
                for member in data['members']:
                    if "-BP" not in member and member not in interfaces_not_to_remove:
                        remove_count += remove_xml_entries(
                            minigraph_file,
                            text_to_remove=member,
                            element_tag_to_check=None,
                            remove_parent_if_matched=False)

            for neighbor in minigraph_data['minigraph_neighbors']:
                if "-BP" not in neighbor and neighbor not in interfaces_not_to_remove:
                    remove_count += remove_xml_entries(
                        minigraph_file,
                        text_to_remove=neighbor,
                        element_tag_to_check=None,
                        remove_parent_if_matched=True)

            for port_name, value in minigraph_data['minigraph_ports'].items():
                if "-BP" not in port_name and port_name not in interfaces_not_to_remove:
                    remove_count += remove_xml_entries(
                        minigraph_file,
                        text_to_remove=value['name'],
                        element_tag_to_check=None,
                        remove_parent_if_matched=True)
                    remove_count += remove_xml_entries(
                        minigraph_file,
                        text_to_remove=value['alias'],
                        element_tag_to_check=None,
                        remove_parent_if_matched=True)
                    remove_count += remove_xml_entries(
                        minigraph_file,
                        text_to_remove=minigraph_data['minigraph_port_name_to_alias_map'][port_name],
                        element_tag_to_check=None,
                        remove_parent_if_matched=True)
    else:
        # On this path names and IP addresses are matched exactly (exact_match=True), so that
        # e.g. PortChannel1 does not also remove PortChannel10..19, or 10.0.0.1 remove 10.0.0.10.
        # Use .get() as the facts of an ASIC may not carry every section (e.g. no portchannels).
        for pc, data in minigraph_data.get('minigraph_portchannels', {}).items():
            for member in data['members']:
                if (member in interfaces_to_remove):
                    remove_count += remove_xml_entries(
                        minigraph_file,
                        text_to_remove=pc,
                        element_tag_to_check=None,
                        remove_parent_if_matched=True,
                        exact_match=True)

        bgp_peer_to_remove = []
        for key, value in minigraph_data.get('minigraph_neighbors', {}).items():
            if key in interfaces_to_remove:
                logger.info('To remove BGP neighbor:{}'.format(value['name']))
                bgp_peer_to_remove.append(value['name'])
                # Match the whole neighbor name (T1 must not remove T10); only an explicit
                # '-ASIC<n>' suffix is allowed, as used by some router declarations.
                remove_count += remove_xml_entries(
                    minigraph_file,
                    text_to_remove=value['name'],
                    element_tag_to_check=None,
                    remove_parent_if_matched=True,
                    exact_match=True,
                    allowed_suffix=r'-ASIC\d+')
            else:
                logger.info('BGP peer that will not be removed in test:{}'.format(value['name']))

        bgp_peers = [
            x for x in minigraph_data.get('minigraph_bgp', [])
            if (
                ("ASIC" not in x['name'])
                and (x['name'] in bgp_peer_to_remove)
            )
        ]

        addr_list = []
        peer_list = []
        for peer in bgp_peers:
            if peer.get('addr'):
                addr_list.append(peer['addr'])
            if peer.get('peer_addr'):
                peer_list.append(peer['peer_addr'])

        addr_list = list(set(addr_list))
        peer_list = list(set(peer_list))

        for addr in addr_list:
            logger.info('To remove addr:{} from minigraph'.format(addr))
            remove_count += remove_xml_entries(
                minigraph_file,
                text_to_remove=addr,
                element_tag_to_check=None,
                remove_parent_if_matched=True,
                exact_match=True)

        for peer in peer_list:
            logger.info('To remove peer addr:{} from minigraph'.format(peer))
            remove_count += remove_xml_entries(
                minigraph_file,
                text_to_remove=peer,
                element_tag_to_check=None,
                remove_parent_if_matched=True,
                exact_match=True)

    return remove_count
