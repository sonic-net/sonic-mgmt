import xml.etree.ElementTree as ET
import os
import logging
logger = logging.getLogger(__name__)


def remove_xml_entries(file_path, text_to_remove, element_tag_to_check=None, remove_parent_if_matched=True):
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

        # Check if the element's text contains the string to remove
        if tag_matches_criteria and elem.text and text_to_remove in elem.text:
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


def modify_minigraph(minigraph_file, minigraph_data, rsb_mode):
    if "minigraph_interfaces" not in minigraph_data:
        raise RuntimeError("Couldnot find any interface data in minigraph_data")

    all_active_ports = minigraph_data['minigraph_ports'].keys()
    all_active_fp_ports = [x for x in all_active_ports if "-BP" not in x]
    if rsb_mode == "no_front_panel_ports":
        interfaces_to_remove = all_active_fp_ports
        interfaces_not_to_remove = []
    elif rsb_mode == "one_front_panel_port":
        if len(all_active_fp_ports) > 1:
            interfaces_to_remove = all_active_fp_ports[1:]
            interfaces_not_to_remove = [all_active_fp_ports[0]]
        else:
            # This becomes a no-op.
            interfaces_to_remove = []
            interfaces_not_to_remove = all_active_fp_ports

    remove_count = 0
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

        for entry in minigraph_data['minigraph_neighbors']:
            if "-BP" not in entry and entry not in interfaces_not_to_remove:
                remove_count += remove_xml_entries(
                    minigraph_file,
                    text_to_remove=entry,
                    element_tag_to_check=None,
                    remove_parent_if_matched=True)

        for entry, value in minigraph_data['minigraph_ports'].items():
            if "-BP" not in entry and entry not in interfaces_not_to_remove:
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
                    text_to_remove=minigraph_data['minigraph_port_name_to_alias_map'][entry],
                    element_tag_to_check=None,
                    remove_parent_if_matched=True)
    return remove_count
