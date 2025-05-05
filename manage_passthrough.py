#!/usr/bin/env python3

import subprocess
import os
import re
from lxml import etree as ET
import yaml
from collections import defaultdict
import sys
import libvirt # Import the libvirt library
from xmldiff import main as xmldiff_main
from xmldiff import formatting as xmldiff_formatting
import argparse
import difflib

def pretty_print_xml(xml_string):
    """Pretty-prints an XML string using minidom and removes the XML declaration."""
    try:
        # Parse the XML string
        # Use lxml's built-in pretty printing
        # Note: Requires parsing first, which might be redundant if already parsed
        root = ET.fromstring(xml_string.encode('utf-8')) # lxml needs bytes
        pretty_xml = ET.tostring(root, pretty_print=True, encoding='unicode', xml_declaration=False)
        return pretty_xml
    except Exception as e:
        print(f"Warning: Could not pretty-print XML for diff: {e}", file=sys.stderr)
        # Fallback to the original string if pretty-printing fails
        return xml_string

def get_pci_details(bdf):
    """Get detailed information for a given PCI BDF."""
    details = {
        'bdf': bdf,
        'vendor_id': None,
        'device_id': None,
        'vendor_device_id': None,
        'driver': None,
        'description': None
    }
    try:
        # Get vendor/device IDs using lspci -nmm
        lspci_output = subprocess.check_output(['lspci', '-nmm', '-s', bdf], text=True, stderr=subprocess.DEVNULL).strip()
        match_vd = re.search(r'\[([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\]', lspci_output)
        if match_vd:
            details['vendor_id'] = match_vd.group(1)
            details['device_id'] = match_vd.group(2)
            details['vendor_device_id'] = f"{match_vd.group(1)}:{match_vd.group(2)}"
        else:
            # Fallback using lspci -n
            lspci_output_n = subprocess.check_output(['lspci', '-n', '-s', bdf], text=True, stderr=subprocess.DEVNULL).strip()
            match_n_vd = re.search(r':\s*([0-9a-fA-F]{4}):([0-9a-fA-F]{4})', lspci_output_n)
            if match_n_vd:
                details['vendor_id'] = match_n_vd.group(1)
                details['device_id'] = match_n_vd.group(2)
                details['vendor_device_id'] = f"{match_n_vd.group(1)}:{match_n_vd.group(2)}"
            else:
                print(f"Warning: Could not extract vendor/device ID for {bdf}", file=sys.stderr)

    except subprocess.CalledProcessError:
        print(f"Warning: Failed to execute lspci for BDF {bdf}", file=sys.stderr)
    except Exception as e:
        print(f"Warning: Error parsing lspci output for BDF {bdf}: {e}", file=sys.stderr)

    # Get driver info from sysfs
    driver_link = f"/sys/bus/pci/devices/{bdf}/driver"
    try:
        if os.path.islink(driver_link):
            driver_path = os.readlink(driver_link)
            details['driver'] = os.path.basename(driver_path)
    except OSError as e:
        # Ignore if path doesn't exist or permission error, means no driver or inaccessible
        if e.errno != 2 and e.errno != 13:
             print(f"Warning: Error checking driver for {bdf}: {e}", file=sys.stderr)
        pass # No driver bound or error reading link

    return details

def get_bdf_from_hostdev_element(hostdev_element):
    """Extracts the physical BDF string from a hostdev XML element."""
    source = hostdev_element.find('./source/address')
    if source is None:
        # Try finding source address directly under hostdev for older formats if needed
        source = hostdev_element.find('./address[@type="pci"]')
        if source is None:
            return None
    # Handle potential missing attributes gracefully, defaulting to typical values
    domain = source.get('domain', '0x0000').replace('0x', '').zfill(4)
    bus = source.get('bus', '0x00').replace('0x', '').zfill(2)
    slot = source.get('slot', '0x00').replace('0x', '').zfill(2)
    # Function might not always be zero
    function = source.get('function', '0').replace('0x', '')
    return f"{domain}:{bus}:{slot}.{function}"

def get_iommu_groups():
    """
    Parses /sys/kernel/iommu_groups to map groups to devices and get device details.

    Returns:
        tuple: (groups, device_to_group, all_device_details)
            groups (dict): group_id -> list of device BDFs
            device_to_group (dict): device BDF -> group_id
            all_device_details (dict): device BDF -> dict of device details (from get_pci_details)
    """
    iommu_base = "/sys/kernel/iommu_groups"
    groups = defaultdict(list)
    device_to_group = {}
    all_device_details = {}

    if not os.path.isdir(iommu_base):
        print(f"Error: IOMMU directory not found at {iommu_base}. Is IOMMU enabled?", file=sys.stderr)
        return {}, {}, {}

    try:
        group_ids = sorted([d for d in os.listdir(iommu_base) if os.path.isdir(os.path.join(iommu_base, d)) and d.isdigit()], key=int)
    except OSError as e:
        print(f"Error reading IOMMU groups directory {iommu_base}: {e}", file=sys.stderr)
        return {}, {}, {}
    except PermissionError:
        print(f"Error: Permission denied when trying to read {iommu_base}. Run as root?", file=sys.stderr)
        return {}, {}, {}

    print(f"Found {len(group_ids)} IOMMU groups. Parsing devices...")
    for group_id_str in group_ids:
        group_path = os.path.join(iommu_base, group_id_str, "devices")
        if not os.path.isdir(group_path):
            continue
        try:
            device_bdfs = os.listdir(group_path)
            for bdf in device_bdfs:
                if re.match(r'^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]$', bdf):
                    groups[group_id_str].append(bdf)
                    device_to_group[bdf] = group_id_str
                    # Get detailed info for each device
                    details = get_pci_details(bdf)
                    all_device_details[bdf] = details
        except OSError as e:
             print(f"Warning: Could not read devices for IOMMU group {group_id_str}: {e}", file=sys.stderr)
        except PermissionError:
             print(f"Warning: Permission denied reading devices for IOMMU group {group_id_str}", file=sys.stderr)

    print("Finished parsing IOMMU groups.")
    return groups, device_to_group, all_device_details

def parse_pci_address(bdf):
    """Parses a BDF string '0000:bb:ss.f' into components needed for XML."""
    # Correct regex: Need to escape the dot.
    match = re.match(r'([0-9a-fA-F]{4}):([0-9a-fA-F]{2}):([0-9a-fA-F]{2})\.([0-9a-fA-F])', bdf)
    if match:
        return {
            'domain': f'0x{match.group(1)}',
            'bus': f'0x{match.group(2)}',
            'slot': f'0x{match.group(3)}',
            'function': f'0x{match.group(4)}'
        }
    return None

def update_vm_definition(vm_name, vm_config, groups, device_to_group, all_device_details):
    """
    Calculates the list of PCI BDFs that should be passed through for a VM based on its config.

    Args:
        vm_name (str): Name of the virtual machine.
        vm_config (dict): Configuration dictionary for the VM.
        groups (dict): IOMMU group ID -> list of device BDFs mapping.
        device_to_group (dict): Device BDF -> IOMMU group ID mapping.
        all_device_details (dict): Device BDF -> detailed info dictionary.

    Returns:
        tuple: (set, int) - A tuple containing:
                 - set: A set of BDF strings to be passed through. None if config invalid.
                 - int: The number of resolution warnings encountered.
            Returns (None, 0) if the VM config is invalid.
    """
    passthrough_requests = vm_config.get('passthrough_devices', []) or []

    # --- Validate passthrough_requests format ---
    if not isinstance(passthrough_requests, list):
        print(f"Error: 'passthrough_devices' for VM '{vm_name}' must be a list of match criteria.", file=sys.stderr)
        return None, 0 # Indicate invalid config
    for i, req in enumerate(passthrough_requests):
        if not isinstance(req, dict) or 'match' not in req or not isinstance(req['match'], dict):
             print(f"Error: Entry {i} in 'passthrough_devices' for VM '{vm_name}' is invalid. Expected format: {{ 'match': {{ key: value, ... }} }}", file=sys.stderr)
             return None, 0 # Indicate invalid config

    print(f"\n--- Analyzing Config for VM: {vm_name} ---")

    # --- Determine the full set of devices needed based on matching criteria and IOMMU groups ---
    final_passthrough_bdfs = set()
    processed_groups = set()
    resolution_warnings = 0
    matched_request_indices = set()

    # Iterate through all known devices found on the host
    for bdf, device_info in all_device_details.items():
        # Check if this device matches any of the requested criteria sets
        for idx, request_set in enumerate(passthrough_requests):
            match_criteria = request_set['match']
            matches_all = True
            if not match_criteria: # Skip empty match blocks
                matches_all = False
                continue

            for key, value in match_criteria.items():
                # Compare criteria key with the corresponding key in device_info
                if key not in device_info:
                    # We don't issue a warning here anymore, just doesn't match
                    # print(f"Debug: Key '{key}' not in device_info for {bdf}. Skipping criteria.", file=sys.stderr)
                    matches_all = False
                    break # Stop checking this criteria set for this device

                device_value = device_info.get(key) # Use .get for safety, though check above helps
                # Simple string comparison for now (case-insensitive)
                if isinstance(device_value, str) and isinstance(value, str):
                    if device_value.lower() != value.lower():
                        matches_all = False
                        break # Stop checking this criteria set for this device
                elif device_value != value: # Allow comparison for non-string types if added later
                     matches_all = False
                     break

            # If this device matched ALL criteria in the current request_set
            if matches_all:
                print(f"  Device {bdf} ({device_info.get('vendor_device_id', 'N/A')}, driver: {device_info.get('driver', 'None')}) matches criteria set {idx+1}: {match_criteria}")
                matched_request_indices.add(idx)

                # Find the IOMMU group for this matched device
                group_id = device_to_group.get(bdf)
                if not group_id:
                    print(f"Warning: Could not find IOMMU group for matched device {bdf}. Cannot add its group.", file=sys.stderr)
                    resolution_warnings += 1
                    continue # Try next request set for this BDF

                # If this group hasn't been processed yet, add all its devices
                if group_id not in processed_groups:
                    print(f"  Device {bdf} is in IOMMU Group {group_id}.")
                    group_devices_bdfs = groups.get(group_id, [])
                    if not group_devices_bdfs:
                        print(f"Warning: IOMMU group {group_id} associated with {bdf} appears empty in parsed data!", file=sys.stderr)
                        resolution_warnings += 1
                    else:
                        print(f"  Checking devices from IOMMU Group {group_id}: {', '.join(group_devices_bdfs)}")
                        # Iterate and filter devices before adding
                        added_from_group = []
                        skipped_count = 0
                        for dev_bdf in group_devices_bdfs:
                            device_details = all_device_details.get(dev_bdf, {})
                            driver = device_details.get('driver')
                            # Check if the device *itself* is a PCIe bridge/switch (more reliable than checking driver)
                            # Use lspci to check the class code. Bridges are class 0x06.
                            # This check might need root if lspci requires it.
                            # Let's stick to the driver check for now to avoid adding root requirement here.
                            if driver == 'pcieport':
                                 print(f"    - Skipping {dev_bdf} (driver: pcieport) as it's likely a bridge/switch.")
                                 skipped_count += 1
                            # Add other drivers to skip if needed (e.g., 'shpchp'?)
                            else:
                                 final_passthrough_bdfs.add(dev_bdf)
                                 added_from_group.append(dev_bdf)

                        if added_from_group:
                            print(f"  Planning to add {len(added_from_group)} device(s) from group {group_id} for {vm_name}: {', '.join(sorted(added_from_group))}")
                        if skipped_count > 0 and not added_from_group:
                             print(f"Warning: All devices in group {group_id} were skipped (likely bridges/switches). Check if the requested device ({bdf}) is actually usable for passthrough.", file=sys.stderr)
                             resolution_warnings += 1 # Count this as a potential issue

                        processed_groups.add(group_id)
                # else: Group already added by a previous match

                # Continue checking other request sets for the same BDF.
                # This allows a BDF to satisfy multiple requests if needed, although
                # its group is added only once.

    # Check if any requested criteria sets were not matched by any device
    unmatched_warnings = False
    for idx, req in enumerate(passthrough_requests):
        if idx not in matched_request_indices and req['match']: # Check non-empty match blocks
            print(f"Warning: No host device found matching criteria set {idx+1} for VM '{vm_name}': {req['match']}", file=sys.stderr)
            resolution_warnings += 1
            unmatched_warnings = True

    if not final_passthrough_bdfs and not unmatched_warnings and passthrough_requests:
        print(f"  No devices matched the criteria for VM '{vm_name}', resulting in an empty passthrough set.")
    elif not passthrough_requests:
        print(f"  No 'passthrough_devices' defined for VM '{vm_name}'.")


    # Return the set of BDFs and the warning count
    return final_passthrough_bdfs, resolution_warnings


def apply_libvirt_changes(conn, vm_name, target_bdfs, all_device_details, non_interactive=False, dry_run=False, debug_xml_file=None):
    """Applies the calculated passthrough changes to a VM using the libvirt API."""

    original_xml_string = None
    modified_xml_string = None
    made_changes_in_tree = False
    resolution_warnings = 0 # Track warnings specific to this phase

    print(f"\n--- Processing Libvirt Definition for VM: {vm_name} ---")

    try:
        try:
            dom = conn.lookupByName(vm_name)
        except libvirt.libvirtError as e:
            print(f"Error: Failed to find domain '{vm_name}': {e}", file=sys.stderr)
            return False # Indicate failure for this VM

        original_xml_string = dom.XMLDesc(0)
        if not original_xml_string:
             print(f"Error: Failed to get XML description for domain '{vm_name}'.", file=sys.stderr)
             return False

        # Parse with lxml, which needs bytes
        parser = ET.XMLParser(remove_blank_text=True, recover=True)
        root = ET.fromstring(original_xml_string.encode('utf-8'), parser=parser)
        devices_element = root.find('./devices')
        if devices_element is None:
            print(f"Error: Cannot find <devices> element in XML for VM '{vm_name}'", file=sys.stderr)
            return False

        # --- Analyze existing vs target --- 
        target_bdfs_set = set(target_bdfs) # Ensure it's a set for efficient lookups

        existing_hostdevs = devices_element.findall("./hostdev[@type='pci'][@mode='subsystem']")
        current_bdf_to_element = {}
        current_bdfs = set()

        for elem in existing_hostdevs:
            bdf = get_bdf_from_hostdev_element(elem)
            if bdf:
                current_bdfs.add(bdf)
                current_bdf_to_element[bdf] = elem
            else:
                # Try to get some identifying info even if parsing fails
                elem_str = ET.tostring(elem, encoding='unicode').strip()
                print(f"Warning: Could not parse BDF from an existing hostdev element in VM '{vm_name}'. Element: {elem_str}. It might be ignored or preserved unexpectedly.", file=sys.stderr)

        bdfs_to_remove = current_bdfs - target_bdfs_set
        bdfs_to_add = target_bdfs_set - current_bdfs
        bdfs_to_keep = current_bdfs.intersection(target_bdfs_set)

        print(f"  Hostdev Analysis: Keep={len(bdfs_to_keep)}, Add={len(bdfs_to_add)}, Remove={len(bdfs_to_remove)}")

        insertion_index = -1
        if existing_hostdevs:
            try:
                # Find the index relative to the parent <devices> element
                insertion_index = devices_element.index(existing_hostdevs[0])
                print(f"  Found existing hostdevs. Modifications will occur around index {insertion_index}.")
            except ValueError:
                print(f"Warning: Could not find index for first hostdev in VM '{vm_name}', new devices will append.", file=sys.stderr)
                insertion_index = -1
        else:
            print(f"  No existing PCI hostdevs found. New devices will be appended.")

        # --- Apply Changes to XML Tree --- 
        made_changes_in_tree = False

        # 1. Remove devices
        removed_count = 0
        if bdfs_to_remove:
            print(f"  Removing {len(bdfs_to_remove)} hostdev element(s):")
            for bdf in sorted(list(bdfs_to_remove)):
                element_to_remove = current_bdf_to_element.get(bdf)
                if element_to_remove is not None:
                    try:
                        devices_element.remove(element_to_remove)
                        print(f"    - Removing: {bdf}")
                        removed_count += 1
                        made_changes_in_tree = True
                    except ValueError:
                        print(f"Warning: Failed to remove element for BDF {bdf} (already removed or detached from tree?) Attempting to ignore.", file=sys.stderr)
                else:
                    print(f"Warning: BDF {bdf} marked for removal but element not found in map.", file=sys.stderr)

        # 2. Add devices
        added_count = 0
        new_dev_index = 0 # Track insertion offset relative to original insertion_index
        if bdfs_to_add:
            print(f"  Adding {len(bdfs_to_add)} new hostdev element(s):")
            for bdf in sorted(list(bdfs_to_add)):
                pci_addr = parse_pci_address(bdf)
                if not pci_addr:
                    print(f"Warning: Could not parse BDF '{bdf}' for adding. Skipping.", file=sys.stderr)
                    resolution_warnings += 1
                    continue

                # Create the new hostdev element *without* the virtual <address>
                hostdev_attrib = {'mode': 'subsystem', 'type': 'pci', 'managed': 'yes'}
                hostdev = ET.Element('hostdev', **hostdev_attrib)
                source = ET.SubElement(hostdev, 'source')
                # Source address uses precise parsed components
                source_address_attrib = {
                    'type': 'pci',
                    'domain': pci_addr['domain'], 'bus': pci_addr['bus'],
                    'slot': pci_addr['slot'], 'function': pci_addr['function']
                }
                ET.SubElement(source, 'address', **source_address_attrib)

                # Insert at the calculated index or append
                actual_insertion_point = -1
                if insertion_index != -1:
                    # Calculate insertion point dynamically based on original index + added count
                    actual_insertion_point = insertion_index + new_dev_index
                    devices_element.insert(actual_insertion_point, hostdev)
                else:
                    devices_element.append(hostdev) # Fallback to appending

                added_count += 1
                new_dev_index += 1 # Increment for next insertion
                made_changes_in_tree = True

                # Print info
                dev_info_print = all_device_details.get(bdf, {})
                insert_pos_str = f"at index {actual_insertion_point}" if actual_insertion_point != -1 else "by appending"
                print(f"    + Adding: {bdf} (Vendor:Device {dev_info_print.get('vendor_device_id', 'N/A')}) {insert_pos_str}")

            if added_count > 0:
                 print(f"  Note: Libvirt will assign virtual PCI slots for the {added_count} newly added device(s)." )

        # --- Final XML String Generation --- 
        if not made_changes_in_tree:
            print(f"  No effective changes required for hostdev elements in VM '{vm_name}'.")
            modified_xml_string = original_xml_string # Use original if no tree changes
        else:
            # Regenerate XML string only if changes were made to the tree
            modified_xml_string = ET.tostring(root, encoding='unicode', xml_declaration=False)

        # --- Save debug XML if requested (do this *after* potential modifications) ---
        if debug_xml_file:
            try:
                print(f"  Saving proposed XML for {vm_name} to '{debug_xml_file}'...")
                pretty_debug_xml = pretty_print_xml(modified_xml_string)
                with open(debug_xml_file, 'w') as f:
                    f.write(pretty_debug_xml)
                print(f"  Successfully saved debug XML.")
            except Exception as e:
                print(f"Warning: Failed to save debug XML to '{debug_xml_file}': {e}", file=sys.stderr)

        # --- Show Diff and Ask for Confirmation ---
        try:
            original_root = ET.fromstring(original_xml_string.encode('utf-8'))
            pretty_original_xml = ET.tostring(original_root, pretty_print=True, encoding='unicode')
        except ET.XMLSyntaxError:
            print("Warning: Could not pretty-print original XML for diff.", file=sys.stderr)
            pretty_original_xml = original_xml_string

        try:
            modified_root = ET.fromstring(modified_xml_string.encode('utf-8'))
            pretty_modified_xml = ET.tostring(modified_root, pretty_print=True, encoding='unicode')
        except ET.XMLSyntaxError:
            print("Warning: Could not pretty-print modified XML for diff.", file=sys.stderr)
            pretty_modified_xml = modified_xml_string

        if pretty_original_xml != pretty_modified_xml:
            try:
                # Use difflib for a more readable text-based diff
                diff_lines = difflib.unified_diff(
                    pretty_original_xml.splitlines(keepends=True),
                    pretty_modified_xml.splitlines(keepends=True),
                    fromfile=f'{vm_name}-original.xml',
                    tofile=f'{vm_name}-proposed.xml',
                    lineterm='\n' # Ensure consistent line endings for diff
                )

                diff_result = "".join(diff_lines) # Join the lines into a single string

                if diff_result:
                    print("\n" + "-" * 15 + f" Proposed changes for {vm_name} (unified diff) " + "-" * 15)
                    # Print line by line to ensure correct terminal output
                    for line in diff_result.splitlines():
                         print(line)
                    print("-" * (30 + len(f" Proposed changes for {vm_name} (unified diff) ")))

                    if dry_run:
                        print("Dry run requested. No changes will be applied.")
                        return True # Indicate success for dry run completion

                    if non_interactive:
                        print("Non-interactive mode: Assuming Yes.")
                        confirm = 'y'
                    else:
                        try:
                            confirm = input("Apply these changes? [y/N]: ").strip().lower()
                        except EOFError:
                            confirm = 'n'
                            print("\nNo input detected, assuming No.", file=sys.stderr)

                    if confirm == 'y':
                        print(f"\nApplying updated definition to libvirt for VM '{vm_name}'...")
                        conn.defineXML(modified_xml_string)
                        print(f"Successfully applied changes to '{vm_name}'.")
                        return True # Indicate success
                    else:
                        print(f"Changes for VM '{vm_name}' aborted by user.")
                        return True # Indicate success (aborted by user is not a script failure)
                else:
                    # This case might occur if only whitespace/formatting differs insignificantly
                    # after pretty printing both versions similarly.
                    print(f"  No significant textual changes detected by diff for VM '{vm_name}'.")
                    return True # Indicate success

            except Exception as e:
                print(f"Error during diff generation or confirmation for VM '{vm_name}': {e}", file=sys.stderr)
                # Don't proceed if diff/confirm fails
                return False # Indicate failure

        else:
            # This case implies made_changes_in_tree was true, but diff showed no change
            # which could happen if only whitespace/comments differed.
            print(f"  No effective changes detected for VM '{vm_name}' after XML processing.")
            return True # Indicate success


    except libvirt.libvirtError as e:
        print(f"Error: Libvirt API error processing VM '{vm_name}': {e}", file=sys.stderr)
        return False
    except ET.XMLSyntaxError as e:
        print(f"Error: Failed to parse XML for VM '{vm_name}': {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error: An unexpected error occurred while applying changes to VM '{vm_name}': {e}", file=sys.stderr)
        return False
    # No finally block needed here as connection is managed outside


def main():
    parser = argparse.ArgumentParser(description="Manage Libvirt PCI passthrough using the libvirt API.")
    parser.add_argument('--config', default='passthrough_config.yaml',
                        help="Path to the YAML configuration file (default: passthrough_config.yaml)")
    parser.add_argument('--debug-xml', metavar='FILENAME',
                        help="Save the proposed XML for each VM to the specified file before applying.")
    parser.add_argument('--yes', '-y', action='store_true',
                        help="Assume yes to confirmation prompts (non-interactive mode).")
    parser.add_argument('--dry-run', action='store_true',
                        help="Show proposed changes (diff) but do not prompt or apply them.")
    parser.add_argument('--vm', action='append', metavar='VM_NAME',
                        help="Target specific VM(s). Can be specified multiple times. If omitted, all VMs in the config are processed.")

    args = parser.parse_args()
    config_file = args.config

    print("Libvirt Passthrough Manager")
    print("=" * 55)

    # --- Step 1: Gather Host Info (Attempt as current user) ---
    print("Gathering IOMMU group and PCI device information...")
    try:
        groups, device_to_group, all_device_details = get_iommu_groups()
        if not device_to_group:
            print("Error: Failed to get IOMMU group or device information. Is IOMMU enabled and are permissions sufficient?", file=sys.stderr)
            # Attempting to run lspci might need root in some cases
            if os.geteuid() != 0:
                 print("Hint: Try running the script with sudo.", file=sys.stderr)
            return 1
    except PermissionError as e:
        print(f"Error: Permission denied during hardware scan: {e}.", file=sys.stderr)
        if os.geteuid() != 0:
            print("Hint: Try running the script with sudo.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error during hardware scan: {e}", file=sys.stderr)
        return 1

    # --- Step 2: Load Configuration (Current User) ---
    print(f"\nLoading configuration from '{config_file}'...")
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file '{config_file}' not found.", file=sys.stderr)
        return 1
    except yaml.YAMLError as e:
        print(f"Error: Failed to parse configuration file '{config_file}': {e}", file=sys.stderr)
        return 1
    except PermissionError:
         print(f"Error: Permission denied reading config file '{config_file}'.", file=sys.stderr)
         return 1
    except Exception as e:
        print(f"Error: Could not read config file '{config_file}': {e}", file=sys.stderr)
        return 1

    if not config or 'vms' not in config or not isinstance(config['vms'], dict):
        print(f"Error: Configuration file '{config_file}' is invalid. It must contain a top-level 'vms' dictionary.", file=sys.stderr)
        return 1
    if not config['vms']:
         print("Info: No VMs defined in the 'vms' section of the configuration file. Nothing to do.")
         return 0

    # --- Step 3: Calculate Proposed Changes (Current User) ---
    print("\nCalculating required passthrough devices based on config...")
    vm_changes = {}
    total_config_vms = len(config['vms'])
    analysis_warnings = 0
    invalid_configs = 0

    # Determine which VMs to process
    if args.vm:
        vms_to_analyze = {vm_name: config['vms'][vm_name] for vm_name in args.vm if vm_name in config['vms']}
        missing_vms = [vm_name for vm_name in args.vm if vm_name not in config['vms']]
        if missing_vms:
            print(f"Warning: The following specified VMs were not found in the config file: {', '.join(missing_vms)}", file=sys.stderr)
        if not vms_to_analyze:
            print("Error: None of the specified VMs were found in the configuration. Nothing to analyze.", file=sys.stderr)
            return 1
    else:
        vms_to_analyze = config['vms']

    total_vms_to_process = len(vms_to_analyze)
    print(f"Analyzing {total_vms_to_process} VM(s) specified for processing.")

    for vm_name, vm_config_data in vms_to_analyze.items():
        if not isinstance(vm_config_data, dict):
            print(f"Warning: Invalid configuration format for VM '{vm_name}' (expected a dictionary). Skipping analysis.", file=sys.stderr)
            invalid_configs += 1
            continue

        target_bdfs, warnings = update_vm_definition(vm_name, vm_config_data, groups, device_to_group, all_device_details)
        analysis_warnings += warnings

        if target_bdfs is not None: # Check for invalid config return from update_vm_definition
            vm_changes[vm_name] = target_bdfs
        else:
            invalid_configs += 1 # Treat invalid config as failure

    if analysis_warnings > 0:
        print(f"\nNote: Encountered {analysis_warnings} warnings during device resolution analysis.")

    if not vm_changes and invalid_configs == total_vms_to_process:
         print("Error: All processed VM configurations were invalid. Cannot proceed.", file=sys.stderr)
         return 1
    elif not vm_changes:
         print("\nInfo: Analysis complete. No VMs require passthrough device changes based on current config.")
         return 0

    # --- Step 4: Check Privileges and Potentially Re-invoke --- 
    if os.geteuid() != 0:
        if args.dry_run:
            print("\n-- DRY RUN --")
            print("Running as non-root. Cannot connect to libvirt to show diff or apply changes.")
            print("Planned actions based on analysis:")
            for vm_name, bdfs in vm_changes.items():
                 if bdfs:
                     print(f"  - {vm_name}: Propose passing through {len(bdfs)} device(s): {', '.join(sorted(list(bdfs)))}")
                 else:
                     print(f"  - {vm_name}: Propose removing all existing PCI passthrough devices.")
            print("Re-run with sudo (without --dry-run) to apply these changes.")
            return 0
        else:
            print("\nRoot privileges needed to interact with libvirt.")
            print("Attempting to re-run script with sudo...")
            try:
                # Construct the command to re-execute the script with sudo
                sudo_cmd = ['sudo', sys.executable] + sys.argv
                print(f"Executing: {' '.join(sudo_cmd)}")
                os.execvp('sudo', sudo_cmd)
                # execvp replaces the current process, so code below here won't run if successful
                # If execvp fails, it raises an OSError
            except OSError as e:
                print(f"Error: Failed to execute sudo: {e}. Cannot elevate privileges.", file=sys.stderr)
                return 1
            except Exception as e:
                print(f"Error: Unexpected issue during sudo attempt: {e}", file=sys.stderr)
                return 1
            # Should not be reached if execvp succeeds
            return 1

    # --- Step 5: Apply Changes (Running as Root) ---
    print("\nRunning with root privileges. Connecting to libvirt...")
    conn = None
    applied_count = 0
    failed_count = 0
    skipped_count = 0 # Count VMs skipped due to user abort or no changes detected

    try:
        conn = libvirt.open(None)
        if conn is None:
            print('Error: Failed to open connection to the hypervisor even as root.', file=sys.stderr)
            return 1

        print("Connected to libvirt. Applying changes...")
        for vm_name, target_bdfs in vm_changes.items():
            # Construct a specific debug filename for each VM if the flag is set
            vm_debug_xml_file = None
            if args.debug_xml:
                base, ext = os.path.splitext(args.debug_xml)
                vm_debug_xml_file = f"{base}_{vm_name}{ext}"

            # Apply the changes using the dedicated function
            apply_result = apply_libvirt_changes(
                conn,
                vm_name,
                target_bdfs,
                all_device_details,
                non_interactive=args.yes,
                dry_run=args.dry_run,
                debug_xml_file=vm_debug_xml_file
            )

            if apply_result:
                # apply_libvirt_changes returns True for success (applied, dry-run ok, aborted by user, no changes needed)
                # We need to refine counting based on actual action or lack thereof?
                # Let's assume True means 'processed without script error'
                applied_count += 1 # Count all non-failure scenarios as processed
            else:
                failed_count += 1
                print(f"Error applying changes to VM '{vm_name}'. See logs above.", file=sys.stderr)

    except libvirt.libvirtError as e:
        print(f"Error: Libvirt API error during bulk processing: {e}", file=sys.stderr)
        # Can't reliably continue if connection fails mid-way
        failed_count = total_vms_to_process - applied_count # Mark remaining as failed
    except Exception as e:
        print(f"Error: An unexpected error occurred during libvirt operations: {e}", file=sys.stderr)
        failed_count = total_vms_to_process - applied_count
    finally:
        if conn:
            try:
                conn.close()
                print("\nClosed connection to libvirt.")
            except libvirt.libvirtError:
                 pass # Ignore errors closing connection

    # --- Step 6: Summary --- 
    print("\n" + "=" * 55)
    print("Processing Complete.")
    print(f"  VMs Analyzed: {total_vms_to_process}")
    if invalid_configs > 0:
        print(f"  Invalid Configurations Skipped: {invalid_configs}")
    if args.dry_run:
         print(f"  Mode: Dry Run (No changes applied)")
         print(f"  VMs with proposed changes: {len(vm_changes)}")
    else:
         print(f"  VMs Processed (Applied/Skipped/No Change): {applied_count}")
         print(f"  VMs Failed: {failed_count}")
    print("=" * 55)

    if failed_count > 0:
        print("\nCheck warnings/errors above for details on failures.", file=sys.stderr)
        return 1

    # If we ran as root initially or successfully re-invoked
    # Consider 0 if no failures, even if warnings occurred
    return 0


if __name__ == "__main__":
    sys.exit(main()) 