#!/usr/bin/env python3

import subprocess
import os
import re
from lxml import etree as ET # Use lxml
import yaml  # Requires PyYAML installation
from collections import defaultdict
import sys
# import shutil # No longer needed for backup when using API
import libvirt # Import the libvirt library
import difflib # For showing differences
# from xml.dom import minidom # No longer needed? lxml can pretty print
import argparse # For command-line arguments

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
        'description': None # Potentially add later if needed
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

def update_vm_definition(vm_name, vm_config, groups, device_to_group, all_device_details, non_interactive=False, dry_run=False, debug_xml_file=None):
    """Updates the VM definition using the libvirt API based on the configuration, showing diff and asking for confirmation."""
    # passthrough_devices should now be a list of dictionaries (match criteria sets)
    passthrough_requests = vm_config.get('passthrough_devices', []) or []

    # --- Validate passthrough_requests format --- 
    if not isinstance(passthrough_requests, list):
        print(f"Error: 'passthrough_devices' for VM '{vm_name}' must be a list of match criteria.", file=sys.stderr)
        return False
    for i, req in enumerate(passthrough_requests):
        if not isinstance(req, dict) or 'match' not in req or not isinstance(req['match'], dict):
             print(f"Error: Entry {i} in 'passthrough_devices' for VM '{vm_name}' is invalid. Expected format: {{ 'match': {{ key: value, ... }} }}", file=sys.stderr)
             return False

    print(f"\n--- Processing VM: {vm_name} ---")

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
                    print(f"Warning: Unknown match key '{key}' in request for VM '{vm_name}'. Skipping criteria.", file=sys.stderr)
                    matches_all = False
                    break # Stop checking this criteria set for this device
                
                device_value = device_info[key]
                # Simple string comparison for now
                if isinstance(device_value, str) and isinstance(value, str):
                    if device_value.lower() != value.lower():
                        matches_all = False
                        break # Stop checking this criteria set for this device
                elif device_value != value: # Allow comparison for non-string types if added later
                     matches_all = False
                     break
            
            # If this device matched ALL criteria in the current request_set
            if matches_all:
                print(f"  Device {bdf} ({device_info.get('vendor_device_id', 'N/A')}, driver: {device_info.get('driver', 'None')}) matches criteria set {idx+1}.")
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
                            if driver == 'pcieport':
                                 print(f"    - Skipping {dev_bdf} (driver: pcieport) as it's likely a bridge/switch.")
                                 skipped_count += 1
                            else:
                                 final_passthrough_bdfs.add(dev_bdf)
                                 added_from_group.append(dev_bdf)
                        if added_from_group:
                            print(f"  Adding {len(added_from_group)} device(s) from group {group_id}: {', '.join(added_from_group)}")
                        if skipped_count == len(group_devices_bdfs):
                            print(f"Warning: All devices in group {group_id} were skipped (likely bridges/switches). Check if the requested device ({bdf}) is actually usable for passthrough.", file=sys.stderr)
                            resolution_warnings += 1 # Count this as a potential issue

                        processed_groups.add(group_id)
                # else: Group already added by a previous match
                
                # Since this device satisfied one request, move to the next device
                # (A single device can satisfy multiple requests, but its group is only added once)
                # Let's continue checking other criteria sets for the *same* device in case
                # it matches another set that belongs to an *unprocessed* group.
                # If we break here, we might miss adding a different group this device belongs to if
                # it also matches another criteria set tied to that different group (highly unlikely scenario).
                # break # Optional: If one match is enough per device? safer not to break.

    # Check if any requested criteria sets were not matched by any device
    for idx, req in enumerate(passthrough_requests):
        if idx not in matched_request_indices and req['match']: # Check non-empty match blocks
            print(f"Warning: No host device found matching criteria set {idx+1} for VM '{vm_name}': {req['match']}", file=sys.stderr)
            resolution_warnings += 1

    # --- Connect to libvirt and Prepare Potential Changes ---
    conn = None
    original_xml_string = None
    modified_xml_string = None # This will have double quotes from ET
    made_changes_in_tree = False

    try:
        conn = libvirt.open(None)
        if conn is None:
            print('Error: Failed to open connection to the hypervisor. Run as root?', file=sys.stderr)
            return False

        try:
            dom = conn.lookupByName(vm_name)
        except libvirt.libvirtError as e:
            print(f"Error: Failed to find domain '{vm_name}': {e}", file=sys.stderr)
            return False

        original_xml_string = dom.XMLDesc(0)
        if not original_xml_string:
             print(f"Error: Failed to get XML description for domain '{vm_name}'.", file=sys.stderr)
             return False

        # Parse with lxml, which needs bytes
        # Use a parser that attempts to recover from errors and remove blank text
        parser = ET.XMLParser(remove_blank_text=True, recover=True)
        root = ET.fromstring(original_xml_string.encode('utf-8'), parser=parser)
        devices_element = root.find('./devices')
        if devices_element is None:
            print(f"Error: Cannot find <devices> element in XML for VM '{vm_name}'", file=sys.stderr)
            return False

        # --- Apply potential changes to the parsed XML Tree ---
        removed_count = 0
        existing_hostdevs = devices_element.findall("./hostdev[@type='pci'][@mode='subsystem']")
        for hostdev in existing_hostdevs:
            devices_element.remove(hostdev)
            removed_count += 1

        if removed_count > 0:
            print(f"  Will remove {removed_count} existing PCI subsystem hostdev element(s)...")
            made_changes_in_tree = True

        added_count = 0
        if final_passthrough_bdfs:
             print(f"  Will add {len(final_passthrough_bdfs)} devices for passthrough:")
             # Sort BDFs for consistent ordering in the XML
             for bdf in sorted(list(final_passthrough_bdfs)):
                 pci_addr = parse_pci_address(bdf)
                 if not pci_addr:
                     print(f"Warning: Could not parse BDF '{bdf}' into PCI address components. Skipping.", file=sys.stderr)
                     resolution_warnings += 1 # Count this as a warning
                     continue
                 # Create elements using lxml's ElementMaker if desired, or standard ET API
                 hostdev_attrib = {
                     'mode': 'subsystem', 'type': 'pci', 'managed': 'yes'
                 }
                 hostdev = ET.Element('hostdev', **hostdev_attrib) # lxml prefers kwargs for attrib
                 source = ET.SubElement(hostdev, 'source')
                 address_attrib = {
                     'type': 'pci',
                     'domain': pci_addr['domain'], 'bus': pci_addr['bus'],
                     'slot': pci_addr['slot'], 'function': pci_addr['function']
                 }
                 ET.SubElement(source, 'address', **address_attrib)
                 devices_element.append(hostdev)
                 added_count += 1
                 made_changes_in_tree = True
                 # Get device info for print statement
                 dev_info_print = all_device_details.get(bdf, {})
                 print(f"    + Proposing: {bdf} (Vendor:Device {dev_info_print.get('vendor_device_id', 'N/A')}, Driver: {dev_info_print.get('driver', 'None')})")
        elif removed_count == 0:
             print(f"  No changes to PCI passthrough devices needed for VM '{vm_name}'.")
             return True

        if made_changes_in_tree:
            # Generate the potentially compact XML string from the modified tree
            # Use lxml's tostring, ensuring unicode output for libvirt
            # Keep pretty_print=False here for the actual application
            modified_xml_string = ET.tostring(root, encoding='unicode', xml_declaration=False)
        else:
            modified_xml_string = original_xml_string

        # --- Save debug XML if requested ---
        if debug_xml_file:
            try:
                print(f"  Saving proposed XML for {vm_name} to '{debug_xml_file}'...")
                # Use pretty_print_xml to make the saved file readable
                pretty_debug_xml = pretty_print_xml(modified_xml_string)
                with open(debug_xml_file, 'w') as f:
                    f.write(pretty_debug_xml)
                print(f"  Successfully saved debug XML.")
            except Exception as e:
                print(f"Warning: Failed to save debug XML to '{debug_xml_file}': {e}", file=sys.stderr)

        # --- Show Diff and Ask for Confirmation ---

        # Pretty-print both versions *for diffing only*
        pretty_original_xml = pretty_print_xml(original_xml_string)
        pretty_modified_xml = pretty_print_xml(modified_xml_string)

        # Normalize quotes and spacing on the pretty-printed versions for diffing
        modified_xml_for_diff = re.sub(r'=(["\'])(.*?)\1', r"='\2'", pretty_modified_xml)
        original_xml_for_diff = re.sub(r'=(["\'])(.*?)\1', r"='\2'", pretty_original_xml)
        modified_xml_for_diff = re.sub(r'\s+/>', '/>', modified_xml_for_diff)
        original_xml_for_diff = re.sub(r'\s+/>', '/>', original_xml_for_diff)

        # Compare the normalized, pretty-printed versions
        if original_xml_for_diff != modified_xml_for_diff:
            print("\n" + "-" * 15 + f" Proposed changes for {vm_name} " + "-" * 15)
            # Note: Diff formatting includes normalization effects
            print("(Note: Diff ignores attribute quotes and self-closing tag spacing)")
            diff = difflib.unified_diff(
                original_xml_for_diff.splitlines(keepends=True),
                modified_xml_for_diff.splitlines(keepends=True),
                fromfile='current definition',
                tofile='proposed definition',
                lineterm='\n'
            )
            sys.stdout.writelines(diff)
            print("-" * (30 + len(f" Proposed changes for {vm_name} "))) # Match header length

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
                # IMPORTANT: Apply the *original* modified string (from ET.tostring)
                # not the pretty-printed one, to avoid potential format conflicts.
                conn.defineXML(modified_xml_string)
                print(f"Successfully applied changes to '{vm_name}'.")
            else:
                print(f"Changes for VM '{vm_name}' aborted by user.")
        else:
            print(f"  No effective changes detected for VM '{vm_name}' after processing (ignoring quote style and tag spacing).")

        if resolution_warnings > 0:
            print(f"NOTE: There were {resolution_warnings} warnings during device resolution for this VM.")
        return True

    except libvirt.libvirtError as e:
        print(f"Error: Libvirt API error processing VM '{vm_name}': {e}", file=sys.stderr)
        return False
    except ET.XMLSyntaxError as e: # lxml uses XMLSyntaxError
        print(f"Error: Failed to parse XML received from libvirt for VM '{vm_name}': {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error: An unexpected error occurred while processing VM '{vm_name}': {e}", file=sys.stderr)
        return False
    finally:
        if conn:
            try:
                conn.close()
            except libvirt.libvirtError:
                 pass

def main():
    parser = argparse.ArgumentParser(description="Manage Libvirt PCI passthrough using the libvirt API.")
    parser.add_argument('--config', default='passthrough_config.yaml',
                        help="Path to the YAML configuration file (default: passthrough_config.yaml)")
    parser.add_argument('--debug-xml', metavar='FILENAME',
                        help="Save the proposed XML for each VM to the specified file before applying.")
    # Add other arguments here later (e.g., --yes, --dry-run, --vm)
    parser.add_argument('--yes', '-y', action='store_true',
                        help="Assume yes to confirmation prompts (non-interactive mode).")
    parser.add_argument('--dry-run', action='store_true',
                        help="Show proposed changes (diff) but do not prompt or apply them.")
    parser.add_argument('--vm', action='append', metavar='VM_NAME',
                        help="Target specific VM(s). Can be specified multiple times. If omitted, all VMs in the config are processed.")

    args = parser.parse_args()

    config_file = args.config

    print("Libvirt Passthrough Manager (API Mode with Diff/Confirm)")
    print("=" * 55)

    if os.geteuid() != 0:
         print("Error: This script needs root privileges to connect to the system libvirt daemon and modify domain definitions.", file=sys.stderr)
         return 1

    print("Gathering IOMMU group information...")
    # Get the enhanced device details
    groups, device_to_group, all_device_details = get_iommu_groups()
    if not device_to_group: # Check if the core mapping was populated
        print("Error: Failed to get IOMMU group or device information. Exiting.", file=sys.stderr)
        return 1

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

    print("\nProcessing VM configurations...")
    processed_count = 0
    fail_count = 0
    # Filter VMs if --vm is specified
    if args.vm:
        vms_to_process = {vm_name: config['vms'][vm_name] for vm_name in args.vm if vm_name in config['vms']}
        missing_vms = [vm_name for vm_name in args.vm if vm_name not in config['vms']]
        if missing_vms:
            print(f"Warning: The following specified VMs were not found in the config file: {', '.join(missing_vms)}", file=sys.stderr)
        if not vms_to_process:
            print("Error: None of the specified VMs were found in the configuration. Nothing to do.", file=sys.stderr)
            return 1
    else:
        vms_to_process = config['vms']

    total_vms = len(vms_to_process)
    print(f"Planning to process {total_vms} VM(s).")

    for vm_name, vm_config_data in vms_to_process.items():
        # Construct a specific debug filename for each VM if the flag is set
        vm_debug_xml_file = None
        if args.debug_xml:
            # Insert VM name before the extension, or append if no extension
            base, ext = os.path.splitext(args.debug_xml)
            vm_debug_xml_file = f"{base}_{vm_name}{ext}"

        if not isinstance(vm_config_data, dict):
            print(f"Warning: Invalid configuration format for VM '{vm_name}' (expected a dictionary). Skipping.", file=sys.stderr)
            fail_count += 1
            continue

        # Pass the debug filename and flags to the update function
        if update_vm_definition(vm_name, vm_config_data, groups, device_to_group, all_device_details, non_interactive=args.yes, dry_run=args.dry_run, debug_xml_file=vm_debug_xml_file):
            processed_count += 1
        else:
            fail_count += 1

    # --- Summary --- (remains the same)
    print("\n" + "=" * 55)
    print("Processing Complete.")
    print(f"  Total VMs in config: {total_vms}")
    print(f"  Successfully processed: {processed_count}")
    print(f"  Failed/Skipped: {fail_count}")
    print("=" * 55)

    if fail_count > 0:
        print("\nCheck warnings/errors above for details on failures.", file=sys.stderr)
        return 1
    elif processed_count == 0 and total_vms > 0:
         print("\nNo VMs were successfully processed (check config and warnings).")
         return 1

    return 0

if __name__ == "__main__":
    sys.exit(main()) 