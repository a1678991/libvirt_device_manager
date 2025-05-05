# Libvirt Device Manager

A Python tool to reliably manage PCI(e) device passthrough for Libvirt virtual machines using the libvirt API. It focuses on stable device identification and correct IOMMU group handling, simplifying VFIO setups.

## Problem Solved

Managing VFIO passthrough can be complex. Relying on PCI bus addresses is fragile as they can change between host boots or hardware adjustments. Furthermore, ensuring all devices within an IOMMU group are correctly passed through or bound to the `vfio-pci` driver is crucial for stability. This tool automates these aspects using a declarative configuration file and direct interaction with the libvirt API.

## Features

*   **Configuration Driven:** Define passthrough requirements using a simple YAML file.
*   **Stable Device Identification:** Match devices using persistent identifiers like:
    *   Vendor ID (`vendor_id`)
    *   Device ID (`device_id`)
    *   Vendor:Device ID pair (`vendor_device_id`)
    *   Kernel driver currently bound (`driver`)
*   **Automatic IOMMU Group Handling:** Automatically identifies and includes all necessary devices from the same IOMMU group as a matched device.
*   **Libvirt API Integration:** Interacts directly with the libvirt daemon via `libvirt-python` (no unsafe direct XML file manipulation).
*   **Safety Checks:**
    *   Shows a diff (using `xmldiff`) of proposed XML changes before applying.
    *   Requires user confirmation (`[y/N]`) before modifying VM definitions (can be bypassed with `-y`).
*   **Dry Run Mode:** Use `--dry-run` to see what changes would be made without applying them.
*   **Targeted Updates:** Process all VMs in the config or target specific VMs using `--vm <name>`.
*   **Debugging:** Save the proposed XML for a VM to a file using `--debug-xml <filename>`.
*   **Intelligent Group Handling:** Skips adding devices likely to be PCI bridges/switches (those using the `pcieport` driver) from IOMMU groups.
*   **Uses `lxml`:** Leverages the `lxml` library for robust XML parsing.
*   **Minimized XML Diffs:** Preserves existing `<hostdev>` definitions when possible to reduce noise in configuration changes.

## Dependencies

*   **Python:** 3.x
*   **System:**
    *   `lspci` command-line tool (usually provided by the `pciutils` package on most Linux distributions).
    *   `libvirtd` daemon running and accessible.
    *   Root privileges (required for system libvirt connection, `/sys` access, and potentially device detachment).
*   **Python Packages:** (Install via `pip install -r requirements.txt`)
    *   `PyYAML`
    *   `libvirt-python`
    *   `lxml`
    *   `xmldiff`

## Installation

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd libvirt-device-manager # Or your repository directory name
    ```
2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Consider using a virtual environment)*
3.  **Ensure system dependencies are met:** Install `pciutils` if `lspci` is not found. Make sure libvirt is installed and the daemon is running.

## Configuration

Create a YAML configuration file (e.g., `passthrough_config.yaml`). The default filename is `passthrough_config.yaml`.

The file structure should be:

```yaml
vms:
  <vm-name-1>:
    passthrough_devices:
      - match:
          # Criteria set 1 (e.g., identify a specific GPU)
          vendor_id: "10de"
          device_id: "1b81" # NVIDIA GeForce GTX 1070
      - match:
          # Criteria set 2 (e.g., identify its audio function)
          vendor_id: "10de"
          device_id: "10f0"
      - match:
          # Criteria set 3 (e.g., identify a specific USB controller by driver)
          driver: "xhci_hcd"
          select_index: 1
  <vm-name-2>:
    passthrough_devices:
      - match:
          # Example: Pass through a specific network card
          vendor_id: "8086"
          device_id: "153a"
# Add more VMs as needed
```

**Explanation:**

*   `vms`: Top-level key containing a dictionary of VM configurations.
*   `<vm-name-N>`: The name of the libvirt domain (must match `virsh list --all`).
*   `passthrough_devices`: A list of device requests for this VM.
*   `- match:`: Each item in the list represents a request to find and pass through a device (and its IOMMU group).
*   `key: value`: Inside `match`, specify one or more criteria. All criteria within a single `match` block must be met (AND logic) for a device to be considered a match.
    *   Supported keys:
        * `vendor_id`, `device_id`, `driver`: Criteria for matching devices (case-insensitive strings).
        * `select_index` (Optional, integer, default: `0`): If multiple devices match the criteria, this selects which device (from a list sorted by PCI BDF address) to use for IOMMU group identification. `0` is the first match, `1` is the second, and so on.

If a device matches any `match` block, its entire IOMMU group (excluding `pcieport` devices) will be added to the passthrough list for that VM. The script removes any pre-existing `<hostdev type='pci' mode='subsystem'>` entries before adding the newly determined set.

## Usage

Run the script with root privileges:

```bash
sudo ./manage_passthrough.py [OPTIONS]
```

**Options:**

*   `--config FILE`: Path to the YAML configuration file (default: `passthrough_config.yaml`).
*   `--vm VM_NAME`: Target only the specified VM(s). Can be used multiple times. If omitted, all VMs defined in the configuration file are processed.
*   `--yes`, `-y`: Assume 'yes' to the confirmation prompt; run non-interactively.
*   `--dry-run`: Show proposed XML changes (diff) but do not prompt for confirmation or apply any changes to the VM definitions.
*   `--debug-xml FILENAME`: Save the proposed XML for each processed VM to a file. The VM name will be inserted into the filename (e.g., `debug_vm1.xml`, `debug_vm2.xml` if `FILENAME` is `debug.xml`).

**Example:**

```bash
# Check changes for vm 'win10' using a custom config, don't apply
sudo ./manage_passthrough.py --config my_setup.yaml --vm win10 --dry-run

# Apply changes for all VMs in the default config, skip prompt
sudo ./manage_passthrough.py -y
```

## How it Works

1.  **Scan Host:** Reads `/sys/kernel/iommu_groups` to map PCI devices to their IOMMU groups.
2.  **Gather Device Details:** Uses `lspci` and `/sys` to get vendor/device IDs and driver information for all relevant PCI devices.
3.  **Load Configuration:** Parses the specified YAML configuration file.
4.  **Process VMs:** For each VM (either all in the config or those specified by `--vm`):
    a.  **Match Devices:** Compares host devices against the `passthrough_devices` criteria defined for the VM.
    b.  **Resolve IOMMU Groups:** Identifies the full IOMMU groups for all matched devices.
    c.  **Fetch Current XML:** Connects to libvirt and retrieves the current XML definition for the VM.
    d.  **Calculate New XML:** Compares the target devices (from config + IOMMU groups) with the existing PCI `<hostdev>` entries in the VM's XML.
       *   Removes `<hostdev>` elements for devices no longer specified in the target set.
       *   Adds new `<hostdev>` elements only for devices newly specified in the target set (libvirt will assign virtual slots).
       *   Keeps existing `<hostdev>` elements untouched if the device remains in the target set, preserving their virtual PCI slot assignments.
    e.  **Generate Diff:** Compares the original XML with the proposed new XML using `difflib` (after pretty-printing both). The goal is to only show meaningful additions/removals.
    f.  **Confirm & Apply:** If not in `--dry-run` mode, displays the diff, prompts for confirmation (unless `-y` is used), and if confirmed, uses `conn.defineXML()` to update the VM definition in libvirt.

## Development Status

The core functionality for managing PCI passthrough based on the described features is implemented.

See [docs/current_status.md](docs/current_status.md) for a detailed list of implemented features.

## Roadmap & Tasks

Future plans include enhanced matching criteria, host driver management (detaching/reattaching), support for USB and SR-IOV, improved logging, and more robust testing.

See [docs/roadmap.md](docs/roadmap.md) for the general direction and [docs/tasks.md](docs/tasks.md) for a list of pending tasks.

## Contributing

*(Contributions are welcome! Please open an issue or submit a pull request.)* - Placeholder

## License

*(Specify your license, e.g., MIT License)* - Placeholder 