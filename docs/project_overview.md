# Project Overview: Libvirt Passthrough Manager

## Goal

To provide a robust and flexible way to manage PCI device passthrough for libvirt virtual machines. The primary objectives are:

1.  **Stable Device Identification:** Use stable hardware identifiers (like Vendor/Device IDs) instead of relying on potentially volatile PCI bus addresses.
2.  **Correct IOMMU Group Handling:** Automatically identify and include all necessary devices from the same IOMMU group as a requested device, as required for VFIO passthrough.
3.  **Configuration Driven:** Allow users to define which devices should be passed through to which VMs via a simple configuration file.
4.  **Safe Application:** Provide checks and balances (like diff views and confirmations) before modifying VM configurations.

## Implementation

The project consists of a Python script (`manage_passthrough.py`) that leverages the `libvirt-python` library to interact directly with the libvirt API.

-   **Configuration:** Passthrough assignments are defined in `passthrough_config.yaml`.
-   **Device Discovery:** The script gathers IOMMU group information from `/sys/kernel/iommu_groups/` and detailed PCI device information (Vendor ID, Device ID, Driver) using `lspci` and `/sys`.
-   **Matching:** It allows flexible device matching based on criteria specified in the configuration file (e.g., `vendor_id`, `device_id`, `vendor_device_id`, `driver`). Multiple criteria within a single match block are combined using AND logic.
-   **VM Update:** It retrieves the current VM definition via the libvirt API, calculates the necessary `<hostdev>` modifications, shows a diff of the proposed changes (ignoring attribute quote differences), asks for user confirmation, and then applies the changes using `conn.defineXML()`.

## Dependencies

-   Python 3.x
-   `PyYAML` (for reading the config file)
-   `libvirt-python` (for interacting with the libvirt API)
-   `lxml` (for XML parsing and manipulation)
-   `lspci` command-line tool (expected to be in PATH)
-   Root privileges (for accessing `/sys` and the libvirt daemon) 