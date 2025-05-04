# Project Roadmap

This document outlines potential future features and improvements for the Libvirt Passthrough Manager script.

_(Note: Specific items have been broken down into actionable tasks in `docs/tasks.md`.)_

## General Directions

-   Improve device identification flexibility.
-   Add support for more device types (USB, SR-IOV).
-   Enhance user control and feedback (logging, driver management).
-   Increase robustness through better error handling and testing.
-   Integrate more smoothly with VM lifecycles.

## Potential Features

-   **Enhanced Matching Criteria:**
    -   Match by PCI Class ID.
        Match by PCI Device ID as last resort (hardware changes broke this)
    -   Match by device name and description (possibly using regular expressions).
-   **Host Driver Management:**
    -   Option to automatically detach devices from host drivers (e.g., `nvidia`, `nouveau`, `xhci_hcd`) before VM start or device assignment using `virNodeDeviceDettach`.
    -   Option to automatically re-attach devices to their original host drivers after VM stop or device removal using `virNodeDeviceReAttach`.
    -   Requires storing the original driver state.
-   **Security**
    -   Use privileges only when truly necessary.
-   **Broader Device Support:**
    -   Manage USB host device passthrough (`<hostdev type='usb'>`).
    -   Manage SR-IOV Virtual Function (VF) assignment (`<interface type='hostdev'>`).
-   **Improved User Experience:**
    -   Add command-line arguments using `argparse`:
        -   Specify configuration file path.
        -   `--yes` / `--non-interactive` flag to skip confirmation prompt.
        -   `--dry-run` flag to show diffs without prompting or applying.
        -   Target specific VMs (`--vm <name>`).
    -   More verbose logging options.
-   **Robustness and Testing:**
    -   Improve error handling (e.g., more specific exceptions, better recovery).
    -   Add unit tests for helper functions (`get_pci_details`, `parse_pci_address`).
    -   Add integration tests (requires a test libvirt environment).
-   **Workflow Integration:**
    -   Optionally integrate with `virsh` commands or libvirt API calls for VM state management (e.g., ensure VM is off before applying `defineXML`).
-   **Technical Improvements:**
    -   Consider using `lxml` instead of `xml.etree.ElementTree` for potentially better preservation of XML comments and formatting during modification (though `defineXML` might reformat anyway). 