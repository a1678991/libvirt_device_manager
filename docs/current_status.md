# Current Status

As of the last update, the following features and components are implemented:

-   **Core Script:** `manage_passthrough.py` exists and contains the main logic.
-   **Configuration:** `passthrough_config.yaml` is used to define VM passthrough requirements.
-   **Dependencies:** `requirements.txt` lists `PyYAML` and `libvirt-python`.
-   **Libvirt API Integration:** The script interacts directly with the libvirt daemon via `libvirt-python` (using `conn.lookupByName`, `dom.XMLDesc`, `conn.defineXML`). Direct XML file modification is no longer used.
-   **Device Discovery:**
    -   IOMMU group information is parsed from `/sys/kernel/iommu_groups/`.
    -   Detailed PCI device information (BDF, Vendor ID, Device ID, Vendor:Device ID, Driver) is gathered using `lspci` and `/sys`.
-   **Flexible Matching:**
    -   `passthrough_config.yaml` supports a list of match criteria sets.
    -   Each set uses a `match` block containing key-value pairs.
    -   Supported keys: `vendor_id`, `device_id`, `vendor_device_id`, `driver`.
    -   Matching logic uses AND for criteria within a single `match` block.
-   **IOMMU Group Handling:** When a device matches a criteria set, its full IOMMU group (all devices within it) is correctly identified and added to the passthrough list.
-   **Diff View:** Before applying changes, a unified diff is generated comparing the current VM definition with the proposed definition.
-   **Quote Normalization:** The diff generation normalizes attribute quotes (`'` vs `"`) to provide a cleaner comparison, ignoring cosmetic differences.
-   **User Confirmation:** A `[y/N]` prompt is displayed after the diff, requiring user confirmation before `conn.defineXML()` is called.
-   **Error Handling:** Basic error handling for file access, YAML parsing, `lspci` execution, and libvirt API calls is included.
-   **Root Requirement:** The script checks for root privileges, as they are generally required for libvirt system connection and `/sys` access.
-   **XML Parser:** Uses the `lxml` library for parsing and manipulating VM XML definitions. 