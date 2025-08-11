# Network Scanner (Python, ARP-based)

This **Python-based network scanner** discovers active devices on a local network and reports their **IP address**, **MAC address**, **hostname**, and **hardware vendor**. It uses ARP (Address Resolution Protocol) for device discovery and supports multiple export formats.

---

## Features

- **Device Discovery**
  - Sends ARP requests to detect active devices in a target IP/CIDR range (e.g., `192.168.1.0/24`).
  - Uses Scapy for crafting and sending packets.

- **Metadata Collection**
  - **MAC Address** – Extracted from ARP replies.
  - **Hostname** – Reverse DNS lookup for each IP (falls back to `"Unknown"` if unavailable).
  - **Vendor** – Determined via the `manuf` vendor database.

- **Multiple Output Formats**
  - Console table with color-coded headings.
  - Export to **JSON**, **CSV**, or **TXT**.

- **Input Validation**
  - Validates target IP/CIDR format.
  - Requires **root/sudo privileges** for raw packet operations.

---

## Workflow

1. **Permission Check** – Exits if not run with administrative/root privileges.
2. **Argument Parsing** – Requires a target network range; optional export file.
3. **Scan Execution** – Broadcasts ARP requests, collects responses, resolves metadata.
4. **Result Handling** – Prints a formatted table; optionally exports results.

---

## Requirements

* **Python 3.x**
* **Dependencies:**

  ```bash
  pip install scapy manuf
  ```

---

## Usage

**Basic Scan:**
```bash
sudo python3 network_scanner.py -t 192.168.1.0/24
````

**Scan and Export to CSV:**

```bash
sudo python3 network_scanner.py -t 192.168.1.0/24 -o results.csv
```

**Scan and Export to JSON:**

```bash
sudo python3 network_scanner.py -t 192.168.1.0/24 -o results.json
```

**Scan and Export to TXT:**

```bash
sudo python3 network_scanner.py -t 192.168.1.0/24 -o results.txt
```

---
