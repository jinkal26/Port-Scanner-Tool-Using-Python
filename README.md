# Port-Scanner-Tool-Using-Python

## Overview

A lightweight, multi-threaded TCP port scanner written in Python. This project demonstrates socket programming, banner grabbing, and concurrency using `concurrent.futures.ThreadPoolExecutor`. It scans a specified range of ports on a target host to identify open ports and attempts to retrieve service banners for quick service identification.

> **Disclaimer:** Use this tool only on systems you own or are explicitly authorized to test. Unauthorized scanning or probing of systems may be illegal and unethical.

---

## Features

* Scans a user-specified range of TCP ports on a target IP or hostname
* Multi-threaded scanning for improved performance
* Banner grabbing to attempt service identification
* Clean, formatted output (table-friendly)
* Robust error and exception handling

---

## Key Concepts Covered

* Socket programming with Python (`socket` module)
* TCP banner grabbing
* Concurrency using `ThreadPoolExecutor`
* Command-line interaction and argument parsing
* Structuring and formatting results for readability

---

## Requirements

* Python 3.8+
* Standard library modules only (no third-party dependencies required for the basic scanner)

Optional (for enhancements):

* `rich` or `tabulate` for prettier terminal tables

---

## Installation

1. Clone this repository:

```bash
git clone https://github.com/<your-username>/port-scanner-using-python.git
cd port-scanner-using-python
```

2. (Optional) Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate    # macOS / Linux
venv\Scripts\activate     # Windows
```

3. Install optional dependencies (if you decide to use them):

```bash
pip install rich
```

---

## Usage

Run the scanner from the command line and provide a target IP/hostname and a port range.

Basic example (interactive prompts):

```bash
python port_scanner.py
```

Example with command-line arguments (if implemented in your script):

```bash
python port_scanner.py --target 192.168.1.10 --start 1 --end 1024 --threads 100 --timeout 1.5
```

Typical command-line options to implement:

* `--target` / `-t`: target IP address or hostname
* `--start` / `-s`: starting port (default: 1)
* `--end` / `-e`: ending port (default: 1024)
* `--threads` / `-n`: number of worker threads (default: 100)
* `--timeout` / `-T`: socket timeout in seconds (default: 1.0)

---

## Example Output

(Your script should print a table similar to the following):

```
PORT    STATE   SERVICE     BANNER
22      OPEN    ssh         SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
80      OPEN    http        Apache/2.4.29 (Ubuntu)
443     FILTERED https       
```

---

## Implementation Notes (Suggested)

* Use `socket.socket()` with `socket.AF_INET` and `socket.SOCK_STREAM` for TCP scans.
* Call `socket.connect_ex((target, port))` to test if a port is open (return code `0`).
* For banner grabbing, send a simple probe or read the first few bytes after connection using `recv()` (respect the service and do not abuse).
* Use `ThreadPoolExecutor` to submit port-scan tasks concurrently.
* Collect results in a thread-safe structure such as a `list` with proper locking if necessary, or gather futures and process results after completion.
* Add meaningful exception handling for `socket.timeout`, `ConnectionRefusedError`, `OSError`, and user interruptions (`KeyboardInterrupt`).

---

## Enhancements & Next Steps

* Add UDP scanning capability (requires careful design; UDP is connectionless and often slower).
* Integrate OS/service fingerprinting (e.g., by analyzing banners and response behavior).
* Create a GUI (Tkinter, PySimpleGUI, or a web UI) for usability.
* Output results to a CSV/JSON file for reporting.
* Integrate `nmap`-style timing templates or use `scapy` for advanced probes.

---

## Security & Legal

* Only scan targets you own or have explicit permission to test.
* Understand local laws and organizational policies related to network scanning.
* Use scanning results responsibly — disclose vulnerabilities to the appropriate parties.

---
# OUTPUT:


