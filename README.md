# 🛡️ MyFirewall: Intelligent Linux Network Monitor & Firewall Dashboard

MyFirewall is a highly responsive, real-time Linux network monitoring console and bidirectional host isolation firewall. Written in Python and powered by a beautiful terminal dashboard, it intercepts, classifies, and manages kernel socket activity across **TCP, UDP, and RAW** sockets, helping security operators track, isolate, and neutralize cyber threats instantly.

---

## 📐 System Architecture

MyFirewall utilizes direct ProcFS API harvesting and custom iptables Netfilter rulesets to ensure real-time host-level threat analysis and active defenses:

![MyFirewall Architecture](./firewall_architecture.png)

### Architectural Flow:
1. **Socket Harvester**: Scans `/proc/net/tcp{,6}`, `/proc/net/udp{,6}`, and `/proc/net/raw{,6}` directly inside Linux Kernel space at a highly reactive rate (**5Hz / every 0.2s**), keeping CPU consumption low (~4.4%).
2. **PID & Process Resolver**: Correlates socket inodes on-the-fly by parsing `/proc/<PID>/fd/` symlink associations.
3. **Asynchronous Geolocation Resolver**: Dispatches remote IPs to an active background consumer queue (`geo_queue`) processing lookups sequentially. This avoids locking the harvester or UI loops and respects external API rate limiting standards.
4. **Firewall Manager**: Hooks directly into the system's `INPUT` (inbound) and `OUTPUT` (outbound) Netfilter strings, dropping target traffic from source (`-s`) and destination (`-d`) channels for total host-defense isolation.

---

## ✨ Features

* **Expanded Socket Coverage**: Harvests, translates, and filters `TCP`, `UDP`, and `RAW` sockets for both `IPv4` and `IPv6` protocols.
* **Transient Connection Persistence (10s decay buffer)**: Captures sub-100ms connection events before they tear down. Terminated sockets transition to greyed out **`(INACTIVE)`** text for **10 seconds** rather than immediately vanishing, protecting operators against time-window evasion attempts.
* **Asynchronous GeoIP Mapping**: Translates raw remote connection destinations to physical countries asynchronously without blocking updates.
* **Bidirectional Host Isolation**: One-key blocking isolates both inbound probes and outbound exfiltrations or reverse shells by generating matching source/destination drops in a custom iptables chain (`MYFIREWALL_BLOCKS`).
* **Fallback Simulation Support**: Detects root privileges on launch and dynamically activates mock mode simulation safe-nets when running as a non-privileged user.

---

## 🚀 Quickstart

### Prerequisites:
Make sure python3, iptables (optional for live blocking), and connection requirements are met.

```bash
# Clone the repository and install requirements
pip3 install -r requirements.txt
```

### Run the Dashboard:

* **Production Live Guard (Requires Root / sudo)**:
  ```bash
  sudo python3 myfirewall.py
  ```
* **Development / Simulator mode (Non-root fallback)**:
  ```bash
  python3 myfirewall.py
  ```

---

## ⌨️ Interactive Controls Guide

The Live Console supports real-time terminal hotkeys for active analysis and response:

| Key | Action | Description |
| :---: | :--- | :--- |
| **`B`** | **Block IP** | Prompt for connection index `#` or direct IP to toggle bidirectional iptables drop rules. |
| **`U`** | **Unblock IP** | Prompts to reverse drop rules on target IPs (visible inside the blocked list). |
| **`I`** | **Ignore Host / Proc** | Prompt to ignore specific IP or Process Name on the live feed. |
| **`L`** | **Toggle View** | Instantly switch view state between **Live Dashboard** and **Active Block List**. |
| **`H`** | **Help** | Overlay interactive user guides and descriptions. |
| **`Q` / `ESC`** | **Quit** | Gracefully tear down threads and exit. |

---

## 🧪 Running Unit Tests

The test suite consists of mock-driven units verifying parsing, address re-orderings, state conditions, and IPTables chain setup profiles with zero environment dependencies.

```bash
# Run all tests
python3 -m unittest test_network_monitor.py test_firewall_manager.py
```

### Validated Units:
* `test_hex_to_ip_port_ipv4`: Validates accurate little-endian IPv4 network translation.
* `test_hex_to_ip_port_ipv6`: Verifies complex packing/unpacking loopback IPv6 parsing.
* `test_get_active_connections`: Tests multi-protocol ProcFS harvesting and duplicate filtering.
* `test_mock_block_ip`: Asserts duplicate block security and ignore profiles.

---

## 📁 Codebase Directory Layout

```text
myfirewall-linux/
├── myfirewall.py             # Main frontend application & dashboard loop
├── network_monitor.py        # ProcFS socket parsing core (TCP, UDP, RAW)
├── firewall_manager.py       # IPTables wrapper and rules generator
├── process_resolver.py       # Inode mapping and executable PID correlator
├── test_network_monitor.py   # Unit test coverage for network parses
├── test_firewall_manager.py  # Unit test coverage for firewall commands
├── firewall_architecture.png # Technical system architecture infographic
├── requirements.txt          # Visual dependencies (rich, requests)
└── debug.log                 # Appendable application trace log
```
