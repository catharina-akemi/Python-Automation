# automation
# automscript

A small collection of Python scripts for hands-on network and traffic-analysis practice, built while studying for cybersecurity and GRC roles.

## ⚠️ Ethical use notice
These tools (especially `ipdoorcheck.py`) are for learning and for testing networks/systems **you own or have explicit permission to test**. Scanning networks without authorization may be illegal depending on your jurisdiction.

## Scripts

### `ipdoorcheck.py`
A simple multithreaded port scanner. Takes an IP or CIDR range and a list/range of ports, then reports which ports are open or closed.

**Requirements:** Python 3 standard library only (no external packages).

**Usage:**
```bash
python ipdoorcheck.py
# Type IP or Network (ex.: 192.168.0.1 ou 192.168.0.0/24): 192.168.0.1
# Type doors to be verified (ex.: 22, 80, 443 ou 1-1024): 22,80,443
```

### `packageanalysisV1.py`
An early, minimal version of the packet analysis tool: captures live packets, shows a quick protocol/IP breakdown, and plots protocol counts. Kept here to show the starting point before the more complete version below.

### `packageanalysisV2Complete.py`
The full version of the traffic analysis tool. Captures live packets with `scapy`, enriches them into a `pandas` DataFrame, and flags suspicious traffic using:
- **Rule-based detection:** port scans (many distinct ports from one source in a short window), traffic spikes (packets/sec threshold), and packet-size outliers (z-score)
- **ML-based detection (optional):** Isolation Forest over packet features, if `scikit-learn` is installed

Outputs a CSV of captured packets, a CSV of detected anomalies, and protocol/IP charts via `matplotlib`.

**Requirements:**
```bash
pip install scapy pandas numpy matplotlib scikit-learn
```

**Usage:**
```bash
sudo python packageanalysisanomalies.py   # raw packet capture needs elevated privileges
```

## Notes
- Tested on \[add your OS/environment here, e.g. Windows 11 / Ubuntu 22.04].
- Packet capture requires admin/root privileges and an active network interface.
