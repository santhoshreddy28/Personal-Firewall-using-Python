#!/usr/bin/env python3
"""
Minimal Personal Firewall - safe-to-run version
- Sniffs packets with scapy
- Loads rules.json for blocked_ips and blocked_ports
- Logs to firewall_log.txt
"""
import os
import json
import time
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except Exception:
    print("Scapy import failed. Install via: pip install scapy")
    raise

RULES_FILE = "rules.json"
LOG_FILE = "firewall_log.txt"

def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def load_rules():
    if not os.path.exists(RULES_FILE):
        default = {"blocked_ips": [], "blocked_ports": []}
        with open(RULES_FILE, "w") as f:
            json.dump(default, f, indent=2)
        return default
    with open(RULES_FILE) as f:
        return json.load(f)

def log(msg):
    line = f"{time.strftime('%H:%M:%S')} - {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

def packet_summary(pkt):
    if not pkt.haslayer(IP):
        return pkt.summary()
    ip = pkt[IP]
    src = ip.src
    dst = ip.dst
    proto = None
    dport = None
    if pkt.haslayer(TCP):
        proto = "TCP"
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = "UDP"
        dport = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
    else:
        proto = ip.proto
    return f"{src} -> {dst} proto={proto} dport={dport}"

def handle(pkt):
    rules = load_rules()
    summary = packet_summary(pkt)
    # default allow
    reason = "Allowed by rules"
    should_block = False

    # only check IPv4 IP layer here
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dport = None
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport

        if src in rules.get("blocked_ips", []):
            should_block = True
            reason = "Blocked IP"
        elif dport and dport in rules.get("blocked_ports", []):
            should_block = True
            reason = "Blocked Port"

    if should_block:
        log(f"🚫 BLOCKED: {summary} | reason: {reason}")
    else:
        log(f"✅ ALLOWED: {summary} | reason: {reason}")

def main():
    print("Loading rules from", RULES_FILE)
    print("Starting sniffer (Ctrl+C to stop).")
    try:
        sniff(prn=handle, store=False)
    except PermissionError:
        print("Permission error: run with sudo to sniff packets.")
    except KeyboardInterrupt:
        print("Stopping.")

if __name__ == '__main__':
    main()
