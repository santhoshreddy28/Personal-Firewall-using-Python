from tkinter import *
import json
import threading
import time
import os

# ===== CONFIG =====
LOG_FILE = "firewall_log.txt"
RULES_FILE = "rules.json"
REFRESH_INTERVAL = 1  # seconds

# ===== GLOBAL VARIABLES =====
blocked_count = 0
allowed_count = 0

# ===== HELPER FUNCTIONS =====
def load_rules():
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r") as f:
            return json.load(f)
    return {"blocked_ips": [], "blocked_ports": []}

def add_block_ip():
    ip = block_ip_entry.get().strip()
    if ip:
        rules = load_rules()
        if "blocked_ips" not in rules:
            rules["blocked_ips"] = []
        if ip not in rules["blocked_ips"]:
            rules["blocked_ips"].append(ip)
        with open(RULES_FILE, "w") as f:
            json.dump(rules, f, indent=4)
        block_ip_entry.delete(0, END)

def add_block_port():
    port = block_port_entry.get().strip()
    if port.isdigit():
        rules = load_rules()
        if "blocked_ports" not in rules:
            rules["blocked_ports"] = []
        if int(port) not in rules["blocked_ports"]:
            rules["blocked_ports"].append(int(port))
        with open(RULES_FILE, "w") as f:
            json.dump(rules, f, indent=4)
        block_port_entry.delete(0, END)

# ===== GUI SETUP =====
root = Tk()
root.title("Personal Firewall GUI")

# Counters
blocked_var = IntVar(value=0)
allowed_var = IntVar(value=0)

Label(root, text="Blocked Packets:", fg="red").grid(row=0, column=0, sticky=W)
Label(root, textvariable=blocked_var).grid(row=0, column=1, sticky=W)
Label(root, text="Allowed Packets:", fg="green").grid(row=1, column=0, sticky=W)
Label(root, textvariable=allowed_var).grid(row=1, column=1, sticky=W)

# Log area
log_text = Text(root, height=20, width=80)
log_text.grid(row=2, column=0, columnspan=4, padx=5, pady=5)
log_text.tag_config('blocked', foreground='red')
log_text.tag_config('allowed', foreground='green')

# Input fields
Label(root, text="Block IP:").grid(row=3, column=0, sticky=W)
block_ip_entry = Entry(root)
block_ip_entry.grid(row=3, column=1, sticky=W)
Button(root, text="Add Block IP", command=add_block_ip).grid(row=3, column=2, sticky=W)

Label(root, text="Block Port:").grid(row=4, column=0, sticky=W)
block_port_entry = Entry(root)
block_port_entry.grid(row=4, column=1, sticky=W)
Button(root, text="Add Block Port", command=add_block_port).grid(row=4, column=2, sticky=W)

# ===== LOG MONITOR THREAD =====
def monitor_log():
    global blocked_count, allowed_count
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    with open(LOG_FILE, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(REFRESH_INTERVAL)
                continue
            line = line.strip()
            if "BLOCKED" in line:
                blocked_count += 1
                blocked_var.set(blocked_count)
                log_text.insert(END, line + "\n", 'blocked')
            else:
                allowed_count += 1
                allowed_var.set(allowed_count)
                log_text.insert(END, line + "\n", 'allowed')
            log_text.see(END)

# Start log monitoring in a separate thread
t = threading.Thread(target=monitor_log, daemon=True)
t.start()

root.mainloop()
