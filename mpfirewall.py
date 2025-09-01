import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
from scapy.all import sniff, IP
import threading
import os
from datetime import datetime

# =========================
# 🔧 Helper Functions
# =========================

def add_iptables_rule(ip, port, protocol, action):
    try:
        rule = f"-A INPUT -p {protocol.lower()} --dport {port} -s {ip} -j {action.upper()}"
        subprocess.run(f"iptables {rule}", shell=True, check=True)
    except subprocess.CalledProcessError as e:
        log_packet(f"Failed to add rule: {e}")

def delete_iptables_rule(rule_str):
    try:
        delete_rule = rule_str.replace("-A", "-D", 1)
        subprocess.run(f"iptables {delete_rule}", shell=True, check=True)
        log_packet(f"Rule deleted: {delete_rule}")
    except subprocess.CalledProcessError as e:
        log_packet(f"Failed to delete rule: {e}")

def get_iptables_rules():
    try:
        result = subprocess.check_output("iptables -L INPUT -n --line-numbers", shell=True).decode()
        return result
    except subprocess.CalledProcessError:
        return "Error retrieving rules."

# =========================
# 🗒️ Logging Functions
# =========================

def log_packet(msg):
    log_area.insert(tk.END, msg + "\n")
    log_area.see(tk.END)

def log_rule(ip, port, protocol, action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {action.upper()} → IP: {ip}, Port: {port}, Protocol: {protocol.upper()}"
    log_area.insert(tk.END, entry + "\n")
    log_area.see(tk.END)

    # Save to file
    with open("user_rules.log", "a") as f:
        f.write(entry + "\n")

# =========================
# 🔍 Packet Sniffer
# =========================

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        log_packet(f"Packet: {src_ip} ➝ {dst_ip}")

def start_sniffing():
    sniff(filter="ip", prn=packet_callback, store=0)

# =========================
# 🖼️ GUI Logic
# =========================

def add_rule():
    ip = ip_entry.get()
    port = port_entry.get()
    protocol = proto_entry.get()
    user_action = action_var.get()

    if not ip or not port or not protocol:
        messagebox.showwarning("Input Error", "Please fill all fields.")
        return

    action = "DROP" if user_action == "Block" else "ACCEPT"
    add_iptables_rule(ip, port, protocol, action)

    # Log to GUI and file
    log_rule(ip, port, protocol, user_action)
    
    update_rules()

def update_rules():
    rules_text.delete(1.0, tk.END)
    rules = get_iptables_rules()
    rules_text.insert(tk.END, rules)

def remove_rule():
    line_num = remove_entry.get()
    if not line_num.isdigit():
        messagebox.showwarning("Input Error", "Enter a valid rule line number.")
        return

    try:
        subprocess.run(f"iptables -D INPUT {line_num}", shell=True, check=True)
        log_packet(f"Rule at line {line_num} deleted.")
        update_rules()
    except subprocess.CalledProcessError:
        log_packet("Failed to delete rule.")

# =========================
# 🧠 Main GUI Setup
# =========================

root = tk.Tk()
root.title("My Personal Firewall")
root.geometry("800x600")

# --- Input Frame ---
input_frame = tk.Frame(root)
input_frame.pack(pady=10)

tk.Label(input_frame, text="IP:").grid(row=0, column=0)
ip_entry = tk.Entry(input_frame)
ip_entry.grid(row=0, column=1)

tk.Label(input_frame, text="Port:").grid(row=0, column=2)
port_entry = tk.Entry(input_frame)
port_entry.grid(row=0, column=3)

tk.Label(input_frame, text="Protocol:").grid(row=0, column=4)
proto_entry = tk.Entry(input_frame)
proto_entry.grid(row=0, column=5)

# Action dropdown: Block or Unblock
action_var = tk.StringVar(value="Block")
tk.Label(input_frame, text="Action:").grid(row=0, column=6)
tk.OptionMenu(input_frame, action_var, "Block", "Unblock").grid(row=0, column=7)

tk.Button(input_frame, text="Add Rule", command=add_rule).grid(row=0, column=8, padx=10)

# --- Rules Display ---
rules_frame = tk.Frame(root)
rules_frame.pack(pady=10)

tk.Label(rules_frame, text="Current iptables Rules:").pack()
rules_text = scrolledtext.ScrolledText(rules_frame, height=10, width=100)
rules_text.pack()

tk.Button(rules_frame, text="Refresh Rules", command=update_rules).pack(pady=5)

# --- Rule Removal ---
remove_frame = tk.Frame(root)
remove_frame.pack(pady=10)

tk.Label(remove_frame, text="Remove Rule by Line Number:").pack(side=tk.LEFT)
remove_entry = tk.Entry(remove_frame, width=5)
remove_entry.pack(side=tk.LEFT, padx=5)
tk.Button(remove_frame, text="Remove", command=remove_rule).pack(side=tk.LEFT)

# --- Logging Area ---
tk.Label(root, text="Packet & Firewall Log:").pack()
log_area = scrolledtext.ScrolledText(root, height=10, width=100)
log_area.pack()

# --- Load Previous Log Entries on Startup ---
if os.path.exists("user_rules.log"):
    with open("user_rules.log", "r") as f:
        for line in f:
            log_area.insert(tk.END, line)

# --- Start Sniffing in Background ---
threading.Thread(target=start_sniffing, daemon=True).start()

# --- Start GUI Loop ---
update_rules()
root.mainloop()
