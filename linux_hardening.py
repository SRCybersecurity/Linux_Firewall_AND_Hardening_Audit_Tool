import os
import subprocess
import stat
from datetime import datetime

def run_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error running command {cmd}: {e}"

# --- Checks and scoring ---
def check_firewall():
    max_score = 2  # UFW active + iptables rules present
    section_score = 0

    print("=== Firewall Rules ===")
    ufw_status = run_command("ufw status")
    print("UFW Status:\n", ufw_status)

    iptables_rules = run_command("iptables -L")
    print("iptables Rules:\n", iptables_rules)
    print()

    ufw_active = "Status: active" in ufw_status
    iptables_nonempty = len(iptables_rules.strip()) > 0 and "Chain" in iptables_rules

    if ufw_active:
        section_score += 1
    if iptables_nonempty:
        section_score += 1

    details = {
        "ufw_status": ufw_status,
        "iptables_rules": iptables_rules
    }

    return section_score, max_score, details

def check_services():
    max_score = 2
    section_score = 0

    print("=== Enabled Services ===")
    services = run_command("systemctl list-unit-files --type=service --state=enabled")
    print(services)
    print()

    # Example: penalize for risky services running
    risky_services = ["telnet.service", "ftp.service", "rsh.service"]
    found_risky = any(rs in services for rs in risky_services)

    if not found_risky:
        section_score = max_score
    else:
        section_score = max_score - 1

    details = {
        "enabled_services": services,
        "risky_services_found": found_risky
    }

    return section_score, max_score, details

def check_ssh_settings():
    max_score = 4
    section_score = 0

    ssh_config_path = "/etc/ssh/sshd_config"
    settings_of_interest = {
        "PermitRootLogin": None,
        "PasswordAuthentication": None,
        "PermitEmptyPasswords": None,
        "ChallengeResponseAuthentication": None,
    }

    print("=== SSH Configuration ===")
    if not os.path.exists(ssh_config_path):
        print("SSH config not found.\n")
        return 0, max_score, {}

    with open(ssh_config_path, "r") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        for key in settings_of_interest.keys():
            if line.startswith(key):
                _, val = line.split(None, 1)
                settings_of_interest[key] = val.lower()

    for k, v in settings_of_interest.items():
        print(f"{k}: {v}")
    print()

    if settings_of_interest["PermitRootLogin"] in ("no", "without-password", "prohibit-password"):
        section_score += 1
    if settings_of_interest["PasswordAuthentication"] == "no":
        section_score += 1
    if settings_of_interest["PermitEmptyPasswords"] == "no":
        section_score += 1
    if settings_of_interest["ChallengeResponseAuthentication"] == "no":
        section_score += 1

    return section_score, max_score, settings_of_interest

def check_permissions():
    max_score = 2
    section_score = 0
    files_to_check = ["/etc/passwd", "/etc/shadow"]
    perms = {}

    print("=== Permissions on Key Files ===")
    for filepath in files_to_check:
        if os.path.exists(filepath):
            st = os.stat(filepath)
            permissions = stat.filemode(st.st_mode)
            owner = st.st_uid
            group = st.st_gid
            print(f"{filepath}: Permissions {permissions}, Owner UID {owner}, Group GID {group}")
            perms[filepath] = {"permissions": permissions, "owner": owner, "group": group}
        else:
            print(f"{filepath} does not exist!")
            perms[filepath] = None

    passwd_ok = perms.get("/etc/passwd") and perms["/etc/passwd"]["permissions"] == "-rw-r--r--"
    shadow_ok = perms.get("/etc/shadow") and perms["/etc/shadow"]["permissions"] == "-rw-------"

    if passwd_ok:
        section_score += 1
    if shadow_ok:
        section_score += 1
    print()

    return section_score, max_score, perms

def check_rootkits():
    max_score = 2
    section_score = 0

    suspicious_files = [
        "/usr/bin/..",    # suspicious path
        "/dev/.lib",      # common hidden directory
        "/usr/sbin/inetd" # rootkit target
    ]

    found_suspicious = []

    print("=== Rootkit Indicators ===")
    for f in suspicious_files:
        if os.path.exists(f):
            print(f"Suspicious file found: {f}")
            found_suspicious.append(f)
    if not found_suspicious:
        section_score = max_score
    else:
        section_score = 0

    print("For more thorough rootkit checks, consider using tools like chkrootkit or rkhunter.\n")

    details = {
        "suspicious_files_found": found_suspicious
    }

    return section_score, max_score, details

def generate_report():
    print("=== Report Summary ===")
    print("This is a basic audit report with CIS scoring and HTML export.\n")

def recommend_actions():
    print("=== Recommendations ===")
    print("- Ensure firewall is enabled and configured.")
    print("- Disable unused services.")
    print("- Harden SSH settings (disable root login, disable password authentication).")
    print("- Restrict permissions on sensitive files.")
    print("- Run dedicated rootkit detection tools regularly.\n")

# --- HTML report generator ---
def generate_html_report(results, total_score, max_score):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def color(score, max_s):
        pct = score / max_s
        if pct == 1:
            return "green"
        elif pct >= 0.5:
            return "orange"
        else:
            return "red"

    html = f"""
    <html>
    <head>
        <title>Linux Security Audit Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f4f9; padding: 20px; }}
            h1 {{ color: #333; }}
            .section {{ background: white; padding: 15px; margin-bottom: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            .pass {{ color: green; font-weight: bold; }}
            .warn {{ color: orange; font-weight: bold; }}
            .fail {{ color: red; font-weight: bold; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
            th {{ background: #eee; }}
            pre {{ background: #eee; padding: 10px; border-radius: 5px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <h1>Linux Security Audit Report</h1>
        <p><em>Generated on: {now}</em></p>
        <h2>Total Score: <span style="color:{color(total_score, max_score)}">{total_score} / {max_score}</span></h2>
    """

    for section, data in results.items():
        s_score, s_max, s_details = data["score"], data["max"], data["details"]
        c = color(s_score, s_max)
        html += f'<div class="section">'
        html += f'<h3>{section} - Score: <span class="{c}">{s_score} / {s_max}</span></h3>'
        html += "<pre>" + str(s_details) + "</pre>"
        html += "</div>"

    html += "</body></html>"

    return html

def main():
    print("Starting Linux Security Audit...\n")

    results = {}
    total_score = 0
    max_score = 0

    checks = [
        ("Firewall Rules", check_firewall),
        ("Enabled Services", check_services),
        ("SSH Configuration", check_ssh_settings),
        ("Permissions on Key Files", check_permissions),
        ("Rootkit Indicators", check_rootkits),
    ]

    for name, func in checks:
        score, max_s, details = func()
        results[name] = {"score": score, "max": max_s, "details": details}
        total_score += score
        max_score += max_s

    print(f"Overall Score: {total_score} / {max_score}\n")

    generate_report()
    recommend_actions()

    # Generate and save HTML report
    html_report = generate_html_report(results, total_score, max_score)
    report_file = "linux_audit_report.html"
    with open(report_file, "w") as f:
        f.write(html_report)
    print(f"HTML report saved to {report_file}")

if __name__ == "__main__":
    main()
