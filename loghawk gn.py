import os
import re
from collections import defaultdict

# === CONFIG ===
base_path = (file_path)     # Enter file path

# Log file paths
access_log = os.path.join(base_path, "access.log")
auth_log = os.path.join(base_path, "auth.log")
sys_log = os.path.join(base_path, "sys.log")
app_log = os.path.join(base_path, "app.log")

# === FUNCTIONS ===

def read_log(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    else:
        print(f"❌ File not found: {file_path}")
        return []

def detect_brute_force(access_lines, auth_lines):
    brute_force_ips = defaultdict(int)

    # Access log: multiple 401 responses
    for line in access_lines:
        match = re.search(r'(\d+\.\d+\.\d+\.\d+).+?"\S+ \S+ \S+" 401', line)
        if match:
            ip = match.group(1)
            brute_force_ips[ip] += 1

    # Auth log: failed SSH logins
    for line in auth_lines:
        if "Failed password" in line:
            match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                brute_force_ips[ip] += 1

    return {ip: count for ip, count in brute_force_ips.items() if count >= 3}


def detect_traffic_spikes(access_lines):
    ip_counter = defaultdict(int)
    for line in access_lines:
        match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip = match.group(1)
            ip_counter[ip] += 1
    return {ip: count for ip, count in ip_counter.items() if count >= 5}


def detect_critical_errors(system_lines, app_lines):
    critical_errors = []
    for line in system_lines + app_lines:
        if "CRITICAL" in line or "ERROR" in line:
            critical_errors.append(line.strip())
    return critical_errors


def detect_suspicious_scripts(auth_lines, sys_lines):
    suspicious_lines = []
    keywords = ['cron', 'script', 'unauthorized', 'bash', 'sh', 'python', 'wget', 'curl']
    for line in auth_lines + sys_lines:
        if any(kw in line.lower() for kw in keywords):
            suspicious_lines.append(line.strip())
    return suspicious_lines

# === MAIN ===

# Load logs
access_data = read_log(access_log)
auth_data = read_log(auth_log)
sys_data = read_log(sys_log)
app_data = read_log(app_log)

# Run detectors
brute_force = detect_brute_force(access_data, auth_data)
traffic_spikes = detect_traffic_spikes(access_data)
critical_errors = detect_critical_errors(sys_data, app_data)
suspicious_scripts = detect_suspicious_scripts(auth_data, sys_data)

# === REPORT ===

print("\n🛑 BRUTE-FORCE ATTEMPTS:")
if brute_force:
    for ip, count in brute_force.items():
        print(f" - {ip} → {count} failed attempts")
else:
    print("Nothing suspicious.")

print("\n⚠️ TRAFFIC SPIKES (>=5 requests):")
if traffic_spikes:
    for ip, count in traffic_spikes.items():
        print(f" - {ip} → {count} requests")
else:
    print("No unusual traffic.")

print("\n🔥 CRITICAL SYSTEM ERRORS:")
if critical_errors:
    for line in critical_errors[:10]:  # show up to 10
        print(f" - {line}")
else:
    print("System stable.")

print("\n🦠 SUSPICIOUS SCRIPT ACTIVITY:")
if suspicious_scripts:
    for line in suspicious_scripts[:10]:  # show up to 10
        print(f" - {line}")
else:
    print("No suspicious scripts.")

print("\n✅ Log analysis complete.")

output_file = os.path.join(base_path, "report.txt")  # Define where to save the report

with open(output_file, 'w', encoding='utf-8') as f:
    # Write Brute-Force results
    f.write("\n🛑 BRUTE-FORCE ATTEMPTS:\n")
    if brute_force:
        for ip, count in brute_force.items():
            f.write(f" - {ip} → {count} failed attempts\n")
    else:
        f.write("Nothing suspicious.\n")

    # Write Traffic Spikes results
    f.write("\n⚠️ TRAFFIC SPIKES (>=5 requests):\n")
    if traffic_spikes:
        for ip, count in traffic_spikes.items():
            f.write(f" - {ip} → {count} requests\n")
    else:
        f.write("No unusual traffic.\n")

    # Write Critical Errors results
    f.write("\n🔥 CRITICAL SYSTEM ERRORS:\n")
    if critical_errors:
        for line in critical_errors[:10]:  # Limiting to top 10 errors
            f.write(f" - {line}\n")
    else:
        f.write("System stable.\n")

    # Write Suspicious Scripts results
    f.write("\n🦠 SUSPICIOUS SCRIPT ACTIVITY:\n")
    if suspicious_scripts:
        for line in suspicious_scripts[:10]:  # Limiting to top 10 suspicious activities
            f.write(f" - {line}\n")
    else:
        f.write("No suspicious scripts.\n")

    f.write("\n✅ Log analysis complete.\n")

print(f"✅ Report generated and saved to {output_file}.")

