import re
from collections import defaultdict

# === FUNCTION DEFINITIONS ===

def read_log(file_path):
    """
    Reads a log file from the given path and returns its lines as a list.
    If the file does not exist, returns an empty list.
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
        return []


def detect_brute_force(access_lines, auth_lines, threshold=3):
    """
    Detects potential brute-force attempts based on multiple failed logins.
    
    Parameters:
    - access_lines: list of strings from the access log
    - auth_lines: list of strings from the authentication log
    - threshold: minimum number of failed attempts to be flagged

    Returns:
    - Dictionary of IPs and their failed attempt counts
    """
    brute_force_ips = defaultdict(int)

    # Detect based on HTTP 401 Unauthorized responses
    for line in access_lines:
        match = re.search(r'(\d+\.\d+\.\d+\.\d+).+?"\S+ \S+ \S+" 401', line)
        if match:
            ip = match.group(1)
            brute_force_ips[ip] += 1

    # Detect based on SSH or authentication failures
    for line in auth_lines:
        if "Failed password" in line:
            match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                ip = match.group(1)
                brute_force_ips[ip] += 1

    return {ip: count for ip, count in brute_force_ips.items() if count >= threshold}


def detect_traffic_spikes(access_lines, threshold=5):
    """
    Detects IPs making a high number of requests (traffic spikes).

    Parameters:
    - access_lines: list of strings from the access log
    - threshold: minimum number of requests to be flagged

    Returns:
    - Dictionary of IPs and their request counts
    """
    ip_counter = defaultdict(int)

    for line in access_lines:
        match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if match:
            ip = match.group(1)
            ip_counter[ip] += 1

    return {ip: count for ip, count in ip_counter.items() if count >= threshold}


def detect_critical_errors(system_lines, app_lines):
    """
    Detects critical errors from system and application logs.

    Parameters:
    - system_lines: list of system log lines
    - app_lines: list of application log lines

    Returns:
    - List of critical error lines
    """
    critical_errors = []

    for line in system_lines + app_lines:
        if "CRITICAL" in line or "ERROR" in line:
            critical_errors.append(line.strip())

    return critical_errors


def detect_suspicious_scripts(auth_lines, system_lines):
    """
    Detects suspicious script activities based on keywords.

    Parameters:
    - auth_lines: list of authentication log lines
    - system_lines: list of system log lines

    Returns:
    - List of suspicious activity lines
    """
    suspicious_lines = []
    keywords = ['cron', 'script', 'unauthorized', 'bash', 'sh', 'python', 'wget', 'curl']

    for line in auth_lines + system_lines:
        if any(keyword in line.lower() for keyword in keywords):
            suspicious_lines.append(line.strip())

    return suspicious_lines


def generate_report(brute_force, traffic_spikes, critical_errors, suspicious_scripts):
    """
    Generates a text-based report based on detected findings.

    Parameters:
    - brute_force: dictionary of brute-force IPs and counts
    - traffic_spikes: dictionary of traffic spike IPs and counts
    - critical_errors: list of critical error lines
    - suspicious_scripts: list of suspicious script activity lines

    Returns:
    - String containing the formatted report
    """
    report = []

    # Brute-force attempts
    report.append("\n🛑 BRUTE-FORCE ATTEMPTS:")
    if brute_force:
        for ip, count in sorted(brute_force.items(), key=lambda x: x[1], reverse=True):
            report.append(f" - {ip} → {count} failed attempts")
    else:
        report.append("Nothing suspicious.")

    # Traffic spikes
    report.append("\n⚠️ TRAFFIC SPIKES:")
    if traffic_spikes:
        for ip, count in sorted(traffic_spikes.items(), key=lambda x: x[1], reverse=True):
            report.append(f" - {ip} → {count} requests")
    else:
        report.append("No unusual traffic.")

    # Critical system errors
    report.append("\n🔥 CRITICAL SYSTEM ERRORS:")
    if critical_errors:
        for error in critical_errors[:10]:  # Limit output
            report.append(f" - {error}")
    else:
        report.append("System stable.")

    # Suspicious script activity
    report.append("\n🦠 SUSPICIOUS SCRIPT ACTIVITY:")
    if suspicious_scripts:
        for activity in suspicious_scripts[:10]:
            report.append(f" - {activity}")
    else:
        report.append("No suspicious scripts detected.")

    report.append("\n✅ Log analysis complete.\n")

    return "\n".join(report)


# === HOW TO USE ===
# 
# 1. Read logs into variables using `read_log(file_path)`.
# 2. Pass the log lines to detection functions.
# 3. Collect results and call `generate_report(...)` to create the report string.
# 4. Print or save the report as needed.
# 
# Example:
#
# access_lines = read_log("path_to_access.log")
# auth_lines = read_log("path_to_auth.log")
# system_lines = read_log("path_to_sys.log")
# app_lines = read_log("path_to_app.log")
#
# brute_force = detect_brute_force(access_lines, auth_lines)
# traffic_spikes = detect_traffic_spikes(access_lines)
# critical_errors = detect_critical_errors(system_lines, app_lines)
# suspicious_scripts = detect_suspicious_scripts(auth_lines, system_lines)
#
# report = generate_report(brute_force, traffic_spikes, critical_errors, suspicious_scripts)
# print(report)
#
# To save to file:
# with open("report.txt", "w", encoding="utf-8") as file:
#     file.write(report)
