# log_analyzer.py - Mini Log Analyzer (SIEM-lite)
# Detects brute-force login attempts from a log file.
import os

LOG_FILE = "server_log.txt"   # file to read
THRESHOLD = 5                 # more failed attempts than this = suspicious

SAMPLE_LOG = """2026-11-01 10:01, 192.168.1.5, admin, FAILED
2026-11-01 10:02, 192.168.1.5, admin, FAILED
2026-11-01 10:02, 192.168.1.9, alok, SUCCESS
2026-11-01 10:03, 192.168.1.5, root, FAILED
2026-11-01 10:03, 10.0.0.77, admin, FAILED
2026-11-01 10:04, 192.168.1.5, admin, FAILED
2026-11-01 10:04, 10.0.0.77, root, FAILED
2026-11-01 10:05, 192.168.1.5, user, FAILED
2026-11-01 10:05, 192.168.1.12, riya, SUCCESS
2026-11-01 10:06, 10.0.0.77, admin, FAILED
2026-11-01 10:06, 192.168.1.5, admin, FAILED
2026-11-01 10:07, 192.168.1.9, alok, FAILED
2026-11-01 10:07, 10.0.0.77, test, FAILED
2026-11-01 10:08, 192.168.1.5, root, FAILED
2026-11-01 10:08, 10.0.0.77, admin, FAILED
2026-11-01 10:09, 192.168.1.9, alok, SUCCESS
2026-11-01 10:09, 192.168.1.5, admin, FAILED
2026-11-01 10:10, 10.0.0.77, root, FAILED
2026-11-01 10:10, 192.168.1.12, riya, FAILED
2026-11-01 10:11, 192.168.1.12, riya, SUCCESS
"""


def create_sample_log():
    """If the log file is missing, create it with sample data."""
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as file:
            file.write(SAMPLE_LOG)
        print(f"({LOG_FILE} was missing, so a sample file was created)\n")


def read_logs(filename):
    """Read the log file and return a list of (time, ip, user, status)."""
    entries = []
    with open(filename, "r") as file:
        for line in file:
            line = line.strip()
            if line == "":
                continue
            parts = line.split(",")
            if len(parts) != 4:
                continue
            time, ip, user, status = [p.strip() for p in parts]
            entries.append((time, ip, user, status))
    return entries


def count_failed(entries):
    """Count FAILED attempts for every IP. Returns a dictionary."""
    failed_per_ip = {}
    for time, ip, user, status in entries:
        if status == "FAILED":
            failed_per_ip[ip] = failed_per_ip.get(ip, 0) + 1
    return failed_per_ip


def print_report(failed_per_ip, total_entries):
    """Print the final analysis report."""
    total_failed = sum(failed_per_ip.values())

    print("===== LOG ANALYSIS REPORT =====")
    print(f"Total log entries   : {total_entries}")
    print(f"Total failed logins : {total_failed}")
    print()

    sorted_ips = sorted(failed_per_ip.items(), key=lambda item: item[1], reverse=True)

    print("SUSPICIOUS IPs:")
    found = False
    for ip, count in sorted_ips:
        if count > THRESHOLD:
            print(f"  {ip:<15} -> {count} failed attempts  (ALERT!)")
            found = True
    if not found:
        print("  None found")

    print()
    print("NORMAL IPs:")
    for ip, count in sorted_ips:
        if count <= THRESHOLD:
            print(f"  {ip:<15} -> {count} failed attempts")


def main():
    create_sample_log()
    entries = read_logs(LOG_FILE)
    failed_per_ip = count_failed(entries)
    print_report(failed_per_ip, len(entries))


main()