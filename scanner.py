import socket
import json
import csv
from datetime import datetime

SUSPICIOUS_PORTS = [21, 23, 3389]
# most common ports used on a system
PORTS_TO_SCAN = [21, 22, 23, 25, 80, 443, 3306, 3389, 8080, 8443]


def check_port(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()

        return result == 0
    except Exception:
        return False


def scan_target(ip):
    print(f"Scanning {ip}...")

    open_ports = []
    suspicious_findings = []

    for port in PORTS_TO_SCAN:
        is_open = check_port(ip, port)

        if is_open:
            open_ports.append(port)
            print(f" [OPEN] Port {port}")

            if port in SUSPICIOUS_PORTS:
                warning = f"Alert: Suspicious port {port} is open on {ip}"
                suspicious_findings.append(warning)
                print(f" *** {warning} ***")
    return {
        "ip": ip,
        "scan_time": datetime.now().isoformat(),
        "open_ports": open_ports,
        "suspicious_ports": suspicious_findings,
        "risk_level": "HIGH" if suspicious_findings else "LOW"
    }


def save_json_report(results, filename="scan_report.json"):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nJSON report saved to {filename}")


def save_csv_report(results, filename="scan_report.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "Scan Time", "Open Ports", "Suspicious Ports", "Risk Level"])

        for result in results:
            writer.writerow([
                result["ip"],
                result["scan_time"],
                ", ".join(map(str, result["open_ports"])),
                "; ".join(result["suspicious_ports"]),
                result["risk_level"]
            ])
    print(f"CSV report saved to {filename}")


def main():
    targets = [
        "127.0.0.1",
    ]

    all_results = []

    for ip in targets:
        result = scan_target(ip)
        all_results.append(result)

    save_json_report(all_results)
    save_csv_report(all_results)

    print("\n=== SCAN SUMMARY ===")
    high_risk = [r for r in all_results if r["risk_level"] == "HIGH"]
    print(f"Total targets scanned: {len(all_results)}")
    print(f"High risk targets: {len(high_risk)}")

    if high_risk:
        print("\nHIGH RISK TARGETS:")
        for r in high_risk:
            print(f" - {r['ip']}: {r['suspicious_ports']}")


if __name__ == "__main__":
    main()

