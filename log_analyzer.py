#!/usr/bin/env python3
import re
import json
import datetime
from collections import Counter

def parse_log_line(line):
    """Extract IP, timestamp, request, status, size from a common log format."""
    pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)'
    match = re.search(pattern, line)
    if match:
        ip, timestamp, request, status, size = match.groups()
        return {
            'ip': ip,
            'timestamp': timestamp,
            'request': request,
            'status': int(status),
            'size': int(size)
        }
    return None

def is_suspicious(request):
    """Check if the request contains possible attack patterns."""
    attack_keywords = ['union', 'select', 'sql', 'eval', 'exec', 'system', 'cmd=', 'wp-admin', 'admin.php']
    return any(keyword in request.lower() for keyword in attack_keywords)

def analyze_log(log_file):
    """Read log file and produce statistics."""
    ip_counts = Counter()
    status_counts = Counter()
    suspicious_entries = []
    total_requests = 0

    with open(log_file, 'r', errors='ignore') as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                total_requests += 1
                ip_counts[parsed['ip']] += 1
                status_counts[parsed['status']] += 1
                if is_suspicious(parsed['request']):
                    suspicious_entries.append(parsed)

    # Generate report
    report = {
        'timestamp': datetime.datetime.now().isoformat(),
        'log_file': log_file,
        'total_requests': total_requests,
        'unique_ips': len(ip_counts),
        'top_ips': ip_counts.most_common(5),
        'status_codes': dict(status_counts),
        'suspicious_count': len(suspicious_entries),
        'suspicious_entries': suspicious_entries[:5]  # show first 5 for brevity
    }
    return report

def main():
    log_file = input("Enter path to log file (or press Enter for sample_access.log): ").strip()
    if not log_file:
        log_file = "sample_access.log"
    print(f"[*] Analyzing: {log_file}")
    report = analyze_log(log_file)

    # Print a summary
    print("\n" + "=" * 50)
    print("  LOG ANALYSIS DASHBOARD")
    print("=" * 50)
    print(f"Total requests: {report['total_requests']}")
    print(f"Unique IPs: {report['unique_ips']}")
    print(f"Suspicious requests: {report['suspicious_count']}")
    print("\nTop 5 IPs by request count:")
    for ip, count in report['top_ips']:
        print(f"  {ip}: {count}")
    print("\nStatus codes:")
    for code, count in sorted(report['status_codes'].items()):
        print(f"  {code}: {count}")
    if report['suspicious_entries']:
        print("\n[!] Sample suspicious requests:")
        for entry in report['suspicious_entries'][:3]:
            print(f"  {entry['ip']} - {entry['request']}")

    # Save JSON report
    output_file = f"log_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n[*] Full report saved to: {output_file}")

if __name__ == "__main__":
    main()
