import re
from collections import defaultdict
from datetime import datetime

def analyze_log(log_file, threshold=5):
    failed_attempts = defaultdict(int)
    failed_ips = []

    print(f"\n{'='*50}")
    print(f"SSH Brute Force Detector")
    print(f"Analyzing: {log_file}")
    print(f"Threshold: {threshold} failed attempts")
    print(f"{'='*50}\n")

    try:
        with open(log_file, "r") as f:
            for line in f:
                if "Failed password" in line:
                    match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        ip = match.group(1)
                        failed_attempts[ip] += 1

    except FileNotFoundError:
        print(f"Log file not found: {log_file}")
        return

    if not failed_attempts:
        print("No failed SSH attempts found.")
        return

    print(f"{'IP Address':<20} {'Failed Attempts':<20} {'Status'}")
    print("-" * 50)

    for ip, count in sorted(failed_attempts.items(), 
                            key=lambda x: x[1], reverse=True):
        if count >= threshold:
            status = "⚠️  SUSPICIOUS - POSSIBLE BRUTE FORCE"
            failed_ips.append(ip)
        else:
            status = "✅ Normal"
        print(f"{ip:<20} {count:<20} {status}")

    print(f"\nScan complete at: {datetime.now()}")
    print(f"Total suspicious IPs detected: {len(failed_ips)}")

    if failed_ips:
        print("\nSuspicious IPs:")
        for ip in failed_ips:
            print(f"  ⚠️  {ip} — recommend blocking with: sudo ufw deny from {ip}")

if __name__ == "__main__":
    print("1. Analyze real auth log")
    print("2. Analyze sample log (for testing)")
    choice = input("\nChoose: ")

    if choice == "1":
        analyze_log("/var/log/auth.log")
    elif choice == "2":
        analyze_log("sample_auth.log")
    else:
        print("Invalid choice")
