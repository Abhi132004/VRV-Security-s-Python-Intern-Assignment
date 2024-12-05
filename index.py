import re
import csv
from collections import Counter, defaultdict

def parse_log_file(file_path):
    ip_request_count = Counter()
    endpoint_count = Counter()
    failed_login_attempts = defaultdict(int)
    failed_login_lines = []

    failed_login_pattern = re.compile(r'401|Invalid credentials')

    with open(file_path, 'r') as log_file:
        for line in log_file:
            ip_match = re.match(r'^(\S+)', line)
            ip_address = ip_match.group(1) if ip_match else None

            endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD)\s(\S+)', line)
            endpoint = endpoint_match.group(1) if endpoint_match else None

            if ip_address:
                ip_request_count[ip_address] += 1
            if endpoint:
                endpoint_count[endpoint] += 1

            if failed_login_pattern.search(line):
                if ip_address:
                    failed_login_attempts[ip_address] += 1
                    failed_login_lines.append(line.strip())

    return ip_request_count, endpoint_count, failed_login_attempts, failed_login_lines

def detect_suspicious_activity(failed_login_attempts):
    return failed_login_attempts  

def save_results_to_csv(ip_request_count, endpoint_count, suspicious_activity):
    with open('log_analysis_results.csv', 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write Requests per IP
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_request_count.most_common():
            writer.writerow([ip, count])
        writer.writerow([])  

        # Write Most Accessed Endpoint
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        for endpoint, count in endpoint_count.most_common():
            writer.writerow([endpoint, count])
        writer.writerow([])  

        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    log_file = 'sample.log'
    ip_request_count, endpoint_count, failed_login_attempts, failed_login_lines = parse_log_file(log_file)

    print("Failed login attempt detected:")
    print(f"{failed_login_lines[0]}")  # Print the first line explicitly
    print("... (continues for all detected failed login attempts)")

    sorted_ip_requests = ip_request_count.most_common()

    most_accessed_endpoint = endpoint_count.most_common(1)[0] if endpoint_count else ("None", 0)

    suspicious_activity = detect_suspicious_activity(failed_login_attempts)

    print("\nIP Address           Request Count")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count}")

    #results to CSV
    save_results_to_csv(ip_request_count, endpoint_count, suspicious_activity)
    print("\nResults have been saved to 'log_analysis_results.csv'.")

if __name__ == "__main__":
    main()
