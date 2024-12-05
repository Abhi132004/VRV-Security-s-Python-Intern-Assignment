# **Log File Analysis Tool**

## **Overview**

This Python-based log analyzer processes server log files to extract meaningful insights and detect potential suspicious activities. It tracks request counts, analyzes endpoint access, and flags failed login attempts, providing a comprehensive overview of server activity. The tool is ideal for system administrators and security analysts aiming to monitor and analyze logs effectively.

---

## **Features**

- **Requests per IP**: Tracks and counts the number of requests from each IP address.
- **Endpoint Analysis**: Identifies and counts access to specific endpoints (e.g., `/login`).
- **Failed Login Detection**: Detects failed login attempts using patterns like HTTP 401 errors or "Invalid credentials."
- **Suspicious Activity Identification**: Highlights IPs with high numbers of failed login attempts.
- **CSV Report Generation**: Exports analysis results into a structured CSV file for further review.

---

## **Input Format**

The tool processes a standard server log file (e.g., `sample.log`) where each entry contains details such as IP addresses, request methods, endpoints, HTTP response codes, and metadata.

**Example log entry**:

---

## **Installation**

1. Clone this repository:
   ```bash
   git clone https://github.com/your-repo/log-file-analysis-tool.git
   cd log-file-analysis-tool
   ```
2. Ensure you have Python 3.6 or higher installed.
3. Place your log file in the project directory as sample.log (or update the file path in the script).

## **Usage**
Run the script using the command:
```
python index.py
```
## **Output**

### **Console Output**

The script displays the following information:

## **Requests per IP**
```text
IP Address           Request Count
203.0.113.5          8
198.51.100.23        8
192.168.1.1          7
```
Most Accessed Endpoint:
```
/login (Accessed 13 times)
```
## **Suspicious Activity:**
```
IP Address           Failed Login Attempts
203.0.113.5          8
192.168.1.100        5
```
## **Failed Login Attempt Details:**
```
Failed login attempt detected:
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
... (continues for all detected failed login attempts)
```
### **CSV Output**

Results are saved to `log_analysis_results.csv` with the following sections:
- **Requests per IP**
- **Most accessed endpoints**
- **Suspicious activity** (IP and failed login attempts)

---

### **Code Structure**

- **`parse_log_file(file_path)`**: Extracts IP requests, endpoint access counts, and failed login attempts.
- **`detect_suspicious_activity(failed_login_attempts)`**: Identifies and highlights IPs with significant failed login counts.
- **`save_results_to_csv(ip_request_count, endpoint_count, suspicious_activity)`**: Saves the analyzed data into a CSV file.
- **`main()`**: Coordinates the entire log analysis process.

### **Future Enhancements**

- **Support additional log formats** (e.g., Nginx).
- **Add visualization tools** for graphical representation of results.
- **Implement real-time log monitoring** for live analysis.
- **Extend suspicious activity detection patterns** (e.g., SQL injection).

