import nmap
import requests
import ssl
import socket
from datetime import datetime

DANGEROUS_PATHS = [
    "/admin", "/backup.zip", "/config.php", "/.git", "/.env", "/test", "/phpinfo.php"
]

OUTDATED_SERVERS = {
    "Apache": ["2.2", "2.0", "1.3"],
    "nginx": ["1.14", "1.12", "1.10"],
    "IIS": ["6.0", "7.0"]
}

def scan_ports(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-T3 -F')
    scanned_ports = list(nm[target]['tcp'].keys()) if target in nm.all_hosts() else []
    return nm[target]['tcp'] if target in nm.all_hosts() else {}, scanned_ports

def check_http_headers(url):
    try:
        response = requests.get(url)
        return response.headers
    except Exception as e:
        return {"error": str(e)}

def scan_dangerous_files(url):
    found = []
    for path in DANGEROUS_PATHS:
        try:
            resp = requests.get(url + path, timeout=3)
            if resp.status_code == 200:
                found.append(path)
        except Exception:
            continue
    return found

def check_outdated_server(headers):
    server = headers.get("Server", "")
    for name, versions in OUTDATED_SERVERS.items():
        if name in server:
            for v in versions:
                if v in server:
                    return f"{server} (outdated version detected)"
    return None

def check_directory_listing(url):
    try:
        resp = requests.get(url, timeout=3)
        if "Index of /" in resp.text:
            return True
    except Exception:
        pass
    return False

def check_certificate_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = cert['notAfter']
                expiry_date = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
                if expiry_date < datetime.utcnow():
                    return f"Certificate expired on {expiry_date}"
                elif (expiry_date - datetime.utcnow()).days < 30:
                    return f"Certificate will expire soon: {expiry_date}"
                else:
                    return f"Certificate is valid until {expiry_date}"
    except Exception as e:
        return f"Could not check certificate: {e}"

def check_sql_injection(url):
    test_paths = [
        "/login?username=admin' OR '1'='1&password=admin",
        "/search?q=test' OR '1'='1",
        "/product?id=1' OR '1'='1"
    ]
    vulnerable = []
    for path in test_paths:
        try:
            resp = requests.get(url + path, timeout=5)
            if any(err in resp.text.lower() for err in [
                "sql syntax", "mysql", "syntax error", "you have an error in your sql", "warning: mysql"
            ]):
                vulnerable.append(path)
        except Exception:
            continue
    return vulnerable

def check_xss(url):
    test_paths = [
        "/search?q=<script>alert('xss')</script>",
        "/comment?msg=<script>alert('xss')</script>"
    ]
    vulnerable = []
    for path in test_paths:
        try:
            resp = requests.get(url + path, timeout=5)
            if "<script>alert('xss')</script>" in resp.text:
                vulnerable.append(path)
        except Exception:
            continue
    return vulnerable

def analyze_risks(scan_results, headers, dangerous_files, outdated_server, dir_listing, sql_injection_vuln, xss_vuln):
    risks = []
    solutions = []
    vulnerable_ports = []

    # Check for HTTP port open
    if 80 in scan_results:
        risks.append({"risk": "HTTP port (80) open", "priority": "medium", "port": 80})
        solutions.append("Consider disabling unused HTTP services or securing them with HTTPS.")
        vulnerable_ports.append(80)

    # Check for Server header exposure
    if 'Server' in headers:
        risks.append({"risk": f"Server header exposed: {headers['Server']}", "priority": "low", "port": "HTTP"})
        solutions.append("Remove or modify the Server header to reduce information disclosure.")

    # Dangerous files
    if dangerous_files:
        risks.append({"risk": f"Dangerous files exposed: {', '.join(dangerous_files)}", "priority": "high", "port": "HTTP"})
        solutions.append("Remove or restrict access to sensitive files and directories.")

    # Outdated server
    if outdated_server:
        risks.append({"risk": f"Outdated server detected: {outdated_server}", "priority": "high", "port": "HTTP"})
        solutions.append("Update your web server to the latest stable version.")

    # Directory listing
    if dir_listing:
        risks.append({"risk": "Directory listing is enabled", "priority": "medium", "port": "HTTP"})
        solutions.append("Disable directory listing in your web server configuration.")

    # SQL Injection
    if sql_injection_vuln:
        risks.append({"risk": f"Possible SQL Injection points: {', '.join(sql_injection_vuln)}", "priority": "high", "port": "HTTP"})
        solutions.append("Sanitize all user inputs and use parameterized queries to prevent SQL injection.")

    # XSS
    if xss_vuln:
        risks.append({"risk": f"Possible XSS points: {', '.join(xss_vuln)}", "priority": "high", "port": "HTTP"})
        solutions.append("Properly encode output and validate/sanitize user input to prevent XSS.")

    return risks, solutions, vulnerable_ports

def save_report(scanned_ports, risks, solutions, vulnerable_ports, server_version, cert_status, brute_force_results, sql_injection_vuln, xss_vuln, filename="pentest_report.txt"):
    with open(filename, "w") as f:
        f.write("--- PenTest Bot Scan Process ---\n")
        f.write("1. Port scanning initiated...\n")
        f.write(f"   Scanned Ports: {', '.join(str(p) for p in scanned_ports)}\n")
        f.write("2. HTTP header analysis started...\n")
        f.write(f"   Server Version: {server_version}\n")
        f.write("3. Dangerous files scan started...\n")
        f.write("4. Outdated server and misconfiguration checks started...\n")
        f.write("5. SSL certificate check...\n")
        f.write(f"   Certificate Status: {cert_status}\n")
        f.write("6. Brute force login attempt...\n")
        if brute_force_results:
            f.write(f"   Brute force login successful with: {', '.join(brute_force_results)}\n")
        else:
            f.write("   Brute force login: Not successful\n")
        f.write("7. Risk analysis completed...\n\n")
        f.write("--- Vulnerability Report ---\n")

        # Track which vulnerabilities were found
        found = {
            "server_header": False,
            "dangerous_files": False,
            "outdated_server": False,
            "directory_listing": False,
            "certificate": False,
            "sql_injection": False,
            "xss": False
        }

        for i, risk in enumerate(risks):
            if "Server header exposed" in risk['risk']:
                found["server_header"] = True
                f.write(f"\nVulnerability found on port: {risk.get('port', 'N/A')}\n")
                f.write(f"Risk: {risk['risk']} | Priority: {risk['priority']}\n")
                f.write(f"Solution: {solutions[i]}\n")
            elif "Dangerous files exposed" in risk['risk']:
                found["dangerous_files"] = True
                f.write(f"\nVulnerability found on port: {risk.get('port', 'N/A')}\n")
                f.write(f"Risk: {risk['risk']} | Priority: {risk['priority']}\n")
                f.write(f"Solution: {solutions[i]}\n")
            elif "Outdated server detected" in risk['risk']:
                found["outdated_server"] = True
                f.write(f"\nVulnerability found on port: {risk.get('port', 'N/A')}\n")
                f.write(f"Risk: {risk['risk']} | Priority: {risk['priority']}\n")
                f.write(f"Solution: {solutions[i]}\n")
            elif "Directory listing is enabled" in risk['risk']:
                found["directory_listing"] = True
                f.write(f"\nVulnerability found on port: {risk.get('port', 'N/A')}\n")
                f.write(f"Risk: {risk['risk']} | Priority: {risk['priority']}\n")
                f.write(f"Solution: {solutions[i]}\n")
            elif "Certificate" in risk['risk']:
                found["certificate"] = True
                f.write(f"\nVulnerability found: SSL Certificate Issue\n")
                f.write(f"Risk: {risk['risk']} | Priority: {risk['priority']}\n")
                f.write(f"Solution: {solutions[i]}\n")
            elif "SQL Injection vulnerability detected" in risk['risk']:
                found["sql_injection"] = True
                f.write(f"\nVulnerability found: SQL Injection\n")
                f.write(f"Risk: {risk['risk']} | Priority: {risk['priority']}\n")
                f.write(f"Solution: {solutions[i]}\n")
            elif "XSS vulnerability detected" in risk['risk']:
                found["xss"] = True
                f.write(f"\nVulnerability found: XSS\n")
                f.write(f"Risk: {risk['risk']} | Priority: {risk['priority']}\n")
                f.write(f"Solution: {solutions[i]}\n")

        # Write "Not found" for each category not detected
        if not found["server_header"]:
            f.write("\nServer header exposure: Not found\n")
        if not found["dangerous_files"]:
            f.write("\nDangerous files exposure: Not found\n")
        if not found["outdated_server"]:
            f.write("\nOutdated server: Not found\n")
        if not found["directory_listing"]:
            f.write("\nDirectory listing: Not found\n")
        if not found["certificate"]:
            f.write("\nSSL certificate issues: Not found\n")
        if not found["sql_injection"]:
            f.write("\nSQL Injection vulnerabilities: Not found\n")
        if not found["xss"]:
            f.write("\nXSS vulnerabilities: Not found\n")

def pentest():
    target = input("Enter target domain or IP: ")
    url = f"http://{target}"
    print("Scanning ports...")
    scan_results, scanned_ports = scan_ports(target)
    print(f"Scanned Ports: {', '.join(str(p) for p in scanned_ports)}")
    print("Checking HTTP headers...")
    headers = check_http_headers(url)
    server_version = headers.get("Server", "Unknown")
    print(f"Server Version: {server_version}")
    print("Scanning for dangerous files...")
    dangerous_files = scan_dangerous_files(url)
    print("Checking for outdated server versions...")
    outdated_server = check_outdated_server(headers)
    print("Checking for directory listing...")
    dir_listing = check_directory_listing(url)
    print("Checking for SQL injection vulnerabilities...")
    sql_injection_vuln = check_sql_injection(url)
    print("Checking for XSS vulnerabilities...")
    xss_vuln = check_xss(url)
    print("Attempting brute force login on /login ...")
    brute_force_results = brute_force_login(url)
    print("Analyzing risks...")
    risks, solutions, vulnerable_ports = analyze_risks(
        scan_results, headers, dangerous_files, outdated_server, dir_listing, sql_injection_vuln, xss_vuln
    )
    print("\n--- Vulnerability Report ---")
    print(f"Scanned Ports: {', '.join(str(p) for p in scanned_ports)}")
    print(f"Server Version: {server_version}")
    if sql_injection_vuln:
        print(f"\nPossible SQL Injection points: {', '.join(sql_injection_vuln)}")
    else:
        print("\nSQL Injection: Not found")
    if xss_vuln:
        print(f"\nPossible XSS points: {', '.join(xss_vuln)}")
    else:
        print("\nXSS: Not found")
    if brute_force_results:
        print(f"\nBrute force login successful with: {', '.join(brute_force_results)}")
    else:
        print("\nBrute force login: Not successful")
    if risks:
        for i, risk in enumerate(risks):
            print(f"\nVulnerability found on port: {risk.get('port', 'N/A')}")
            print(f"Risk: {risk['risk']} | Priority: {risk['priority']}")
            print(f"Solution: {solutions[i]}")
    else:
        print("No major risks detected.")
    cert_status = check_certificate_expiry(target)
    save_report(scanned_ports, risks, solutions, vulnerable_ports, server_version, cert_status, brute_force_results, sql_injection_vuln, xss_vuln)

def brute_force_login(url):
    login_endpoint = url + "/login/user"
    demo_credentials = [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "user", "password": "user"},
        {"username": "test", "password": "test"}
    ]
    successful = []
    for creds in demo_credentials:
        try:
            resp = requests.post(login_endpoint, data=creds, timeout=5)
            # Adjust this check based on the target's response for failed logins
            if resp.status_code == 200 and ("logout" in resp.text.lower() or "dashboard" in resp.text.lower()):
                successful.append(f"{creds['username']}:{creds['password']}")
        except Exception:
            continue
    return successful

def main():
    print("Welcome to the PenTest Bot!")
    pentest()

if __name__ == "__main__":
    main()