import socket
import requests
import time
import os
import sys

SPRING_BOOT_API = "http://localhost:8080/api/scanner/submit-findings"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
PORTS_TO_SCAN = [21, 22, 80, 443, 8080, 3306, 3389, 5432, 27017]

# ──────────────────────────────────────────────
# NVD lookup — works WITHOUT an API key too.
# The public unauthenticated rate limit is 5 req/30s,
# so we add a short sleep between calls.
# ──────────────────────────────────────────────
import re

def clean_banner_for_nvd(banner):
    """Extracts a clean 'Software Version' string from a raw banner for NVD lookup."""
    patterns = [
        (r'OpenSSH[_/\s](\d+\.\d+[\.\d]*)',        'OpenSSH'),
        (r'Apache[/\s](\d+\.\d+[\.\d]*)',           'Apache HTTP Server'),
        (r'nginx[/\s](\d+\.\d+[\.\d]*)',            'nginx'),
        (r'Microsoft-IIS[/\s](\d+\.\d+)',           'Microsoft IIS'),
        (r'ProFTPD[_\s](\d+\.\d+[\.\d]*)',          'ProFTPD'),
        (r'vsftpd[_\s](\d+\.\d+[\.\d]*)',           'vsftpd'),
        (r'FileZilla[_\s](\d+\.\d+[\.\d]*)',        'FileZilla Server'),
        (r'MySQL[_\s](\d+\.\d+[\.\d]*)',            'MySQL'),
        (r'PostgreSQL[_\s](\d+\.\d+[\.\d]*)',       'PostgreSQL'),
        (r'MongoDB[_\s](\d+\.\d+[\.\d]*)',          'MongoDB'),
        (r'OpenSSL[_/\s](\d+\.\d+[\.\da-z]*)',      'OpenSSL'),
        (r'lighttpd[/\s](\d+\.\d+[\.\d]*)',         'lighttpd'),
        (r'Exim[_\s](\d+\.\d+[\.\d]*)',             'Exim'),
        (r'Postfix[_\s](\d+\.\d+[\.\d]*)',          'Postfix'),
        (r'Samba[_\s](\d+\.\d+[\.\d]*)',            'Samba'),
        (r'Pure-FTPd[_\s](\d+\.\d+[\.\d]*)',        'Pure-FTPd'),
    ]
    for pattern, name in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            try:
                return f"{name} {match.group(1)}"
            except IndexError:
                return name
    generic = re.search(r'([A-Za-z][\w\-]+)[/\s_](\d+\.\d+[\.\d]*)', banner)
    if generic:
        return f"{generic.group(1)} {generic.group(2)}"
    return None


def get_cve_for_banner(banner, host, port):
    search_term = clean_banner_for_nvd(banner)

    if not search_term:
        print(f"[-] Could not parse banner. Using NOMATCH fallback.")
        time.sleep(6.5)
        return f"NOMATCH-{host}-{port}-{int(time.time())}"

    print(f"[*] Querying NVD for: '{search_term}'...")
    headers = {"User-Agent": "Mozilla/5.0"}
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={requests.utils.quote(search_term)}&resultsPerPage=1"

    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 429:
            print("[-] NVD rate-limited. Waiting 10s...")
            time.sleep(10)
            r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            if data.get("totalResults", 0) > 0:
                cve = data["vulnerabilities"][0]["cve"]["id"]
                print(f"[+] NVD match: {cve}")
                time.sleep(6.5)
                return cve
            else:
                print(f"[-] NVD: 0 results for '{search_term}'")
        else:
            print(f"[-] NVD API Error: {r.status_code}")
    except Exception as e:
        print(f"[-] NVD query error: {e}")

    time.sleep(6.5)
    return f"NOMATCH-{host}-{port}-{int(time.time())}"



def submit_finding(payload):
    try:
        r = requests.post(SPRING_BOOT_API, json=payload, timeout=10)
        if r.status_code in (200, 201):
            print(f"[+] Finding saved: {payload['cveID']}")
        else:
            print(f"[-] Server rejected finding: HTTP {r.status_code}")
    except Exception as e:
        print(f"[-] Failed to submit finding: {e}")


SERVICE_MAP = {
    21: "FTP Service",
    22: "SSH Service",
    80: "HTTP Web Service",
    443: "HTTPS Web Service",
    8080: "HTTP Alt Service",
    3306: "MySQL Database",
    3389: "RDP Remote Desktop",
    5432: "PostgreSQL Database",
    27017: "MongoDB Database",
}


def scan_ports(host):
    import ssl
    for port in PORTS_TO_SCAN:
        print(f"[*] Probing {host}:{port}...")
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((host, port))

            protocol_alert = ""
            if port == 443:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    # Enable legacy protocols so we can detect if the server accepts them
                    s = ctx.wrap_socket(s, server_hostname=host)
                    tls_version = s.version()
                    if tls_version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
                        protocol_alert = f" [CRITICAL: Vulnerable {tls_version} detected!]"
                    else:
                        protocol_alert = f" [Secured with {tls_version}]"
                except Exception as e:
                    # If SSL negotiation fails, the socket is destroyed. 
                    # We must recreate it to continue with the raw HTTP probe.
                    s = socket.socket()
                    s.settimeout(3)
                    s.connect((host, port))

            # Send a minimal HTTP probe on web ports so the server replies
            if port in [80, 8080, 443]:
                http_req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Vigilance-Scanner/1.0\r\nConnection: close\r\n\r\n"
                s.sendall(http_req.encode('utf-8'))

            banner = s.recv(2048).decode('utf-8', errors='ignore').strip()
            s.close()

            if banner:
                clean_banner = banner.split('\n')[0].strip() + protocol_alert
                print(f"[+] Discovered Service on Port {port}: {clean_banner}")

                cve_id = get_cve_for_banner(clean_banner, host, port)
                service_name = SERVICE_MAP.get(port, f"Service on Port {port}")

                submit_finding({
                    "cveID": cve_id,
                    "product": clean_banner[:80],
                    "vulnerabilityName": f"Exposed {service_name} on Port {port}",
                    "vendorProject": host
                })
            else:
                print(f"[~] Port {port} open but no banner received.")
                # Still report the open port even without banner
                service_name = SERVICE_MAP.get(port, f"Service on Port {port}")
                submit_finding({
                    "cveID": f"NOMATCH-{host}-{port}-{int(time.time())}",
                    "product": f"Open port {port}",
                    "vulnerabilityName": f"Exposed {service_name} on Port {port}",
                    "vendorProject": host
                })

        except ConnectionRefusedError:
            print(f"[-] Port {port} closed (connection refused)")
        except socket.timeout:
            print(f"[-] Port {port} filtered (timeout)")
        except Exception as e:
            print(f"[-] Port {port} error: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <host>  OR  python scanner.py --file hosts.txt")
        sys.exit(1)
    if sys.argv[1] == "--file":
        with open(sys.argv[2]) as f:
            hosts = [line.strip() for line in f if line.strip()]
    else:
        hosts = [sys.argv[1]]

    for h in hosts:
        print(f"\n===== Scanning target: {h} =====")
        scan_ports(h)