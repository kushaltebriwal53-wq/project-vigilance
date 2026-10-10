import ssl
import socket
import sys
import time
import requests
import json
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID

SPRING_BOOT_API = "http://localhost:8080/api/scanner/submit-findings"

def raw_fuzz_weak_protocols(host, port=443):
    """
    Bypasses standard OS/Python SSL libraries by sending raw, hardcoded
    ClientHello hexadecimal packets down a dumb TCP pipe. 
    This acts like a mini Qualys SSL Labs engine to detect obsolete protocols.
    """
    vulnerable_found = []
    
    # Pre-computed raw ClientHello bytes for obsolete protocols
    probes = {
        "SSLv3":  bytes.fromhex('160300002f0100002b0300500bafd7d4c111983368cb04e2aab2d4cd0db2604206b8aef7b8efd325e3d7b2000002002f01000000'),
        "TLSv1.0": bytes.fromhex('160301002f0100002b0301500bafd7d4c111983368cb04e2aab2d4cd0db2604206b8aef7b8efd325e3d7b2000002002f01000000'),
        "TLSv1.1": bytes.fromhex('160302002f0100002b0302500bafd7d4c111983368cb04e2aab2d4cd0db2604206b8aef7b8efd325e3d7b2000002002f01000000')
    }
    
    for proto_name, raw_packet in probes.items():
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.send(raw_packet)
            resp = s.recv(1024)
            s.close()
            # If server responds with Handshake (0x16), it accepted the protocol!
            if len(resp) >= 3 and resp[0] == 0x16:
                vulnerable_found.append(proto_name)
        except Exception:
            pass
            
    return vulnerable_found

def check_ssl_certificate(host, port=443):
    result = {
        "host": host,
        "trusted": False, 
        "self_signed": False, 
        "expired": False, 
        "hostname_mismatch": True,
        "issuer": None, 
        "subject": None, 
        "expiration_date": None,
        "days_remaining": 0,
        "error": None,
        "san_list": [],
        "hidden_obsolete_protocols": raw_fuzz_weak_protocols(host, port)
    }
    
    try:
        # Context that verifies cert completely (host + trust)
        verify_ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with verify_ctx.wrap_socket(sock, server_hostname=host):
                    result["trusted"] = True
                    result["hostname_mismatch"] = False
        except ssl.SSLCertVerificationError as e:
            if "certificate verify failed" in str(e):
                result["trusted"] = False
            if "hostname" in str(e).lower() and "doesn't match" in str(e).lower():
                result["hostname_mismatch"] = True
        except Exception as e:
            pass # We will re-raise or catch in the untrusted fetch below

        # Fetch certificate completely (even if untrusted) to grab details
        untrusted_ctx = ssl.create_default_context()
        untrusted_ctx.check_hostname = False
        untrusted_ctx.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=5) as sock:
            with untrusted_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                result["tls_version"] = ssock.version()

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        result["issuer"] = issuer
        result["subject"] = subject
        result["self_signed"] = (issuer == subject)
        
        exp_date = cert.not_valid_after_utc
        result["expiration_date"] = exp_date.isoformat()
        
        now = datetime.now(timezone.utc)
        result["expired"] = exp_date < now
        result["days_remaining"] = (exp_date - now).days
        
        # Check SAN for hostname matching
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = san_ext.value.get_values_for_type(x509.DNSName)
            result["san_list"] = san_list
            
            # Simple wildcard matching
            for san in san_list:
                if san == host or (san.startswith("*.") and host.endswith(san[2:])):
                    result["hostname_mismatch"] = False
                    break
        except x509.ExtensionNotFound:
            # Fallback to Subject CN
            try:
                cn_list = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_list and cn_list[0].value == host:
                     result["hostname_mismatch"] = False
            except Exception:
                pass

    except Exception as e:
        result["error"] = str(e)
        
    return result

def submit_finding(host, result):
    if result.get("error"):
        print(json.dumps({"status": "ERROR", "error": result["error"], "host": host}))
        return

    issues, priority = [], 10.0
    if result["self_signed"]:
        issues.append("Self-signed certificate")
        priority = 95.0
    if result["expired"]:
        issues.append("Certificate has EXPIRED")
        priority = max(priority, 85.0)
    
    # Check the negotiated TLS version
    if result.get("tls_version") in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
        issues.append(f"VULNERABLE PROTOCOL: {result['tls_version']}")
        priority = max(priority, 98.0)
        
    # Check if the server secretly accepts hidden obsolete protocols!
    if result.get("hidden_obsolete_protocols"):
        bad_protos = ", ".join(result["hidden_obsolete_protocols"])
        issues.append(f"DEPRECATED PROTOCOLS ENABLED (Qualys F-Grade): {bad_protos}")
        priority = max(priority, 98.0)
        
    if result["hostname_mismatch"]:
        issues.append("Hostname mismatch (Certificate is for different domains)")
        priority = max(priority, 90.0)
    elif not result["trusted"] and not result["self_signed"]:
        issues.append("Certificate not trusted by system CA store")
        priority = max(priority, 70.0)

    if not issues:
        description = f"Valid and trusted HTTPS Certificate ({result.get('tls_version', 'Unknown')})"
        cve_id = f"SSL-CERT-VALID-{host}-{int(time.time())}"
        print(json.dumps({"status": "VALID", "details": result, "host": host}))
    else:
        description = " | ".join(issues)
        cve_id = f"SSL-CERT-ISSUE-{host}-{int(time.time())}"
        print(json.dumps({"status": "ISSUES_FOUND", "issues": issues, "details": result, "host": host}))

    payload = {
        "cveID": cve_id,
        "product": host,
        "vulnerabilityName": f"SSL/TLS Status: {description}",
        "vendorProject": host,
        "priorityScore": priority
    }
    
    try:
        requests.post(SPRING_BOOT_API, json=payload, timeout=10)
    except Exception as e:
        # Ignore DB posting errors for stdout purity used by Java
        pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"status": "ERROR", "error": "Usage: python ssl_checker.py <host>"}))
        sys.exit(1)
    host = sys.argv[1]
    submit_finding(host, check_ssl_certificate(host))