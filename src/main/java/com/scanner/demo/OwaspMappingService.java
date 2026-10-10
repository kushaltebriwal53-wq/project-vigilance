package com.scanner.demo;

import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class OwaspMappingService {

    private final VulnerabilityRepository repository;

    public OwaspMappingService(VulnerabilityRepository repository) {
        this.repository = repository;
    }

    public String mapOwaspCategories(Vulnerability vuln) {
        return determineCategory(vuln);
    }

    private String determineCategory(Vulnerability vuln) {
        String text = ((vuln.vulnerabilityName != null ? vuln.vulnerabilityName : "") + " " +
                (vuln.description != null ? vuln.description : "")).toLowerCase();

        if (text.contains("sql injection") || text.contains("command injection") || text.contains("code injection") || text.contains("rce")) {
            return "A03:2021-Injection";
        } else if (text.contains("authentication") || text.contains("login") || text.contains("bypass")) {
            return "A07:2021-Identification and Authentication Failures";
        } else if (text.contains("authorization") || text.contains("privilege escalation") || text.contains("access control")) {
            return "A01:2021-Broken Access Control";
        } else if (text.contains("buffer overflow") || text.contains("heap") || text.contains("memory corruption")) {
            return "A06:2021-Vulnerable and Outdated Components";
        } else if (text.contains("cross-site scripting") || text.contains("xss") || text.contains("csrf")) {
            return "A03:2021-Injection (XSS)";
        } else if (text.contains("cryptographic") || text.contains("encryption") || text.contains("plaintext") || text.contains("cert")) {
            return "A02:2021-Cryptographic Failures";
        } else {
            return "A05:2021-Security Misconfiguration";
        }
    }
}