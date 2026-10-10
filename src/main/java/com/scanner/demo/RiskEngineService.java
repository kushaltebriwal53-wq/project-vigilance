package com.scanner.demo;

import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class RiskEngineService {

    private final VulnerabilityRepository repository;

    public RiskEngineService(VulnerabilityRepository repository) {
        this.repository = repository;
    }

    public Double calculateRiskScores(Vulnerability vuln) {
        return calculateFormula(vuln);
    }




    private Double calculateFormula(Vulnerability vuln) {
        double cvss = (vuln.cvssScore != null) ? vuln.cvssScore : 0.0;

        // If it's a genuine CVE but has 0.0 CVSS score (often newly published CVEs),
        // assign a baseline score
        if (cvss == 0.0 && vuln.cveID != null && vuln.cveID.startsWith("CVE-")) {
            cvss = 7.5; // Baseline high/moderate risk for unscored CVE
        }

        double epss = 0.0;
        if (vuln.epssScore != null && !vuln.epssScore.isBlank()) {
            try {
                epss = Double.parseDouble(vuln.epssScore);
            } catch (NumberFormatException e) {
                epss = 0.0;
            }
        }

        double calculatedScore = (cvss * 6.0) + (epss * 100 * 4.0);

        // Add robust baseline scoring for internal/private IPs without explicit CVE
        // records
        if (calculatedScore == 0.0 && vuln.cveID != null && vuln.cveID.startsWith("NOMATCH")) {
            String name = (vuln.vulnerabilityName != null) ? vuln.vulnerabilityName.toUpperCase() : "";
            if (name.contains("SSH") || name.contains("TELNET") || name.contains("RDP")) {
                calculatedScore = 45.0; // Moderate risk for exposed privileged consoles
            } else if (name.contains("FTP") || name.contains("SMB") || name.contains("SQL")) {
                calculatedScore = 60.0; // High baseline risk for exposed file/DB servers
            } else if (name.contains("HTTP")) {
                calculatedScore = 20.0; // Low-Medium risk for generic web exposed
            } else {
                calculatedScore = 25.0; // Fallback baseline for unknown open port
            }
        }

        return Math.round(calculatedScore * 100.0) / 100.0;
    }
}