package com.scanner.demo;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class AutomationScheduler {

    private final CisaKevService cisaKevService;
    private final EmailAlertService emailAlertService;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final NvdService nvdService;
    private final EpssService epssService;
    private final RiskEngineService riskEngineService;
    private final TrackedTargetRepository trackedTargetRepository;
    private final OwaspMappingService owaspMappingService;

    public AutomationScheduler(CisaKevService cisaKevService, EmailAlertService emailAlertService,
            VulnerabilityRepository vulnerabilityRepository, NvdService nvdService,
            EpssService epssService, RiskEngineService riskEngineService,
            TrackedTargetRepository trackedTargetRepository, OwaspMappingService owaspMappingService) {
        this.cisaKevService = cisaKevService;
        this.emailAlertService = emailAlertService;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.nvdService = nvdService;
        this.epssService = epssService;
        this.riskEngineService = riskEngineService;
        this.trackedTargetRepository = trackedTargetRepository;
        this.owaspMappingService = owaspMappingService;
    }

    @Scheduled(initialDelay = 3600000, fixedRate = 43200000)
    public void runScheduledScan() {
        System.out.println("Executing automated background CISA KEV sync...");

        try {
            List<Vulnerability> newThreats = cisaKevService.fetchCisaData();

            if (newThreats.isEmpty()) {
                System.out.println("Sync complete. No new vulnerabilities found.");
                return;
            }

            StringBuilder emailBody = new StringBuilder(
                    "⚠️ SECURITY ALERT: New Exploited Vulnerabilities Detected\n\n");
            emailBody.append("The automated background sync found ").append(newThreats.size())
                    .append(" new CVE(s) added to CISA KEV:\n\n");

            for (Vulnerability v : newThreats) {
                emailBody.append("• CVE: ").append(v.cveID).append("\n")
                        .append("  Target: ").append(v.vendorProject).append(" - ").append(v.product).append("\n")
                        .append("  Composite Risk Score: ").append(v.priorityScore).append("\n")
                        .append("  Metrics: CVSS ").append(v.cvssScore).append(" | EPSS ").append(v.epssScore)
                        .append("\n")
                        .append("  OWASP: ").append(v.owaspCategory).append("\n\n");
            }

            emailBody.append("Log in to your dashboard to analyze full metrics and mitigation steps.");

            emailAlertService.sendAlert("🚨 CRITICAL: " + newThreats.size() + " New Vulnerability Threats Logged",
                    emailBody.toString());

        } catch (Exception e) {
            emailAlertService.sendAlert("⚠️ Vulnerability Platform Error",
                    "Automated background sync failed: " + e.getMessage());
        }
    }

    @Scheduled(initialDelay = 3600000, fixedRate = 86400000) // Delayed so it doesn't block the scheduler thread
    public void reScorePendingCVEs() {
        System.out.println("Running scheduled re-scoring for unscored CVEs...");
        try {
            List<Vulnerability> allVulns = vulnerabilityRepository.findAll();
            int rescoredCount = 0;

            for (Vulnerability vuln : allVulns) {
                if (vuln.cveID != null && vuln.cveID.startsWith("CVE-")
                        && (vuln.cvssScore == null || vuln.cvssScore == 0.0)) {
                    Double newCvss = nvdService.fetchCvssScore(vuln.cveID);
                    if (newCvss != null && newCvss > 0.0) {
                        vuln.cvssScore = newCvss;
                        vuln.epssScore = epssService.fetchEpssScore(vuln.cveID);
                        vuln.priorityScore = riskEngineService.calculateRiskScores(vuln);
                        vulnerabilityRepository.save(vuln);
                        rescoredCount++;
                    }
                }
            }
            if (rescoredCount > 0) {
                System.out.println(
                        "Successfully re-scored " + rescoredCount + " previously unscored vulnerabilities from NVD.");
            } else {
                System.out.println("No missing CVE scores were updated today.");
            }
        } catch (Exception e) {
            System.err.println("Failed during automated CVE rescoring: " + e.getMessage());
        }
    }

    @Scheduled(initialDelay = 60000, fixedRate = 86400000) // Runs 1 minute after boot, then every 24 hours
    public void runScheduledTrackedTargets() {
        System.out.println("Running automated checks for Tracked Targets...");
        List<TrackedTarget> targets = trackedTargetRepository.findByAutoScheduleTrue();
        
        for (TrackedTarget target : targets) {
            if ("SOFTWARE".equals(target.targetType)) {
                System.out.println("Auto-checking software: " + target.targetName);
                List<Vulnerability> findings = nvdService.searchByKeywordMulti(target.targetName, null);
                int newCount = 0;
                if (findings != null) {
                    for (Vulnerability finding : findings) {
                        if (!vulnerabilityRepository.existsByCveID(finding.cveID)) {
                            finding.vendorProject = target.targetName;
                            finding.product = target.targetName;
                            finding.epssScore = epssService.fetchEpssScore(finding.cveID);
                            finding.priorityScore = riskEngineService.calculateRiskScores(finding);
                            finding.owaspCategory = owaspMappingService.mapOwaspCategories(finding);
                            vulnerabilityRepository.save(finding);
                            newCount++;
                        }
                    }
                }
                if (newCount > 0) {
                    String subject = "🛡️ Automated Monitor: New Vulnerabilities for " + target.targetName;
                    String body = "The scheduled background monitor detected " + newCount + " new vulnerability records for: " + target.targetName + ".\nPlease log in to the dashboard to review risk scores.";
                    if (target.userEmail != null && !target.userEmail.trim().isEmpty()) {
                        emailAlertService.sendAlertTo(target.userEmail, subject, body);
                    } else {
                        emailAlertService.sendAlert(subject, body);
                    }
                }
            } else if ("HOST".equals(target.targetType)) {
                System.out.println("Auto-checking host: " + target.targetName);
                try {
                    List<Vulnerability> existing = vulnerabilityRepository.findByVendorProjectIgnoreCase(target.targetName);
                    if (existing != null && !existing.isEmpty()) {
                        vulnerabilityRepository.deleteAll(existing);
                    }
                    ProcessBuilder pb = new ProcessBuilder("python", "scanner.py", target.targetName);
                    pb.redirectErrorStream(true);
                    Process process = pb.start();
                    process.waitFor();

                    // Check results after scan and email summary
                    List<Vulnerability> findings = vulnerabilityRepository.findByVendorProjectIgnoreCase(target.targetName);
                    String subject = "🎯 Automated Scheduled Scan Complete: " + target.targetName;
                    String body = "The automated background scanner completed its probe on: " + target.targetName + "\n" +
                        "Total active services/findings recorded: " + (findings != null ? findings.size() : 0) + "\n" +
                        "All metrics have been refreshed in PostgreSQL.";
                    if (target.userEmail != null && !target.userEmail.trim().isEmpty()) {
                        emailAlertService.sendAlertTo(target.userEmail, subject, body);
                    } else {
                        emailAlertService.sendAlert(subject, body);
                    }
                } catch (Exception e) {
                    System.err.println("Failed to auto-check host " + target.targetName + ": " + e.getMessage());
                }
            }
        }
        System.out.println("Tracked Targets check complete!");
    }
}