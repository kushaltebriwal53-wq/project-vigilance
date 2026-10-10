package com.scanner.demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/software-check")
public class SoftwareCheckController {

    private final NvdService nvdService;
    private final EpssService epssService;
    private final RiskEngineService riskEngineService;
    private final OwaspMappingService owaspMappingService;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final EmailAlertService emailAlertService;
    private final TrackedTargetRepository trackedTargetRepository;

    public SoftwareCheckController(NvdService nvdService, EpssService epssService,
            RiskEngineService riskEngineService, OwaspMappingService owaspMappingService,
            VulnerabilityRepository vulnerabilityRepository, EmailAlertService emailAlertService,
            TrackedTargetRepository trackedTargetRepository) {
        this.nvdService = nvdService;
        this.epssService = epssService;
        this.riskEngineService = riskEngineService;
        this.owaspMappingService = owaspMappingService;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.emailAlertService = emailAlertService;
        this.trackedTargetRepository = trackedTargetRepository;
    }

    @GetMapping
    public String showPage() {
        return "software-check";
    }

    @PostMapping("/check")
    @ResponseBody
    public java.util.Map<String, Object> checkSoftware(@RequestParam String name,
            @RequestParam(required = false) String version, 
            @RequestParam(required = false) String userEmail,
            @RequestParam(required = false, defaultValue = "false") boolean autoSchedule) {
        
        if (autoSchedule) {
            TrackedTarget target = trackedTargetRepository.findByTargetNameAndTargetType(name, "SOFTWARE");
            if (target == null) {
                target = new TrackedTarget(name, "SOFTWARE", true, userEmail);
            } else {
                target.autoSchedule = true;
                if (userEmail != null && !userEmail.trim().isEmpty()) {
                    target.userEmail = userEmail;
                }
            }
            trackedTargetRepository.save(target);
        }

        java.util.Map<String, Object> response = new java.util.HashMap<>();
        java.util.List<Vulnerability> findings = nvdService.searchByKeywordMulti(name, version);

        if (findings == null || findings.isEmpty()) {
            response.put("status", "NOT_FOUND");
            response.put("message",
                    "No known CVEs found for: " + name + (version != null && !version.isEmpty() ? " " + version : ""));
            return response;
        }

        java.util.List<java.util.Map<String, Object>> cveList = new java.util.ArrayList<>();

        for (Vulnerability finding : findings) {
            finding.vendorProject = name;
            finding.product = (version != null && !version.isEmpty()) ? version : name;
            finding.epssScore = epssService.fetchEpssScore(finding.cveID);
            finding.priorityScore = riskEngineService.calculateRiskScores(finding);
            finding.owaspCategory = owaspMappingService.mapOwaspCategories(finding);

            vulnerabilityRepository.save(finding);

            java.util.Map<String, Object> map = new java.util.HashMap<>();
            map.put("cve", finding.cveID);
            map.put("description", finding.description != null ? finding.description : finding.vulnerabilityName);
            map.put("cvss", finding.cvssScore);
            map.put("epss", finding.epssScore);
            map.put("priority", finding.priorityScore);
            map.put("owasp", finding.owaspCategory);
            cveList.add(map);
        }

        // Sort by priority score descending
        cveList.sort((a, b) -> Double.compare(
                b.get("priority") != null ? (Double) b.get("priority") : 0.0,
                a.get("priority") != null ? (Double) a.get("priority") : 0.0));

        response.put("status", "FOUND");
        response.put("vulnerabilities", cveList);

        if (userEmail != null && !userEmail.trim().isEmpty()) {
            emailAlertService.sendAlertTo(userEmail, "Software Scan Result: " + name,
                    "Risk Summary: " + findings.size() + " vulnerabilities found.\nLog in to dashboard for details.");
        }

        return response;
    }
}