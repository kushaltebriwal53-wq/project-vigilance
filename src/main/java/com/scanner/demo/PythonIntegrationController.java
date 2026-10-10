package com.scanner.demo;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/scanner")
public class PythonIntegrationController {

    private final VulnerabilityRepository vulnerabilityRepository;
    private final NvdService nvdService;
    private final EpssService epssService;
    private final RiskEngineService riskEngineService;
    private final OwaspMappingService owaspMappingService;
    private final EmailAlertService emailAlertService;

    public PythonIntegrationController(VulnerabilityRepository vulnerabilityRepository, NvdService nvdService,
                                       EpssService epssService, RiskEngineService riskEngineService,
                                       OwaspMappingService owaspMappingService, EmailAlertService emailAlertService) {
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.nvdService = nvdService;
        this.epssService = epssService;
        this.riskEngineService = riskEngineService;
        this.owaspMappingService = owaspMappingService;
        this.emailAlertService = emailAlertService;
    }

    @PostMapping("/submit-findings")
    public String receiveFinding(@RequestBody Vulnerability finding) {

        boolean isCertFinding = finding.cveID != null && finding.cveID.startsWith("SSL-CERT");

        if (isCertFinding) {
            if (finding.priorityScore == null) {
                finding.priorityScore = 80.0;
            }
        } else {
            finding.cvssScore = nvdService.fetchCvssScore(finding.cveID);
            finding.epssScore = epssService.fetchEpssScore(finding.cveID);
            finding.priorityScore = riskEngineService.calculateRiskScores(finding);
        }

        finding.owaspCategory = owaspMappingService.mapOwaspCategories(finding);

        vulnerabilityRepository.save(finding);

        return "Finding recorded: " + finding.cveID;
    }
}