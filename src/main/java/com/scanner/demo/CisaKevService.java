package com.scanner.demo;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.ArrayList;
import java.util.List;

@Service
public class CisaKevService {

    private static final String CISA_KEV_URL =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    private final RestTemplate restTemplate = new RestTemplate();
    private final VulnerabilityRepository repository;
    private final NvdService nvdService;
    private final EpssService epssService;
    private final RiskEngineService riskEngineService;
    private final OwaspMappingService owaspMappingService;

    public CisaKevService(VulnerabilityRepository repository, NvdService nvdService, EpssService epssService,
                          RiskEngineService riskEngineService, OwaspMappingService owaspMappingService) {
        this.repository = repository;
        this.nvdService = nvdService;
        this.epssService = epssService;
        this.riskEngineService = riskEngineService;
        this.owaspMappingService = owaspMappingService;
    }

    public List<Vulnerability> fetchCisaData() {
        List<Vulnerability> newlyAdded = new ArrayList<>();

        try {
            CisaResponse response = restTemplate.getForObject(CISA_KEV_URL, CisaResponse.class);

            if (response == null || response.vulnerabilities == null) {
                System.out.println("CISA feed returned no data.");
                return newlyAdded;
            }

            System.out.println("Fetched " + response.vulnerabilities.size() + " total entries from CISA KEV.");

            for (Vulnerability v : response.vulnerabilities) {
                if (v.cveID == null || repository.existsByCveID(v.cveID)) {
                    continue;
                }

                // We explicitly DO NOT call nvdService.fetchCvssScore(v.cveID) here anymore!
                // Fetching CVSS for 1,710 vulnerabilities instantly crashes the NVD Public Rate limit.
                v.cvssScore = 0.0;
                v.epssScore = epssService.fetchEpssScore(v.cveID);
                v.owaspCategory = owaspMappingService.mapOwaspCategories(v);
                v.priorityScore = riskEngineService.calculateRiskScores(v);

                repository.save(v);
                newlyAdded.add(v);
            }

            System.out.println("Added " + newlyAdded.size() + " new vulnerabilities from CISA KEV.");

        } catch (Exception e) {
            System.err.println("Failed to fetch CISA KEV data: " + e.getMessage());
        }

        return newlyAdded;
    }
}