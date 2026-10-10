package com.scanner.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * NvdService — talks to the NVD REST API v2.
 *
 * Modified to rely exclusively on the public API (no API key required).
 * Implements a strict 6-second delay between requests to avoid the
 * 5-requests-per-30-seconds rate limit (Error 429).
 */
@Service
public class NvdService {

    private static final String NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    // ── Shared header builder ─────────────────────────────────────────────────
    private HttpHeaders buildHeaders() {
        HttpHeaders h = new HttpHeaders();
        h.set("User-Agent",
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
              "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36");
        // API key removed for robust public access
        return h;
    }

    // ── Safe request executor with rate limit handling ────────────────────────
    private synchronized ResponseEntity<String> safeExchange(URI uri) throws InterruptedException {
        // Enforce a strict 6-second delay to guarantee we never exceed 5 req/30 sec
        System.out.println("[NvdService] Sleeping for 6s to respect public rate limits...");
        Thread.sleep(6000);
        
        HttpEntity<String> entity = new HttpEntity<>(buildHeaders());
        try {
            return restTemplate.exchange(uri, HttpMethod.GET, entity, String.class);
        } catch (org.springframework.web.client.HttpClientErrorException.TooManyRequests e) {
            System.err.println("[NvdService] Hit 429 Rate Limit despite sleep. Waiting 10 more seconds...");
            Thread.sleep(10000);
            return restTemplate.exchange(uri, HttpMethod.GET, entity, String.class);
        }
    }

    // ── Extract the best CVSS score from a metrics node ───────────────────────
    private Double extractCvss(JsonNode metrics) {
        if (metrics == null || metrics.isMissingNode()) return null;
        String[] keys = {"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"};
        for (String key : keys) {
            if (metrics.has(key)) {
                JsonNode score = metrics.path(key).path(0).path("cvssData").path("baseScore");
                if (!score.isMissingNode()) return score.asDouble();
            }
        }
        return null;
    }

    // ── Fetch CVSS for a known CVE-ID ─────────────────────────────────────────
    public Double fetchCvssScore(String cveId) {
        try {
            URI uri = UriComponentsBuilder.fromHttpUrl(NVD_BASE)
                    .queryParam("cveId", cveId)
                    .build()
                    .toUri();
            ResponseEntity<String> resp = safeExchange(uri);
            if (resp.getBody() != null) {
                JsonNode root = objectMapper.readTree(resp.getBody());
                JsonNode metrics = root.path("vulnerabilities").path(0).path("cve").path("metrics");
                return extractCvss(metrics);
            }
        } catch (Exception e) {
            System.err.println("[NvdService] fetchCvssScore error for " + cveId + ": " + e.getMessage());
        }
        return null;
    }

    // ── Keyword search — returns up to 25 results ─────────────────────────────
    public List<Vulnerability> searchByKeywordMulti(String softwareName, String version) {
        List<Vulnerability> results = new ArrayList<>();

        // Build the keyword — if version is given, append it
        String keyword = (version != null && !version.isBlank())
                ? softwareName.trim() + " " + version.trim()
                : softwareName.trim();

        URI uri;
        try {
            uri = UriComponentsBuilder.fromHttpUrl(NVD_BASE)
                    .queryParam("keywordSearch", keyword)
                    .queryParam("resultsPerPage", 25)
                    .build()
                    .encode()
                    .toUri();
        } catch (Exception e) {
            System.err.println("[NvdService] Failed to build URI: " + e.getMessage());
            return results;
        }

        System.out.println("[NvdService] Searching NVD: " + uri);

        try {
            ResponseEntity<String> resp = safeExchange(uri);

            System.out.println("[NvdService] NVD HTTP status: " + resp.getStatusCode());

            if (resp.getBody() == null || resp.getBody().isBlank()) {
                System.err.println("[NvdService] Empty response body from NVD.");
                return results;
            }

            JsonNode root = objectMapper.readTree(resp.getBody());
            int total = root.path("totalResults").asInt(0);
            System.out.println("[NvdService] NVD totalResults: " + total);

            JsonNode vulns = root.path("vulnerabilities");
            if (!vulns.isArray()) return results;

            for (JsonNode node : vulns) {
                JsonNode cveNode = node.path("cve");
                if (cveNode.isMissingNode() || !cveNode.has("id")) continue;

                Vulnerability v = new Vulnerability();
                v.cveID = cveNode.path("id").asText();

                // CVSS score
                v.cvssScore = extractCvss(cveNode.path("metrics"));
                // Fall back to 7.5 for published-but-unscored CVEs
                if (v.cvssScore == null || v.cvssScore == 0.0) v.cvssScore = 7.5;

                // Description (first English entry)
                JsonNode descs = cveNode.path("descriptions");
                if (descs.isArray()) {
                    for (JsonNode d : descs) {
                        if ("en".equals(d.path("lang").asText())) {
                            v.description = d.path("value").asText();
                            break;
                        }
                    }
                    if (v.description == null && descs.size() > 0) {
                        v.description = descs.path(0).path("value").asText();
                    }
                }

                v.vulnerabilityName = (v.description != null && v.description.length() > 80)
                        ? v.description.substring(0, 80) + "…"
                        : v.description;

                results.add(v);
            }

        } catch (Exception e) {
            System.err.println("[NvdService] searchByKeywordMulti error: " + e.getMessage());
        }

        System.out.println("[NvdService] Returning " + results.size() + " results for: " + keyword);
        return results;
    }
}