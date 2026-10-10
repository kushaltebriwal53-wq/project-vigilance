package com.scanner.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class EpssService {

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public String fetchEpssScore(String cveId) {
        String url = "https://api.first.org/data/v1/epss?cve=" + cveId;

        try {
            String response = restTemplate.getForObject(url, String.class);

            if (response != null) {
                JsonNode root = objectMapper.readTree(response);
                JsonNode dataArray = root.path("data");

                if (dataArray.isArray() && dataArray.size() > 0) {
                    return dataArray.path(0).path("epss").asText();
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to fetch live EPSS for " + cveId + ": " + e.getMessage());
        }

        return "0.0";
    }
}