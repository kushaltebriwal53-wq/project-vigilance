package com.scanner.demo;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CisaResponse {
    public List<Vulnerability> vulnerabilities;
}