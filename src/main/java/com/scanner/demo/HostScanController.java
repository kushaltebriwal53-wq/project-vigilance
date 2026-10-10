package com.scanner.demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/host-scan")
public class HostScanController {

    private final VulnerabilityRepository vulnerabilityRepository;
    private final EmailAlertService emailAlertService;
    private final TrackedTargetRepository trackedTargetRepository;

    public HostScanController(VulnerabilityRepository vulnerabilityRepository, EmailAlertService emailAlertService, TrackedTargetRepository trackedTargetRepository) {
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.emailAlertService = emailAlertService;
        this.trackedTargetRepository = trackedTargetRepository;
    }

    @GetMapping
    public String showPage() {
        return "host-scan";
    }

    @PostMapping("/single")
    @ResponseBody
    public Map<String, Object> scanSingleHost(@RequestParam String host,
            @RequestParam(required = false) String userEmail,
            @RequestParam(required = false, defaultValue = "false") boolean autoSchedule) {
        
        if (autoSchedule) {
            TrackedTarget target = trackedTargetRepository.findByTargetNameAndTargetType(host, "HOST");
            if (target == null) {
                target = new TrackedTarget(host, "HOST", true, userEmail);
            } else {
                target.autoSchedule = true;
                if (userEmail != null && !userEmail.trim().isEmpty()) {
                    target.userEmail = userEmail;
                }
            }
            trackedTargetRepository.save(target);
        }

        StringBuilder terminalLog = new StringBuilder();
        try {
            // Remove old history for this specific host to prevent duplicate buildup in the
            // UI
            List<Vulnerability> existing = vulnerabilityRepository.findByVendorProjectIgnoreCase(host);
            if (existing != null && !existing.isEmpty()) {
                vulnerabilityRepository.deleteAll(existing);
            }

            // Run Python scanner synchronously and capture terminal output
            ProcessBuilder pb = new ProcessBuilder("python", "scanner.py", host);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                terminalLog.append(line).append("\n");
            }
            process.waitFor();
        } catch (Exception e) {
            terminalLog.append("Error executing scanner: ").append(e.getMessage());
        }

        // Fetch all findings Python submitted to the database for this host
        List<Vulnerability> findings = vulnerabilityRepository
                .findByVendorProjectIgnoreCase(host);

        Map<String, Object> response = new HashMap<>();
        response.put("log", terminalLog.toString());
        response.put("vulnerabilities", findings);

        if (userEmail != null && !userEmail.trim().isEmpty()) {
            emailAlertService.sendAlertTo(userEmail, "Host Scan Results: " + host,
                    "Scan Completed.\nTotal Open Services Found: " + findings.size()
                            + "\nRaw Python Execution logs attached inside UI.");
        }

        return response;
    }

    @PostMapping("/file")
    @ResponseBody
    public String scanHostFile(@RequestParam("file") MultipartFile file) {
        try {
            File tempFile = File.createTempFile("hosts-", ".txt");
            file.transferTo(tempFile);
            ProcessBuilder pb = new ProcessBuilder("python", "scanner.py", "--file", tempFile.getAbsolutePath());
            pb.redirectErrorStream(true);
            pb.start();
            return "Scan started for uploaded host list.";
        } catch (Exception e) {
            return "Failed to start scan: " + e.getMessage();
        }
    }
}