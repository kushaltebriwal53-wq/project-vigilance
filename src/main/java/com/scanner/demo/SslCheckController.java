package com.scanner.demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;

@Controller
@RequestMapping("/ssl-check")
public class SslCheckController {

    private final EmailAlertService emailAlertService;

    public SslCheckController(EmailAlertService emailAlertService) {
        this.emailAlertService = emailAlertService;
    }

    @GetMapping
    public String showPage() {
        return "ssl-check";
    }

    @PostMapping(value = "/run", produces = "application/json")
    @ResponseBody
    public String checkSsl(@RequestParam String host, @RequestParam(required = false) String userEmail) {
        try {
            ProcessBuilder pb = new ProcessBuilder("python", "ssl_checker.py", host);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();

            String outStr = output.toString();

            if (userEmail != null && !userEmail.trim().isEmpty()) {
                emailAlertService.sendAlertTo(userEmail, "Scan Results for: " + host,
                        "Your SSL Scan completed. Results:\n\n" + outStr);
            }

            // Check if output is empty
            if (outStr.trim().isEmpty()) {
                return "{\"status\": \"ERROR\", \"error\": \"No output from scanner.\"}";
            }
            return output.toString();
        } catch (Exception e) {
            return "{\"status\": \"ERROR\", \"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }
    }
}