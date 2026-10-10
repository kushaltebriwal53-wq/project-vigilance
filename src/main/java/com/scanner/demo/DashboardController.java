package com.scanner.demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class DashboardController {

    private final SystemSettingsRepository settingsRepository;

    public DashboardController(SystemSettingsRepository settingsRepository) {
        this.settingsRepository = settingsRepository;
    }

    @PostMapping("/save-email")
    public String saveAdminEmail(@RequestParam String email) {
        SystemSettings settings = settingsRepository.findAll().stream().findFirst().orElse(new SystemSettings());
        settings.adminEmail = email;
        settingsRepository.save(settings);
        return "redirect:/";
    }

    @GetMapping("/")
    public String viewHome() {
        return "dashboard";
    }
}