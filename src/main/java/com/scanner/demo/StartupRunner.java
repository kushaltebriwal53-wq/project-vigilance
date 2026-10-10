package com.scanner.demo;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class StartupRunner implements CommandLineRunner {

    private final CisaKevService cisaKevService;
    private final SystemSettingsRepository settingsRepository;

    public StartupRunner(CisaKevService cisaKevService, SystemSettingsRepository settingsRepository) {
        this.cisaKevService = cisaKevService;
        this.settingsRepository = settingsRepository;
    }

    @Override
    public void run(String... args) {
        System.out.println("Running initial CISA KEV sync on startup...");
        cisaKevService.fetchCisaData();

        // Ensure default alert recipient is saved in PostgreSQL for scheduler
        if (settingsRepository.count() == 0) {
            SystemSettings s = new SystemSettings();
            s.adminEmail = "kushal.kumar2024@vitstudent.ac.in";
            settingsRepository.save(s);
            System.out.println("Default admin alert email configured: " + s.adminEmail);
        }
    }
}