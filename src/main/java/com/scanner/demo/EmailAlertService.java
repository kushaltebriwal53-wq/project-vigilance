package com.scanner.demo;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailAlertService {

    private final JavaMailSender mailSender;
    private final SystemSettingsRepository settingsRepository;

    public EmailAlertService(JavaMailSender mailSender, SystemSettingsRepository settingsRepository) {
        this.mailSender = mailSender;
        this.settingsRepository = settingsRepository;
    }

    public void sendAlert(String subject, String messageBody) {
        SystemSettings settings = settingsRepository.findAll().stream().findFirst().orElse(null);

        if (settings == null || settings.adminEmail == null || settings.adminEmail.isEmpty()) {
            System.out.println("No admin email configured. Skipping email alert.");
            return;
        }

        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(settings.adminEmail);
            message.setSubject(subject);
            message.setText(messageBody);

            mailSender.send(message);
            System.out.println("Security alert dispatched to " + settings.adminEmail);
        } catch (Exception e) {
            System.err.println("Failed to send email alert: " + e.getMessage());
        }
    }
    
    public void sendAlertTo(String email, String subject, String messageBody) {
        if (email == null || email.trim().isEmpty()) return;
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(email);
            message.setSubject(subject);
            message.setText(messageBody);
            mailSender.send(message);
            System.out.println("Result dispatched to user email: " + email);
        } catch (Exception e) {
            System.err.println("Failed to send email to " + email + ": " + e.getMessage());
        }
    }
}