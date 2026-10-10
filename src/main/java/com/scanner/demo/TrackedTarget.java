package com.scanner.demo;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class TrackedTarget {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;

    public String targetName; // e.g., "Apache" or "scanme.nmap.org"
    
    public String targetType; // e.g., "SOFTWARE" or "HOST"

    public boolean autoSchedule;

    public String userEmail; // The email provided by the user who requested daily monitoring

    public TrackedTarget() {
    }

    public TrackedTarget(String targetName, String targetType, boolean autoSchedule, String userEmail) {
        this.targetName = targetName;
        this.targetType = targetType;
        this.autoSchedule = autoSchedule;
        this.userEmail = userEmail;
    }
}
