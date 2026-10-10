package com.scanner.demo;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class SystemSettings {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)

    public Long id;
    public String adminEmail;

}