# 🛡️ Project Vigilance — Automated Threat Intelligence & Vulnerability Management Platform

A full-stack cybersecurity platform built with **Spring Boot**, **PostgreSQL**, and **Python** that automates vulnerability discovery, risk scoring, and threat intelligence monitoring.

---

## 🚀 Features

| Module | Description |
|---|---|
| 🎯 **Host Scanner** | Socket-based port reconnaissance with NVD CVE cross-referencing and banner analysis |
| ⚠️ **CVE Auditor** | Real-time NVD API queries for software version vulnerabilities with CVSS + EPSS scoring |
| 🔒 **SSL/TLS Checker** | Raw hex packet fuzzing to detect deprecated protocols (SSLv3, TLS 1.0/1.1) |
| 📡 **Automated Monitoring** | Daily background scheduler auto-rescans enrolled targets and sends email alerts |
| 🧠 **Threat Intelligence Feed** | CISA KEV catalog sync on startup (1,700+ actively exploited CVEs) |
| 📊 **Risk Engine** | Custom composite risk score: `Priority = (CVSS × 0.6) + (EPSS × 0.4)` |
| 🗂️ **OWASP Mapping** | Automatic classification of vulnerabilities into OWASP Top 10 categories |
| 📧 **Email Alerts** | Automated SMTP notifications for high-risk findings and scheduled scan results |

---

## 🏗️ Tech Stack

- **Backend:** Java 21, Spring Boot 3.3.4, Spring Data JPA, Spring Scheduler
- **Database:** PostgreSQL 14
- **Frontend:** Thymeleaf, HTML5, CSS3, Vanilla JavaScript
- **Python Scripts:** `scanner.py` (port scanner), `ssl_checker.py` (TLS analyzer)
- **APIs:** NIST NVD REST API v2, CISA KEV, FIRST EPSS API
- **Email:** Gmail SMTP via Spring Mail

---

## ⚙️ Setup Instructions

### Prerequisites
- Java 21+
- Maven 3.8+
- PostgreSQL 14+
- Python 3.x with packages: `requests`, `cryptography`
- IntelliJ IDEA (recommended)

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/project-vigilance.git
cd project-vigilance
```

### 2. Set Up PostgreSQL
```sql
CREATE DATABASE vigilance;
```

### 3. Configure application.properties
```bash
cp src/main/resources/application.properties.template src/main/resources/application.properties
```
Edit `application.properties` and fill in:
- PostgreSQL username and password
- Gmail address and App Password
- Admin alert email

### 4. Install Python Dependencies
```bash
pip install requests cryptography
```

### 5. Run the Application
Open in IntelliJ IDEA and click **Run**, or:
```bash
mvn spring-boot:run
```

### 6. Open in Browser
```
http://localhost:8080
```

---

## 📁 Project Structure

```
src/
├── main/
│   ├── java/com/scanner/demo/
│   │   ├── DemoApplication.java          # Entry point
│   │   ├── StartupRunner.java            # CISA sync on boot
│   │   ├── AutomationScheduler.java      # Background cron jobs
│   │   ├── CisaKevService.java           # CISA KEV downloader
│   │   ├── NvdService.java               # NVD API client
│   │   ├── EpssService.java              # FIRST EPSS client
│   │   ├── RiskEngineService.java        # Risk score calculator
│   │   ├── OwaspMappingService.java      # OWASP Top 10 classifier
│   │   ├── EmailAlertService.java        # SMTP alert dispatcher
│   │   ├── HostScanController.java       # /host-scan endpoint
│   │   ├── SoftwareCheckController.java  # /software-check endpoint
│   │   ├── SslCheckController.java       # /ssl-check endpoint
│   │   ├── TrackedTargetController.java  # /api/targets endpoints
│   │   └── PythonIntegrationController.java  # Python findings receiver
│   └── resources/
│       ├── application.properties.template   # Config template
│       └── templates/
│           ├── dashboard.html
│           ├── host-scan.html
│           ├── software-check.html
│           └── ssl-check.html
├── scanner.py       # Python port scanner & banner grabber
└── ssl_checker.py   # Python SSL/TLS protocol fuzzer
```

---

## 🔒 Security Note

`application.properties` is excluded from version control via `.gitignore`.  
Never commit database passwords or SMTP credentials to GitHub.

---

## 📜 License

MIT License — free to use for educational and academic purposes.
