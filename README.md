# TMDS — Tamper Monitoring and Detection System

TMDS (Tamper Monitoring and Detection System) is a full-stack healthcare security application designed to protect medical records from unauthorized modification, deletion, privilege violations, and suspicious user activity.

The system combines **cryptographic integrity verification, role-based access control, audit logging, security alerts, attack simulation, and AI-based anomaly detection** into a single security monitoring platform.

---

## 📌 Project Overview

Medical databases contain highly sensitive information and must maintain both **confidentiality and data integrity**.

TMDS provides a security layer that continuously monitors medical-record operations and identifies suspicious activities.

The application consists of three major components:

* **Frontend:** React + Vite security dashboard
* **Backend:** Node.js + Express REST API
* **AI Module:** Python + Flask anomaly-detection service

The backend uses **SHA-256 cryptographic hashing** to verify the integrity of patient records. If a record is modified outside the authorized application workflow, the recalculated hash no longer matches the stored hash, allowing the system to identify possible tampering.

---

## ✨ Key Features

### 🔐 1. Medical Record Integrity Verification

Each patient record receives a SHA-256 integrity hash based on important clinical fields.

The system compares:

```text
Stored Record Hash
        ↓
Recalculate SHA-256 Hash
        ↓
Compare Both Hashes
        ↓
Match → Record Valid
Mismatch → Tampering Detected
```

When a mismatch is detected, TMDS:

* Marks the record as tampered
* Generates a security alert
* Creates an audit log
* Records the integrity violation

---

### 👥 2. Role-Based Access Control

TMDS supports three primary user roles:

| Role         | Patient Records           | Security Dashboard | Audit Logs | User Management |
| ------------ | ------------------------- | ------------------ | ---------- | --------------- |
| Admin        | Full Access               | ✅                  | ✅          | ✅               |
| Doctor       | View/Create/Update/Delete | ❌                  | ❌          | ❌               |
| Receptionist | View/Create               | ❌                  | ❌          | ❌               |

JWT authentication is used to identify users, while role-based middleware controls access to protected resources.

---

### 📋 3. Audit Logging

The application records important security and user activities, including:

* Successful logins
* Failed login attempts
* Patient creation
* Patient updates
* Patient deletion
* Unauthorized access attempts
* Privilege violations
* Integrity violations
* Simulated attacks

Administrators can view these events through the **Audit Logs** dashboard.

---

### 🚨 4. Security Alerts

TMDS generates security alerts for suspicious or dangerous activities such as:

* Database tampering
* Record deletion
* Brute-force login attempts
* Privilege violations
* NoSQL injection attempts

Administrators can review and resolve alerts from the security dashboard.

---

### 🤖 5. AI-Based Anomaly Detection

The project includes a Python Flask machine-learning service using the **Isolation Forest** algorithm.

The AI module analyzes activity logs using features such as:

* User role
* Action performed
* Success/failure status
* Access hour
* Weekend activity

The model classifies activities as normal or anomalous and assigns a risk level.

Possible risk levels include:

```text
LOW
MEDIUM
HIGH
```

The AI service provides an API endpoint for analyzing activity logs.

---

### 🧪 6. Attack Simulation

TMDS includes an educational attack-simulation module for demonstrating how security mechanisms respond to attacks.

Currently supported simulations include:

#### Unauthorized Record Modification

A patient field is modified without updating its original integrity hash.

This demonstrates how cryptographic integrity validation detects unauthorized changes.

#### Record Deletion

A patient record is deleted and the system generates a security alert and audit entry.

#### NoSQL Injection Demonstration

The project provides both:

* Vulnerable NoSQL authentication demonstration
* Secured/sanitized authentication demonstration

This allows users to compare the behavior of an unsafe query with a protected implementation.

> These endpoints are intended for controlled educational demonstration within the application.

---

### 🛡️ 7. Backend Security

The Express backend includes several security mechanisms:

* JWT authentication
* bcrypt password hashing
* Helmet security middleware
* CORS configuration
* Express rate limiting
* Role-based authorization
* Cryptographic integrity validation
* Security auditing

---

### 🔑 8. Passwo
