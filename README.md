
# CyberSentinel

> **Automated Security Assessment, Network Traffic Intelligence & Cryptographic Forensic Evidence Platform**

[![Tests](https://img.shields.io/badge/tests-25%2F25%20passing-brightgreen)](scripts/test_e2e.sh)
[![Architecture](https://img.shields.io/badge/architecture-microservices-blue)](ARCHITECTURE.md)
[![Threat Model](https://img.shields.io/badge/threat%20model-STRIDE%20compliant-purple)](THREAT_MODEL.md)
[![Backend](https://img.shields.io/badge/backend-Go%201.21%2B-00ADD8)](backend/)
[![Analytics](https://img.shields.io/badge/analytics-Python%203.11%20%7C%20PySpark-yellow)](analysis/)
[![Frontend](https://img.shields.io/badge/frontend-React%2018%20%7C%20Tailwind%20CSS-61DAFB)](frontend/)
[![Database](https://img.shields.io/badge/database-PostgreSQL%2015-336791)](backend/migrations/)

---

## 1. Executive Overview

**CyberSentinel** is an enterprise-grade cybersecurity platform that bridges the traditional divide between **Offensive Security (Pentesting)**, **Network Traffic Intelligence**, and **Digital Forensics**.

Rather than running disparate command-line tools that output unverified text files, CyberSentinel orchestrates live security assessments against an isolated Docker cyber range, records raw wire traffic simultaneously, dynamically correlates multi-stage security events, and establishes an unbroken chain of custody using modern cryptography.

### Platform Workflow

```text
[ Controlled Cyber Range ]
          |
          v
[ Security Assessment Engine ]
          |
          v
[ Traffic Capture & Deep Packet Inspection ]
          |
          v
[ Dynamic Incident Correlation Engine ]
          |
          v
[ Cryptographic Evidence Sealing ]
          |
     +----+----+
     |    |    |
     v    v    v
   SHA-256 AES-GCM RSA-2048
   Integrity Privacy Authenticity
     |    |    |
     +----+----+
          |
          v
[ Searchable Encrypted Vault ]
(HMAC-SHA256 Blind Index / Trapdoors)
          |
          v
[ PostgreSQL 15 ACID Persistence ]
          |
          v
[ Court-Ready Signed Forensic Report Export ]
```

---

## 2. Core Capabilities

### A. Controlled Multi-Target Cyber Range

* **`target-web` (Corporate Application Server - 172.18.0.2):**
  * **Port 21/tcp:** `vsftpd` (FTP with Anonymous login enabled - OWASP A05)
  * **Port 80/tcp:** Apache/PHP application featuring real CVSS-rated vulnerabilities:
    * **OS Command Injection (Remote Code Execution - CVSS 9.8 CRITICAL)**
    * **Server-Side Request Forgery (SSRF - CVSS 8.6 HIGH)**
    * **SQL Injection Authentication Bypass (CVSS 8.5 HIGH)**
    * **Insecure Direct Object Reference (IDOR - CVSS 8.1 HIGH)**
    * **Arbitrary File Read / Path Traversal (CVSS 7.5 HIGH)**
    * **Reflected Cross-Site Scripting (XSS - CVSS 7.2 MEDIUM)**
  * **Port 8080/tcp:** Apache internal diagnostic administrative portal

* **`target-ssh` (Bastion & Management Host - 172.18.0.3):**
  * **Port 22/tcp:** Primary OpenSSH Server with live credential brute-force simulation
  * **Port 2222/tcp:** Legacy / Backup remote management port
  * **Port 111/tcp:** Linux RPC Portmapper (`rpcbind`)

* **Network Isolation:** All targets and scanners reside exclusively on an isolated private Docker bridge network (`cyber-net`).

### B. Traffic Intelligence & Big Data Analytics

* **Live Synchronized Packet Sniffing:** `tshark` line-buffered recording directly to raw `.pcap` files on network interface `eth0`.
* **Deep Packet Inspection (DPI):** Python/Pyshark parsing TCP SYN flags, User-Agents (NSE fingerprints), and destination ports.
* **Apache PySpark (Standalone Engine):** Distributed DataFrame analytics processing high-volume network flow summaries (`flows.csv`):
  * Source IP volume distributions (Top Talkers)
  * Protocol composition analytics (TCP, HTTP, SSH, FTP)
  * Port-sweep anomaly clustering identifying active port scans

### C. Dynamic Incident Correlation Engine

* Evaluates scan findings and live packet metrics to generate typed, confidence-scored `Incidents`:
  * *Active Network Reconnaissance / Port Scan* (SYN probe volume + port entropy)
  * *Automated Scanner Tooling Detected* (NSE User-Agent in wire packets)
  * *SSH Credential Brute-Force Attack* (High-frequency Port 22 handshake bursts)
  * *Critical Remote Code Execution Verified* (OS shell command output confirmation)

### D. Cryptographic Evidence Layer (The Forensic Chain)

* **SHA-256 Digest:** Cryptographic integrity checksum detecting single-bit tampering.
* **AES-256-GCM:** Authenticated symmetric encryption with random 12-byte Nonces (AEAD).
* **RSA-2048 Digital Signatures:** Asymmetric private key signing ensuring platform non-repudiation.
* **Symmetric Searchable Encryption (SSE):** Cryptographic Blind Index using `HMAC-SHA256(K_search, keyword)` trapdoor tokens to query encrypted evidence without decryption.

### E. Enterprise Control Plane & Persistence

* **Role-Based Access Control (RBAC):** Token authorization enforcing strict role boundaries (`Admin`, `Analyst`, `Investigator`, `Auditor`).
* **Immutable Audit Trail:** SHA-256 hash-chained log linking every action:

  \[
  \text{Hash}_i = \text{SHA-256}(\text{Index} \parallel \text{Timestamp} \parallel \text{User} \parallel \text{Action} \parallel \text{Hash}_{i-1})
  \]

* **PostgreSQL 15 Relational Persistence:** ACID storage for audit logs, incidents, and evidence records.
* **Court-Ready Export:** One-click export of verifiable signed forensic reports (`.json`) including case references and Root CA public keys.

---

## 3. System Architecture

```text
+-----------------------------------------------------------------------------------+
|                                  USER LAYER                                       |
|                            React 18 + Tailwind CSS                               |
|                           (Browser @ localhost:5173)                              |
+------------------------------------------+----------------------------------------+
                                           |
                                    HTTP / REST
                                    (X-Auth-Token)
                                           |
                                           v
+-----------------------------------------------------------------------------------+
|                         CONTROL PLANE & API GATEWAY                               |
|                                  Go (Golang)                                      |
|                                                                                   |
|  - RBAC Middleware (Admin, Analyst, Investigator, Auditor)                       |
|  - SHA-256 Hash-Chained Immutable Audit Logger                                   |
|  - Cryptographic Evidence Engine (SHA-256, AES-256-GCM, RSA-2048)                 |
|  - Searchable Symmetric Encryption Index (HMAC-SHA256 Blind Index)                |
|  - Multi-rule Incident Correlation Engine                                        |
+---------------------+-------------------------------+-----------------------------+
                      |                               |
                      | Docker Network                | cyber-net (Port 5000)
                      v                               v
+-------------------------------+   +-----------------------------------------------+
|      CONTROLLED TARGET RANGE  |   |          TRAFFIC INTELLIGENCE & SPARK         |
|                               |   |                  Python 3.11                  |
|  1. target-web (172.18.0.2)   |   |                                               |
|     - Apache/PHP 8.2          |   |  - Deep Packet Inspection (Pyshark / TShark) |
|     - Ports 21, 80, 8080      |   |    Extracts TCP Flags, Ports, User-Agents    |
|     - RCE, SQLi, SSRF, IDOR   |   |                                               |
|                               |   |  - Apache PySpark Standalone Engine          |
|  2. target-ssh (172.18.0.3)   |   |    Distributed flow aggregations & clustering|
|     - OpenSSH & rpcbind       |   +-----------------------+-----------------------+
|     - Ports 22, 111, 2222     |                           |
|     - Brute-Force Auth Lab    |                           | Reads / Writes
+---------------+---------------+                           v
                |                           +-----------------------------------------------+
                | Live Capture              |              PERSISTENCE VOLUMES              |
                | (tshark -i eth0)           |                                               |
                +-------------------------->| - evidence-vault/ : capture_*.pcap (.enc)     |
                                            | - flows/ : flows.csv                          |
                                            | - postgres_data/ : Relational DB storage      |
                                            +-----------------------------------------------+
```

---

## 4. Quickstart Guide

### Prerequisites

* [Docker Desktop](https://www.docker.com/products/docker-desktop/) (macOS / Linux / Windows)
* [Node.js 18+](https://nodejs.org/)

### 1. Launch Backend Services, Database & Cyber Range

```bash
# Clone the repository
git clone https://github.com/arunima10a/cybersentinel.git
cd cybersentinel

# Build and start all 5 containers
docker-compose up -d --build
```

### 2. Launch the SOC Dashboard

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 5. RBAC Persona Matrix

| Persona | Role | Pre-Seeded Token | Allowed Actions |
|---|---|---|---|
| `admin_root` | Administrator | `token_admin_root` | Global permissions (Scan, Exploit, Seal, Sign, Search, Audit, Export) |
| `analyst_alice` | Security Analyst | `token_analyst_123` | Launch Scans, Web Exploits, SSH Brute Force, PySpark Analytics |
| `investigator_bob` | Forensic Investigator | `token_investigator_456` | Seal Evidence, Generate Signatures, Query Blind Index, Export Court Report |
| `auditor_clara` | Auditor | `token_auditor_789` | Read-only verification of hash-chained audit trails |

---

## 6. Automated Verification Test Suite

CyberSentinel includes an automated end-to-end verification suite validating **25 distinct system assertions**.

### Run the Test Suite

```bash
./scripts/test_e2e.sh
```

### Verification Results

```text
==================================================================
        CYBERSENTINEL - AUTOMATED SYSTEM VERIFICATION SUITE
==================================================================

Stage 1: Core Service & Health Verification
  [PASS] API Gateway Online (HTTP 200)
  [PASS] Health Response Body (Verified: 'online')

Stage 2: Security Assessment & Exploitation Verification
  [PASS] Assessment Scan (target-web) (HTTP 200)
  [PASS] Port 80 Discovery (Verified: '"port":80')
  [PASS] Web Exploit Assessment Execution (HTTP 200)
  [PASS] RCE Exploit Verification (Verified: 'CRITICAL')
  [PASS] SQLi Auth Bypass Verification (Verified: 'SQL Injection')
  [PASS] Path Traversal Verification (Verified: 'passwd')

Stage 3: Traffic Feature Extraction & Dynamic Correlation
  [PASS] Correlation Engine Evaluation (HTTP 200)
  [PASS] Dynamic Reconnaissance Incident (Verified: 'Active Network Reconnaissance')

Stage 4: Cryptographic Evidence Layer & Vault Operations
  [PASS] Evidence Sealing (SHA-256 / AES-GCM) (HTTP 200)
  [PASS] SHA-256 Hash Generated (Verified: '"hash":')
  [PASS] RSA-2048 Digital Signature Generation (HTTP 200)
  [PASS] Signature Authority Signer (Verified: 'CyberSentinel_Root_CA')
  [PASS] Zero-Knowledge Blind Index Search (HTTP 200)
  [PASS] HMAC Trapdoor Token Generated (Verified: '"trapdoor_token":')
  [PASS] Encrypted PCAP Match Located (Verified: '.enc')

Stage 5: RBAC Role Separation & Permission Matrix Checks
  [PASS] Analyst CAN run scans (HTTP 200)
  [PASS] Analyst CANNOT seal evidence (HTTP 403)
  [PASS] Investigator CAN seal evidence (HTTP 200)
  [PASS] Investigator CANNOT run scans (HTTP 403)
  [PASS] Auditor CAN read audit logs (HTTP 200)
  [PASS] Auditor CANNOT run scans (HTTP 403)
  [PASS] Admin has global authority (HTTP 200)
  [PASS] Invalid token rejected (HTTP 401)

==================================================================
Total Tests Executed: 25
Passed: 25
Failed: 0
==================================================================

✓ ALL END-TO-END FLOWS AND SECURITY BOUNDARIES VERIFIED SUCCESSFULLY!
```

---

## 7. Project Structure

```text
cybersentinel/
├── ARCHITECTURE.md                 # System architecture & Mermaid topology
├── THREAT_MODEL.md                 # STRIDE threat model & mitigations
├── README.md                       # Master documentation
├── docker-compose.yml              # Container orchestration
│
├── backend/                        # Go API Gateway & Control Plane
│   ├── cmd/
│   │   ├── Dockerfile              # Backend container specification
│   │   └── main.go                 # REST API, routing, crypto & DB integration
│   │
│   ├── internal/
│   │   ├── auth/rbac.go            # RBAC engine & SHA-256 hash-chained logger
│   │   ├── correlation/engine.go   # Dynamic multi-rule incident correlator
│   │   ├── db/postgres.go          # PostgreSQL database repository layer
│   │   │
│   │   ├── forensics/
│   │   │   ├── crypto.go           # SHA-256, AES-256-GCM, RSA-2048 signatures
│   │   │   └── searchable.go       # HMAC-SHA256 Blind Index / Trapdoors
│   │   │
│   │   └── scanner/
│   │       ├── nmap.go             # Assessment orchestrator
│   │       ├── parser.go           # Structured vulnerability model parser
│   │       ├── ssh_attack.go       # SSH target scanner & brute-force simulator
│   │       └── web_exploit.go      # Automated RCE, SQLi, SSRF, IDOR exploit tests
│   │
│   └── migrations/
│       └── init.sql                # PostgreSQL relational database schema
│
├── analysis/                       # Traffic Intelligence & PySpark Engine
│   ├── Dockerfile                  # Python 3.11, OpenJDK, TShark image
│   ├── requirements.txt            # Python dependencies (pyshark, pyspark)
│   ├── server.py                   # Microservice REST server (:5000)
│   ├── analyze.py                  # Pyshark Deep Packet Inspection
│   │
│   └── spark_engine/
│       ├── pcap_to_flows.py        # High-speed native TShark flow generator
│       └── traffic_analytics.py    # Apache PySpark distributed DataFrame job
│
├── lab-targets/                    # Controlled Cyber Range
│   ├── web-vulnerable/             # Apache/PHP target (Ports 21, 80, 8080)
│   └── ssh-target/                 # OpenSSH target (Ports 22, 111, 2222)
│
├── frontend/                       # React 18 + Tailwind CSS SOC Dashboard
│   └── src/App.jsx                 # Real-time operations interface
│
├── scripts/
│   ├── test_e2e.sh                 # 25-point automated verification suite
│   └── clean.sh                    # Environment reset & cache cleanup utility
│
└── evidence-vault/                 # Persistent storage for PCAP artifacts
```
