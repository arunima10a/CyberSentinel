# CyberSentinel — Research & Operational Methodology

This document outlines the six-stage scientific and engineering methodology implemented in the CyberSentinel platform.

---

## 1. Visual Methodology Lifecycle (Mermaid)

```mermaid
flowchart TD
    subgraph Stage1 ["Stage 1: Sandboxed Range Provisioning"]
        A1["Define Target Topology<br/>(target-web & target-ssh)"] --> A2["Isolate Virtual Bridge Subnet<br/>(Docker: cyber-net)"]
        A2 --> A3["Establish Baseline Defenses<br/>& Network Access Controls"]
    end

    subgraph Stage2 ["Stage 2: Offensive Security Assessment"]
        B1["Target Selection & Authentication<br/>(X-Auth-Token via RBAC)"] --> B2["Network Reconnaissance<br/>(Nmap -sV Service Fingerprinting)"]
        B2 --> B3["Automated Exploit Execution<br/>- OS Command Injection (CVSS 9.8)<br/>- SQL Injection (CVSS 8.5)<br/>- SSH Brute-Force Simulation"]
    end

    subgraph Stage3 ["Stage 3: Synchronized Traffic Capture & DPI"]
        C1["Trigger Background Capture<br/>(tshark -l -i eth0)"] --> C2["Record Raw Packets<br/>(capture_*.pcap)"]
        C2 --> C3["Deep Packet Inspection (Pyshark)<br/>Extract SYN Counts, Ports & User-Agents"]
        C2 --> C4["Flow Aggregation (pcap_to_flows)<br/>Output: flows.csv"]
    end

    subgraph Stage4 ["Stage 4: Multi-Stage Correlation & Big Data Analytics"]
        D1["Dynamic Rule Engine (Go)<br/>Cross-reference Nmap + DPI Facts"] --> D2["Declare Typed Incidents<br/>(Recon, NSE Tooling, RCE, Brute-Force)"]
        C4 --> D3["Apache PySpark Engine<br/>Distributed DataFrame Aggregation"]
        D3 --> D4["Compute Anomaly Indicators<br/>(Top Talkers & Port Sweeps)"]
    end

    subgraph Stage5 ["Stage 5: Cryptographic Sealing & Chain of Custody"]
        E1["Raw Evidence Artifact (.pcap)"] --> E2["1. SHA-256 Digest<br/>(Integrity Verification)"]
        E1 --> E3["2. AES-256-GCM Encryption<br/>(Confidentiality with 12-byte Nonce)"]
        E2 --> E4["3. RSA-2048 Digital Signature<br/>(Authenticity & Non-Repudiation)"]
        E1 --> E5["4. Blind Index Trapdoor Token<br/>HMAC-SHA256(K_search, Keyword)"]
    end

    subgraph Stage6 ["Stage 6: Enterprise Control, Audit & Reporting"]
        F1["RBAC Authorization<br/>(Admin, Analyst, Investigator, Auditor)"] --> F2["SHA-256 Hash-Chained Audit Trail<br/>Hash_i = SHA256(Log_i || Hash_i-1)"]
        F2 --> F3[("PostgreSQL 15 ACID Persistence<br/>audit_logs | incidents | evidence")]
        E5 --> F4["Zero-Knowledge Search Query<br/>Query vault without decrypting"]
        E4 --> F5["Export Court-Ready Package<br/>(court_ready_forensic_report.json)"]
    end

    %% Inter-Stage Transitions
    Stage1 --> Stage2
    Stage2 -->|"Live Wire Sniffing"| Stage3
    Stage3 --> Stage4
    Stage4 --> Stage5
    Stage5 --> Stage6