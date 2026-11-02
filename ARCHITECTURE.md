# CyberSentinel — System Architecture & Technical Specifications

This document outlines the end-to-end component topology, data flows, cryptographic pipeline, network boundaries, and database relationships of the CyberSentinel platform.

---

## 1. High-Level Component Topology (Mermaid)

```mermaid
graph TD
    subgraph ClientLayer ["1. Presentation Layer"]
        UI["React 18 Dashboard<br/>(Tailwind CSS, Lucide, Axios)<br/>:5173"]
    end

    subgraph GatewayLayer ["2. Control Plane & API Gateway (Go) :8080"]
        GW["HTTP API Gateway"]
        RBAC["RBAC Middleware<br/>(Admin, Analyst, Investigator, Auditor)"]
        AuditEngine["Hash-Chained Audit Engine<br/>SHA-256(Log_i || Hash_i-1)"]
        ScanEngine["Assessment Engine<br/>(Nmap Orchestrator & Parsers)"]
        Correlator["Multi-Rule Correlation Engine"]
        CryptoEngine["Cryptographic Core<br/>SHA-256 | AES-256-GCM | RSA-2048"]
        SearchIndex["Searchable Encryption<br/>HMAC-SHA256 Blind Index"]
    end

    subgraph AnalyticsLayer ["3. Traffic & Big Data Engine (Python) :5000"]
        PyServer["Microservice Server<br/>(server.py)"]
        DPI["Deep Packet Inspection<br/>(Pyshark / TShark)"]
        FlowGen["Flow Generator<br/>(pcap_to_flows.py)"]
        SparkCore["Apache PySpark Core<br/>(Distributed DataFrame Analytics)"]
    end

    subgraph RangeLayer ["4. Controlled Target Range (Docker 'cyber-net')"]
        WebTarget["target-web (172.18.0.2:80)<br/>Apache/PHP 8.2<br/>- RCE: /cmd.php (CVSS 9.8)<br/>- SQLi: /login.php (CVSS 8.5)<br/>- LFI: /file.php (CVSS 7.5)"]
        SSHTarget["target-ssh (172.18.0.3:22)<br/>Alpine OpenSSH 10.3<br/>- Credential Brute-Force Lab"]
    end

    subgraph PersistenceLayer ["5. Persistence & Storage Layer"]
        PG[("PostgreSQL 15 :5432<br/>audit_logs<br/>incidents<br/>evidence_records")]
        Vault[("Evidence Vault Volume<br/>/app/evidence<br/>*.pcap | *.pcap.enc")]
        FlowStore[("Flow Volume<br/>/app/flows<br/>flows.csv")]
    end

    %% Client Interactions
    UI -->|"HTTP / REST (X-Auth-Token)"| GW
    GW --> RBAC
    RBAC --> AuditEngine

    %% Gateway to Internal Engines
    GW --> ScanEngine
    GW --> Correlator
    GW --> CryptoEngine
    GW --> SearchIndex

    %% Orchestration & Sniffing
    ScanEngine -->|"Probes / Exploits"| RangeLayer
    ScanEngine -->|"Live Sniff (tshark -i eth0)"| Vault

    %% Traffic Intelligence
    GW -->|"HTTP GET /features, /spark"| PyServer
    PyServer --> DPI
    PyServer --> FlowGen
    FlowGen --> SparkCore
    DPI --> Vault
    FlowGen --> Vault
    FlowGen --> FlowStore
    SparkCore --> FlowStore

    %% Correlation Pipeline
    PyServer -.->|"Extracted Packet Features"| Correlator

    %% Persistence
    AuditEngine -->|"INSERT audit_logs"| PG
    Correlator -->|"INSERT incidents"| PG
    CryptoEngine -->|"INSERT evidence_records"| PG
    CryptoEngine -->|"Read / Write Encrypted PCAP"| Vault
    SearchIndex -->|"HMAC Trapdoor Index"| GatewayLayer