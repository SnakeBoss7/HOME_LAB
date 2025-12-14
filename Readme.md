# Windows Endpoint Telemetry & SOAR Automation

Windows Endpoint Telemetry System using Sysmon + Splunk Indexer + UF + Generating Alerts + SPL Queries + Dashboards + Atomic Red Team Attacks + Writing Sysmon XML Rules + Python SOAR Mini-Clone.

## Project Workflow

```mermaid
graph TD
    %% Global Styles
    classDef phase1 fill:#ffcccc,stroke:#333,stroke-width:2px,color:black;
    classDef phase2 fill:#ccffcc,stroke:#333,stroke-width:2px,color:black;
    classDef phase3 fill:#ccccff,stroke:#333,stroke-width:2px,color:black;
    classDef phase4 fill:#ffffcc,stroke:#333,stroke-width:2px,color:black;

    subgraph Phase1 [Phase 1: Attack Simulation]
        direction TB
        A[Atomic Red Team]:::phase1 -->|Executes TTPs| B(Windows Endpoint):::phase1
    end

    subgraph Phase2 [Phase 2: Detection Engineering]
        direction TB
        B -->|Sysmon Event| C[Splunk UF]:::phase2
        C -->|Forward Data| D[Splunk Indexer]:::phase2
        D -->|SPL & XML Rules| E{Alert Triggered?}:::phase2
    end

    subgraph Phase3 [Phase 3: Python SOAR Mini-Clone]
        direction TB
        E -->|Yes: JSON Payload| F[Python Script]:::phase3
        F -->|Extract Artifacts| G(IP / Hash / URL):::phase3
        G -->|API Lookup| H[Enrichment Modules]:::phase3
        
        H -.-> VT[VirusTotal]:::phase3
        H -.-> SH[Shodan]:::phase3
        H -.-> AB[AbuseIPDB]:::phase3
        
        H -->|Enriched Data| I[Severity Scoring Logic]:::phase3
        I -->|Context Request| J[LLM Integration]:::phase3
        J -->|Returns Analysis| K[Report Builder]:::phase3
    end

    subgraph Phase4 [Phase 4: Response]
        direction TB
        K -->|Create Ticket| L[Jira Ticket]:::phase4
    end
```

## System Architecture & Components

### 1. Telemetry & Detection (Sysmon + Splunk)
The foundation of the project is robust telemetry and detection.
*   **Sysmon**: Configured with custom XML rules to capture relevant endpoint telemetry.
    *   [Installation Guide](Window/Sysmon/Insatallion.md)
*   **Splunk**: Acts as the SIEM, ingesting logs via Universal Forwarder (UF), running SPL queries, and hosting dashboards.
    *   [Windows UF Installation](Window/SplunkUF/Installtion.md)
    *   [Splunk Custom Alert](Linux/Splunk/customAlert.md)

### 2. Python SOAR Mini-Clone
A custom automation pipeline that processes alerts triggered by Splunk.

**Pipeline Steps:**
1.  **Ingest**: Receives the Alert JSON payload from Splunk.
2.  **Extraction**: Parses the payload to extract artifacts (IPs, Hashes, URLs).
3.  **Enrichment**: Queries external APIs (VirusTotal, Shodan, AbuseIPDB) for reputation data.
4.  **Scoring**: Calculates a severity score based on enrichment data.
5.  **AI Analysis**: Queries an LLM to format the analysis, map to MITRE ATT&CK, and suggest response actions.
    *   *Note: AI is used primarily for formatting and structure, as it may not be reliable for critical risk assessment.*
6.  **Response**: Automatically creates a Jira ticket with all gathered context.

**Scripts:**
- [Alert Script](SoarWorkflow/soar_flow.py) - Main controller for the SOAR pipeline.

### 3. Attack Simulation & Detection (Atomic Red Team)
Simulated attacks used to test and validate the detection pipeline.

#### Windows Attacks
*   **T1003.001 (OS Credential Dumping)**
    *   [Analysis](AtomicRedteam/T1003.001-Playbook/Analysis.md)
    *   [Attack Execution](AtomicRedteam/T1003.001-Playbook/Detection.md)
*   **T1053.005 (Scheduled Task)**
    *   [Analysis](AtomicRedteam/T1053.005-Playbook/Analysis.md)
    *   [Attack Execution](AtomicRedteam/T1053.005-Playbook/Detection.md)
*   **T1059 (Command and Scripting Interpreter)**
    *   [Guide](AtomicRedteam/T1059-Playbook/Guide.md)
*   **T1110 (Password Spray and Brute Force Login)**
    *   [Guide](/Linux/T1110-Playbook/Setup_AND_security_event_analysis.md)
    *   [Attack Execution](/Linux/T1110-Playbook/pre_access.md)

#### Active Directory Attacks
*   **T1558.003 (Kerberoasting)**
    *   [Attack Execution](/AtomicRedteam/AD-ATTACKS/T1558.003-Playbook/Analysis.md)
    *   [Guide](/AtomicRedteam/AD-ATTACKS/T1558.003-Playbook/Detection.md)
*   **T1550.002 (Pass the Hash)**
    *   [Attack Execution](/AtomicRedteam/AD-ATTACKS/T1550.002&003-Playbook/Analysis.md)
    *   [Guide](/AtomicRedteam/AD-ATTACKS/T1550.002&003-Playbook/Detection.md)
*   **T1550.003 (Pass the Ticket)**
    *   [Attack Execution](/AtomicRedteam/AD-ATTACKS/T1550.002&003-Playbook/Analysis.md)
    *   [Guide](/AtomicRedteam/AD-ATTACKS/T1550.002&003-Playbook/Detection.md)

### 4. Integration Guides
- [Jira Python Connection](Jira/Python_Connection.md)
- [Jira Setup](Jira/Setup_Guide.md)