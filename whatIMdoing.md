Home Lab — Project Description (Markdown)

Project name: SOC/Home Lab — Endpoint & Visibility Platform
Owner: chico
Purpose: Build an isolated, repeatable home lab to learn Sysmon, EDR telemetry, Splunk (or another SIEM), detection engineering, and SOC workflows. The lab is defensive and educational only — every test is performed in isolated VMs with snapshots.

1. Project overview

This home lab is a compact, hands‑on SOC environment you can use to:

Learn Sysmon configuration and how it generates telemetry.

Ingest endpoint telemetry into Splunk (or an alternate SIEM).

Create, test, and tune detection rules for common attacker techniques (e.g., T1059 command interpreters, lateral movement patterns).

Practice incident investigation workflows and playbook creation.

Validate detections using benign test artifacts and controlled scenarios only.

2. Goals & success criteria

Primary goals

Collect rich endpoint telemetry (process creation, network connections, file writes, image loads) from Windows hosts using Sysmon.

Ingest that telemetry into a SIEM and produce actionable detections (low false positive rate).

Build repeatable test cases to validate detections and demonstrate a detection → triage → remediation flow.

Success metrics

Sysmon logs from all lab endpoints received in SIEM within 60s.

At least 5 reliable detection rules for high-priority techniques (e.g., suspicious PowerShell usage, unexpected child processes, download+execute chains).

Playbook documenting triage steps for a triggered alert, including pivot queries and remediation actions.

Clean snapshots and automation that re-create the lab in <2 hours.

3. Scope & constraints

Included

2–3 Windows 10/11 VMs (endpoint), 1 Windows Server VM (optional), 1 SIEM VM (Splunk/ELK/other), 1 attacker/test VM, jump host for management.

Sysmon configured with focused rules to capture process, network, and image-load events.

Logging-forwarder (Winlogbeat/Universal Forwarder) to the SIEM.

Basic EDR-like monitoring via open-source tools or the SIEM’s own rules.

Excluded

No connection to production networks.

No live malware samples; use benign emulation scripts and tools like Atomic Red Team (controlled, well-known tests) only in isolated lab.

No hosting of malicious payloads on public internet.

4. Logical architecture (text diagram)
[Management Host / Jumpbox]  (admin)
         |
    isolated lab network (host-only)
         |
  -------------------------------
  |       |         |           |
[Endpoint][Endpoint][Attacker] [SIEM Server]
 (Win)     (Win)     (Win)      (Splunk/ELK)
  |         |                       |
 Sysmon +  UF/Forwarder   <---- indexed logs / dashboards

5. Components & tools

Virtualization: VirtualBox / VMware / Proxmox / Hyper-V (choose one)

OS images: Windows 10/11 evaluation ISOs; optionally Win Server

Sysmon (Microsoft Sysinternals) — for process/driver/file/image telemetry

Sysmon config template (restrictive but noisy-optimized)

Log forwarder: Splunk Universal Forwarder or Winlogbeat

SIEM: Splunk Enterprise (trial), Elastic Stack, or an open alternative

Management & test tools: PowerShell, Sysinternals Suite (Procmon, TCPView), browser (patched)

Optional: Open-source EDR or hunting frameworks, Jumpbox automation (Ansible/PowerShell)

Source control: Git repo for configs, detection rules, playbooks