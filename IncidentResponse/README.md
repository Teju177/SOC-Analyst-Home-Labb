# Project 5 — Incident Response Workflow with Splunk

## Overview

This project ties together all previous SOC Home Lab projects into a complete end-to-end Incident Response (IR) investigation using Splunk as the primary SIEM. A simulated multi-stage attack is detected, triaged, contained, and documented following the NIST Incident Response lifecycle.

---

## Objective

Demonstrate a full Tier 1 SOC analyst workflow — from receiving a triggered alert in Splunk, through investigation and containment, to writing a post-incident report (PIR).

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Splunk Enterprise | Primary SIEM — search, correlation, dashboards, alerts |
| Splunk Universal Forwarder | Log collection from Windows host |
| Windows PowerShell | Attack simulation (brute force, privilege escalation, phishing) |
| Windows Event Viewer | Verify events before Splunk ingestion |

---

## NIST IR Lifecycle — Phases Covered

| Phase | What Was Done |
|-------|--------------|
| Preparation | Verified Splunk running, all alerts from Projects 1–4 active |
| Detection & Analysis | Received triggered alerts, queried Splunk to identify attack chain |
| Containment | Identified affected host and user accounts, scoped the incident |
| Eradication | Removed rogue admin account, deleted simulated payload files |
| Recovery | Confirmed clean state, re-verified alerts |
| Lessons Learned | Wrote Post-Incident Report, updated detection recommendations |

---

## Attack Simulation — Stages Run

### Stage 1 — Brute Force (Replicates Project 1)
Simulated 6 failed login attempts generating **EventCode 4625** in Windows Security logs.

### Stage 2 — Privilege Escalation (Replicates Project 2)
Created rogue local user `AttackerIR` and added to Administrators group, generating **EventCode 4720** and **EventCode 4732**.

### Stage 3 — Phishing Payload (Replicates Project 4)
Executed Base64-encoded PowerShell command and dropped a simulated executable in `%TEMP%`, generating **EventCode 4688**.

---

## Key Event IDs Monitored

| Event ID | Meaning | Attack Stage |
|----------|---------|-------------|
| 4625 | Failed Login | Brute Force |
| 4720 | New User Account Created | Privilege Escalation |
| 4732 | User Added to Local Admin Group | Privilege Escalation |
| 4672 | Special Privileges Assigned | Privilege Escalation |
| 4688 | Process Creation | Phishing / Payload Execution |

---

## SPL Queries

All SPL queries used in this investigation are documented in [`splunk-queries.md`](./splunk-queries.md).

Key queries include:
- Full correlated attack timeline across all event IDs
- Affected user accounts breakdown
- Timeline chart (for dashboard visualisation)
- Scope of compromise by host

---

## Splunk Dashboard Built

**Dashboard Name:** IR Investigation Dashboard

Panels included:
1. Attack Timeline — Line chart (timechart by EventCode)
2. Event Type Breakdown — Bar chart (count by Event_Type)
3. Affected User Accounts — Table
4. Scope of Compromise — Table (events per host)
5. IOC Lookup Results — Table (from Project 4 lookup)

---

## Indicators of Compromise (IOCs)

| IOC | Type | Severity |
|-----|------|---------|
| `AttackerIR` local account | Rogue admin account | CRITICAL |
| `powershell.exe -EncodedCommand` | Encoded PowerShell execution | HIGH |
| `%TEMP%\ir_test_payload.exe` | Suspicious file drop | HIGH |
| `malicious-phish.xyz` | Known phishing domain (IOC lookup) | HIGH |

---

## Containment & Eradication Actions

```powershell
# Remove rogue admin account
Remove-LocalUser -Name 'AttackerIR'

# Remove simulated payload file
Remove-Item -Path "$env:TEMP\ir_test_payload.exe" -Force
```

---

## Post-Incident Report (PIR)

**Incident ID:** IR-2024-001  
**Severity:** CRITICAL  
**Status:** CLOSED — Lab simulation, no real systems affected

**Summary:** A simulated multi-stage attack was detected and investigated. The attack chain included brute force authentication attempts, privilege escalation via rogue admin account creation, and phishing payload delivery via encoded PowerShell. All activity was contained to the lab environment.

**Recommendations:**
1. Enable MFA to reduce brute force risk
2. Alert on any new local admin account creation in real-time
3. Block PowerShell `-EncodedCommand` by default for non-admin users
4. Expand IOC lookup table with live threat feeds (e.g., MISP, AlienVault OTX)

---

## Outcome

- Successfully detected a simulated multi-stage attack using Splunk
- Reconstructed the full attack timeline using correlated SPL queries
- Built an IR Investigation Dashboard covering all 5 attack stages
- Completed containment and eradication actions
- Documented all findings in a professional Post-Incident Report

---

## Screenshots

| File | Description |
|------|-------------|
| `ir-dashboard.png` | Full IR Investigation Dashboard in Splunk |
| `timeline-query.png` | Full attack timeline SPL query results |
| `triggered-alerts.png` | Activity → Triggered Alerts showing all fired alerts |
| `pir-document.png` | Post-Incident Report document |

---

## Related Projects

| Project | Topic |
|---------|-------|
| [Project 1](../Project-1/) | Brute Force Detection using Splunk |
| [Project 2](../Project-2/) | Privilege Escalation Detection |
| [Project 3](../Project-3/) | Network Traffic Analysis with Wireshark |
| [Project 4](../Project-4/) | Phishing Email Detection & URL Analysis |
| **Project 5** | **Incident Response Workflow — this project** |

---

*SOC Analyst Home Lab | Splunk · Windows Security · Incident Response*
