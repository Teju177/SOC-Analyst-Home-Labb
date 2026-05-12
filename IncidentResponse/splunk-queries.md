# Project 5 — Splunk SPL Queries
## Incident Response Workflow

Time range: **Last 2 Hours** | Run in **Splunk Web → Search & Reporting**

---

## Investigation Query 1 — Reconstruct the Attack Timeline

```spl
index=main (EventCode=4688 OR EventCode=4625 OR EventCode=4624
OR EventCode=4720 OR EventCode=4728 OR EventCode=4698)
| eval Phase=case(
    EventCode=4688 AND match(CommandLine,"EncodedCommand"), "1-Phishing",
    EventCode=4625, "2-BruteForce",
    EventCode=4624, "2-Login",
    EventCode=4720, "3-NewUser",
    EventCode=4728, "3-AdminGroup",
    EventCode=4698, "4-Persistence",
    true(), "Other"
  )
| table _time, Phase, EventCode, Account_Name, ComputerName
| sort _time
```

Reconstructs the full attack timeline in chronological order across all phases.  
**Dashboard Panel 1** → Table view → title: Attack Timeline

---

## Investigation Query 2 — Identify the Compromised Account

```spl
index=main EventCode=4720
| table _time, Account_Name, SAM_Account_Name, ComputerName
| rename SAM_Account_Name as NewAccountCreated
```

Finds the new account created during the privilege escalation phase.

---

## Investigation Query 3 — Persistence Check (Scheduled Tasks)

```spl
index=main EventCode=4698
| table _time, Account_Name, TaskName, ComputerName
| sort -_time
```

Any scheduled task created after initial access is a persistence indicator.

---

## Investigation Query 4 — Scope of Impact (All Affected Users)

```spl
index=main (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) as FailedLogins,
        count(eval(EventCode=4624)) as SuccessfulLogins
  by Account_Name, ComputerName
| where FailedLogins > 2
| sort -FailedLogins
```

Shows every account with suspicious login patterns to scope the incident.  
**Dashboard Panel 2** → Bar Chart → title: Login Anomalies

---

## Investigation Query 5 — Executive Summary Stats

```spl
index=main (EventCode=4688 OR EventCode=4625 OR EventCode=4624
OR EventCode=4720 OR EventCode=4698)
| stats count by EventCode
| eval Description=case(
    EventCode=4688, "Process Creation",
    EventCode=4625, "Failed Logon (Brute Force)",
    EventCode=4624, "Successful Logon",
    EventCode=4720, "New Account Created",
    EventCode=4698, "Scheduled Task Created",
    true(), "Other"
  )
| table EventCode, Description, count
```

High-level count of all incident-related events. Use this in your IR report executive summary.  
**Dashboard Panel 3** → Pie Chart → title: Incident Event Summary

---

## Event ID Reference

| Event ID | Meaning | Attack Phase |
|----------|---------|-------------|
| 4688 | Process Creation | Phase 1 — Phishing |
| 4625 | Failed Logon | Phase 2 — Brute Force |
| 4624 | Successful Logon | Phase 2 — Login |
| 4720 | New Account Created | Phase 3 — Privilege Escalation |
| 4728 | User Added to Global Group | Phase 3 — Privilege Escalation |
| 4698 | Scheduled Task Created | Phase 4 — Persistence |

---

*Project 5 — SOC Analyst Home Lab | Incident Response with Splunk*
