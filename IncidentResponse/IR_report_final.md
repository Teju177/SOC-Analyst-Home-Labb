# Incident Response Report
**Incident ID:** IR-2026-001
**Date:** 09-May-2026
**Analyst:** Tejas C
**Severity:** CRITICAL
**Status:** RESOLVED
## Executive Summary
Three simultaneous attacks detected: brute force login attempts,
unauthorized admin account creation, and port scanning activity.
All threats contained and eradicated within the simulation.
## Timeline
| Time | Event | EventCode |
|-------|------------------------------------|-----------|
| T+0 | Multiple failed logins detected | 4625 |
| T+2 | New user IRTestUser created | 4720 |
| T+3 | IRTestUser added to Admins group | 4732 |
| T+5 | Port scan detected on localhost | TCP SYN |
## MITRE ATT&CK; Mapping
- T1110 — Brute Force
- T1136 — Create Account
- T1078 — Valid Accounts (Privilege Escalation)
- T1046 — Network Service Scanning
## Containment Actions
1. Identified attacker account: IRTestUser
2. Removed from Administrators group
3. Deleted test account
4. Splunk alerts verified and active
## Eradication
Remove-LocalUser -Name 'IRTestUser' [COMPLETED]
## Lessons Learned
- Alert thresholds work correctly
- Detection time under 2 minutes for all attack types
- Combined Splunk dashboard enables faster triage