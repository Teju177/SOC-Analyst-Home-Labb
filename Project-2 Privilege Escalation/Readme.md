# Project 2 - Privilege Escalation Detection

## Objective
Detect privilege escalation attempts using Splunk and Windows Security Event Logs.

## Tools Used
- Splunk (SIEM)
- Windows PowerShell
- Windows Event Viewer
- Windows Security Event Logs

## Event IDs Monitored
| Event ID | Description |
|----------|-------------|
| 4720 | New User Account Created |
| 4732 | User Added to Local Admin Group |
| 4728 | User Added to Global Security Group |
| 4672 | Special Privileges Assigned |

## Attack Simulation
Used PowerShell to create a test user `TestHacker` and add them to the Administrators group to generate real Windows Security events.

## Outcome
- Successfully detected simulated privilege escalation within 2 minutes
- Created automated Splunk alert triggered on result count > 0