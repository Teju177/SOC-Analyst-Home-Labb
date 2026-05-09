# Splunk SPL Queries — Brute Force Detection

## Failed Login Detection
index=windows_security EventCode=4625
| stats count by Account_Name
| sort -count

## Brute Force Alert Query
index=windows_security EventCode=4625
| stats count by Account_Name
| where count > 5

## Timeline Analysis
index=windows_security EventCode=4625
| timechart count span=1h as "Failed Logins"

## Successful Logins
index=windows_security EventCode=4624
| stats count by Account_Name
| sort -count