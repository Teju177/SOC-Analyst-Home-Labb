# SOC-Analyst-Home-Labb

## Project 1 - Brute Force Detection using Splunk

### Tools Used
- Splunk Enterprise 10.2
- Splunk Universal Forwarder
- Windows 10
- Windows Security Event Logs

### What I Built
- Configured Splunk Universal Forwarder to collect Windows Security logs
- Enabled Windows Audit Policy for login monitoring
- Detected failed login attempts using Event ID 4625
- Created automated Splunk Alert for brute force detection
- Built a SOC monitoring dashboard with multiple panels

### SPL Queries Used

Failed Login Detection:
index=windows_security EventCode=4625
| stats count by Account_Name
| sort -count

Brute Force Alert:
index=windows_security EventCode=4625
| stats count by Account_Name
| where count > 5
| sort -count

### What I Learned
- Splunk Universal Forwarder configuration
- Windows Audit Policy setup
- SPL query writing for threat detection
- SOC dashboard creation
