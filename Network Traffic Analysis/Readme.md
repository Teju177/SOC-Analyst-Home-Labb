# Project 3 - Network Traffic Analysis 
## Objective Capture and analyze network traffic using Wireshark to detect suspicious activity. 
## Tools Used - Wireshark (packet capture and analysis) - Splunk Enterprise (log correlation) - Windows PowerShell (portscan simulation) 
## Key Wireshark Filters Used - dns (DNS traffic analysis) - http (HTTP traffic monitoring) - tcp.flags.syn == 1 (port scan detection) - ip.addr ==[target IP] 
## Attack Simulation Simulated port scan using PowerShell Test-NetConnection. Captured and identified SYN packets in Wireshark. 
## Outcome
Successfully identified port scan traffic pattern. Exported pcap file and imported into Splunk for correlation.