# Project 3 - Suspicious Network Traffic Analysis Using Wireshark & Splunk

## Objective
Capture and analyze network traffic using Wireshark to identify suspicious activity and correlate logs using Splunk.

---

## Tools Used
- Wireshark (Packet Capture & Analysis)
- Splunk Enterprise (Log Correlation & Monitoring)
- Windows PowerShell (Port Scan Simulation)

---

## Wireshark Filters Used

```wireshark
dns
http
tcp.flags.syn == 1
ip.addr == [Target IP]
