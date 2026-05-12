# 📧 Project 4 — Phishing Email Analysis

**Analyst:** Tejas C  
**Difficulty:** Beginner  
**Status:** Completed  
**Tools Used:** MXToolbox · VirusTotal · Any.run · URLScan.io · AbuseIPDB · Email Headers · Notepad

---

## 📌 Objective

Analyze a suspicious phishing email, extract Indicators of Compromise (IOCs), identify phishing indicators, and document findings like a real SOC L1 analyst.

---

## 🧠 Skills Demonstrated

- Reading and analyzing raw email headers
- Identifying spoofed/typosquatted sender domains
- Extracting and investigating IOCs (URLs, IPs, domains)
- Safe URL analysis using sandboxes (Any.run, URLScan.io)
- Using free SOC tools: MXToolbox, VirusTotal, AbuseIPDB
- Writing a structured SOC Incident Report

---

## 🗂️ Repository Structure

```
Project4-Phishing-Email-Analysis/
├── screenshots/
│   ├── email-headers-analysis.png
│   ├── virustotal-domain.png
│   ├── urlscan-results.png
│   └── abuseipdb-ip.png
├── IOCs.md
├── incident_report.md
├── splunk-queries.md
└── README.md
```

---

## 🔍 Sample Phishing Email Analyzed

```
From: security-alert@amaz0n-support.com
To: victim@gmail.com
Subject: URGENT: Your Amazon account has been suspended!
Date: Mon, 05 May 2026 10:23:45 +0000
Received: from mail.amaz0n-support.com (192.168.100.55)
X-Originating-IP: 185.234.219.47

http://amaz0n-account-restore.tk/login?id=98273
```

---

## 🚩 Key Findings

| Indicator | Value | Result |
|-----------|-------|--------|
| Sender Domain | amaz0n-support.com | ⚠️ Typosquatting |
| SPF Check | FAIL | 🔴 Phishing Indicator |
| DKIM Check | FAIL | 🔴 Phishing Indicator |
| DMARC Check | FAIL | 🔴 Phishing Indicator |
| Phishing URL | amaz0n-account-restore.tk | 🔴 Malicious |
| Originating IP | 185.234.219.47 | 🔴 Flagged on AbuseIPDB |
| Domain Age | Recently Registered | ⚠️ Red Flag |

---

## 🛠️ Tools & Steps

### Step 1 — Email Header Analysis
- Tool: [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
- Pasted raw email headers and analyzed SPF/DKIM/DMARC results
- Identified originating IP: `185.234.219.47`

### Step 2 — Domain Investigation
- Tool: [VirusTotal](https://www.virustotal.com)
- Searched domain: `amaz0n-support.com`
- Result: Flagged as **MALICIOUS** by multiple vendors

### Step 3 — WHOIS / Domain Registration
- Tool: [ICANN Lookup](https://lookup.icann.org)
- Domain was recently registered — major red flag

### Step 4 — URL Analysis (Safe Sandbox)
- Tool: [URLScan.io](https://urlscan.io) / [Any.run](https://any.run)
- Submitted: `http://amaz0n-account-restore.tk/login`
- Identified redirects and resolved IP of the phishing server

### Step 5 — IP Reputation Check
- Tool: [AbuseIPDB](https://www.abuseipdb.com) + [IPInfo.io](https://ipinfo.io)
- IP `185.234.219.47` has multiple abuse reports

---

## 🎯 MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Phishing: Spearphishing Link | T1566.002 | Malicious URL delivered via email |

---

## 📋 Incident Summary

> A phishing email impersonating **Amazon** was analyzed. The email used a typosquatted sender domain (`amaz0n-support.com`), failed all email authentication checks (SPF/DKIM/DMARC), and contained a malicious link pointing to a fake Amazon login page hosted on `amaz0n-account-restore.tk`. The originating IP `185.234.219.47` was confirmed malicious via AbuseIPDB.

**Severity:** 🔴 HIGH  
**Recommended Actions:**
1. Block sender domain at email gateway
2. Block IP `185.234.219.47` at firewall
3. Alert users about active phishing campaign
4. Report domain to registrar for takedown

---

## 📚 References

- [MITRE ATT&CK T1566.002](https://attack.mitre.org/techniques/T1566/002/)
- [PhishTank](https://www.phishtank.com)
- [MXToolbox](https://mxtoolbox.com)
- [VirusTotal](https://www.virustotal.com)
- [AbuseIPDB](https://www.abuseipdb.com)
