# 🔍 Splunk Queries — Project 4: Phishing Email Analysis
# Analyst: Tejas C
# Date: 05-May-2026
# Index: Adjust index name to match your Splunk environment

# ============================================================
# QUERY 1 — Search for Phishing Emails by Sender Domain
# Detects emails from known typosquatted/malicious domains
# ============================================================

index=email_logs sourcetype=email
| search sender="*amaz0n-support.com*" OR sender="*amaz0n-account-restore*"
| table _time, sender, recipient, subject, src_ip
| sort -_time

# ============================================================
# QUERY 2 — Detect Emails with SPF / DKIM / DMARC Failures
# SPF/DKIM/DMARC failures are strong phishing indicators
# ============================================================

index=email_logs sourcetype=email
| search spf=FAIL OR dkim=FAIL OR dmarc=FAIL
| stats count by sender, spf, dkim, dmarc
| sort -count

# ============================================================
# QUERY 3 — Find Emails with URGENT or Suspicious Keywords
# Social engineering lures typically use urgency-based language
# ============================================================

index=email_logs sourcetype=email
| search subject="*URGENT*" OR subject="*suspended*" OR subject="*verify*"
        OR subject="*account locked*" OR subject="*confirm*"
| table _time, sender, recipient, subject
| sort -_time

# ============================================================
# QUERY 4 — Detect Emails from Recently Registered Domains
# Domains < 30 days old are a high-confidence phishing indicator
# ============================================================

index=email_logs sourcetype=email
| search domain_age_days < 30
| table _time, sender, domain, domain_age_days, subject
| sort domain_age_days

# ============================================================
# QUERY 5 — Search for Known Malicious IP (X-Originating-IP)
# Hunt for emails originating from the flagged IP
# ============================================================

index=email_logs sourcetype=email
| search src_ip="185.234.219.47"
| table _time, sender, recipient, subject, src_ip
| sort -_time

# ============================================================
# QUERY 6 — Search for Malicious URLs in Email Body
# Identifies typosquatted or .tk / .ml / .ga domains in links
# ============================================================

index=email_logs sourcetype=email
| search body="*.tk*" OR body="*.ml*" OR body="*.ga*"
        OR body="*amaz0n*" OR body="*paypa1*" OR body="*g00gle*"
| table _time, sender, recipient, body
| sort -_time

# ============================================================
# QUERY 7 — Detect Users Who Clicked Phishing Links
# Correlate email events with proxy/web logs to find victims
# ============================================================

index=proxy_logs OR index=web_logs
| search url="*amaz0n-account-restore.tk*" OR url="*amaz0n-support.com*"
| table _time, src_ip, user, url, http_status
| sort -_time

# ============================================================
# QUERY 8 — Top Targeted Recipients (Phishing Campaign Scope)
# Shows which users are being targeted most
# ============================================================

index=email_logs sourcetype=email
| search sender="*amaz0n-support.com*"
| stats count as phishing_emails_received by recipient
| sort -phishing_emails_received
| head 20

# ============================================================
# QUERY 9 — Phishing Email Volume Over Time (Timechart)
# Visualize the campaign timeline
# ============================================================

index=email_logs sourcetype=email
| search spf=FAIL AND dkim=FAIL AND dmarc=FAIL
| timechart span=1h count as failed_auth_emails

# ============================================================
# QUERY 10 — Combined Phishing Indicator Alert
# High-confidence phishing detection: multi-factor correlation
# ============================================================

index=email_logs sourcetype=email
| eval is_typosquat=if(match(sender, "amaz0n|paypa1|g00gle|micros0ft"), 1, 0)
| eval auth_fail=if(spf="FAIL" AND dkim="FAIL" AND dmarc="FAIL", 1, 0)
| eval suspicious_subject=if(match(subject, "(?i)urgent|suspended|verify|locked"), 1, 0)
| eval phishing_score=is_typosquat + auth_fail + suspicious_subject
| where phishing_score >= 2
| table _time, sender, recipient, subject, phishing_score, src_ip
| sort -phishing_score

# ============================================================
# QUERY 11 — Block List Lookup — Known Malicious Domains
# Check if sender domain matches a threat intel block list
# ============================================================

index=email_logs sourcetype=email
| lookup threat_intel_domains domain AS sender_domain OUTPUT threat_level
| where threat_level="MALICIOUS" OR threat_level="SUSPICIOUS"
| table _time, sender, recipient, subject, threat_level
| sort -_time

# ============================================================
# QUERY 12 — IOC Summary Dashboard Query
# Single-pane summary of all phishing IOCs detected today
# ============================================================

index=email_logs sourcetype=email earliest=-24h
| eval IOC_Type=case(
    match(sender, "amaz0n|paypa1|g00gle"), "Typosquatted Domain",
    spf="FAIL" AND dkim="FAIL", "Auth Failure",
    match(body, "\.tk|\.ml|\.ga"), "Suspicious URL Extension",
    src_ip="185.234.219.47", "Known Malicious IP",
    true(), "Other")
| stats count by IOC_Type
| sort -count
