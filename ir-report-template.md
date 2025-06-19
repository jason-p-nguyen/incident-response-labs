## 🔐 Incident Response Lab: [Incident Title Here]

**Author**: [Your Name]  
**Date**: [Date of Completion]

**Tools, Technologies & Frameworks Used**:
- [e.g., Microsoft Sentinel, Defender for Endpoint (MDE), Azure VMs, KQL]
- [Any other tools you used]
- NIST 800-61 Framework

---

### 📘 Summary

This lab demonstrates how I detected and responded to a simulated [incident type] in [cloud/on-prem/hybrid] infrastructure. I followed the [NIST 800-61](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) incident response lifecycle, using tools like [e.g., Microsoft Sentinel, Defender for Endpoint, KQL] to analyze and respond to the threat.

---

### 🧠 Objectives

* [Objective 1 — e.g., Detect and respond to X using Y]
* [Objective 2 — e.g., Practice triage and incident handling]
* [Objective 3 — e.g., Use NSG to contain malicious access]
* [Objective 4 — e.g., Document IR process]

---

### 🔎 Detection Logic (KQL or equivalent)

[Insert query used for detection]

```kql
// Example
DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize Attempts = count() by RemoteIP, DeviceName
| where Attempts > 10
````

\[Explain what the query does and how it relates to the detection.]

---

### ⚙️ Alert Rule or Detection Setup

* **Trigger Type**: \[e.g., Scheduled Analytics Rule, Real-time Alert]
* **Schedule/Lookback**: \[e.g., Every 4 hours, 5h lookback]
* **Entities Mapped**:

  * \[e.g., RemoteIP → IP]
  * \[e.g., DeviceName → Hostname]
* **MITRE ATT\&CK Mapping**:

  * \[Tactic] (\[Technique ID] – \[Technique Name])

---

### 🚨 Incident Investigation

**Summary of Events**:

* \[e.g., Repeated login failures from malicious IPs targeting multiple VMs]
* \[e.g., Unusual script execution or suspicious file downloads]

**Key Findings**:

* \[IP Address or Indicator] → \[Action/Impact]
* \[Any hostnames, file hashes, or user accounts involved]

**Validation Query (if applicable)**:

```kql
// Confirming successful access or further activity
[Insert follow-up query]
```

✅ \[Summarize whether compromise occurred]

---

### 🛡️ Response & Containment

* \[Step 1 — e.g., Block malicious IP using NSG or firewall]
* \[Step 2 — e.g., Isolate VM in MDE]
* \[Step 3 — e.g., Run Defender AV scan or custom script]
* \[Optional — Describe real-world analog or suggestion]

---

### 📋 Post-Incident Activities

* **Lessons Learned**:

  * \[e.g., Importance of log visibility, NSG hardening, alert tuning]

* **Policy Update Recommendations**:

  * \[e.g., Enforce NSG restrictions with Azure Policy]
  * \[e.g., Monitor new admin account creations]

* **Final Disposition**:

  * \[e.g., Closed as true positive / false positive / benign alert]

---

### 🧩 Challenges & Takeaways

* \[List 2–3 personal takeaways or difficulties you encountered]

  * \[e.g., Reading long KQL queries]
  * \[e.g., Understanding Sentinel’s workbook visualizations]
  * \[e.g., Delay in VM setup, needing lab workaround]

---

### ✅ Skills Demonstrated

* Threat detection and KQL development
* IR triage and investigation workflows
* Alert creation and Sentinel rule config
* Application of the NIST IR lifecycle
* Azure security tools: NSG, MDE, Log Analytics

---

## 📎 Notes

* \[e.g., This lab was completed as part of Josh Madakor's Cyber Range]
* \[Any additional personal context, links to labs, or datasets]
