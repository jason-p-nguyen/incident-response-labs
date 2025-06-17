## 🔐 Incident Response Lab: Brute Force Detection & Response in Microsoft Sentinel

**Author**: Jason Nguyen  
**Date**: 18 June 2025

**Tools, Technologies & Frameworks Used**:
- Microsoft Azure
- Microsoft Sentinel
- Microsoft Defender for Endpoint (MDE)
- Log Analytics Workspace
- Network Security Group (NSG)
- KQL (Kusto Query Language)
- GitHub (Markdown, Repo Management)
- NIST 800-61 Framework

**Tooling**: Microsoft Sentinel · KQL · Microsoft Defender for Endpoint (MDE) · Azure VM · Log Analytics · Network Security Group (NSG)

### 📘 Summary

This project demonstrates how I detected and responded to a simulated brute force attack on an Azure virtual machine using Microsoft Sentinel. I created a scheduled query rule to detect repeated failed logon attempts, triggered an incident, and walked through the full incident response lifecycle using the [NIST 800-61 framework](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final).

---

### 🧠 Objectives

* Build and deploy a brute force detection rule in Microsoft Sentinel using KQL and Log Analytics.
* Investigate and respond to a security incident using MDE and Sentinel.
* Apply real-world practices for containment, eradication, and recovery using NSGs.
* Document the entire workflow following NIST 800-61.

---

### 🔎 Detection Logic (KQL)

I used the `DeviceLogonEvents` table from Microsoft Defender for Endpoint to detect brute force attempts:

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
````

This query identifies external IP addresses that failed to log in 10 or more times to the same Azure VM within the last 5 hours.

---

### ⚙️ Sentinel Alert Rule Configuration

* **Schedule**: Runs every 4 hours, looks back 5 hours.
* **Entity Mappings**:

  * `RemoteIP` → IP
  * `DeviceName` → Host
* **MITRE ATT\&CK Mapping**:

  * Initial Access (T1078 – Valid Accounts)
  * Brute Force (T1110 – Password Guessing)

The alert was configured to automatically create an incident and group alerts into a single incident every 24 hours.

---

### 🚨 Incident Investigation

Once triggered, I investigated the incident in Sentinel:

**Findings**:

* Brute force attempts from the following IPs:

  * `109.235.48.179` → 99 failed logons to `kayetvm`
  * `92.63.197.52` → 92 failed logons to `alino-mde-test1`
  * `45.10.175.246` → 45 failed logons to `linux-target-1`

To ensure no successful compromises occurred, I validated using this query:

```kql
DeviceLogonEvents
| where RemoteIP in ("109.235.48.179", "92.63.197.52", "45.10.175.246")
| where ActionType != "LogonFailed"
```

✅ No successful logons were detected from the attacker IPs.

---

### 🛡️ Response & Containment

To mitigate the threat, I:

* Proposed corporate policy to restrict NSG access to known IPs only.
* Simulated NSG lockdown to allow only my local PC access to the VM.
* Discussed real-world use of Microsoft Defender for Endpoint (MDE) to isolate infected machines and run AV scans.

---

### 📋 Post-Incident Activities

* **Lessons Learned**:

  * NSGs should be restricted by default. Open RDP access is a critical risk.
  * Visualization in Sentinel entity mapping helped clarify attack paths.
* **Policy Update Recommendation**:

  * Implement Azure Policy to enforce NSG hardening across all VMs.
* **Final Steps**:

  * Documented findings and closed the case as a *true positive* in Sentinel.

---

### 🧩 Challenges & Takeaways

* Initial VM setup was slow and unstable, so I used a pre-configured lab VM.
* Struggled to build my own KQL initially but learned through provided examples.
* Found the visual entity mapping in Sentinel extremely useful, though interpreting it took practice.
* Gained hands-on experience walking through an end-to-end detection and response workflow using real cloud tools.

---

### ✅ Skills Demonstrated

* Threat detection and KQL query development
* Security incident triage and investigation
* Microsoft Sentinel rule configuration
* Incident handling using NIST 800-61 lifecycle
* NSG and network access control in Azure

## 📎 Notes

* This report is part of my cybersecurity learning portfolio from Josh Madakor's Cyber Range.
