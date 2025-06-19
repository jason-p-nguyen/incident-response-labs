## 🔐 Incident Response Lab: Potential Impossible Travel Detection in Microsoft Sentinel

**Author**: Jason Nguyen  
**Date**: 20 June 2025

**Tools, Technologies & Frameworks Used**:
- Microsoft Sentinel
- Azure Log Analytics Workspace (LAW)
- Microsoft Entra ID (formerly Azure AD)
- KQL (Kusto Query Language)
- MITRE ATT&CK
- GitHub (Markdown Reporting)
- NIST 800-61 Framework

---

### 📘 Summary

This incident response scenario involved detecting potentially malicious logins using a technique called **impossible travel**, where a user logs in from geographically distant locations within an implausible time frame. I created a scheduled analytics rule in Microsoft Sentinel to surface these patterns, triaged the alerts, and performed investigation using Microsoft Sentinel and Entra ID Sign-in Logs. The incident was handled according to the [NIST 800-61](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) incident response lifecycle.

---

### 🧠 Objectives

* Detect and investigate impossible travel login patterns using KQL and Sign-in logs.
* Perform entity analysis and confirm whether logins are legitimate or potentially malicious.
* Document the triage and response workflow for multiple users.
* Simulate post-incident recommendations for security posture improvement.

---

### 🔎 Detection Logic (KQL)

```kql
let TimePeriodThreshold = timespan(7d);
let NumberOfDifferentLocationsAllowed = 4;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
````

This query flags users who appear to have logged in from more than four unique geographic regions within seven days — a strong indicator of potential account compromise or VPN misuse.

---

### ⚙️ Sentinel Alert Rule Configuration

* **Rule Name**: J - Potential Impossible Travel
* **Trigger Type**: Scheduled Analytics Rule
* **Schedule**: Every 5 hours
* **Lookback**: Last 7 days
* **Alert Threshold**: Greater than 0
* **Entity Mapping**:

  * Account → `AadUserId` → `UserId`
  * Display Name → `UserPrincipalName`
* **MITRE ATT\&CK Mapping**:

  * T1708 – Application Layer Protocol: Web Protocols
* **Suppression**: 24 hours after trigger
* **Incident Creation**: Enabled
* **Event Grouping**: Group all events into a single alert

---

### 🚨 Incident Investigation

After the rule was triggered, I investigated three user accounts:

#### Account 1 — `a9d973022d...` (7 instances)

Login activity raised suspicion:

* **13 June 2025, 3:27 PM** – New York, US
* **13 June 2025, 9:39 PM** – Hackney, GB
* **13 June 2025, 9:48 PM** – Lagos, NG
* **14 June 2025, 5:21 AM** – London, GB

⚠️ **Analysis**: This account showed geographically implausible logins within a short time window, suggesting potential account compromise. No associated AzureActivity logs were found. Incident escalated to management.

#### Account 2 — `9e2e306086...` (6 instances)

All logins were from within **Italy**, consistent and low-risk.
✅ False positive – **benign** activity.

#### Account 3 — `431810045c...` (6 instances)

All logins originated in **the Philippines**, showing normal user behavior.
✅ False positive – **benign** activity.

---

### 🛡️ Response & Containment

* Accounts 2 and 3: **No action required** – determined to be expected behavior.
* Account 1 (`a9d973022d...`):

  * 🔒 **Account disabled**
  * ☎️ **Management contacted**
  * 🛑 Device was **isolated** by the IT security team
  * 🧼 Device was **reimaged** after malware was found

---

### 📋 Post-Incident Activities

* Endpoint scanning frequency was **increased** across the organization.
* A **geo-fencing policy** was implemented in Entra ID to restrict logins from specific high-risk countries.
* A review of **remote access tooling** was conducted; all users were instructed to use only approved remote desktop software.
* Internal policy updated to improve detection of impossible travel and account anomalies.

---

### 🧩 Challenges & Takeaways

* Encountered several **KQL errors** during alert configuration due to incorrect `UserId` field usage.
* Initial entity mapping failed; required query revision to include `UserId`.
* Realized importance of **understanding JSON parsing** in KQL when dealing with complex log structures.
* Appreciated the value of correlating **logins with geography**, but noted limitations without additional contextual data (e.g. device health, app logins).

---

### ✅ Skills Demonstrated

* KQL development for anomaly detection
* Sentinel Scheduled Rule configuration
* Triage of multiple user alerts
* NIST-based IR workflow documentation
* Use of geo-data in threat detection
* Cross-team incident handling simulation

---

## 📎 Notes

* This lab was part of Josh Madakor’s Cyber Range series.
* The detection rule was deleted post-lab to avoid unnecessary triggers.
* While the lab was more challenging due to entity mapping and log inconsistencies, it reinforced real-world skills in log correlation and KQL troubleshooting.
