# Enterprise SOC Lab & Incident Detection Environment

## Table of Contents
- [Project Overview](#project-overview)
- [Network Architecture](#network-architecture--components)
- [Phase 1: Data Ingestion & Endpoint Telemetry](#phase-1-data-ingestion--endpoint-telemetry-blue-team-setup)
- [Phase 2: Attack Simulation](#phase-2-attack-simulation-rdp-brute-force)
- [Phase 3: Detection Engineering & SIEM Alerting](#phase-3-detection-engineering--siem-alerting-splunk)
- [Key Findings & Results](#key-findings--results)
- [Technologies Used](#technologies-used)
- [Getting Started](#getting-started)
- [Troubleshooting](#troubleshooting)
- [Future Improvements](#future-improvements)

---

## Project Overview

This project demonstrates the design, implementation, and configuration of a functional, self-hosted **Security Operations Center (SOC)** home lab. The environment is engineered to simulate a small enterprise network and showcases the complete workflow from threat detection to incident response.

### Objectives

The primary objectives of this lab are to:

- Understand how malicious activities (generated from an attacker machine) propagate through a network
- Learn how endpoint logging systems capture and record security events
- Develop practical skills in SIEM configuration, log analysis, and detection engineering
- Design and implement correlation rules for real-time threat alerting
- Understand the tools and techniques used in modern Security Operations Centers

---

## Network Architecture & Components

The lab environment consists of four core virtual machines interconnected via a **host-only/NAT isolated network** to ensure a safe testing environment:

```
┌─────────────────────────────────────────────────────────────┐
│                    Isolated Lab Network                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────┐ │
│  │  Windows Server  │  │ Windows 10/11    │  │    Kali    │ │
│  │  (DC + AD)       │  │   (Endpoint)     │  │   Linux    │ │
│  │  - AD DS         │  │  - Domain Member │  │ (Attacker) │ │
│  │  - DNS           │  │  - Splunk UF     │  │            │ │
│  │  - Splunk UF     │  │  - Sysmon        │  └────────────┘ │
│  └──────────────────┘  └──────────────────┘                  │
│           │                     │                             │
│           └─────────┬───────────┘                             │
│                     │                                         │
│            ┌────────▼──────────┐                              │
│            │  Splunk Enterprise│                              │
│            │   (SIEM/Indexer)  │                              │
│            │   Port 9997 (UF)  │                              │
│            │   Port 8000 (Web) │                              │
│            └───────────────────┘                              │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### VMs at a Glance

| VM | Role | Key Services | Purpose |
|---|---|---|---|
| **Windows Server** | Domain Controller & Infrastructure | Active Directory, DNS, Splunk UF | Centralized identity management and log forwarding |
| **Windows 10/11** | Endpoint / Target | Domain Member, Splunk UF, Sysmon | Represents corporate user environment under attack |
| **Kali Linux** | Attacker Platform | Hydra, Nmap, Metasploit | Simulates red team attacks for validation |
| **Splunk Enterprise** | SIEM & Analytics | Central Log Repository, Indexer, Search | Aggregates, indexes, and analyzes all telemetry |

---

## Phase 1: Data Ingestion & Endpoint Telemetry (Blue Team Setup)

To achieve deep visibility into the Windows ecosystem, advanced logging and telemetry collection was configured as follows:

### 1. Active Directory & OS Logging

- **Windows Advanced Audit Policy:** Enabled detailed logging via Group Policy Objects (GPOs) for:
  - Account Management (Event ID 4720-4726)
  - Process Creation (Event ID 4688) - with command-line arguments
  - Logon Events (Event ID 4624 - Successful, 4625 - Failed)
  - Account Logon Events (Event ID 4768-4771)

- **Microsoft Sysmon (System Monitor):** Deployed on both the Windows Server and Windows Workstation using a customized configuration file to capture deep telemetry:
  - Process Creation (Event ID 1)
  - Process Terminated (Event ID 5)
  - Network Connection (Event ID 3)
  - Pipe Created/Connected (Event ID 17, 18)
  - DNS Query (Event ID 22)
  - File Created (Event ID 11)

### 2. Log Forwarding via Splunk Universal Forwarder

- **Installation:** Splunk Universal Forwarder deployed on Windows Workstation and Windows Server
- **outputs.conf Configuration:** Securely forwards data to central Splunk Enterprise instance on port `9997` with SSL encryption
- **inputs.conf Configuration:** Harvests telemetry from:
  - `Security` Windows Event Log (4625, 4624, 4688, etc.)
  - `Application` Windows Event Log
  - `System` Windows Event Log
  - `Microsoft-Windows-Sysmon/Operational` event stream
  - Custom log directories (if applicable)

### 3. Data Flow

```
[Windows Endpoints] → [Sysmon + Event Logs] → [Splunk UF] → [Splunk Enterprise] → [Analysis & Alerting]
```

---

## Phase 2: Attack Simulation (RDP Brute Force)

To validate the effectiveness of the monitoring system, a controlled **RDP Brute Force attack** was executed from the Kali Linux machine against the Windows endpoint.

### Attack Parameters

- **Tool Used:** `Hydra` (or `Crowbar`)
- **Target:** Windows Workstation RDP (Port 3389)
- **Attack Type:** Credential brute force attack

### Attack Command

```bash
hydra -L users.txt -P passwords.txt rdp://<TARGET_IP> -V
```

**Parameters Explained:**
- `-L users.txt` - List of usernames to test
- `-P passwords.txt` - List of passwords to test
- `rdp://` - Target protocol (RDP)
- `-V` - Verbose output

### Expected Results

The attack generates multiple failed logon attempts (Event ID 4625) visible in Windows Security Event Logs, which are captured by Sysmon and forwarded to Splunk.

---

## Phase 3: Detection Engineering & SIEM Alerting (Splunk)

Following the attack simulation, generated logs were analyzed in Splunk Enterprise to design and implement a robust correlation rule for real-time alerting.

### 1. Log Analysis & Telemetry Identification

- **Event Focus:** Windows Security Event ID **4625** (An account failed to log on)
- **Key Fields Extracted:**
  - `TargetUserName` - The account being targeted
  - `src_ip` (IpAddress) - Source IP of the attacker
  - `Logon_Type` - Type 10 indicates RDP interactive network logon
  - `ComputerName` - Target machine
  - `EventID` - 4625 for failed logons

### 2. Custom Splunk SPL Query

Engineered a precise Search Processing Language (SPL) query to detect brute force attacks:

```spl
index=wineventlog EventCode=4625 Logon_Type=10
| stats count by src_ip, TargetUserName
| where count > 10
```

**Query Breakdown:**
1. `index=wineventlog EventCode=4625` - Filter to Windows Event Log failed logons
2. `Logon_Type=10` - Only RDP logons (network interactive)
3. `| stats count by src_ip, TargetUserName` - Count failures per source IP and target user
4. `| where count > 10` - Alert when >10 failures detected in time window

### 3. Alert Configuration

- **Trigger Condition:** Evaluated on a **5-minute scheduled basis**, firing immediately when the threshold (>10 failed attempts) is breached
- **Time Window:** 5-minute rolling window for real-time detection
- **Severity:** Configured as **Medium/High** based on risk alignment
- **Alert Action:** Log alert and notify SOC team via email/Slack

### 4. Mitigation Strategy

In an enterprise production environment, this alert is designed to:

- Trigger an automated **SOAR playbook** to:
  - Block the malicious source IP on the perimeter firewall
  - Isolate the affected endpoint from the network
  - Notify security team for immediate investigation
  - Snapshot event logs for forensic analysis

---

## Key Findings & Results

### Detection Effectiveness

✅ Successfully detected RDP brute force attack within 5-minute window  
✅ Correlation rules identified malicious source IP with high accuracy  
✅ Event ID 4625 combined with network context provided clear attack indicators  

### Attack Progression Observed

1. **Minutes 0-2:** Initial connection attempts (Connection refused / Timeout)
2. **Minutes 2-5:** Failed authentication attempts (Event ID 4625 generated)
3. **Minutes 5+:** Alert triggered upon threshold breach

### Lessons Learned

- **Windows Event Logs alone insufficient** - Needed Sysmon for process-level telemetry
- **Time window tuning is critical** - 5 minutes balanced detection speed vs. false positives
- **Source IP analysis is key** - Multiple failures from single IP = high confidence indicator
- **Authentication logs are gold** - Event ID 4625 is the most valuable telemetry for brute force detection

---

## Technologies Used

| Component | Product | Version | Purpose |
|---|---|---|---|
| **SIEM** | Splunk Enterprise | 9.0+ | Central log aggregation, indexing, and alerting |
| **Endpoint 1** | Windows Server 2019/2022 | Latest | Domain Controller with Active Directory |
| **Endpoint 2** | Windows 10/11 | Latest | Corporate workstation (attack target) |
| **Attacker VM** | Kali Linux | 2024.x | Red team attack platform |
| **Telemetry** | Microsoft Sysmon | v14+ | Advanced system/network monitoring |
| **Telemetry** | Windows Event Logs | Native | OS-level security events |
| **Log Forwarding** | Splunk Universal Forwarder | 9.0+ | Secure log collection and forwarding |
| **Attack Tool** | Hydra | 9.4+ | Password spraying/brute force |
| **Hypervisor** | VirtualBox/VMware | Latest | Lab infrastructure |

### Key Resources

- [Splunk Enterprise Documentation](https://docs.splunk.com/)
- [Microsoft Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Windows Event Log Reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - For attack technique mapping

---

## Getting Started

### Prerequisites

- **Hypervisor:** VirtualBox or VMware with 16+ GB RAM (8 GB minimum for testing)
- **Storage:** 150+ GB free disk space for all VMs
- **Network:** Isolated lab network (no internet exposure)
- **Skills:** Basic Windows administration, Linux command line, networking

### Installation Steps

#### 1. Create Virtual Machines

```bash
# Create host-only or NAT network first
# Then provision 4 VMs with the following specs:

VM1 - Windows Server (DC):
  - RAM: 4 GB
  - vCPUs: 2
  - Disk: 60 GB
  - Network: Isolated Lab Network

VM2 - Windows 10/11 (Endpoint):
  - RAM: 4 GB
  - vCPUs: 2
  - Disk: 60 GB
  - Network: Isolated Lab Network

VM3 - Kali Linux (Attacker):
  - RAM: 4 GB
  - vCPUs: 2
  - Disk: 40 GB
  - Network: Isolated Lab Network

VM4 - Splunk Enterprise (SIEM):
  - RAM: 4 GB
  - vCPUs: 2
  - Disk: 100 GB
  - Network: Isolated Lab Network
```

#### 2. Setup Active Directory

```powershell
# On Windows Server:
Install-WindowsFeature AD-Domain-Services
Install-ADDSForest -DomainName "enterprise-soc.local"
```

#### 3. Deploy Sysmon

```powershell
# Download Sysmon and config from:
# https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with SwiftOnSecurity config:
sysmon.exe -i sysmon-config.xml
```

#### 4. Install Splunk Universal Forwarder

```powershell
# Download from Splunk.com and install:
msiexec.exe /i splunkforwarder-9.0.0-windows-x64.msi AGREETOLICENSE=Yes

# Configure outputs.conf and inputs.conf
# Restart Splunk Forwarder service
```

#### 5. Launch Splunk Enterprise Attack Simulation

```bash
# On Kali Linux:
# Prepare usernames and passwords files, then:
hydra -L users.txt -P passwords.txt rdp://<Windows_IP> -V
```

---

## Troubleshooting

### Issue: Splunk not receiving logs

**Solution:**
1. Verify Splunk Universal Forwarder service is running: `Get-Service SplunkForwarder`
2. Check `$SPLUNK_HOME\etc\system\local\outputs.conf` has correct IP and port
3. Verify firewall allows port 9997 outbound
4. Check Splunk Enterprise is listening: `netstat -an | findstr 9997`

### Issue: Sysmon not capturing events

**Solution:**
1. Verify Sysmon service is running: `Get-Service Sysmon`
2. Check Event Viewer > Applications and Services Logs > Microsoft-Windows-Sysmon
3. Ensure Group Policy has not blocked Sysmon
4. Reinstall with correct config: `sysmon.exe -c sysmon-config.xml`

### Issue: Failed logon events not appearing

**Solution:**
1. Verify Windows Advanced Audit Policy is enabled via `gpresult /h report.html`
2. Check Group Policy: Computer Config > Policies > Windows Settings > Advanced Audit Policy Configuration
3. Event ID 4625 must be logged under Security and Account Logon events
4. Run `gpupdate /force` to refresh policies

---

## Future Improvements

- [ ] **Multi-stage Attack Scenarios:** Implement lateral movement, privilege escalation, and data exfiltration
- [ ] **SOAR Integration:** Add ServiceNow or Demisto playbooks for automated response
- [ ] **Advanced Detection Rules:** Implement MITRE ATT&CK-based correlation searches
- [ ] **Threat Intelligence Integration:** Add ThreatStream or AlienVault OTX feeds to Splunk
- [ ] **Persistence Mechanisms:** Test and detect scheduled tasks, registry modifications, and service installations
- [ ] **Web Application Testing:** Add vulnerable web app for SQL injection and XSS detection
- [ ] **Machine Learning:** Implement Splunk ML Toolkit for anomaly detection
- [ ] **Compliance Mapping:** Map alerts to compliance frameworks (NIST, CIS, SANS)
- [ ] **Documentation:** Add Jupyter notebooks for attack walkthrough analysis
- [ ] **CI/CD Integration:** Automate lab deployment with Terraform/Ansible

---

## Contributing

Feel free to open issues or pull requests to improve this lab guide. Suggestions for additional attack scenarios, detection rules, or documentation improvements are welcome.

## License

This project is provided as-is for educational purposes. Use responsibly.

---

**Last Updated:** June 2026  
**Author:** osman7700
