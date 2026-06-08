# Enterprise SOC Lab & Incident Detection Environment

##  Project Overview
This project demonstrates the design, implementation, and configuration of a functional, self-hosted Security Operations Center (SOC) home lab. The environment is engineered to simulate a small enterprise network, allowing for practical hands-on experience in attack simulation, log ingestion, threat hunting, and blue team detection engineering.

The primary objective of this lab is to understand how malicious activities (generated from an attacker machine) propagate through a network, how they are recorded by endpoint logging systems, and how to centralize and analyze these logs using a SIEM platform.

---

##  Network Architecture & Components
The lab environment consists of four core virtual machines interconnected via a host-only/NAT isolated network to ensure a safe testing environment:

1. **SIEM & Analytics Platform:** Windows Machine hosting **Splunk Enterprise** (Central Log Repository and Indexer).
2. **Domain Controller / Infrastructure:** Windows Server (Active Directory Domain Services, DNS, and Identity Management).
3. **Endpoint / Target:** Windows Workstation (Joined to the Active Directory domain, representing the corporate user environment).
4. **Attacker Platform:** Kali Linux (Used to execute controlled network attacks, credential dumping, and persistence techniques).

---

##  Data Ingestion & Endpoint Telemetry (Blue Team Setup)
To achieve deep visibility into the Windows ecosystem, advanced logging was configured as follows:

### 1. Active Directory & OS Logging
* **Windows Advanced Audit Policy:** Enabled detailed logging for account management, process creation (Event ID 4688), and logon events (Event ID 4624) via Group Policy Objects (GPOs) on the Windows Server.
* **Microsoft Sysmon (System Monitor):** Deployed on both the Windows Server and Windows Workstation using a customized configuration file to capture deep telemetry such as Process Creation (Event ID 1), Network Connections (Event ID 3), and File Creation Time Changes (Event ID 2).

### 2. Log Forwarding via Splunk Universal Forwarder
* Installed the **Splunk Universal Forwarder** on the Windows Workstation and Windows Server.
* Configured `outputs.conf` to securely forward data to the central Splunk Enterprise instance on port `9997`.
* Configured `inputs.conf` on endpoints to harvest:
  * `Security`, `Application`, and `System` Windows Event Logs.
  * `Microsoft-Windows-Sysmon/Operational` event streams.

---

##  Phase 2: Attack Simulation (RDP Brute Force)
To validate the effectiveness of the monitoring system, a controlled RDP Brute Force attack was executed from the **Kali Linux** machine against the **Windows endpoint**.

* **Tool Used:** `Hydra` (or `Crowbar`)
* **Attack Command:**
```bash
hydra -L users.txt -P passwords.txt rdp://<TARGET_IP> -V


Phase 3: Detection Engineering & SIEM Alerting (Splunk)
Following the attack simulation, the generated logs were analyzed inside Splunk Enterprise to design and implement a robust correlation rule for real-time alerting.

1. Log Analysis & Telemetry Identification
Focused on monitoring the Windows Security Event ID 4625 (An account failed to log on).

Extracted and filtered core investigative fields: TargetUserName (targeted account), IpAddress (source attacker IP), and Logon_Type (Type 10, indicating an RDP interactive network logon).

2. Custom Splunk SPL Query
Engineered a precise Search Processing Language (SPL) query designed to trigger an alert if a single source IP generates more than 10 failed logon attempts within a 5-minute time window:


index=wineventlog EventCode=4625 Logon_Type=10
| stats count by src_ip, TargetUserName
| where count > 10

3. Alert Configuration
Trigger Condition: Evaluated on a scheduled basis, firing an alert immediately when the threshold count is breached.

Severity: Configured as Medium/High based on risk alignment.

Mitigation Strategy: In an enterprise production environment, this alert is designed to trigger an automated SOAR playbook to block the malicious source IP on the perimeter firewall and isolate the affected host.

Technologies Used
SIEM: Splunk Enterprise

Endpoints: Windows Server, Windows 10/11, Kali Linux

Telemetry: Microsoft Sysmon, Windows Event Logs
