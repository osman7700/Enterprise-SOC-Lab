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

##  Upcoming Phases
* **Phase 2: Attack Simulation:** Executing specific MITRE ATT&CK techniques (e.g., Brute Force, RDP Hijacking, LSASS dumping) from the Kali Linux machine.
* **Phase 3: Detection Engineering:** Writing custom Splunk SPL (Search Processing Language) queries to build alerts and dashboards for the simulated attacks.

---
##  Technologies Used
* **SIEM:** Splunk Enterprise
* **Endpoints:** Windows Server, Windows 10/11, Kali Linux
* **Telemetry:** Microsoft Sysmon, Windows Event Logs
