# EndpointAuditor

A lightweight, zero-telemetry endpoint security auditing tool built in C#. 

EndpointAuditor safely queries the Windows Registry and native PowerShell cmdlets to verify the integrity of critical system configurations. It is designed with a strict "Read-Only" architecture, ensuring the tool can safely evaluate system posture without the risk of accidental modification or system instability.

## 🛡️ Core Security Audits

Currently, Version 1.0 (CLI) checks five high-value targets commonly exploited for privilege escalation and lateral movement:

1. **Windows Defender Real-Time Protection:** Bypasses Tamper Protection via direct API queries to ensure the core antivirus engine has not been disabled by malware.
2. **Windows Firewall Profiles:** Verifies that Domain, Private, and Public network filtering are actively engaged.
3. **User Account Control (UAC):** Validates both the `EnableLUA` core engine state and the UI consent prompt settings to prevent silent administrative executions.
4. **Legacy SMBv1 Protocol:** Scans for the active presence of the SMBv1-Server component, a heavily deprecated protocol vulnerable to the EternalBlue exploit (WannaCry).
5. **Built-in Guest Account:** Ensures the default Windows Guest account is disabled, mitigating a common vector for unauthorized network access.

## 🏗️ Architecture

This application was built using strict **Separation of Concerns**:
* `SecurityAuditor.cs` acts as the standalone engine, handling all logic, try/catch safety nets, and OS-level queries.
* `Program.cs` handles the UI and console outputs. 
This modular design ensures the engine is completely environment-agnostic and ready to be integrated into a broader Graphical User Interface.

## 🚀 How to Run (For Reviewers)

*Note: EndpointAuditor requires Administrative privileges to successfully query locked registry hives (like UAC configurations) and execute native PowerShell modules.*

1. Clone the repository.
2. Open `EndpointAuditor.sln` in Visual Studio.
3. Build the solution in **Release** mode.
4. Run the resulting `EndpointAuditor.exe` as an Administrator. 

## 🗺️ Roadmap
- **Phase 1:** Minimum Viable Product (CLI Engine) - *Completed*
- **Phase 2:** Transition to a polished Graphical User Interface (GUI) dashboard for enhanced usability.
